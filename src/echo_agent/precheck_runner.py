"""사전 점검 러너(AI 에이전트 4): 설정 차이를 규칙으로 비교하고, 모델 검토를 한 번 더해 WAS 에 낸다.

    claim(러너 토큰) → 하트비트 시작(30초) → INPUT_LOAD → 규칙 비교 → CONFIG_DIFF·ANALYZE 이벤트
    → 모델 검토 한 번(ANALYZE 이벤트) → result(실행 토큰) → 하트비트 멈춤

- 결과는 `simulated=false`(실제 `inputSnapshot` 으로 계산한 값), `sandbox=null`(작업 공간
  컨테이너를 쓰지 않음). 모델 검토가 되면 `model={id, effort, promptVersion, refusal}`
  (→ WAS 가 `aiReviewed=true`)과 `origin: "AI"` WARN finding 이 붙는다(`precheck_model.py`).
- 모델이 실패·거절하거나 마감이 가까우면 규칙 결과만으로 `SUCCEEDED`·`model=null`
  (SPEC `specs/ai-4-precheck-model-review.md` D-7·D-8·D-9). `--no-model` 이면 처음부터 규칙만.
- 모델 검토 뒤 규칙 패치 제안 단계가 돈다(`precheck_patch.py`). 기본은 끔이고 `--patch` 로 켠다.
  WAS 가 패치가 실린 결과를 422 `RESULT_INVALID` 로 거절하면 `patches=[]` 로 한 번 다시 낸다.
- 마감(`deadlineAt`) 1분 전이 지나면 분석 결과 대신 `FAILED`·`DEADLINE` 을 낸다(계약 §7).
- 스냅숏 모양이 v1 이 아니면 `FAILED`·`INPUT_INVALID`, 그 밖의 예외는 `FAILED`·`RUNNER_ERROR`.

실행: `ECHO_WAS_URL=… ECHO_RUNNER_TOKEN=… ANTHROPIC_API_KEY=… uv run python -m
echo_agent.precheck_runner --once`
"""

import argparse
import os
import signal
import sys
import threading
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from types import FrameType
from typing import Any

from echo_agent.apply_runner import (
    APPLY_PATCH_KIND,
    ApplyConfigError,
    apply_patch_enabled,
    claim_capabilities,
    process_apply_run,
)
from echo_agent.events import EventLevel, RunEventLog, RunStep
from echo_agent.precheck_model import (
    PROMPT_VERSION,
    ModelConfigError,
    ModelReview,
    PrecheckReviewer,
    ReviewStatus,
)
from echo_agent.precheck_patch import RulePatcher
from echo_agent.precheck_rules import (
    FINDINGS_LIMIT,
    PrecheckAnalysis,
    Severity,
    SnapshotError,
    analyze,
    parse_snapshot,
)
from echo_agent.was_client import (
    ClaimedRun,
    ResultAlreadySubmittedError,
    RunNotActiveError,
    WasClient,
    WasConfigError,
    WasError,
)

DEFAULT_RUNNER_NAME = "echo-sandbox-runner"
HEARTBEAT_INTERVAL_SECONDS = 30.0
DEADLINE_MARGIN = timedelta(minutes=1)
IDLE_SECONDS = 5.0

FAILURE_DEADLINE = "DEADLINE"
FAILURE_INPUT_INVALID = "INPUT_INVALID"
FAILURE_KIND_UNSUPPORTED = "KIND_UNSUPPORTED"
FAILURE_RUNNER_ERROR = "RUNNER_ERROR"

RESULT_INVALID = "RESULT_INVALID"

Clock = Callable[[], datetime]
Logger = Callable[[str], None]


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _stderr(message: str) -> None:
    print(f"[precheck-runner] {message}", file=sys.stderr, flush=True)


@dataclass(frozen=True)
class RunOutcome:
    run_id: str
    status: str  # SUCCEEDED · FAILED · LOST(마감·취소로 WAS 가 닫음) · ALREADY_SUBMITTED
    failure_code: str | None
    submitted: bool
    review: str | None = None  # 모델 검토 상태(ReviewStatus 값), 모델을 안 쓰면 None


# ---------------------------------------------------------------- 결과 만들기


def analyze_run(run: ClaimedRun) -> PrecheckAnalysis:
    """실행 하나의 규칙 분석(모델 없음). 모델 검토는 `_review_with_events` 가 그 뒤에 더한다."""
    return analyze(run.input_snapshot)


def build_result(
    analysis: PrecheckAnalysis | None,
    *,
    status: str,
    failure_code: str | None,
    review: ModelReview | None = None,
    patches: Sequence[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    """`RunResult`(echo-was SPEC §5.3). WAS 는 모르는 칸을 422 로 거절하므로 칸을 더하지 않는다.

    규칙 findings 를 먼저 두고, 모델 검토가 됐을 때만 AI findings·`model` 을 붙인다.
    """
    findings = [f.to_json() for f in analysis.findings] if analysis else []
    model = None
    if analysis is not None and review is not None and review.model is not None:
        model = review.model.to_json()
        findings += [f.to_json() for f in review.findings]
    return {
        "status": status,
        "failureCode": failure_code,
        "simulated": False,
        "sandbox": None,
        "model": model,
        "configDiff": [d.to_json() for d in analysis.config_diff] if analysis else [],
        "featureGaps": [],
        "findings": findings[:FINDINGS_LIMIT],
        "patches": [dict(p) for p in patches] if analysis else [],
        "blockedAttempts": [],
    }


# ---------------------------------------------------------------- 하트비트


class Heartbeat:
    """`interval` 마다 임대를 늘린다. 실행이 닫히면(`RUN_NOT_ACTIVE`) `lost` 를 세운다."""

    def __init__(self, client: WasClient, run: ClaimedRun, *, interval: float, log: Logger) -> None:
        self._client = client
        self._run = run
        self._interval = interval
        self._log = log
        self._stop = threading.Event()
        self.lost = threading.Event()
        self._thread = threading.Thread(target=self._loop, name=f"heartbeat-{run.id}", daemon=True)

    def beat(self) -> None:
        try:
            self._client.heartbeat(self._run)
        except RunNotActiveError:
            self.lost.set()
            self._stop.set()
        except (WasError, OSError) as error:
            # 한 번 실패는 넘긴다. 임대(60초) 안에 다음 하트비트가 다시 늘린다.
            self._log(f"heartbeat failed run={self._run.id}: {type(error).__name__} {error}")

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread.is_alive():
            self._thread.join(timeout=self._interval + 5)

    def _loop(self) -> None:
        while not self._stop.wait(self._interval):
            self.beat()


# ---------------------------------------------------------------- 실행 하나


class _EventSender:
    """쌓인 이벤트 중 아직 안 보낸 것만 보낸다. 실패해도 결과 제출은 계속한다."""

    def __init__(self, client: WasClient, run: ClaimedRun, log: Logger) -> None:
        self.events = RunEventLog(run.id)
        self._client = client
        self._run = run
        self._log = log
        self._sent = 0

    def flush(self) -> None:
        pending = [event.to_json() for event in self.events.events[self._sent :]]
        if not pending:
            return
        try:
            self._client.send_events(self._run, pending)
        except RunNotActiveError:
            raise
        except (WasError, OSError) as error:
            self._log(f"events failed run={self._run.id}: {type(error).__name__} {error}")
            return
        self._sent = len(self.events.events)


def process_run(
    client: WasClient,
    run: ClaimedRun,
    *,
    clock: Clock = _utc_now,
    heartbeat_interval: float = HEARTBEAT_INTERVAL_SECONDS,
    log: Logger = _stderr,
    reviewer: PrecheckReviewer | None = None,
    patcher: RulePatcher | None = None,
) -> RunOutcome:
    """가져간 실행 하나를 끝까지 처리한다. 예외를 밖으로 내지 않는다.

    `reviewer` 가 없으면 규칙 비교만 한다(`--no-model`, PR #14 동작).
    `patcher` 가 없으면 패치 단계를 돌리지 않는다(`--no-patch`).
    """
    if run.kind == APPLY_PATCH_KIND and APPLY_PATCH_KIND in claim_capabilities():
        # 반영 실행(스위치 ECHO_APPLY_PATCH=on 일 때만)은 apply_runner 가 맡는다(SPEC ai-5-2).
        apply_beat = Heartbeat(client, run, interval=heartbeat_interval, log=log)
        apply_events = _EventSender(client, run, log)
        outcome = process_apply_run(client, run, apply_beat, apply_events, clock=clock, log=log)
        return RunOutcome(*outcome)
    heartbeat = Heartbeat(client, run, interval=heartbeat_interval, log=log)
    sender = _EventSender(client, run, log)
    # 첫 하트비트가 CLAIMED → RUNNING 을 만든다(echo-was AD-2).
    heartbeat.beat()
    if heartbeat.lost.is_set():
        return RunOutcome(run.id, "LOST", None, submitted=False)
    heartbeat.start()
    try:
        analysis, status, failure_code = _analyze_with_events(run, sender)
        review = None
        if analysis is not None and reviewer is not None and not heartbeat.lost.is_set():
            # 모델 호출이 길어도 하트비트 스레드가 임대를 늘린다.
            review = _review_with_events(run, analysis, reviewer, sender, clock)
        patches: list[dict[str, Any]] = []
        if analysis is not None and patcher is not None and not heartbeat.lost.is_set():
            # docker 검사가 길어도 하트비트 스레드가 임대를 늘린다.
            cutoff = run.deadline_at - DEADLINE_MARGIN
            patches = patcher.propose(run, sender.events, cutoff - clock(), sender.flush)
            sender.flush()
        review_status = review.status.value if review else None
        if heartbeat.lost.is_set():
            return RunOutcome(run.id, "LOST", None, submitted=False, review=review_status)
        if clock() >= run.deadline_at - DEADLINE_MARGIN:
            sender.events.add(RunStep.ANALYZE, "deadline reached before result", EventLevel.ERROR)
            analysis, status, failure_code, review = None, "FAILED", FAILURE_DEADLINE, None
        sender.flush()
        result = build_result(
            analysis, status=status, failure_code=failure_code, review=review, patches=patches
        )
        stored = _submit_or_resend_without_patches(client, run, result, sender)
        return RunOutcome(
            run.id, stored or status, failure_code, submitted=True, review=review_status
        )
    except RunNotActiveError:
        return RunOutcome(run.id, "LOST", None, submitted=False)
    except ResultAlreadySubmittedError:
        return RunOutcome(run.id, "ALREADY_SUBMITTED", None, submitted=False)
    except (WasError, OSError) as error:
        log(f"result failed run={run.id}: {type(error).__name__} {error}")
        return RunOutcome(run.id, "FAILED", FAILURE_RUNNER_ERROR, submitted=False)
    finally:
        heartbeat.stop()


def _submit_or_resend_without_patches(
    client: WasClient, run: ClaimedRun, result: Mapping[str, Any], sender: _EventSender
) -> str | None:
    """결과를 낸다. 패치가 실린 결과가 422 `RESULT_INVALID` 면 `patches=[]` 로 한 번만 다시 낸다.

    WAS 가 패치 칸을 아직 모르거나(예: `origin`) 패치 하나가 검사에 걸려도 실행 하나를 통째로
    잃지 않게 한다(C-AI-1 증거). 다시 낸 결과도 거절되면 그 오류를 그대로 올린다.
    """
    try:
        return client.submit_result(run, result)
    except WasError as error:
        patches = result.get("patches") or []
        if error.status != 422 or error.code != RESULT_INVALID or not patches:
            raise
        sender.events.add(
            RunStep.PATCH_VERIFY,
            "result rejected; resent without rule patch",
            EventLevel.WARN,
            code=RESULT_INVALID,
            droppedPatches=len(patches),
        )
        sender.flush()
        return client.submit_result(run, {**result, "patches": []})


def _analyze_with_events(
    run: ClaimedRun, sender: _EventSender
) -> tuple[PrecheckAnalysis | None, str, str | None]:
    events = sender.events
    if run.kind != "PRECHECK":
        events.add(RunStep.INPUT_LOAD, "run kind not supported", EventLevel.ERROR, kind=run.kind)
        return None, "FAILED", FAILURE_KIND_UNSUPPORTED
    events.add(
        RunStep.INPUT_LOAD,
        "input snapshot loaded",
        inputHash=run.input_hash,
        schemaVersion=_schema_version(run.input_snapshot),
    )
    sender.flush()
    try:
        analysis = analyze_run(run)
    except SnapshotError as error:
        events.add(
            RunStep.INPUT_LOAD, "input snapshot rejected", EventLevel.ERROR, error=str(error)
        )
        return None, "FAILED", FAILURE_INPUT_INVALID
    except Exception as error:  # noqa: BLE001 — 어떤 실패든 FAILED 결과로 닫는다
        events.add(RunStep.ANALYZE, "precheck failed", EventLevel.ERROR, error=type(error).__name__)
        return None, "FAILED", FAILURE_RUNNER_ERROR

    warn_diffs = sum(1 for d in analysis.config_diff if d.severity is Severity.WARN)
    events.add(
        RunStep.CONFIG_DIFF,
        "config diff computed",
        EventLevel.WARN if warn_diffs else EventLevel.INFO,
        differences=len(analysis.config_diff),
        warnings=warn_diffs,
    )
    events.add(
        RunStep.ANALYZE,
        "rule findings built",
        EventLevel.WARN if analysis.warning_count else EventLevel.INFO,
        findings=len(analysis.findings),
        warnings=analysis.warning_count,
        origin="RULE",
    )
    sender.flush()
    return analysis, "SUCCEEDED", None


def _review_with_events(
    run: ClaimedRun,
    analysis: PrecheckAnalysis,
    reviewer: PrecheckReviewer,
    sender: _EventSender,
    clock: Clock,
) -> ModelReview:
    """모델 검토 한 번. 실패·거절·마감 임박이면 AI 항목 없이 돌려준다(실행은 성공으로 닫힘)."""
    events = sender.events
    seconds_left = (run.deadline_at - clock()).total_seconds()
    if reviewer.timeout_for(seconds_left) is not None:
        events.add(
            RunStep.ANALYZE,
            "model review started",
            model=reviewer.model,
            effort=reviewer.effort,
            promptVersion=PROMPT_VERSION,
        )
        sender.flush()
    review = reviewer.review(
        run.input_snapshot,
        parse_snapshot(run.input_snapshot),
        analysis,
        seconds_left=seconds_left,
    )
    if review.status is ReviewStatus.REVIEWED:
        events.add(
            RunStep.ANALYZE,
            "model review finished",
            EventLevel.WARN if review.warning_count else EventLevel.INFO,
            warnings=review.warning_count,
            **review.detail,
        )
    elif review.status is ReviewStatus.REFUSED:
        events.add(
            RunStep.ANALYZE,
            "model declined; no AI review for this run",
            EventLevel.WARN,
            **review.detail,
        )
    elif review.status is ReviewStatus.SKIPPED:
        events.add(
            RunStep.ANALYZE,
            "model review skipped; deadline too close",
            EventLevel.WARN,
            **review.detail,
        )
    else:
        events.add(
            RunStep.ANALYZE,
            "model review failed; rule result only",
            EventLevel.WARN,
            **review.detail,
        )
    sender.flush()
    return review


def _schema_version(snapshot: Mapping[str, Any]) -> Any:
    return snapshot.get("schemaVersion") if isinstance(snapshot, Mapping) else None


# ---------------------------------------------------------------- 루프·명령줄


def run_loop(
    client: WasClient,
    runner_name: str,
    *,
    once: bool,
    stop: threading.Event,
    idle_seconds: float = IDLE_SECONDS,
    log: Logger = _stderr,
    reviewer: PrecheckReviewer | None = None,
    patcher: RulePatcher | None = None,
) -> int:
    """가져갈 실행이 생길 때마다 처리한다. `--once` 면 한 번 가져가 보고 끝낸다."""
    while not stop.is_set():
        try:
            run = client.claim(runner_name, claim_capabilities())
        except (WasError, OSError) as error:
            log(f"claim failed: {type(error).__name__} {error}")
            if once:
                return 1
            stop.wait(idle_seconds)
            continue
        if run is None:
            if once:
                log("no queued run")
                return 0
            stop.wait(idle_seconds)
            continue
        log(f"claimed run={run.id} kind={run.kind} deadline={run.deadline_at.isoformat()}")
        outcome = process_run(client, run, log=log, reviewer=reviewer, patcher=patcher)
        log(
            f"finished run={outcome.run_id} status={outcome.status} "
            f"failure={outcome.failure_code} submitted={outcome.submitted} "
            f"model_review={outcome.review or 'off'}"
        )
        if once:
            return 0 if outcome.submitted else 1
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m echo_agent.precheck_runner",
        description="출발·도착 환경 설정 차이를 규칙으로 비교하고 모델 검토를 더해 WAS 사전 점검 "
        "결과로 낸다.",
    )
    parser.add_argument("--once", action="store_true", help="한 번만 가져가 보고 끝낸다")
    parser.add_argument(
        "--no-model",
        action="store_true",
        help="모델을 부르지 않고 규칙 비교만 한다(ANTHROPIC_API_KEY 불필요, 결과 model=null)",
    )
    patch_switch = parser.add_mutually_exclusive_group()
    patch_switch.add_argument(
        "--patch",
        action="store_true",
        help="규칙 패치를 켠다(기본은 끔. WAS 가 patches[].origin 을 받는 뒤에만, echo-was #79)",
    )
    patch_switch.add_argument(
        "--no-patch",
        action="store_true",
        help="규칙 패치를 끈다(기본값과 같다. 시작 스크립트가 끔을 분명히 하려고 붙인다)",
    )
    parser.add_argument(
        "--runner-name",
        default=os.environ.get("ECHO_RUNNER_NAME", DEFAULT_RUNNER_NAME),
        help="러너 토큰을 발급할 때 쓴 이름(WAS 가 토큰 이름과 대조)",
    )
    args = parser.parse_args(argv)
    try:
        client = WasClient.from_env()
    except WasConfigError as error:
        _stderr(f"config error: {error}")
        return 2
    try:
        _stderr(f"apply patch: {'on' if apply_patch_enabled() else 'off'}")
    except ApplyConfigError as error:
        _stderr(f"config error: {error}")
        return 2
    reviewer = None
    if not args.no_model:
        try:
            reviewer = PrecheckReviewer.from_env()
        except ModelConfigError as error:
            _stderr(f"config error: {error} (규칙만 돌리려면 --no-model)")
            return 2
    _stderr(f"model review: {reviewer.model + ' ' + reviewer.effort if reviewer else 'off'}")
    patcher = RulePatcher() if args.patch else None
    _stderr(f"rule patch: {'on' if patcher else 'off'}")

    stop = threading.Event()

    def _handle_signal(signum: int, frame: FrameType | None) -> None:
        stop.set()

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)
    return run_loop(
        client, args.runner_name, once=args.once, stop=stop, reviewer=reviewer, patcher=patcher
    )


if __name__ == "__main__":
    raise SystemExit(main())
