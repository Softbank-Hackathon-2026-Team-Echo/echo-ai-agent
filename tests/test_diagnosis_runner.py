"""배포 실패 진단 러너 간단판(SPEC ai-5-diagnosis-simple). 가짜 로그·가짜 모델·가짜 WAS·가짜 docker.

git 은 실제로 부른다(`git apply --check`). 네트워크·모델 호출 없음.
"""

import hashlib
import json
import threading
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from echo_agent import apply_runner, diagnosis_runner
from echo_agent.apply_runner import (
    APPLY_REPOSITORY,
    FAILURE_INPUT_INVALID,
    FAILURE_PATCH_APPLY_FAILED,
    FAILURE_PATCH_TARGET_FORBIDDEN,
    ApplyRunner,
    CommandResult,
    ScenarioBuild,
    claim_capabilities,
    compute_patch_hash,
    diagnosis_enabled,
    parse_apply_input,
    subprocess_runner,
)
from echo_agent.diagnosis_runner import (
    PROCESSING_LOCATION,
    Diagnoser,
    DiagnosisModel,
    DiagnosisRunner,
    LocationHint,
    build_diagnosis_result,
    find_location_hints,
    parse_diagnosis_input,
    resolve_path,
)
from echo_agent.events import RunEventLog
from echo_agent.precheck_runner import PROCESSING_IN_SANDBOX, main, process_run, run_loop
from echo_agent.precheck_runner import PROCESSING_LOCATION as PRECHECK_LOCATION
from echo_agent.was_client import ClaimedRun
from tests.test_was_client import RUN_CRED, RUN_ID, FakeWas, _client, _routes, ok

DEMO_REPO = "Softbank-Hackathon-2026-Team-Echo/echo-demo-app"
COMMIT = "a" * 40
HTML = "app/static/index.html"
TOKEN = "ghp_" + "Z" * 36  # 가리기 시험용 가짜 토큰 모양(실제 값 아님)


def _html(broken: bool = True) -> str:
    lines = [f"<!-- line {n} -->\n" for n in range(1, 119)]
    lines += [
        "    <script>\n",
        "      renderStatus(data;\n" if broken else "      renderStatus(data);\n",
        "    </script>\n",
    ]
    lines += [f"<!-- tail {n} -->\n" for n in range(122, 131)]
    return "".join(lines)


MAIN_PY = "import os\n\n\ndef main():\n    return {'ok': True\n"

MODEL_DIFF = (
    "--- a/app/static/index.html\n"
    "+++ b/app/static/index.html\n"
    "@@ -119,3 +119,3 @@\n"
    "     <script>\n"
    "-      renderStatus(data;\n"
    "+      renderStatus(data);\n"
    "     </script>\n"
)

LOG_TAIL = [
    "INFO starting demo app",
    "INFO frontend check: node --check /app/app/static/index.html",
    f"DEBUG token={TOKEN}",
    "ERROR /app/app/static/index.html:120:23",
    "SyntaxError: missing ) after argument list",
]


def _snapshot(**overrides: Any) -> dict[str, Any]:
    failure: dict[str, Any] = {
        "code": "CONTAINER_START_FAILED",
        "message": "The container kept crashing after it started.",
        "container": "app",
        "containerReason": "CrashLoopBackOff",
        "terminationReason": "Error",
        "exitCode": 1,
        "restartCount": 3,
        "logTail": list(LOG_TAIL),
        "logTruncated": False,
        "previousVersionRunning": True,
    }
    failure.update(overrides.pop("failure", {}))
    snapshot: dict[str, Any] = {
        "schemaVersion": 1,
        "service": {
            "id": "svc-uuid",
            "name": "demo",
            "containerPort": 8080,
            "healthCheckPath": "/healthz",
        },
        "deployRequest": {
            "id": "dr-uuid",
            "environmentId": "env-uuid",
            "trigger": "MANUAL",
            "repo": DEMO_REPO,
            "refType": "BRANCH",
            "refValue": "main",
            "commitSha": COMMIT,
            "errorCode": "CONTAINER_START_FAILED",
            "failedAt": "2026-11-07T00:00:00+00:00",
        },
        "environment": {"id": "env-uuid", "kind": "gcp"},
        "variableKeys": ["DATABASE_URL"],
        "failure": failure,
    }
    snapshot.update(overrides)
    return snapshot


def _claimed(snapshot: Mapping[str, Any], kind: str = "CHANGE_PROPOSAL") -> ClaimedRun:
    return ClaimedRun(
        id=RUN_ID,
        kind=kind,
        org_id="org-1",
        service_id="svc-1",
        source_environment_id=None,
        target_environment_id="env-uuid",
        input_snapshot=snapshot,
        input_hash="sha256:" + "d" * 64,
        scenario_ref=None,
        deadline_at=datetime.now(UTC) + timedelta(minutes=15),
        lease_until=None,
        run_token=RUN_CRED,
    )


def _payload(snapshot: Mapping[str, Any], kind: str = "CHANGE_PROPOSAL") -> dict[str, Any]:
    deadline = datetime.now(UTC) + timedelta(minutes=15)
    return {
        "run": {
            "id": RUN_ID,
            "kind": kind,
            "orgId": "org-1",
            "serviceId": "svc-1",
            "sourceEnvironmentId": None,
            "targetEnvironmentId": "env-uuid",
            "inputSnapshot": dict(snapshot),
            "inputHash": "sha256:" + "d" * 64,
            "scenarioRef": None,
            "deadlineAt": deadline.isoformat().replace("+00:00", "Z"),
            "leaseUntil": None,
        },
        "runToken": RUN_CRED,
    }


def _fetcher(html: str | None = None, *, fail: bool = False) -> Any:
    def fetch(repo: str, commit: str, dest: Path, timeout: float) -> Path:
        if fail:
            raise OSError("network down")
        root = dest / f"echo-demo-app-{commit}"
        (root / "app" / "static").mkdir(parents=True)
        (root / "Dockerfile").write_text("FROM python:3.13-slim\nCOPY app ./app\n", "utf-8")
        (root / "app" / "main.py").write_text(MAIN_PY, "utf-8")
        (root / HTML).write_text(_html() if html is None else html, "utf-8")
        (root / "app" / "static" / "secret.txt").write_text(f"key={TOKEN}\n", "utf-8")
        return root

    return fetch


def _model_output(**overrides: Any) -> str:
    output = {
        "result": "DIAGNOSED",
        "category": "CODE",
        "cause": "app/static/index.html 120번째 줄의 괄호가 닫히지 않았습니다.",
        "fixable": True,
        "diff": MODEL_DIFF,
        "unfixableReason": "",
    }
    output.update(overrides)
    return json.dumps(output, ensure_ascii=False)


def _response(text: str | None = None, stop_reason: str = "end_turn") -> SimpleNamespace:
    return SimpleNamespace(
        stop_reason=stop_reason,
        stop_details=None,
        model="claude-opus-5-5",
        content=[
            SimpleNamespace(type="thinking", thinking=""),
            SimpleNamespace(type="text", text=text if text is not None else _model_output()),
        ],
        usage=SimpleNamespace(input_tokens=4_000, output_tokens=700),
    )


class FakeCreate:
    def __init__(self, result: SimpleNamespace | Exception | None = None) -> None:
        self.result = result if result is not None else _response()
        self.calls: list[dict[str, Any]] = []

    def __call__(self, **kwargs: Any) -> SimpleNamespace:
        self.calls.append(kwargs)
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


def _diagnose(
    tmp_path: Path,
    create: FakeCreate | None,
    snapshot: Mapping[str, Any] | None = None,
    fetch: Any = None,
) -> tuple[str, str | None, Any, RunEventLog]:
    model = DiagnosisModel(create) if create is not None else None
    runner = DiagnosisRunner(
        Diagnoser(model), fetch_source=fetch or _fetcher(), workspace_parent=tmp_path
    )
    events = RunEventLog(RUN_ID)
    status, failure, outcome = runner.execute(
        _claimed(snapshot or _snapshot()), events, lambda: None
    )
    return status, failure, outcome, events


def _messages(events: RunEventLog) -> list[str]:
    return [event.message for event in events.events]


# ---------------------------------------------------------------- 규칙


def test_location_hints_cover_python_js_and_paren_forms() -> None:
    tail = [
        "INFO up on 127.0.0.1:8080 http://host.example.com:443",
        'File "/app/app/main.py", line 5',
        "SyntaxError: '{' was never closed (main.py, line 5)",
        "    at render (/app/app/static/index.html:120:23)",
        'File "/usr/local/lib/python3.13/site-packages/x.py", line 9',
    ]
    hints = find_location_hints(tail)
    found = {(h.raw_path, h.line) for h in hints}
    assert ("/app/app/static/index.html", 120) in found
    assert ("/app/app/main.py", 5) in found
    assert ("main.py", 5) in found
    assert not any("site-packages" in h.raw_path for h in hints)
    assert not any(h.raw_path.startswith("127.0.0") for h in hints)
    # 뒤쪽 줄이 먼저다(역추적의 안쪽·마지막 오류).
    assert hints[0].log_line == 4


def test_resolve_path_strips_container_prefix_and_rejects_unknown() -> None:
    files = frozenset({"app/main.py", HTML})
    assert resolve_path("/app/app/main.py", files) == "app/main.py"
    assert resolve_path("./app/static/index.html", files) == HTML
    assert resolve_path("host.example.com", files) is None
    assert resolve_path("/x/../app/main.py", files) is None


def test_parse_input_reads_v1_and_rejects_other_versions() -> None:
    parsed = parse_diagnosis_input(_snapshot())
    assert (parsed.repo, parsed.commit_sha, len(parsed.log_tail)) == (DEMO_REPO, COMMIT, 5)
    with pytest.raises(diagnosis_runner.DiagnosisInputError):
        parse_diagnosis_input({**_snapshot(), "schemaVersion": 2})
    # 저장소·커밋 모양이 틀리면 None(로그만으로 진단).
    bad = _snapshot()
    bad["deployRequest"] = {**bad["deployRequest"], "repo": "not a repo", "commitSha": "abc"}
    parsed = parse_diagnosis_input(bad)
    assert (parsed.repo, parsed.commit_sha) == (None, None)


# ---------------------------------------------------------------- 모델 진단


def test_model_diagnosis_produces_verified_ai_patch(tmp_path: Path) -> None:
    create = FakeCreate()
    status, failure, outcome, events = _diagnose(tmp_path, create)

    assert (status, failure) == ("SUCCEEDED", None)
    diagnosis = outcome.diagnosis
    assert diagnosis["result"] == "DIAGNOSED" and diagnosis["category"] == "CODE"
    assert diagnosis["fixable"] is True and diagnosis["unfixableReason"] is None
    assert "120" in diagnosis["cause"]
    sources = [(item["source"], item["line"], item["path"]) for item in diagnosis["evidence"]]
    assert ("LOG", 5, None) in sources and ("LOG", 4, None) in sources
    assert ("FILE", 120, HTML) in sources
    (patch,) = outcome.patches
    assert patch["origin"] == "AI" and patch["files"] == [HTML]
    assert patch["patchHash"] == "sha256:" + hashlib.sha256(patch["diff"].encode()).hexdigest()
    assert patch["checks"][0]["name"] == "GIT_APPLY" and patch["checks"][0]["result"] == "PASS"
    assert "+      renderStatus(data);\n" in patch["diff"]
    assert outcome.model.to_json()["promptVersion"] == "diagnosis-simple-v1"
    assert "AI patch applies to the repository" in _messages(events)
    assert _messages(events)[-1] == "diagnosis workspace deleted"
    assert len(create.calls) == 1  # 모델은 한 번만


def test_model_input_is_masked_and_limited_to_window(tmp_path: Path) -> None:
    create = FakeCreate()
    _diagnose(tmp_path, create)
    (call,) = create.calls
    text = call["messages"][0]["content"]
    assert TOKEN not in text and "***" in text
    data = json.loads(text.split("<diagnosis_input>\n", 1)[1].split("\n</diagnosis_input>")[0])
    (window,) = data["files"]
    assert window["path"] == HTML and window["focusLine"] == 120 and window["startLine"] == 60
    assert window["content"].count("\n") == 130 - 60 + 1
    assert [item["line"] for item in data["logTail"]] == [1, 2, 3, 4, 5]
    # ID·변수 이름·저장소 경로는 보내지 않는다.
    for absent in ("svc-uuid", "dr-uuid", "env-uuid", "DATABASE_URL", DEMO_REPO, COMMIT):
        assert absent not in text
    assert "secret.txt" not in text


def test_processing_is_recorded_for_model_call(tmp_path: Path) -> None:
    _, _, outcome, _ = _diagnose(tmp_path, FakeCreate())
    result = build_diagnosis_result(outcome, status="SUCCEEDED", failure_code=None)
    processing = result["processing"]
    assert processing["dataClasses"] == ["CONFIG", "SOURCE_CODE", "LOGS"]
    assert processing["externalTransfer"] is True and processing["externalTransferBytes"] > 0
    assert (processing["location"], processing["sandbox"]) == ("gcp/asia-northeast3", False)
    assert processing["modelProvider"] == "ANTHROPIC" and processing["modelRegion"] is None
    assert (PROCESSING_LOCATION, False) == (PRECHECK_LOCATION, PROCESSING_IN_SANDBOX)
    assert result["model"]["id"] == "claude-opus-5-5"


def test_secret_candidate_left_after_masking_reports_secrets(tmp_path: Path) -> None:
    snapshot = _snapshot(failure={"logTail": [*LOG_TAIL, "key=Q9x7Lm2Pz8Rt4Vb6Nc1Kd3Fg5Hj0Ws9Ty"]})
    _, _, outcome, _ = _diagnose(tmp_path, FakeCreate(), snapshot)
    assert outcome.transfer.data_classes[-1] == "SECRETS"


def test_diff_with_wrong_line_numbers_is_normalized(tmp_path: Path) -> None:
    shifted = MODEL_DIFF.replace("@@ -119,3 +119,3 @@", "@@ -100,3 +100,3 @@")
    _, _, outcome, _ = _diagnose(tmp_path, FakeCreate(_response(_model_output(diff=shifted))))
    (patch,) = outcome.patches
    assert "@@ -117,7 +117,7 @@" in patch["diff"]


@pytest.mark.parametrize(
    ("diff", "reason"),
    [
        (MODEL_DIFF.replace("renderStatus(data;", "renderStatus(dat;"), "GIT_APPLY_CHECK_FAILED"),
        (MODEL_DIFF.replace(HTML, "app/main.py"), "PATH_NOT_ALLOWED"),
        ("not a diff", "PATH_NOT_ALLOWED"),
    ],
)
def test_diff_that_does_not_apply_becomes_insufficient_evidence(
    tmp_path: Path, diff: str, reason: str
) -> None:
    create = FakeCreate(_response(_model_output(diff=diff)))
    status, _, outcome, events = _diagnose(tmp_path, create)
    assert status == "SUCCEEDED"
    diagnosis = outcome.diagnosis
    assert diagnosis["result"] == "INSUFFICIENT_EVIDENCE" and diagnosis["fixable"] is False
    assert diagnosis["category"] is None and diagnosis["cause"] is None
    assert "git apply --check" in diagnosis["unfixableReason"]
    assert outcome.patches == ()
    rejected = [e for e in events.events if e.message.startswith("AI patch rejected")]
    assert rejected and rejected[0].data["reason"] == reason


def test_diagnosed_without_diff_is_unfixable(tmp_path: Path) -> None:
    output = _model_output(diff="", fixable=False, unfixableReason="DB 접속 정보가 필요합니다.")
    _, _, outcome, _ = _diagnose(tmp_path, FakeCreate(_response(output)))
    assert outcome.diagnosis["result"] == "DIAGNOSED" and outcome.diagnosis["fixable"] is False
    assert outcome.diagnosis["unfixableReason"] == "DB 접속 정보가 필요합니다."
    assert outcome.patches == ()


def test_model_insufficient_evidence_has_no_category(tmp_path: Path) -> None:
    output = _model_output(result="INSUFFICIENT_EVIDENCE", diff="", unfixableReason="근거 부족")
    _, _, outcome, _ = _diagnose(tmp_path, FakeCreate(_response(output)))
    assert outcome.diagnosis["result"] == "INSUFFICIENT_EVIDENCE"
    assert outcome.diagnosis["category"] is None and outcome.diagnosis["cause"] is None
    assert outcome.model is not None  # 모델이 답했으므로 model 칸은 있다


def test_model_refusal_falls_back_to_rules_but_records_processing(tmp_path: Path) -> None:
    create = FakeCreate(_response(stop_reason="refusal"))
    _, _, outcome, events = _diagnose(tmp_path, create)
    assert outcome.model is None and outcome.transfer is not None
    assert outcome.diagnosis["result"] == "DIAGNOSED" and outcome.diagnosis["fixable"] is False
    assert "모델 진단을 받지 못했습니다" in outcome.diagnosis["unfixableReason"]
    result = build_diagnosis_result(outcome, status="SUCCEEDED", failure_code=None)
    assert result["model"] is None and "processing" in result
    assert "model diagnosis refused; rule result only" in _messages(events)


def test_model_api_error_falls_back_to_rules(tmp_path: Path) -> None:
    _, _, outcome, _ = _diagnose(tmp_path, FakeCreate(RuntimeError("boom")))
    assert outcome.model is None and outcome.diagnosis["result"] == "DIAGNOSED"


# ---------------------------------------------------------------- 모델 없이(--no-model)


def test_no_model_path_uses_rules_only(tmp_path: Path) -> None:
    status, _, outcome, _ = _diagnose(tmp_path, None)
    assert status == "SUCCEEDED"
    diagnosis = outcome.diagnosis
    assert (diagnosis["result"], diagnosis["category"], diagnosis["fixable"]) == (
        "DIAGNOSED",
        "CODE",
        False,
    )
    assert diagnosis["cause"].startswith(f"{HTML} 120번째 줄에서 문법 오류")
    assert "모델 진단이 꺼져 있습니다" in diagnosis["unfixableReason"]
    result = build_diagnosis_result(outcome, status="SUCCEEDED", failure_code=None)
    assert result["model"] is None and result["patches"] == [] and "processing" not in result


def test_python_traceback_location_without_model(tmp_path: Path) -> None:
    tail = ['  File "/app/app/main.py", line 5', "SyntaxError: '{' was never closed"]
    _, _, outcome, _ = _diagnose(tmp_path, None, _snapshot(failure={"logTail": tail}))
    assert outcome.diagnosis["cause"].startswith("app/main.py 5번째 줄에서 문법 오류")


def test_no_location_is_insufficient_evidence(tmp_path: Path) -> None:
    snapshot = _snapshot(failure={"logTail": ["ERROR connection refused to db:5432"]})
    _, _, outcome, _ = _diagnose(tmp_path, None, snapshot)
    assert outcome.diagnosis["result"] == "INSUFFICIENT_EVIDENCE"
    assert outcome.diagnosis["evidence"][0]["source"] == "LOG"


def test_no_failure_detail_is_no_failure_evidence(tmp_path: Path) -> None:
    _, _, outcome, _ = _diagnose(tmp_path, FakeCreate(), {**_snapshot(), "failure": None})
    assert outcome.diagnosis["result"] == "NO_FAILURE_EVIDENCE"
    assert outcome.transfer is None  # 근거가 없으면 모델도 부르지 않는다


def test_source_unavailable_is_log_only(tmp_path: Path) -> None:
    _, _, outcome, events = _diagnose(tmp_path, None, fetch=_fetcher(fail=True))
    assert outcome.diagnosis["result"] == "INSUFFICIENT_EVIDENCE"
    assert "repository source unavailable; log-only diagnosis" in _messages(events)


def test_bad_snapshot_fails_input_invalid(tmp_path: Path) -> None:
    status, failure, outcome, _ = _diagnose(tmp_path, None, {"schemaVersion": 2})
    assert (status, failure, outcome) == ("FAILED", "INPUT_INVALID", None)
    result = build_diagnosis_result(None, status="FAILED", failure_code="INPUT_INVALID")
    assert "diagnosis" not in result and result["patches"] == []


# ---------------------------------------------------------------- 스위치·claim·결과 전송


def test_diagnosis_switch_defaults_off() -> None:
    assert diagnosis_enabled({}) is False
    assert claim_capabilities({}) == ("PRECHECK",)
    assert claim_capabilities({"ECHO_DIAGNOSIS": "on"}) == ("PRECHECK", "CHANGE_PROPOSAL")
    assert claim_capabilities({"ECHO_DIAGNOSIS": "on", "ECHO_APPLY_PATCH": "on"}) == (
        "PRECHECK",
        "APPLY_PATCH",
        "CHANGE_PROPOSAL",
    )
    assert claim_capabilities({"ECHO_DIAGNOSIS": "yes"}) == ("PRECHECK",)


def test_main_stops_on_diagnosis_switch_typo(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ECHO_WAS_URL", "https://api.example.test")
    monkeypatch.setenv("ECHO_RUNNER_TOKEN", "echo_rnr_" + "r" * 32)
    monkeypatch.setenv("ECHO_DIAGNOSIS", "maybe")
    assert main(["--once", "--no-model"]) == 2


RESULT_KEYS = {
    "status",
    "failureCode",
    "simulated",
    "sandbox",
    "model",
    "configDiff",
    "featureGaps",
    "findings",
    "patches",
    "blockedAttempts",
    "diagnosis",
    "processing",
}


def test_claim_to_result_round_trip_with_switch_on(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ECHO_DIAGNOSIS", "on")
    monkeypatch.setattr(diagnosis_runner, "codeload_fetcher", _fetcher())
    fake = FakeWas(_routes(**{"runs:claim": lambda p, b: ok(_payload(_snapshot()))}))
    diagnoser = Diagnoser(DiagnosisModel(FakeCreate()))
    monkeypatch.setattr(
        diagnosis_runner.DiagnosisRunner,
        "__init__",
        _runner_init_with_parent(tmp_path),
    )

    code = run_loop(
        _client(fake),
        "r",
        once=True,
        stop=threading.Event(),
        log=lambda m: None,
        diagnoser=diagnoser,
    )

    assert code == 0
    assert fake.bodies("runs:claim") == [
        {"runnerId": "r", "capabilities": ["PRECHECK", "CHANGE_PROPOSAL"]}
    ]
    (result,) = fake.bodies("result")
    assert set(result) == RESULT_KEYS
    assert (result["status"], result["simulated"], result["sandbox"]) == ("SUCCEEDED", False, None)
    assert set(result["diagnosis"]) == {
        "result",
        "category",
        "cause",
        "fixable",
        "unfixableReason",
        "evidence",
    }
    (patch,) = result["patches"]
    assert set(patch) == {
        "id",
        "patchHash",
        "files",
        "diff",
        "reason",
        "touchesProtectedFiles",
        "checks",
        "origin",
    }
    steps = [e["step"] for body in fake.bodies("events") for e in body["events"]]
    assert steps[0] == "INPUT_LOAD" and steps[-1] == "SANDBOX_DELETE"
    assert {"SANDBOX_CREATE", "ANALYZE", "PATCH_PROPOSE", "PATCH_VERIFY"} <= set(steps)
    assert TOKEN not in json.dumps(fake.calls)


def test_switch_off_closes_change_proposal_as_unsupported(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ECHO_DIAGNOSIS", raising=False)
    fake = FakeWas(_routes())
    outcome = process_run(_client(fake), _claimed(_snapshot()), log=lambda m: None)
    assert (outcome.status, outcome.failure_code) == ("FAILED", "KIND_UNSUPPORTED")


def _runner_init_with_parent(parent: Path) -> Any:
    original = DiagnosisRunner.__init__

    def init(self: DiagnosisRunner, diagnoser: Diagnoser, **kwargs: Any) -> None:
        kwargs.setdefault("workspace_parent", parent)
        original(self, diagnoser, **kwargs)

    return init


# ---------------------------------------------------------------- 반영(APPLY_PATCH) 서비스 저장소


class FakeTools:
    """docker·trivy 가짜. git 은 실제로 부른다. 빌드 문맥의 파일을 기억한다."""

    def __init__(self, *, build_rc: int = 0) -> None:
        self.build_rc = build_rc
        self.calls: list[list[str]] = []
        self.context_files: dict[str, str] = {}
        self.healthz_env: list[str] = []

    def __call__(
        self, args: Sequence[str], timeout: float, env: Mapping[str, str] | None
    ) -> CommandResult:
        args = list(args)
        if args[0] == "git":
            return subprocess_runner(args, timeout, env)
        self.calls.append(args)
        if args[:2] == ["docker", "version"]:
            return CommandResult(0, "28.5.1\n", "")
        if args[:2] == ["docker", "build"]:
            context = Path(args[-1])
            self.context_files = {
                path.relative_to(context).as_posix(): path.read_text("utf-8")
                for path in context.rglob("*")
                if path.is_file()
            }
            return CommandResult(self.build_rc, "", "")
        if args[:2] == ["docker", "run"]:
            self.healthz_env = [args[i + 1] for i, a in enumerate(args) if a == "--env"]
            return CommandResult(0, "", "")
        if args[0] == "docker":
            return CommandResult(0, "", "")
        if args[:2] == ["trivy", "--version"]:
            return CommandResult(0, json.dumps({"Version": "0.76.1"}), "")
        if args[0] == "trivy":
            return CommandResult(0, json.dumps({"Results": []}), "")
        raise AssertionError(f"unexpected command {args}")


def _apply_snapshot(diff: str = MODEL_DIFF, files: list[str] | None = None) -> dict[str, Any]:
    return {
        "schemaVersion": 1,
        "parentRunId": "11111111-1111-1111-1111-111111111111",
        "patch": {
            "id": "ai-fix-1",
            "patchHash": compute_patch_hash(diff),
            "files": files or [HTML],
            "diff": diff,
            "origin": "AI",
        },
        "repo": DEMO_REPO,
        "branch": f"applied/{RUN_ID}",
        "diagnosis": {
            "deployRequestId": "dr-uuid",
            "environmentId": "env-uuid",
            "sourceCommitSha": COMMIT,
        },
    }


def _apply(tmp_path: Path, snapshot: Mapping[str, Any], tools: FakeTools) -> Any:
    runner = ApplyRunner(
        repo_root=tmp_path,
        run_command=tools,
        fetch_source=_fetcher(),
        workspace_parent=tmp_path,
    )
    events = RunEventLog(RUN_ID)
    return runner.execute(_claimed(snapshot, kind="APPLY_PATCH"), events, lambda: None), events


def test_parse_service_apply_input() -> None:
    spec = parse_apply_input(_claimed(_apply_snapshot(), kind="APPLY_PATCH"))
    assert (spec.repo, spec.source_commit, spec.branch) == (DEMO_REPO, COMMIT, f"applied/{RUN_ID}")
    for broken, reason in (
        ({"diagnosis": {"sourceCommitSha": "abc"}}, "SOURCE_COMMIT_SHA"),
        ({"repo": APPLY_REPOSITORY}, "SERVICE_REPO"),
        ({"repo": "../etc"}, "SERVICE_REPO"),
    ):
        with pytest.raises(apply_runner._ApplyFailed) as caught:
            parse_apply_input(_claimed({**_apply_snapshot(), **broken}, kind="APPLY_PATCH"))
        assert (caught.value.code, caught.value.reason) == (FAILURE_INPUT_INVALID, reason)


def test_service_apply_builds_patched_repo_without_push(tmp_path: Path) -> None:
    tools = FakeTools()
    (status, failure, commit_sha, branch), events = _apply(tmp_path, _apply_snapshot(), tools)

    assert (status, failure, branch) == ("SUCCEEDED", None, f"applied/{RUN_ID}")
    assert commit_sha is not None and len(commit_sha) == 40
    assert "      renderStatus(data);\n" in tools.context_files[HTML]
    assert not any(name.startswith(".git") for name in tools.context_files)
    # echo-demo-app 은 시나리오와 같은 healthz 환경(가짜 DB 주소)으로 띄운다.
    assert "AUTO_MIGRATE=false" in tools.healthz_env
    kinds = [" ".join(call[:2]) for call in tools.calls]
    assert "docker build" in kinds and "trivy image" in kinds and "docker exec" in kinds
    assert not any("push" in call for call in tools.calls)
    assert "apply checks passed" in [event.message for event in events.events]
    assert not list(tmp_path.glob("echo-apply-*"))  # 작업 공간을 지웠다


@pytest.mark.parametrize(
    ("diff", "files", "code"),
    [
        (
            MODEL_DIFF.replace("renderStatus(data;", "renderStatus(x;"),
            None,
            FAILURE_PATCH_APPLY_FAILED,
        ),
        (
            MODEL_DIFF.replace(HTML, ".github/workflows/ci.yml"),
            [".github/workflows/ci.yml"],
            FAILURE_PATCH_TARGET_FORBIDDEN,
        ),
        (MODEL_DIFF, ["app/main.py"], FAILURE_PATCH_TARGET_FORBIDDEN),
    ],
)
def test_service_apply_rejects_bad_patch(
    tmp_path: Path, diff: str, files: list[str] | None, code: str
) -> None:
    tools = FakeTools()
    (status, failure, commit_sha, _), _ = _apply(tmp_path, _apply_snapshot(diff, files), tools)
    assert (status, failure, commit_sha) == ("FAILED", code, None)
    assert not any(call[:2] == ["docker", "build"] for call in tools.calls)


def test_diagnosis_patch_applies_in_apply_runner_end_to_end(tmp_path: Path) -> None:
    """진단이 낸 정규화 diff 가 반영 러너의 엄격한 적용기를 그대로 통과한다.

    모델 diff 의 줄 번호가 틀려도(정규화 전) 반영은 성공해야 한다.
    """
    shifted = MODEL_DIFF.replace("@@ -119,3 +119,3 @@", "@@ -101,3 +101,3 @@")
    _, _, outcome, _ = _diagnose(tmp_path, FakeCreate(_response(_model_output(diff=shifted))))
    (patch,) = outcome.patches
    tools = FakeTools()
    (status, failure, _, _), _ = _apply(tmp_path, _apply_snapshot(patch["diff"]), tools)
    assert (status, failure) == ("SUCCEEDED", None)
    assert tools.context_files[HTML] == _html(broken=False)


def test_unknown_service_repo_uses_default_build() -> None:
    build = apply_runner.service_build("acme/shop", COMMIT)
    assert build == ScenarioBuild("acme/shop", COMMIT, "Dockerfile", 8080, "/healthz")
    demo = apply_runner.service_build(DEMO_REPO, COMMIT)
    assert demo.source_commit == COMMIT and demo.healthz_env["AUTO_MIGRATE"] == "false"


def test_location_hint_dataclass_is_frozen() -> None:
    hint = LocationHint("a.py", 1, 1)
    with pytest.raises(AttributeError):
        hint.line = 2  # type: ignore[misc]
