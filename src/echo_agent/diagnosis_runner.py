"""WAS #101 lifecycle/source adapter with #24's sandbox-verified diagnosis engine.

Fixed commit -> sanitized logs/source -> Claude (up to two calls) -> isolated JS
syntax before/after -> strict patch compatibility -> WAS result. No repository push.
ECHO_DIAGNOSIS is off by default; --no-model uses masked location rules without patches.
"""

import asyncio
import difflib
import os
import re
import shutil
import tarfile
import tempfile
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Any

from echo_agent.apply_runner import (
    CHANGE_PROPOSAL_KIND,
    CommandResult,
    CommandRunner,
    EventSenderLike,
    HeartbeatLike,
    SourceFetcher,
    _ApplyFailed,
    apply_patch_to_files,
    codeload_fetcher,
    compute_patch_hash,
    diagnosis_enabled,
    diff_paths,
    subprocess_runner,
)
from echo_agent.diagnosis import DiagnosisService, SyntaxChecker
from echo_agent.diagnosis_input import (
    ALLOWED_FILE,
    MAX_SOURCE_BYTES,
    PURPOSE,
    DiagnosisError,
    redact,
    sensitive_source_path,
)
from echo_agent.diagnosis_model import DiagnosisModel
from echo_agent.diagnosis_result import to_was_result
from echo_agent.events import EventLevel, RunEventLog, RunStep
from echo_agent.precheck_model import (
    ModelInfo,
    ModelTransfer,
    clean_text,
)
from echo_agent.was_client import (
    ClaimedRun,
    ResultAlreadySubmittedError,
    RunNotActiveError,
    WasClient,
    WasError,
)

DIAGNOSIS_INPUT_SCHEMA_VERSION = 1
DEADLINE_MARGIN = timedelta(minutes=1)  # 계약 §7: 마감 1분 전까지 결과를 낸다

# echo-was `AgentRunDataClass`. 진단은 로그·소스 조각을 보낸다.
# precheck_runner.PROCESSING_LOCATION·PROCESSING_IN_SANDBOX 와 같은 값(순환 import 를 피해 둔다).
PROCESSING_LOCATION = "gcp/asia-northeast3"
PROCESSING_IN_SANDBOX = False
_PROCESSING_MODEL = re.compile(r"[A-Za-z0-9._:/@-]{1,64}")

LOG_TAIL_LIMIT = 50  # 입력 failure.logTail 상한과 같다
MAX_EVIDENCE = 6  # WAS 상한은 20
EVIDENCE_TEXT_LIMIT = 300
SOURCE_FETCH_SECONDS = 60.0
GIT_SECONDS = 30.0
CHECK_GIT_APPLY = "GIT_APPLY"

FAILURE_INPUT_INVALID = "INPUT_INVALID"
FAILURE_DEADLINE = "DEADLINE"
FAILURE_RUNNER_ERROR = "RUNNER_ERROR"


_REPO = re.compile(r"^(?!\.\.?/)[A-Za-z0-9_.-]{1,100}/(?!\.\.?$)[A-Za-z0-9_.-]{1,100}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_SAFE_SEGMENT = re.compile(r"^[A-Za-z0-9._-]+$")  # 반영 러너 check_service_target 과 같은 규칙

# 로그 줄에서 파일·줄 번호를 찾는 규칙(앞의 것이 더 믿을 만하다).
_LOCATION_PATTERNS = (
    # Python 역추적: File "/app/app/main.py", line 42
    re.compile(r'File "(?P<path>[^"]+)", line (?P<line>\d+)'),
    # SyntaxError 메시지 꼬리: (main.py, line 42) · (<path>, line 42)
    re.compile(r"\((?P<path>[^\s(),]+\.[A-Za-z][A-Za-z0-9]{0,7}), line (?P<line>\d+)\)"),
    # 경로:줄[:칸] — JS·Node·컴파일러·린터 공통(at /app/x.js:12:5, index.html:120)
    re.compile(
        r"(?<![A-Za-z0-9_./@-])(?P<path>[A-Za-z0-9_./@-]*[A-Za-z0-9_-]\.[A-Za-z][A-Za-z0-9]{0,7})"
        r":(?P<line>\d+)(?::\d+)?"
    ),
)
_ERROR_LINE = re.compile(
    r"(?i)\b(?:[A-Za-z]*Error|Exception|Traceback|panic|fatal|failed|cannot|unexpected)\b"
)
_SYNTAX_ERROR = re.compile(r"(?i)syntax ?error|unexpected token|was never closed|invalid syntax")
_SKIP_PATH_PARTS = ("site-packages", "dist-packages", "node_modules", "/usr/lib/", "<frozen")
_MAX_LINE_NUMBER = 1_000_000

Clock = Callable[[], datetime]
Logger = Callable[[str], None]


class DiagnosisResult(StrEnum):
    DIAGNOSED = "DIAGNOSED"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    NO_FAILURE_EVIDENCE = "NO_FAILURE_EVIDENCE"


class DiagnosisInputError(Exception):
    """입력 사본 모양이 v1 이 아니다. 메시지는 짧은 사유 코드다."""


# ---------------------------------------------------------------- 입력


@dataclass(frozen=True)
class DiagnosisInput:
    service_name: str | None
    repo: str | None
    commit_sha: str | None
    error_code: str | None
    failure: Mapping[str, Any] | None
    log_tail: tuple[str, ...]
    deploy_request_id: str
    environment: str


def parse_diagnosis_input(snapshot: Any) -> DiagnosisInput:
    """`inputSnapshot` v1(echo-was 「러너 계약」). 모양이 다르면 `DiagnosisInputError`."""
    if not isinstance(snapshot, Mapping):
        raise DiagnosisInputError("SNAPSHOT_NOT_OBJECT")
    if (
        type(snapshot.get("schemaVersion")) is not int
        or snapshot.get("schemaVersion") != DIAGNOSIS_INPUT_SCHEMA_VERSION
    ):
        raise DiagnosisInputError("SCHEMA_VERSION")
    request = snapshot.get("deployRequest")
    if not isinstance(request, Mapping):
        raise DiagnosisInputError("DEPLOY_REQUEST_MISSING")
    failure = snapshot.get("failure")
    if failure is not None and not isinstance(failure, Mapping):
        raise DiagnosisInputError("FAILURE_NOT_OBJECT")
    service = snapshot.get("service")
    name = service.get("name") if isinstance(service, Mapping) else None
    repo = request.get("repo")
    commit = request.get("commitSha")
    raw_tail = failure.get("logTail") if failure is not None else None
    if raw_tail is not None and (
        not isinstance(raw_tail, list)
        or len(raw_tail) > LOG_TAIL_LIMIT
        or any(
            not isinstance(line, str) or len(line) > 2000 or "\n" in line or "\r" in line
            for line in raw_tail
        )
    ):
        raise DiagnosisInputError("LOG_TAIL_INVALID")
    environment = snapshot.get("environment")
    if not isinstance(environment, Mapping):
        raise DiagnosisInputError("ENVIRONMENT_MISSING")
    tail = (
        tuple(str(line) for line in raw_tail[-LOG_TAIL_LIMIT:])
        if isinstance(raw_tail, list)
        else ()
    )
    error_code = request.get("errorCode")
    return DiagnosisInput(
        service_name=name if isinstance(name, str) else None,
        repo=repo if isinstance(repo, str) and _REPO.match(repo) else None,
        commit_sha=commit if isinstance(commit, str) and _COMMIT.match(commit) else None,
        error_code=error_code if isinstance(error_code, str) else None,
        failure=failure,
        log_tail=tail,
        deploy_request_id=str(request.get("id") or ""),
        environment=str(environment.get("kind") or ""),
    )


# ---------------------------------------------------------------- 규칙: 로그 → 위치


@dataclass(frozen=True)
class LocationHint:
    """로그 한 줄에서 찾은 파일·줄 후보. `log_line` 은 logTail 의 1부터 줄 번호."""

    raw_path: str
    line: int
    log_line: int


@dataclass(frozen=True)
class Location:
    """저장소 파일로 확인된 위치."""

    path: str
    line: int
    log_line: int


def find_location_hints(log_tail: Sequence[str]) -> list[LocationHint]:
    """로그에서 파일·줄 후보를 모은다. 뒤쪽 줄(역추적의 안쪽 프레임·마지막 오류)이 앞이다.

    같은 (경로, 줄)은 한 번만. 라이브러리 경로(site-packages·node_modules 등)는 뺀다.
    """
    hints: list[LocationHint] = []
    seen: set[tuple[str, int]] = set()
    for index in range(len(log_tail) - 1, -1, -1):
        text = log_tail[index]
        for pattern in _LOCATION_PATTERNS:
            for match in pattern.finditer(text):
                path = match["path"].strip()
                number = int(match["line"])
                if not 1 <= number <= _MAX_LINE_NUMBER:
                    continue
                if any(part in path for part in _SKIP_PATH_PARTS):
                    continue
                key = (path, number)
                if key in seen:
                    continue
                seen.add(key)
                hints.append(LocationHint(path, number, index + 1))
    return hints


def resolve_path(raw_path: str, repo_files: frozenset[str]) -> str | None:
    """컨테이너 안 경로(`/app/app/main.py`)를 저장소 경로(`app/main.py`)로 맞춘다.

    앞 조각을 하나씩 떼어 저장소 파일 목록과 같은 꼬리를 찾는다(가장 긴 꼬리가 먼저).
    """
    path = raw_path.removeprefix("file://").replace("\\", "/")
    parts = [part for part in path.split("/") if part and part != "."]
    if any(part == ".." for part in parts):
        return None
    for start in range(len(parts)):
        candidate = "/".join(parts[start:])
        if candidate in repo_files:
            return candidate
    return None


def resolve_locations(
    hints: Sequence[LocationHint], repo_files: frozenset[str], line_counts: Mapping[str, int]
) -> list[Location]:
    """저장소에 있는 파일이고 줄 번호가 파일 안이면 위치로 확정한다(후보 순서 그대로)."""
    found: list[Location] = []
    for hint in hints:
        path = resolve_path(hint.raw_path, repo_files)
        if path is None or hint.line > line_counts.get(path, 0):
            continue
        if any(item.path == path and item.line == hint.line for item in found):
            continue
        found.append(Location(path, hint.line, hint.log_line))
    return found


def error_log_line(log_tail: Sequence[str]) -> int | None:
    """오류를 말하는 마지막 로그 줄 번호(1부터). 없으면 None."""
    for index in range(len(log_tail) - 1, -1, -1):
        if _ERROR_LINE.search(log_tail[index]):
            return index + 1
    return None


# ---------------------------------------------------------------- 소스


@dataclass(frozen=True)
class SourceTree:
    """받은 소스(커밋 하나). 파일 목록과 텍스트 파일의 줄 수만 들고 있다."""

    root: Path
    files: frozenset[str]
    line_counts: Mapping[str, int]

    def read_lines(self, path: str) -> list[str]:
        if path not in self.files or sensitive_source_path(path):
            raise ValueError("SOURCE_PATH_FORBIDDEN")
        with (self.root / path).open("rb") as handle:
            data = handle.read(MAX_SOURCE_BYTES + 1)
        if len(data) > MAX_SOURCE_BYTES:
            raise ValueError("SOURCE_TOO_LARGE")
        return data.decode("utf-8").splitlines(keepends=True)


def scan_source(root: Path) -> SourceTree:
    """Exclude sensitive paths before reading; bound selected UTF-8 source bytes."""
    files: set[str] = set()
    counts: dict[str, int] = {}
    total = 0
    for index, path in enumerate(root.rglob("*")):
        if index >= 5000 or len(files) >= 100:
            break
        relative = path.relative_to(root).as_posix()
        if (
            sensitive_source_path(relative)
            or path.is_symlink()
            or not path.is_file()
            or not path.resolve().is_relative_to(root.resolve())
            or any(not _SAFE_SEGMENT.fullmatch(part) for part in relative.split("/"))
        ):
            continue
        try:
            with path.open("rb") as handle:
                data = handle.read(MAX_SOURCE_BYTES + 1)
            if len(data) > MAX_SOURCE_BYTES or total + len(data) > 512 * 1024:
                continue
            text = data.decode("utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        total += len(data)
        files.add(relative)
        counts[relative] = len(text.splitlines())
    return SourceTree(root=root, files=frozenset(files), line_counts=counts)


# ---------------------------------------------------------------- diff 검증·정규화


@dataclass(frozen=True)
class VerifiedPatch:
    path: str
    diff: str  # 정규화한 diff(반영 러너의 엄격한 적용기로 같은 결과)
    git_version: str | None


class PatchRejected(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def verify_model_diff(
    diff: str,
    source: SourceTree,
    allowed_paths: Sequence[str],
    workspace: Path,
    run_command: CommandRunner,
    timeout: float,
) -> VerifiedPatch:
    """모델 diff 가 받은 소스에 실제로 적용되는지 `git apply --check` 로 본다.

    통과하면 적용 결과에서 diff 를 다시 만들고(difflib), 반영 러너의 엄격한 적용기
    (`apply_patch_to_files`)로 같은 결과가 나오는지 확인한다. 안 되면 `PatchRejected`.
    """
    if redact(diff) != diff:
        raise PatchRejected("SECRET_IN_DIFF")
    if not diff.strip():
        raise PatchRejected("EMPTY_DIFF")
    paths = diff_paths(diff)
    if len(paths) != 1 or paths[0] not in allowed_paths or paths[0] not in source.files:
        raise PatchRejected("PATH_NOT_ALLOWED")
    if "/dev/null" in diff.split("\n@@", 1)[0]:
        raise PatchRejected("ADD_OR_DELETE")
    path = paths[0]
    parts = path.split("/")
    if any(not _SAFE_SEGMENT.match(part) or part.startswith(".") for part in parts):
        raise PatchRejected("UNSAFE_PATH")
    original = (source.root / path).read_bytes().decode("utf-8")
    work = workspace / "check"
    target = work / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(original.encode("utf-8"))
    patch_file = workspace / "model.diff"
    patch_file.write_bytes(diff.encode("utf-8") if diff.endswith("\n") else (diff + "\n").encode())
    env = {"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull, "GIT_TERMINAL_PROMPT": "0"}
    version = run_command(["git", "--version"], timeout, env)
    git_version = (
        version.stdout.strip().removeprefix("git version ") if version.returncode == 0 else None
    )
    init = run_command(["git", "-C", str(work), "init", "--quiet"], timeout, env)
    if init.returncode != 0:
        raise PatchRejected("GIT_UNAVAILABLE")
    base = ["git", "-C", str(work), "apply", "--recount", "--whitespace=nowarn", "-p1"]
    checked = run_command([*base, "--check", str(patch_file)], timeout, env)
    if checked.returncode != 0:
        raise PatchRejected("GIT_APPLY_CHECK_FAILED")
    applied = run_command([*base, str(patch_file)], timeout, env)
    if applied.returncode != 0:
        raise PatchRejected("GIT_APPLY_FAILED")
    patched = target.read_bytes().decode("utf-8")
    if patched == original:
        raise PatchRejected("NO_CHANGE")
    canonical = "".join(
        difflib.unified_diff(
            original.splitlines(keepends=True),
            patched.splitlines(keepends=True),
            fromfile=f"a/{path}",
            tofile=f"b/{path}",
        )
    )
    if redact(canonical) != canonical:
        raise PatchRejected("SECRET_IN_DIFF")
    try:
        strict = apply_patch_to_files({path: original}, canonical)
    except _ApplyFailed as failure:
        raise PatchRejected(f"STRICT_APPLY_{failure.reason}") from None
    if strict.get(path) != patched:
        raise PatchRejected("STRICT_APPLY_MISMATCH")
    return VerifiedPatch(path=path, diff=canonical, git_version=git_version)


# ---------------------------------------------------------------- 진단(교체 지점)


@dataclass(frozen=True)
class DiagnosisOutcome:
    """진단 하나의 결과. 러너가 이것으로 `RunResult` + `diagnosis` 를 만든다."""

    diagnosis: dict[str, Any]
    patches: tuple[dict[str, Any], ...] = ()
    model: ModelInfo | None = None
    transfer: ModelTransfer | None = None
    status: str = "SUCCEEDED"
    failure_code: str | None = None
    simulated: bool = False
    location: str = PROCESSING_LOCATION


def _evidence(
    diagnosis_input: DiagnosisInput,
    source: SourceTree | None,
    locations: Sequence[Location],
    error_line: int | None,
) -> list[dict[str, Any]]:
    tail = diagnosis_input.log_tail
    items: list[dict[str, Any]] = []
    log_lines = [error_line] if error_line is not None else []
    log_lines += [location.log_line for location in locations[:2]]
    for number in dict.fromkeys(log_lines):
        text = _evidence_text(tail[number - 1])
        if text:
            items.append({"source": "LOG", "line": number, "path": None, "text": text})
    if source is not None:
        for location in locations[:2]:
            lines = source.read_lines(location.path)
            text = _evidence_text(lines[location.line - 1].rstrip("\n"))
            items.append(
                {
                    "source": "FILE",
                    "line": location.line,
                    "path": location.path,
                    "text": text or "(빈 줄)",
                }
            )
    return items[:MAX_EVIDENCE]


def _evidence_text(text: str) -> str:
    cleaned = clean_text(redact(text))
    return (
        cleaned if len(cleaned) <= EVIDENCE_TEXT_LIMIT else cleaned[: EVIDENCE_TEXT_LIMIT - 1] + "…"
    )


def _diagnosis(
    result: DiagnosisResult,
    *,
    category: str | None = None,
    cause: str | None = None,
    fixable: bool = False,
    unfixable_reason: str | None = None,
    evidence: Sequence[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    return {
        "result": result.value,
        "category": category if result is DiagnosisResult.DIAGNOSED else None,
        "cause": cause if result is DiagnosisResult.DIAGNOSED else None,
        "fixable": fixable,
        "unfixableReason": None if fixable else (unfixable_reason or "수정안이 없습니다."),
        "evidence": [dict(item) for item in evidence],
    }


def rule_diagnosis(
    diagnosis_input: DiagnosisInput,
    locations: Sequence[Location],
    evidence: Sequence[Mapping[str, Any]],
    why_no_fix: str,
) -> dict[str, Any]:
    """모델 없이 규칙만으로 낸 진단. 위치를 찾았으면 DIAGNOSED(수정안 없음), 아니면 근거 부족."""
    tail = diagnosis_input.log_tail
    if not locations:
        return _diagnosis(
            DiagnosisResult.INSUFFICIENT_EVIDENCE,
            unfixable_reason=f"로그에서 저장소 파일·줄 위치를 찾지 못했습니다. {why_no_fix}",
            evidence=evidence,
        )
    first = locations[0]
    error_line = error_log_line(tail)
    message = tail[error_line - 1].strip() if error_line is not None else ""
    syntax = bool(_SYNTAX_ERROR.search(message)) or any(_SYNTAX_ERROR.search(t) for t in tail)
    kind = "문법 오류" if syntax else "오류"
    cause = f"{first.path} {first.line}번째 줄에서 {kind}가 났습니다"
    cause += f": {_evidence_text(message)}" if message else "."
    return _diagnosis(
        DiagnosisResult.DIAGNOSED,
        category="CODE",
        cause=clean_text(cause),
        fixable=False,
        unfixable_reason=f"규칙으로 위치만 찾았고 수정안은 만들지 않았습니다. {why_no_fix}",
        evidence=evidence,
    )


class Diagnoser:
    """WAS #101 adapter for the #24 evidence and sandbox-verified repair engine.

    Automatic repair remains limited to existing classic JS in app/static/index.html.
    Other failures can be diagnosed from logs but do not receive unchecked patches.
    """

    def __init__(
        self,
        model: DiagnosisModel | None,
        *,
        checker: SyntaxChecker | None = None,
        location: str = PROCESSING_LOCATION,
        run_command: CommandRunner | None = None,
    ) -> None:
        self.model = model
        self.checker = checker
        self.location = location
        self._run = run_command or subprocess_runner

    def diagnose(
        self,
        diagnosis_input: DiagnosisInput,
        source: SourceTree | None,
        workspace: Path,
        *,
        seconds_left: float,
        events: RunEventLog,
        flush: Callable[[], None],
    ) -> DiagnosisOutcome:
        deadline = time.monotonic() + seconds_left - DEADLINE_MARGIN.total_seconds()
        tail = diagnosis_input.log_tail
        if diagnosis_input.failure is None or not tail:
            return DiagnosisOutcome(
                _diagnosis(
                    DiagnosisResult.NO_FAILURE_EVIDENCE,
                    unfixable_reason="실패 상세(로그 꼬리)가 없어 진단할 근거가 없습니다.",
                )
            )
        locations = (
            resolve_locations(find_location_hints(tail), source.files, source.line_counts)
            if source
            else []
        )
        if self.model is None:
            return DiagnosisOutcome(
                rule_diagnosis(
                    diagnosis_input,
                    locations,
                    _evidence(diagnosis_input, source, locations, error_log_line(tail)),
                    "모델 진단이 꺼져 있습니다.",
                )
            )
        files = []
        if (
            source
            and ALLOWED_FILE in source.files
            and any(item.path == ALLOWED_FILE for item in locations)
        ):
            files = [{"path": ALLOWED_FILE, "content": "".join(source.read_lines(ALLOWED_FILE))}]
        snapshot = {
            "schemaVersion": 1,
            "purpose": PURPOSE,
            "deployRequestId": diagnosis_input.deploy_request_id,
            "environment": diagnosis_input.environment,
            "sourceCommit": diagnosis_input.commit_sha,
            "sourceFiles": files,
            "allowedFiles": [ALLOWED_FILE],
            "simulated": False,
            "failure": dict(diagnosis_input.failure),
            "logs": [
                {
                    "id": "container-tail",
                    "stage": "runtime",
                    "lines": list(tail),
                    "sourceLineStart": None,
                    "truncated": diagnosis_input.failure.get("logTruncated", False),
                }
            ],
        }
        service = DiagnosisService(self.model, self.checker, location=self.location)
        internal = asyncio.run(
            service.execute(
                snapshot,
                seconds=seconds_left - DEADLINE_MARGIN.total_seconds(),
                events=events,
                flush=flush,
            )
        )
        try:
            public = to_was_result(internal, log_tail=True)
        except DiagnosisError:
            public = {
                **internal,
                "status": "FAILED",
                "failureCode": "INVALID_DIAGNOSIS_RESULT",
                "patches": [],
                "diagnosis": _diagnosis(
                    DiagnosisResult.INSUFFICIENT_EVIDENCE,
                    unfixable_reason="진단 결과 계약 검증에 실패했습니다.",
                ),
            }
        # Ensure the actual returned diff also works with #25's strict apply engine.
        if public["patches"]:
            try:
                if source is None:
                    raise PatchRejected("SOURCE_UNAVAILABLE")
                for patch in public["patches"]:
                    left = deadline - time.monotonic()
                    if left <= 0:
                        raise PatchRejected("DEADLINE")
                    verified = verify_model_diff(
                        patch["diff"],
                        source,
                        [ALLOWED_FILE],
                        workspace,
                        self._run,
                        min(GIT_SECONDS, left / 5),
                    )
                    patch["diff"] = verified.diff
                    patch["patchHash"] = compute_patch_hash(verified.diff)
                    patch["checks"].append(
                        {
                            "name": CHECK_GIT_APPLY,
                            "result": "PASS",
                            "summary": "실패 커밋 적용 및 엄격한 적용기와의 일치를 확인했습니다.",
                        }
                    )
            except (PatchRejected, OSError):
                public["patches"] = []
                public["diagnosis"].update(
                    fixable=False,
                    unfixableReason="수정안의 최종 적용·비밀값 검사를 통과하지 못했습니다.",
                )
        model_data = public.get("model")
        model = (
            ModelInfo(model_data["id"], model_data["effort"], model_data["promptVersion"])
            if model_data
            else None
        )
        transfer_data = public.get("processing")
        transfer = (
            ModelTransfer(
                transfer_data["modelProvider"],
                transfer_data["model"],
                transfer_data["modelRegion"],
                tuple(transfer_data["dataClasses"]),
                transfer_data["externalTransferBytes"],
            )
            if transfer_data
            else None
        )
        return DiagnosisOutcome(
            public.get("diagnosis") or _diagnosis(DiagnosisResult.INSUFFICIENT_EVIDENCE),
            tuple(public["patches"]),
            model,
            transfer,
            status=public["status"],
            failure_code=public["failureCode"],
            simulated=public["simulated"],
            location=self.location,
        )


# ---------------------------------------------------------------- 결과


def build_processing(transfer: ModelTransfer | None) -> dict[str, Any] | None:
    """레지던시 기록(echo-was `RunProcessingRequest`). 요청을 보냈을 때만 만든다."""
    if transfer is None or not _PROCESSING_MODEL.fullmatch(transfer.model):
        return None
    return {
        "location": PROCESSING_LOCATION,
        "sandbox": PROCESSING_IN_SANDBOX,
        "modelProvider": transfer.provider,
        "model": transfer.model,
        "modelRegion": transfer.region,
        "dataClasses": list(transfer.data_classes),
        "externalTransfer": True,
        "externalTransferBytes": transfer.request_bytes,
    }


def build_diagnosis_result(
    outcome: DiagnosisOutcome | None,
    *,
    status: str,
    failure_code: str | None,
    transfer: ModelTransfer | None = None,
) -> dict[str, Any]:
    """`RunResult` + `diagnosis`(echo-was `DiagnosisRunResultRequest`). 칸을 더하지 않는다.

    실패(`FAILED`)면 diagnosis 를 빼고 낸다(WAS 가 "Diagnosis run failed: <code>" 로 저장).
    """
    result: dict[str, Any] = {
        "status": status,
        "failureCode": failure_code,
        "simulated": outcome.simulated if outcome else False,
        "sandbox": None,
        "model": outcome.model.to_json() if outcome and outcome.model else None,
        "configDiff": [],
        "featureGaps": [],
        "findings": [],
        "patches": [dict(p) for p in outcome.patches] if outcome else [],
        "blockedAttempts": [],
    }
    if outcome is not None:
        result["diagnosis"] = outcome.diagnosis
    if transfer is None and outcome is not None:
        transfer = outcome.transfer
    processing = build_processing(transfer)
    if processing is not None:
        if outcome:
            processing["location"] = outcome.location
        result["processing"] = processing
    return result


# ---------------------------------------------------------------- 실행 하나


class DiagnosisRunner:
    """진단 실행 하나의 일(입력 → 소스 받기 → 진단 → 정리). 바꿔 끼울 수 있다(시험)."""

    def __init__(
        self,
        diagnoser: Diagnoser,
        *,
        fetch_source: SourceFetcher | None = None,
        clock: Clock | None = None,
        workspace_parent: Path | None = None,
    ) -> None:
        self.diagnoser = diagnoser
        self._fetch = fetch_source or codeload_fetcher
        self._clock = clock or (lambda: datetime.now(UTC))
        self._workspace_parent = workspace_parent

    def execute(
        self, run: ClaimedRun, events: RunEventLog, flush: Callable[[], None]
    ) -> tuple[str, str | None, DiagnosisOutcome | None]:
        """(status, failureCode, outcome). 예외를 밖으로 내지 않는다."""
        if self._clock() >= run.deadline_at - DEADLINE_MARGIN:
            return "FAILED", FAILURE_DEADLINE, None
        try:
            diagnosis_input = parse_diagnosis_input(run.input_snapshot)
        except DiagnosisInputError as error:
            events.add(
                RunStep.INPUT_LOAD, "input snapshot rejected", EventLevel.ERROR, error=str(error)
            )
            return "FAILED", FAILURE_INPUT_INVALID, None
        events.add(
            RunStep.INPUT_LOAD,
            "diagnosis input loaded",
            inputHash=run.input_hash,
            schemaVersion=DIAGNOSIS_INPUT_SCHEMA_VERSION,
            repo=diagnosis_input.repo,
            commitSha=diagnosis_input.commit_sha,
            failureCode=(diagnosis_input.failure or {}).get("code"),
            logLines=len(diagnosis_input.log_tail),
        )
        flush()
        workspace = Path(
            tempfile.mkdtemp(prefix=f"echo-diagnosis-{run.id[:8]}-", dir=self._workspace_parent)
        )
        try:
            source = self._fetch_source(run, diagnosis_input, workspace, events)
            flush()
            seconds_left = (run.deadline_at - self._clock()).total_seconds()
            outcome = self.diagnoser.diagnose(
                diagnosis_input,
                source,
                workspace,
                seconds_left=seconds_left,
                events=events,
                flush=flush,
            )
            return outcome.status, outcome.failure_code, outcome
        except (RunNotActiveError, ResultAlreadySubmittedError):
            raise
        except Exception as error:  # noqa: BLE001 — 어떤 실패든 FAILED 결과로 닫는다
            events.add(
                RunStep.ANALYZE, "diagnosis failed", EventLevel.ERROR, error=type(error).__name__
            )
            return "FAILED", FAILURE_RUNNER_ERROR, None
        finally:
            shutil.rmtree(workspace, ignore_errors=True)
            events.add(RunStep.SANDBOX_DELETE, "diagnosis workspace deleted", pushed=False)

    def _fetch_source(
        self,
        run: ClaimedRun,
        diagnosis_input: DiagnosisInput,
        workspace: Path,
        events: RunEventLog,
    ) -> SourceTree | None:
        """서비스 저장소의 실패 커밋 소스(읽기만). 없거나 못 받으면 None(로그만으로 진단)."""
        if diagnosis_input.repo is None or diagnosis_input.commit_sha is None:
            events.add(
                RunStep.SANDBOX_CREATE,
                "no repository or commit; log-only diagnosis",
                EventLevel.WARN,
            )
            return None
        left = (run.deadline_at - DEADLINE_MARGIN - self._clock()).total_seconds()
        try:
            root = self._fetch(
                diagnosis_input.repo,
                diagnosis_input.commit_sha,
                workspace / "source",
                max(1.0, min(SOURCE_FETCH_SECONDS, left)),
            )
            source = scan_source(root)
        except (_ApplyFailed, OSError, tarfile.TarError, ValueError) as error:
            events.add(
                RunStep.SANDBOX_CREATE,
                "repository source unavailable; log-only diagnosis",
                EventLevel.WARN,
                error=type(error).__name__,
            )
            return None
        events.add(
            RunStep.SANDBOX_CREATE,
            "repository source fetched",
            repo=diagnosis_input.repo,
            commitSha=diagnosis_input.commit_sha,
            files=len(source.files),
            credentials="none",
        )
        return source


def process_diagnosis_run(
    client: WasClient,
    run: ClaimedRun,
    heartbeat: HeartbeatLike,
    sender: EventSenderLike,
    *,
    diagnoser: Diagnoser,
    clock: Clock | None = None,
    log: Logger = lambda message: None,
    runner: DiagnosisRunner | None = None,
) -> tuple[str, str, str | None, bool, str | None]:
    """진단 실행 하나를 끝까지 처리한다(run_id, status, failureCode, submitted, 모델 상태).

    하트비트·이벤트 보내기는 사전 점검 러너의 것을 그대로 받아 쓴다.
    """
    clock = clock or (lambda: datetime.now(UTC))
    runner = runner or DiagnosisRunner(diagnoser, clock=clock)
    heartbeat.beat()  # 첫 하트비트가 CLAIMED → RUNNING 을 만든다(echo-was AD-2).
    if heartbeat.lost.is_set():
        return run.id, "LOST", None, False, None
    heartbeat.start()

    def flush() -> None:
        if heartbeat.lost.is_set():
            raise RunNotActiveError(409, "RUN_NOT_ACTIVE")
        sender.flush()

    try:
        status, failure_code, outcome = runner.execute(run, sender.events, flush)
        review = (
            ("REVIEWED" if outcome.model else "OFF" if diagnoser.model is None else "NOT_REVIEWED")
            if outcome
            else None
        )
        if heartbeat.lost.is_set():
            return run.id, "LOST", None, False, review
        transfer = outcome.transfer if outcome else None
        if clock() >= run.deadline_at - DEADLINE_MARGIN:
            sender.events.add(RunStep.ANALYZE, "deadline reached before result", EventLevel.ERROR)
            status, failure_code, outcome = "FAILED", FAILURE_DEADLINE, None
        sender.flush()
        result = build_diagnosis_result(
            outcome, status=status, failure_code=failure_code, transfer=transfer
        )
        stored = client.submit_result(run, result)
        return run.id, stored or status, failure_code, True, review
    except RunNotActiveError:
        return run.id, "LOST", None, False, None
    except ResultAlreadySubmittedError:
        return run.id, "ALREADY_SUBMITTED", None, False, None
    except (WasError, OSError) as error:
        log(f"diagnosis result failed run={run.id}: {type(error).__name__} {error}")
        return run.id, "FAILED", FAILURE_RUNNER_ERROR, False, None
    finally:
        heartbeat.stop()


# 시험·다른 모듈이 쓰는 이름(외부에서 apply_runner 를 따로 import 하지 않게).
__all__ = [
    "CHANGE_PROPOSAL_KIND",
    "CommandResult",
    "Diagnoser",
    "DiagnosisModel",
    "DiagnosisOutcome",
    "DiagnosisRunner",
    "build_diagnosis_result",
    "diagnosis_enabled",
    "find_location_hints",
    "parse_diagnosis_input",
    "process_diagnosis_run",
    "resolve_path",
    "verify_model_diff",
]
