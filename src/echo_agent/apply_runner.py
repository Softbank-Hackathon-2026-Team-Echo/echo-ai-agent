"""반영 실행 러너(AI 에이전트 5-2 초안): 사람이 승인한 패치를 샌드박스에서 적용·빌드·스캔한다.

    claim(`APPLY_PATCH`) → 하트비트 → INPUT_LOAD(입력·patchHash 재계산) → SANDBOX_CREATE(작업 사본)
    → PATCH_VERIFY(패치 적용·로컬 커밋·이미지 빌드·Trivy·healthz) → SANDBOX_DELETE → result

- 계약: 부록 A v1 2.1절(`APPLY_PATCH` 결과 `{appliedCommitSha, branch}`)·4절(반영 대상은
  echo-ai-agent 시나리오 사본 브랜치 `applied/<runId>` 뿐, 승인 때 `patchHash` 와 다시 계산한 해시가
  같을 때만). 입력 모양은 echo-was SPEC `api-10-patch-approval.md` PD-6. SPEC
  `specs/ai-5-2-apply-patch-runner.md`.
- **push 하지 않는다.** 샌드박스에는 읽기 자격만 있다(배포 키 없음). 커밋은 작업 사본 안에서만
  만들고 원격(origin)을 지운다. 이미지도 push 하지 않고 끝나면 지운다.
- 결과 칸은 계약 2.1절 두 칸 + 모든 결과의 공통 칸(`status`·`failureCode`·`simulated`)뿐이다.
  빌드·스캔·healthz 결과는 결과 칸이 계약에 없어 이벤트 `data` 에만 남긴다.
- 스위치 `ECHO_APPLY_PATCH`(기본 off). 꺼져 있으면 `APPLY_PATCH` 를 claim 하지 않는다.
- 셸을 거치지 않는다. 외부 명령은 인자 목록으로만 부른다.
"""

import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
import threading
import time
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Protocol

from echo_agent.diagnosis_input import redact, sensitive_source_path
from echo_agent.events import EventLevel, RunEventLog, RunStep
from echo_agent.was_client import (
    ClaimedRun,
    ResultAlreadySubmittedError,
    RunNotActiveError,
    WasClient,
    WasError,
)

APPLY_PATCH_KIND = "APPLY_PATCH"
PRECHECK_KIND = "PRECHECK"
CHANGE_PROPOSAL_KIND = "CHANGE_PROPOSAL"
SWITCH_ENV = "ECHO_APPLY_PATCH"
DIAGNOSIS_SWITCH_ENV = "ECHO_DIAGNOSIS"
REPO_ROOT_ENV = "ECHO_APPLY_REPO_ROOT"

APPLY_INPUT_SCHEMA_VERSION = 1
APPLY_REPOSITORY = "Softbank-Hackathon-2026-Team-Echo/echo-ai-agent"
BRANCH_PREFIX = "applied/"
SCENARIOS_DIR = "scenarios"
DEADLINE_MARGIN = timedelta(minutes=1)  # 계약 §7: 마감 1분 전까지 결과를 낸다

FAILURE_INPUT_INVALID = "INPUT_INVALID"
FAILURE_PATCH_HASH_MISMATCH = "PATCH_HASH_MISMATCH"
FAILURE_PATCH_TARGET_FORBIDDEN = "PATCH_TARGET_FORBIDDEN"
FAILURE_PATCH_APPLY_FAILED = "PATCH_APPLY_FAILED"
FAILURE_VERIFY_UNAVAILABLE = "VERIFY_UNAVAILABLE"
FAILURE_SOURCE_UNAVAILABLE = "SOURCE_UNAVAILABLE"
FAILURE_IMAGE_BUILD_FAILED = "IMAGE_BUILD_FAILED"
FAILURE_IMAGE_SCAN_FAILED = "IMAGE_SCAN_FAILED"
FAILURE_HEALTHZ_FAILED = "HEALTHZ_FAILED"
FAILURE_DEADLINE = "DEADLINE"
FAILURE_RUNNER_ERROR = "RUNNER_ERROR"
_INPUT_FAILURES = frozenset(
    {FAILURE_INPUT_INVALID, FAILURE_PATCH_HASH_MISMATCH, FAILURE_PATCH_TARGET_FORBIDDEN}
)

# 단계별 시간 상한(초). 실제 상한은 이것과 "마감 1분 전까지 남은 시간" 중 작은 값이다.
TOOL_PROBE_SECONDS = 10.0
GIT_SECONDS = 60.0
SOURCE_FETCH_SECONDS = 60.0
BUILD_SECONDS = 420.0
SCAN_SECONDS = 300.0
HEALTHZ_SECONDS = 45.0
HEALTHZ_POLL_SECONDS = 1.5
CLEANUP_SECONDS = 30.0
SOURCE_ARCHIVE_LIMIT = 50 * 1024 * 1024
OUTPUT_TAIL = 400

# C-IMG-1 과 같은 기준: 수정 가능한(FixedVersion 있음) HIGH·CRITICAL 이 0 이어야 PASS.
SCAN_SEVERITIES = ("HIGH", "CRITICAL")

COMMIT_AUTHOR_NAME = "Echo AI Runner"
COMMIT_AUTHOR_EMAIL = "echo-ai-runner@echoport.invalid"

_SAFE_SEGMENT = re.compile(r"^[A-Za-z0-9._-]+$")
_HUNK_HEADER = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_COMMIT_SHA = re.compile(r"^[0-9a-f]{40}$")
_SERVICE_REPO = re.compile(r"^(?!\.\.?/)[A-Za-z0-9_.-]{1,100}/(?!\.\.?$)[A-Za-z0-9_.-]{1,100}$")

Clock = Callable[[], datetime]
Logger = Callable[[str], None]


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


# (인자 목록, 시간 제한 초, 더할 환경 변수) → 결과. 시험에서 가짜로 바꿔 끼운다.
CommandRunner = Callable[[Sequence[str], float, Mapping[str, str] | None], CommandResult]
# (저장소, 커밋, 풀 곳, 시간 제한 초) → 소스 루트. 시험에서 가짜로 바꿔 끼운다.
SourceFetcher = Callable[[str, str, Path, float], Path]


class ApplyConfigError(Exception):
    """스위치 값이 on·off 가 아니다."""


class _ApplyFailed(Exception):
    """반영 실행을 FAILED 로 닫는다. `code` 가 `failureCode` 가 된다."""

    def __init__(self, code: str, reason: str) -> None:
        super().__init__(f"{code}: {reason}")
        self.code = code
        self.reason = reason


class HeartbeatLike(Protocol):
    lost: threading.Event

    def beat(self) -> None: ...

    def start(self) -> None: ...

    def stop(self) -> None: ...


class EventSenderLike(Protocol):
    events: RunEventLog

    def flush(self) -> None: ...


# ---------------------------------------------------------------- 스위치


def apply_patch_enabled(env: Mapping[str, str] | None = None) -> bool:
    """`ECHO_APPLY_PATCH` = on|off(없으면 off). 그 밖의 값은 설정 오류다."""
    env = os.environ if env is None else env
    value = env.get(SWITCH_ENV, "off").strip().lower() or "off"
    if value not in {"on", "off"}:
        raise ApplyConfigError(f"{SWITCH_ENV} must be on or off")
    return value == "on"


def diagnosis_enabled(env: Mapping[str, str] | None = None) -> bool:
    """`ECHO_DIAGNOSIS` = on|off(없으면 off). 그 밖의 값은 설정 오류다.

    SPEC `specs/ai-5-diagnosis-simple.md`.
    """
    env = os.environ if env is None else env
    value = env.get(DIAGNOSIS_SWITCH_ENV, "off").strip().lower() or "off"
    if value not in {"on", "off"}:
        raise ApplyConfigError(f"{DIAGNOSIS_SWITCH_ENV} must be on or off")
    return value == "on"


def claim_capabilities(env: Mapping[str, str] | None = None) -> tuple[str, ...]:
    """claim 에 실을 종류. 스위치가 둘 다 꺼져 있으면 지금과 같은 `("PRECHECK",)`."""
    kinds = [PRECHECK_KIND]
    for kind, switch in (
        (APPLY_PATCH_KIND, apply_patch_enabled),
        (CHANGE_PROPOSAL_KIND, diagnosis_enabled),
    ):
        try:
            enabled = switch(env)
        except ApplyConfigError:
            enabled = False  # 시작할 때 main 이 먼저 거른다. 여기서는 꺼진 쪽으로만 간다.
        if enabled:
            kinds.append(kind)
    return tuple(kinds)


# ---------------------------------------------------------------- 입력·해시·대상


@dataclass(frozen=True)
class ApplyInput:
    parent_run_id: str
    patch_id: str
    patch_hash: str
    files: tuple[str, ...]
    diff: str
    origin: str
    repo: str
    branch: str
    # 배포 실패 진단의 패치면 서비스 저장소의 실패 커밋(echo-was SPEC api-98). 아니면 None.
    source_commit: str | None = None


def compute_patch_hash(diff: str) -> str:
    """승인 지문의 `patchHash`: `sha256:` + diff UTF-8 바이트의 SHA-256(PD-14, #18 과 같음)."""
    return "sha256:" + hashlib.sha256(diff.encode("utf-8")).hexdigest()


def parse_apply_input(run: ClaimedRun) -> ApplyInput:
    """`inputSnapshot` v1(PD-6). 모양이 다르면 `INPUT_INVALID`."""
    snapshot = run.input_snapshot
    if not isinstance(snapshot, Mapping):
        raise _ApplyFailed(FAILURE_INPUT_INVALID, "SNAPSHOT_NOT_OBJECT")
    if snapshot.get("schemaVersion") != APPLY_INPUT_SCHEMA_VERSION:
        raise _ApplyFailed(FAILURE_INPUT_INVALID, "SCHEMA_VERSION")
    patch = snapshot.get("patch")
    if not isinstance(patch, Mapping):
        raise _ApplyFailed(FAILURE_INPUT_INVALID, "PATCH_MISSING")
    parent = snapshot.get("parentRunId")
    repo = snapshot.get("repo")
    branch = snapshot.get("branch")
    patch_id = patch.get("id")
    patch_hash = patch.get("patchHash")
    files = patch.get("files")
    diff = patch.get("diff")
    origin = patch.get("origin", "AI")
    if not isinstance(parent, str) or not parent:
        raise _ApplyFailed(FAILURE_INPUT_INVALID, "PARENT_RUN_ID")
    if not isinstance(patch_id, str) or not patch_id:
        raise _ApplyFailed(FAILURE_INPUT_INVALID, "PATCH_ID")
    if not isinstance(patch_hash, str) or not _DIGEST.match(patch_hash):
        raise _ApplyFailed(FAILURE_INPUT_INVALID, "PATCH_HASH_FORMAT")
    if (
        not isinstance(files, list)
        or not files
        or not all(isinstance(name, str) and name for name in files)
    ):
        raise _ApplyFailed(FAILURE_INPUT_INVALID, "PATCH_FILES")
    if not isinstance(diff, str) or not diff:
        raise _ApplyFailed(FAILURE_INPUT_INVALID, "PATCH_DIFF")
    if origin not in {"RULE", "AI"}:
        raise _ApplyFailed(FAILURE_INPUT_INVALID, "PATCH_ORIGIN")
    diagnosis = snapshot.get("diagnosis")
    if diagnosis is not None:
        # 배포 실패 진단의 패치: 서비스 저장소 + 실패 커밋에서 적용·검증한다(SPEC ai-5-diagnosis).
        if not isinstance(diagnosis, Mapping):
            raise _ApplyFailed(FAILURE_INPUT_INVALID, "DIAGNOSIS_NOT_OBJECT")
        source_commit = diagnosis.get("sourceCommitSha")
        if not isinstance(source_commit, str) or not _COMMIT_SHA.match(source_commit):
            raise _ApplyFailed(FAILURE_INPUT_INVALID, "SOURCE_COMMIT_SHA")
        if not isinstance(repo, str) or not _SERVICE_REPO.match(repo) or repo == APPLY_REPOSITORY:
            raise _ApplyFailed(FAILURE_INPUT_INVALID, "SERVICE_REPO")
        if branch != f"{BRANCH_PREFIX}{run.id}":
            raise _ApplyFailed(FAILURE_INPUT_INVALID, "BRANCH_NOT_RUN_ID")
        return ApplyInput(
            parent_run_id=parent,
            patch_id=patch_id,
            patch_hash=patch_hash,
            files=tuple(files),
            diff=diff,
            origin=str(origin),
            repo=repo,
            branch=f"{BRANCH_PREFIX}{run.id}",
            source_commit=source_commit,
        )
    if repo != APPLY_REPOSITORY:
        raise _ApplyFailed(FAILURE_INPUT_INVALID, "REPO_NOT_ALLOWED")
    if branch != f"{BRANCH_PREFIX}{run.id}":
        raise _ApplyFailed(FAILURE_INPUT_INVALID, "BRANCH_NOT_RUN_ID")
    return ApplyInput(
        parent_run_id=parent,
        patch_id=patch_id,
        patch_hash=patch_hash,
        files=tuple(files),
        diff=diff,
        origin=str(origin),
        repo=APPLY_REPOSITORY,
        branch=f"{BRANCH_PREFIX}{run.id}",
    )


def diff_paths(diff: str) -> list[str]:
    """`--- a/…`·`+++ b/…` 머리의 경로(`/dev/null` 제외, 나온 순서, 중복 없음)."""
    paths: list[str] = []
    for line in diff.splitlines():
        for prefix, strip in (("--- ", "a/"), ("+++ ", "b/")):
            if line.startswith(prefix):
                path = line[len(prefix) :].split("\t", 1)[0].strip()
                if path == "/dev/null":
                    continue
                path = path.removeprefix(strip)
                if path not in paths:
                    paths.append(path)
    return paths


def check_target(files: Sequence[str], diff: str) -> str:
    """반영 대상 검사(계약 4절: 시나리오 사본뿐). 통과하면 시나리오 폴더(`scenarios/<이름>`).

    `files` 와 diff 머리 경로가 같은 집합이고, 모두 같은 `scenarios/<이름>/` 아래이며,
    `..`·절대 경로·숨김 경로·시나리오 README 가 없어야 한다.
    """
    headers = diff_paths(diff)
    if set(headers) != set(files):
        raise _ApplyFailed(FAILURE_PATCH_TARGET_FORBIDDEN, "FILES_DIFF_MISMATCH")
    scenario: str | None = None
    for path in files:
        parts = path.split("/")
        if path.startswith("/") or len(parts) < 3 or parts[0] != SCENARIOS_DIR:
            raise _ApplyFailed(FAILURE_PATCH_TARGET_FORBIDDEN, "OUTSIDE_SCENARIOS")
        if any(not _SAFE_SEGMENT.match(part) or part in {".", ".."} for part in parts):
            raise _ApplyFailed(FAILURE_PATCH_TARGET_FORBIDDEN, "UNSAFE_PATH")
        if any(part.startswith(".") for part in parts):
            raise _ApplyFailed(FAILURE_PATCH_TARGET_FORBIDDEN, "UNSAFE_PATH")
        if parts[-1].lower() == "readme.md":
            raise _ApplyFailed(FAILURE_PATCH_TARGET_FORBIDDEN, "PROTECTED_FILE")
        here = "/".join(parts[:2])
        if scenario is not None and here != scenario:
            raise _ApplyFailed(FAILURE_PATCH_TARGET_FORBIDDEN, "MULTIPLE_SCENARIOS")
        scenario = here
    if scenario is None:
        raise _ApplyFailed(FAILURE_INPUT_INVALID, "PATCH_FILES")
    return scenario


def check_real_targets(root: Path, names: Sequence[str]) -> None:
    """작업 사본 `root` 에서 패치 대상의 실제 경로를 검사한다(적용 전, 쓰기 없음).

    경로 문자열 검사(`check_target`)만으로는 체크아웃 안의 심볼릭 링크를 막지 못한다.
    대상 파일과 `scenarios/` 부터의 모든 상위 디렉터리가 심볼릭 링크가 아니어야 하고,
    `resolve()` 한 실제 경로가 작업 사본 `scenarios/` 의 실제 경로 안이어야 한다.
    아직 없는 경로(추가)·지울 경로·이름 바꾸기 양쪽 모두 같은 검사를 받는다.
    """
    scenarios_real = (root / SCENARIOS_DIR).resolve()
    for name in names:
        current = root
        for part in name.split("/"):
            current = current / part
            if current.is_symlink():
                raise _ApplyFailed(FAILURE_PATCH_TARGET_FORBIDDEN, "SYMLINK")
        real = (root / name).resolve()
        if real == scenarios_real or not real.is_relative_to(scenarios_real):
            raise _ApplyFailed(FAILURE_PATCH_TARGET_FORBIDDEN, "REAL_PATH_OUTSIDE_SCENARIOS")


def check_service_target(files: Sequence[str], diff: str, *, cve: bool = False) -> None:
    """서비스 저장소 패치(배포 실패 진단)의 경로 검사.

    `files` 와 diff 머리 경로가 같은 집합이고, `..`·절대 경로·숨김 경로(`.github/` 등)·안전하지
    않은 글자가 없어야 한다. 시나리오 폴더 제한은 없다(대상이 서비스 저장소 자체다).
    """
    if set(diff_paths(diff)) != set(files):
        raise _ApplyFailed(FAILURE_PATCH_TARGET_FORBIDDEN, "FILES_DIFF_MISMATCH")
    from echo_agent.cve_policy import dependency_diff_is_safe

    safe = dependency_diff_is_safe(diff) if cve else redact(diff) == diff
    if not safe:
        raise _ApplyFailed(FAILURE_PATCH_TARGET_FORBIDDEN, "SECRET_IN_DIFF")
    for path in files:
        if sensitive_source_path(path):
            raise _ApplyFailed(FAILURE_PATCH_TARGET_FORBIDDEN, "SENSITIVE_PATH")
        parts = path.split("/")
        if path.startswith("/") or any(
            not _SAFE_SEGMENT.match(part) or part in {".", ".."} for part in parts
        ):
            raise _ApplyFailed(FAILURE_PATCH_TARGET_FORBIDDEN, "UNSAFE_PATH")
        if any(part.startswith(".") for part in parts):
            raise _ApplyFailed(FAILURE_PATCH_TARGET_FORBIDDEN, "UNSAFE_PATH")


def check_real_targets_under(root: Path, names: Sequence[str]) -> None:
    """`root` 안 실제 경로 검사(심볼릭 링크 없음, `resolve()` 가 `root` 안). 쓰기 없음."""
    root_real = root.resolve()
    for name in names:
        current = root
        for part in name.split("/"):
            current = current / part
            if current.is_symlink():
                raise _ApplyFailed(FAILURE_PATCH_TARGET_FORBIDDEN, "SYMLINK")
        real = (root / name).resolve()
        if real == root_real or not real.is_relative_to(root_real):
            raise _ApplyFailed(FAILURE_PATCH_TARGET_FORBIDDEN, "REAL_PATH_OUTSIDE_REPOSITORY")


# ---------------------------------------------------------------- unified diff 적용


def split_file_diffs(diff: str) -> dict[str, str]:
    """파일마다 덩어리 부분(머리 `---`/`+++` 다음부터)만 나눈다."""
    sections: dict[str, list[str]] = {}
    current: str | None = None
    lines = diff.splitlines(keepends=True)
    index = 0
    while index < len(lines):
        line = lines[index]
        if (
            line.startswith("--- ")
            and index + 1 < len(lines)
            and lines[index + 1].startswith("+++ ")
        ):
            new = lines[index + 1][4:].split("\t", 1)[0].strip()
            old = line[4:].split("\t", 1)[0].strip()
            name = new if new != "/dev/null" else old
            current = name.removeprefix("b/").removeprefix("a/")
            sections.setdefault(current, [])
            index += 2
            continue
        if current is not None:
            sections[current].append(line)
        index += 1
    return {name: "".join(body) for name, body in sections.items()}


def apply_file_diff(original: str, hunks: str) -> str:
    """덩어리를 원본에 엄격히 적용한다(문맥·지울 줄이 한 글자라도 다르면 실패).

    `diff --git`·이름 바꾸기·이진 패치·`\\ No newline at end of file` 는 받지 않는다(규칙 패치와
    모델 수정안은 텍스트 파일 고치기뿐이다).
    """
    source = original.splitlines(keepends=True)
    output: list[str] = []
    cursor = 0  # source 에서 다음에 볼 줄(0부터)
    lines = hunks.splitlines(keepends=True)
    index = 0
    saw_hunk = False
    while index < len(lines):
        header = _HUNK_HEADER.match(lines[index])
        if header is None:
            if lines[index].strip() == "":
                index += 1
                continue
            raise _ApplyFailed(FAILURE_PATCH_APPLY_FAILED, "MALFORMED_DIFF")
        saw_hunk = True
        old_start = int(header.group(1))
        old_count = int(header.group(2) or "1")
        new_count = int(header.group(4) or "1")
        start = old_start - 1 if old_count else old_start
        if start < cursor or start > len(source):
            raise _ApplyFailed(FAILURE_PATCH_APPLY_FAILED, "HUNK_OUT_OF_RANGE")
        output.extend(source[cursor:start])
        cursor = start
        index += 1
        seen_old = seen_new = 0
        while index < len(lines) and (seen_old < old_count or seen_new < new_count):
            line = lines[index]
            tag, text = line[:1], line[1:]
            if line.startswith("\\"):
                raise _ApplyFailed(FAILURE_PATCH_APPLY_FAILED, "NO_NEWLINE_MARKER")
            if tag in {" ", "-"}:
                if cursor >= len(source) or source[cursor] != text:
                    raise _ApplyFailed(FAILURE_PATCH_APPLY_FAILED, "CONTEXT_MISMATCH")
                cursor += 1
                seen_old += 1
                if tag == " ":
                    output.append(text)
                    seen_new += 1
            elif tag == "+":
                output.append(text)
                seen_new += 1
            else:
                raise _ApplyFailed(FAILURE_PATCH_APPLY_FAILED, "MALFORMED_DIFF")
            index += 1
        if seen_old != old_count or seen_new != new_count:
            raise _ApplyFailed(FAILURE_PATCH_APPLY_FAILED, "HUNK_LENGTH")
    if not saw_hunk:
        raise _ApplyFailed(FAILURE_PATCH_APPLY_FAILED, "NO_HUNK")
    output.extend(source[cursor:])
    return "".join(output)


def apply_patch_to_files(originals: Mapping[str, str], diff: str) -> dict[str, str]:
    """파일 이름 → 원본 내용에 diff 를 적용한 새 내용. 대상 파일이 없으면 실패."""
    patched: dict[str, str] = {}
    for name, hunks in split_file_diffs(diff).items():
        if name not in originals:
            raise _ApplyFailed(FAILURE_PATCH_APPLY_FAILED, "TARGET_MISSING")
        patched[name] = apply_file_diff(originals[name], hunks)
    return patched


# ---------------------------------------------------------------- 시나리오 빌드 정보


@dataclass(frozen=True)
class ScenarioBuild:
    """시나리오 사본을 이미지로 빌드하는 데 필요한 것. 계약·입력에 없어 러너 상수로 둔다."""

    source_repo: str  # 공개 저장소(읽기만, 토큰 없음)
    source_commit: str
    dockerfile: str  # 시나리오 폴더 안 이름 = 소스 루트 안 이름
    healthz_port: int
    healthz_path: str
    healthz_env: Mapping[str, str] = field(default_factory=dict)


SCENARIO_BUILDS: dict[str, ScenarioBuild] = {
    # scenarios/demo-app-0ff0d44/README.md: echo-demo-app 0ff0d44 의 Dockerfile 바이트 그대로.
    "scenarios/demo-app-0ff0d44": ScenarioBuild(
        source_repo="Softbank-Hackathon-2026-Team-Echo/echo-demo-app",
        source_commit="0ff0d44f64e43d6eb65db63ab4f7844642638562",
        dockerfile="Dockerfile",
        healthz_port=8080,
        healthz_path="/healthz",
        # /healthz 는 프로세스 생존만 본다(DB 없이 뜬다). 접속 문자열은 닿지 않는 가짜 값이다.
        healthz_env={
            "DATABASE_URL": "postgresql://healthz@127.0.0.1:1/healthz",
            "AUTO_MIGRATE": "false",
            "ECHO_ENVIRONMENT": "apply-check",
        },
    ),
}

# 배포 실패 진단 패치의 서비스 저장소별 빌드 정보(저장소 루트가 빌드 문맥). 표에 없으면
# `service_build` 의 기본값(루트 Dockerfile, 8080, /healthz)으로 본다.
# source_commit 은 실행마다 바뀐다.
SERVICE_BUILDS: dict[str, ScenarioBuild] = {
    "Softbank-Hackathon-2026-Team-Echo/echo-demo-app": ScenarioBuild(
        source_repo="Softbank-Hackathon-2026-Team-Echo/echo-demo-app",
        source_commit="",
        dockerfile="Dockerfile",
        healthz_port=8080,
        healthz_path="/healthz",
        healthz_env=SCENARIO_BUILDS["scenarios/demo-app-0ff0d44"].healthz_env,
    ),
}


def service_build(
    repo: str, commit: str, builds: Mapping[str, ScenarioBuild] | None = None
) -> ScenarioBuild:
    """서비스 저장소의 빌드 정보(커밋을 채워서)."""
    known = (SERVICE_BUILDS if builds is None else builds).get(repo)
    if known is None:
        return ScenarioBuild(repo, commit, "Dockerfile", 8080, "/healthz")
    return ScenarioBuild(
        repo,
        commit,
        known.dockerfile,
        known.healthz_port,
        known.healthz_path,
        dict(known.healthz_env),
    )


# ---------------------------------------------------------------- 외부 명령


def subprocess_runner(
    args: Sequence[str], timeout: float, env: Mapping[str, str] | None = None
) -> CommandResult:
    """기본 명령 실행. 셸 없음. 시간 초과는 반환 코드 124 로 돌려준다."""
    merged = {**os.environ, **env} if env else None
    try:
        done = subprocess.run(  # noqa: S603 — 인자 목록만, 셸 없음
            list(args),
            capture_output=True,
            text=True,
            timeout=max(timeout, 0.1),
            check=False,
            env=merged,
        )
    except subprocess.TimeoutExpired as error:
        return CommandResult(124, _text(error.stdout), _text(error.stderr) or "timeout")
    except OSError as error:
        return CommandResult(127, "", type(error).__name__)
    return CommandResult(done.returncode, done.stdout, done.stderr)


def _text(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return value if isinstance(value, str) else ""


def codeload_fetcher(repo: str, commit: str, dest: Path, timeout: float) -> Path:
    """공개 저장소의 고정 커밋 소스를 GitHub tarball 로 받는다(토큰 없음, 읽기만)."""
    url = f"https://codeload.github.com/{repo}/tar.gz/{commit}"
    request = urllib.request.Request(url, headers={"User-Agent": "echo-ai-agent-apply-runner/0.1"})
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 — https 고정
        data = response.read(SOURCE_ARCHIVE_LIMIT + 1)
    if len(data) > SOURCE_ARCHIVE_LIMIT:
        raise _ApplyFailed(FAILURE_SOURCE_UNAVAILABLE, "ARCHIVE_TOO_LARGE")
    dest.mkdir(parents=True, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        members: list[tarfile.TarInfo] = []
        total = 0
        for member in archive:
            total += member.size
            if len(members) >= 10_000 or total > 128 * 1024 * 1024:
                raise _ApplyFailed(FAILURE_SOURCE_UNAVAILABLE, "EXPANDED_ARCHIVE_TOO_LARGE")
            if not (member.isfile() or member.isdir()):
                raise _ApplyFailed(FAILURE_SOURCE_UNAVAILABLE, "ARCHIVE_SPECIAL_ENTRY")
            members.append(member)
        archive.extractall(dest, members=members, filter="data")  # noqa: S202 — bounded data filter
    roots = [child for child in dest.iterdir() if child.is_dir()]
    if len(roots) != 1:
        raise _ApplyFailed(FAILURE_SOURCE_UNAVAILABLE, "ARCHIVE_LAYOUT")
    return roots[0]


def count_fixable(report: Mapping[str, Any]) -> dict[str, int]:
    """Trivy JSON 에서 수정 가능한 HIGH·CRITICAL 수(C-IMG-1·image-scan 요약과 같은 기준)."""
    counts = {severity: 0 for severity in SCAN_SEVERITIES}
    results = report.get("Results")
    if not isinstance(results, list):
        return counts
    for result in results:
        vulns = result.get("Vulnerabilities") if isinstance(result, Mapping) else None
        if not isinstance(vulns, list):
            continue
        for vuln in vulns:
            if not isinstance(vuln, Mapping):
                continue
            severity = vuln.get("Severity")
            if severity in counts and str(vuln.get("FixedVersion") or "") != "":
                counts[severity] += 1
    return counts


def _tail(value: str) -> str:
    value = value.strip()
    return value[-OUTPUT_TAIL:] if len(value) > OUTPUT_TAIL else value


# ---------------------------------------------------------------- 결과


def build_apply_result(
    status: str, failure_code: str | None, commit_sha: str | None, branch: str | None
) -> dict[str, Any]:
    """반영 결과(`ApplyPatchResult`). 계약 2.1절 두 칸 + 공통 칸만. 칸을 더하지 않는다."""
    return {
        "status": status,
        "failureCode": failure_code,
        "simulated": False,
        "appliedCommitSha": commit_sha if status == "SUCCEEDED" else None,
        "branch": branch,
    }


# ---------------------------------------------------------------- 실행 하나


@dataclass
class _Workspace:
    root: Path
    image_tag: str
    container: str
    image_built: bool = False
    container_started: bool = False


class ApplyRunner:
    """반영 실행 하나의 일. 외부 명령·소스 받기·시각은 바꿔 끼울 수 있다(시험)."""

    def __init__(
        self,
        *,
        repo_root: Path | None = None,
        run_command: CommandRunner | None = None,
        fetch_source: SourceFetcher | None = None,
        clock: Clock | None = None,
        workspace_parent: Path | None = None,
        scenario_builds: Mapping[str, ScenarioBuild] | None = None,
        service_builds: Mapping[str, ScenarioBuild] | None = None,
    ) -> None:
        env_root = os.environ.get(REPO_ROOT_ENV, "").strip()
        self.repo_root = repo_root or (
            Path(env_root) if env_root else Path(__file__).resolve().parents[2]
        )
        # 기본값은 부를 때 모듈에서 찾는다(시험이 바꿔 끼울 수 있게).
        self._run = run_command or subprocess_runner
        self._fetch = fetch_source or codeload_fetcher
        self._clock = clock or (lambda: datetime.now(UTC))
        self._workspace_parent = workspace_parent
        self._builds = SCENARIO_BUILDS if scenario_builds is None else scenario_builds
        self._service_builds = service_builds

    # -------------------------------------------------- 시간

    def _budget(self, run: ClaimedRun, cap: float) -> float:
        left = (run.deadline_at - DEADLINE_MARGIN - self._clock()).total_seconds()
        if left <= 0:
            raise _ApplyFailed(FAILURE_DEADLINE, "DEADLINE_MARGIN")
        return min(cap, left)

    # -------------------------------------------------- 단계

    def execute(
        self, run: ClaimedRun, events: RunEventLog, flush: Callable[[], None]
    ) -> tuple[str, str | None, str | None, str | None]:
        """(status, failureCode, appliedCommitSha, branch). 예외를 밖으로 내지 않는다."""
        branch: str | None = None
        workspace: _Workspace | None = None
        try:
            spec = parse_apply_input(run)
            branch = spec.branch
            events.add(
                RunStep.INPUT_LOAD,
                "apply input loaded",
                inputHash=run.input_hash,
                schemaVersion=APPLY_INPUT_SCHEMA_VERSION,
                parentRunId=spec.parent_run_id,
                patchId=spec.patch_id,
                origin=spec.origin,
                files=list(spec.files),
                branch=spec.branch,
            )
            actual = compute_patch_hash(spec.diff)
            if actual != spec.patch_hash:
                events.add(
                    RunStep.INPUT_LOAD,
                    "patch hash mismatch; not applied",
                    EventLevel.ERROR,
                    approved=spec.patch_hash,
                    recomputed=actual,
                )
                raise _ApplyFailed(FAILURE_PATCH_HASH_MISMATCH, "HASH_MISMATCH")
            if spec.source_commit is not None:
                # 배포 실패 진단의 패치: 서비스 저장소의 실패 커밋에서 적용·빌드·스캔·healthz.
                check_service_target(
                    spec.files, spec.diff, cve=run.input_snapshot.get("trigger") == "CVE_WATCH"
                )
                events.add(
                    RunStep.INPUT_LOAD,
                    "patch hash verified",
                    patchHash=actual,
                    repo=spec.repo,
                    sourceCommitSha=spec.source_commit,
                )
                flush()
                workspace = self._create_workspace(run)
                commit_sha = self._apply_service(run, spec, workspace, events, flush)
                events.add(
                    RunStep.PATCH_VERIFY,
                    "apply checks passed",
                    appliedCommitSha=commit_sha,
                    branch=spec.branch,
                    pushed=False,
                )
                return "SUCCEEDED", None, commit_sha, branch
            scenario = check_target(spec.files, spec.diff)
            events.add(
                RunStep.INPUT_LOAD, "patch hash verified", patchHash=actual, scenario=scenario
            )
            flush()

            workspace = self._create_workspace(run)
            commit_sha, originals = self._apply_and_commit(run, spec, scenario, workspace, events)
            flush()
            self._verify_image(run, spec, scenario, workspace, originals, events, flush)
            events.add(
                RunStep.PATCH_VERIFY,
                "apply checks passed",
                appliedCommitSha=commit_sha,
                branch=spec.branch,
                pushed=False,
            )
            return "SUCCEEDED", None, commit_sha, branch
        except _ApplyFailed as failure:
            step = RunStep.INPUT_LOAD if failure.code in _INPUT_FAILURES else RunStep.PATCH_VERIFY
            message = (
                "deadline reached before result"
                if failure.code == FAILURE_DEADLINE
                else "apply failed; nothing pushed"
            )
            events.add(
                step, message, EventLevel.ERROR, failureCode=failure.code, reason=failure.reason
            )
            return "FAILED", failure.code, None, branch
        except Exception as error:  # noqa: BLE001 — 어떤 실패든 FAILED 결과로 닫는다
            events.add(
                RunStep.PATCH_VERIFY,
                "apply failed; nothing pushed",
                EventLevel.ERROR,
                failureCode=FAILURE_RUNNER_ERROR,
                error=type(error).__name__,
            )
            return "FAILED", FAILURE_RUNNER_ERROR, None, branch
        finally:
            if workspace is not None:
                self._delete_workspace(workspace, events)

    def _create_workspace(self, run: ClaimedRun) -> _Workspace:
        parent = self._workspace_parent
        root = Path(tempfile.mkdtemp(prefix=f"echo-apply-{run.id[:8]}-", dir=parent))
        short = re.sub(r"[^a-z0-9]", "", run.id.lower())[:12] or "run"
        return _Workspace(
            root=root, image_tag=f"echo-apply-{short}:local", container=f"echo-apply-{short}"
        )

    def _delete_workspace(self, workspace: _Workspace, events: RunEventLog) -> None:
        removed_container = removed_image = False
        if workspace.container_started:
            done = self._run(["docker", "rm", "-f", workspace.container], CLEANUP_SECONDS, None)
            removed_container = done.returncode == 0
        if workspace.image_built:
            done = self._run(["docker", "rmi", "-f", workspace.image_tag], CLEANUP_SECONDS, None)
            removed_image = done.returncode == 0
        shutil.rmtree(workspace.root, ignore_errors=True)
        events.add(
            RunStep.SANDBOX_DELETE,
            "apply workspace deleted",
            containerRemoved=removed_container if workspace.container_started else None,
            imageRemoved=removed_image if workspace.image_built else None,
        )

    # -------------------------------------------------- ① 패치 적용·로컬 커밋

    def _git_available(self, run: ClaimedRun) -> bool:
        if shutil.which("git") is None:
            return False
        done = self._git(run, ["-C", str(self.repo_root), "rev-parse", "--is-inside-work-tree"])
        return done.returncode == 0 and done.stdout.strip() == "true"

    def _git(self, run: ClaimedRun, args: Sequence[str]) -> CommandResult:
        env = {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
        }
        return self._run(["git", *args], self._budget(run, GIT_SECONDS), env)

    def _apply_and_commit(
        self,
        run: ClaimedRun,
        spec: ApplyInput,
        scenario: str,
        workspace: _Workspace,
        events: RunEventLog,
    ) -> tuple[str | None, dict[str, bytes]]:
        """패치를 작업 사본에 적용하고(git 이 있으면) 로컬 커밋한다.

        (커밋 SHA, 시나리오 폴더 파일의 패치 전 바이트). 빌드 문맥 대조에 쓴다.
        """
        use_git = self._git_available(run)
        base_commit: str | None = None
        tree = workspace.root / "repo"
        if use_git:
            head = self._git(run, ["-C", str(self.repo_root), "rev-parse", "HEAD"])
            base_commit = head.stdout.strip() if head.returncode == 0 else None
            cloned = self._git(
                run,
                ["clone", "--quiet", "--local", "--no-hardlinks", str(self.repo_root), str(tree)],
            )
            if base_commit is None or cloned.returncode != 0:
                raise _ApplyFailed(FAILURE_RUNNER_ERROR, "GIT_CLONE")
            # push 할 길을 없앤다(샌드박스는 읽기 자격만, 배포 키 없음).
            self._git(run, ["-C", str(tree), "remote", "remove", "origin"])
            checkout = self._git(
                run, ["-C", str(tree), "checkout", "--quiet", "-b", spec.branch, base_commit]
            )
            if checkout.returncode != 0:
                raise _ApplyFailed(FAILURE_RUNNER_ERROR, "GIT_CHECKOUT")
        else:
            tree.mkdir(parents=True)
        source_root = tree if use_git else self.repo_root
        events.add(
            RunStep.SANDBOX_CREATE,
            "apply workspace created",
            mode="git-clone" if use_git else "file-copy",
            baseCommit=base_commit,
            scenario=scenario,
        )

        # 읽기·쓰기 전에 실제 경로를 본다: 사본 안 심볼릭 링크로 시나리오 밖을 고치지 않는다.
        try:
            check_real_targets(source_root, sorted({*spec.files, *diff_paths(spec.diff)}))
        except _ApplyFailed as failure:
            events.add(
                RunStep.PATCH_VERIFY,
                "patch target rejected",
                EventLevel.ERROR,
                reason=failure.reason,
            )
            raise
        originals: dict[str, str] = {}
        for name in spec.files:
            path = source_root / name
            if not path.is_file():
                events.add(
                    RunStep.PATCH_VERIFY,
                    "patch did not apply",
                    EventLevel.ERROR,
                    reason="TARGET_MISSING",
                    file=name,
                )
                raise _ApplyFailed(FAILURE_PATCH_APPLY_FAILED, "TARGET_MISSING")
            originals[name] = path.read_bytes().decode("utf-8")
        try:
            patched = apply_patch_to_files(originals, spec.diff)
        except _ApplyFailed as failure:
            events.add(
                RunStep.PATCH_VERIFY, "patch did not apply", EventLevel.ERROR, reason=failure.reason
            )
            raise
        for name, text in patched.items():
            target = tree / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(text.encode("utf-8"))
        commit_sha: str | None = None
        if use_git:
            self._git(run, ["-C", str(tree), "add", "--", *patched])
            message = f"apply: 승인된 패치 {spec.patch_id} 반영 (run {run.id})"
            committed = self._git(
                run,
                [
                    "-C",
                    str(tree),
                    "-c",
                    f"user.name={COMMIT_AUTHOR_NAME}",
                    "-c",
                    f"user.email={COMMIT_AUTHOR_EMAIL}",
                    "-c",
                    "commit.gpgsign=false",
                    "-c",
                    f"core.hooksPath={os.devnull}",
                    "commit",
                    "--quiet",
                    "--no-verify",
                    "-m",
                    message,
                ],
            )
            sha = self._git(run, ["-C", str(tree), "rev-parse", "HEAD"])
            if committed.returncode != 0 or sha.returncode != 0:
                raise _ApplyFailed(FAILURE_RUNNER_ERROR, "GIT_COMMIT")
            commit_sha = sha.stdout.strip()
        events.add(
            RunStep.PATCH_VERIFY,
            "patch applied",
            files=sorted(patched),
            appliedCommitSha=commit_sha,
            committed=commit_sha is not None,
            pushed=False,
        )
        scenario_dir = source_root / scenario
        before = {
            f"{scenario}/{path.relative_to(scenario_dir).as_posix()}": path.read_bytes()
            for path in sorted(scenario_dir.rglob("*"))
            if path.is_file()
        }
        before.update({name: text.encode("utf-8") for name, text in originals.items()})
        return commit_sha, before

    # -------------------------------------------------- ①' 서비스 저장소(배포 실패 진단)

    def _apply_service(
        self,
        run: ClaimedRun,
        spec: ApplyInput,
        workspace: _Workspace,
        events: RunEventLog,
        flush: Callable[[], None],
    ) -> str | None:
        """서비스 저장소의 실패 커밋 소스를 받아 패치를 적용하고(로컬 커밋) 이미지를 검증한다.

        소스는 공개 저장소 tarball(토큰 없음, 읽기만)이다. git 이 있으면 작업 공간 밖 git 폴더
        (`--git-dir`)로 기준 커밋 + 패치 커밋을 만든다(빌드 문맥에 `.git` 이 들어가지 않는다).
        push 하지 않는다. 패치 커밋 SHA(git 이 없으면 None)를 돌려준다.
        """
        if spec.source_commit is None:
            raise _ApplyFailed(FAILURE_INPUT_INVALID, "SOURCE_COMMIT_SHA")
        build = service_build(spec.repo, spec.source_commit, self._service_builds)
        try:
            source = self._fetch(
                spec.repo,
                spec.source_commit,
                workspace.root / "source",
                self._budget(run, SOURCE_FETCH_SECONDS),
            )
        except _ApplyFailed:
            raise
        except (OSError, tarfile.TarError, ValueError) as error:
            events.add(
                RunStep.PATCH_VERIFY,
                "service source unavailable",
                EventLevel.ERROR,
                error=type(error).__name__,
                repo=spec.repo,
            )
            raise _ApplyFailed(FAILURE_SOURCE_UNAVAILABLE, "FETCH") from error
        if run.input_snapshot.get("trigger") == "CVE_WATCH":
            from echo_agent.cve_policy import FILES, target_advisory_present
            from echo_agent.sbom import checked_image_ref

            if (
                os.environ.get("ECHO_CVE_REMEDIATION", "off") != "on"
                or not set(spec.files) <= FILES
            ):
                raise _ApplyFailed(FAILURE_INPUT_INVALID, "CVE_SCOPE_REJECTED")
            snapshot = run.input_snapshot
            try:
                ref = checked_image_ref(snapshot.get("imageRef"), snapshot.get("imageDigest"))
                if not snapshot["finding"].get("synthetic"):
                    baseline = self._run(
                        [
                            "trivy",
                            "image",
                            "--scanners",
                            "vuln",
                            "--format",
                            "json",
                            "--quiet",
                            ref,
                        ],
                        self._budget(run, 120),
                        None,
                    )
                    if baseline.returncode != 0 or not target_advisory_present(
                        json.loads(baseline.stdout),
                        snapshot["finding"],
                        snapshot["remediation"]["package"],
                    ):
                        raise ValueError("ADVISORY_NOT_OBSERVED_IN_BASELINE")
            except (ValueError, KeyError, TypeError) as exc:
                raise _ApplyFailed(FAILURE_IMAGE_SCAN_FAILED, "BASELINE_NOT_VERIFIED") from exc
        use_git = shutil.which("git") is not None
        git_dir = workspace.root / "git"
        events.add(
            RunStep.SANDBOX_CREATE,
            "apply workspace created",
            mode="service-source",
            repo=spec.repo,
            baseCommit=spec.source_commit,
            credentials="none",
        )
        try:
            check_real_targets_under(source, sorted({*spec.files, *diff_paths(spec.diff)}))
        except _ApplyFailed as failure:
            events.add(
                RunStep.PATCH_VERIFY,
                "patch target rejected",
                EventLevel.ERROR,
                reason=failure.reason,
            )
            raise
        originals: dict[str, str] = {}
        for name in spec.files:
            path = source / name
            if not path.is_file():
                events.add(
                    RunStep.PATCH_VERIFY,
                    "patch did not apply",
                    EventLevel.ERROR,
                    reason="TARGET_MISSING",
                    file=name,
                )
                raise _ApplyFailed(FAILURE_PATCH_APPLY_FAILED, "TARGET_MISSING")
            originals[name] = path.read_bytes().decode("utf-8")
        try:
            patched = apply_patch_to_files(originals, spec.diff)
        except _ApplyFailed as failure:
            events.add(
                RunStep.PATCH_VERIFY, "patch did not apply", EventLevel.ERROR, reason=failure.reason
            )
            raise
        if use_git:
            self._service_commit(run, source, git_dir, f"base: {spec.repo}@{spec.source_commit}")
        if run.input_snapshot.get("trigger") == "CVE_WATCH":
            from packaging.requirements import Requirement
            from packaging.utils import canonicalize_name

            from echo_agent.cve_policy import (
                lock_versions,
                project_dependencies,
                validate_manifest_change,
            )

            try:
                original_manifest = (source / "pyproject.toml").read_text()
                validate_manifest_change(
                    original_manifest,
                    patched.get("pyproject.toml", original_manifest),
                    {
                        canonicalize_name(Requirement(dep).name)
                        for dep in project_dependencies(original_manifest)
                    },
                )
                lock = patched.get("uv.lock", (source / "uv.lock").read_text())
                remediation = run.input_snapshot["remediation"]
                if lock_versions(lock, remediation["package"]) != {remediation["toVersion"]}:
                    raise ValueError("TARGET_VERSION_MISMATCH")
            except (ValueError, OSError) as exc:
                raise _ApplyFailed(FAILURE_INPUT_INVALID, "CVE_MANIFEST_REJECTED") from exc
        for name, text in patched.items():
            (source / name).write_bytes(text.encode("utf-8"))
        commit_sha: str | None = None
        if use_git:
            commit_sha = self._service_commit(
                run, source, git_dir, f"apply: 승인된 패치 {spec.patch_id} 반영 (run {run.id})"
            )
        events.add(
            RunStep.PATCH_VERIFY,
            "patch applied",
            files=sorted(patched),
            appliedCommitSha=commit_sha,
            committed=commit_sha is not None,
            pushed=False,
        )
        flush()
        docker_version, trivy_version = self._tool_versions()
        if docker_version is None or trivy_version is None:
            events.add(
                RunStep.PATCH_VERIFY,
                "image checks unavailable; not verified",
                EventLevel.ERROR,
                docker=docker_version,
                trivy=trivy_version,
                scenarioBuild=True,
            )
            raise _ApplyFailed(FAILURE_VERIFY_UNAVAILABLE, "TOOLS")
        events.add(
            RunStep.PATCH_VERIFY,
            "build context ready",
            sourceRepo=build.source_repo,
            sourceCommit=build.source_commit,
        )
        flush()
        self._build_scan_healthz(
            run, source, build, workspace, events, flush, docker_version, trivy_version
        )
        return commit_sha

    def _service_commit(self, run: ClaimedRun, tree: Path, git_dir: Path, message: str) -> str:
        """작업 공간 밖 git 폴더로 `tree` 전체를 커밋하고 SHA 를 돌려준다(hook·서명 없음)."""
        base = ["--git-dir", str(git_dir), "--work-tree", str(tree)]
        if not git_dir.exists():
            init = self._git(run, ["init", "--quiet", "--bare", str(git_dir)])
            if init.returncode != 0:
                raise _ApplyFailed(FAILURE_RUNNER_ERROR, "GIT_INIT")
        self._git(run, [*base, "add", "--all", "--force", "--", "."])
        committed = self._git(
            run,
            [
                *base,
                "-c",
                f"user.name={COMMIT_AUTHOR_NAME}",
                "-c",
                f"user.email={COMMIT_AUTHOR_EMAIL}",
                "-c",
                "commit.gpgsign=false",
                "-c",
                f"core.hooksPath={os.devnull}",
                "commit",
                "--quiet",
                "--no-verify",
                "-m",
                message,
            ],
        )
        sha = self._git(run, [*base, "rev-parse", "HEAD"])
        if committed.returncode != 0 or sha.returncode != 0:
            raise _ApplyFailed(FAILURE_RUNNER_ERROR, "GIT_COMMIT")
        return sha.stdout.strip()

    # -------------------------------------------------- ②③④ 빌드·스캔·healthz

    def _tool_versions(self) -> tuple[str | None, str | None]:
        docker = self._run(
            ["docker", "version", "--format", "{{.Server.Version}}"], TOOL_PROBE_SECONDS, None
        )
        docker_version = docker.stdout.strip() if docker.returncode == 0 else None
        trivy = self._run(["trivy", "--version", "--format", "json"], TOOL_PROBE_SECONDS, None)
        trivy_version: str | None = None
        if trivy.returncode == 0:
            try:
                parsed = json.loads(trivy.stdout)
                trivy_version = str(parsed.get("Version")) if isinstance(parsed, dict) else None
            except json.JSONDecodeError:
                trivy_version = None
        return docker_version or None, trivy_version or None

    def _verify_image(
        self,
        run: ClaimedRun,
        spec: ApplyInput,
        scenario: str,
        workspace: _Workspace,
        originals: Mapping[str, bytes],
        events: RunEventLog,
        flush: Callable[[], None],
    ) -> None:
        build = self._builds.get(scenario)
        docker_version, trivy_version = self._tool_versions()
        if build is None or docker_version is None or trivy_version is None:
            # 빌드·스캔 없이 PASS 를 만들지 않는다.
            events.add(
                RunStep.PATCH_VERIFY,
                "image checks unavailable; not verified",
                EventLevel.ERROR,
                docker=docker_version,
                trivy=trivy_version,
                scenarioBuild=build is not None,
            )
            raise _ApplyFailed(FAILURE_VERIFY_UNAVAILABLE, "TOOLS")

        # 빌드 문맥: 공개 소스의 고정 커밋 + 패치된 Dockerfile.
        try:
            source = self._fetch(
                build.source_repo,
                build.source_commit,
                workspace.root / "source",
                self._budget(run, SOURCE_FETCH_SECONDS),
            )
        except _ApplyFailed:
            raise
        except (OSError, tarfile.TarError, ValueError) as error:
            events.add(
                RunStep.PATCH_VERIFY,
                "build source unavailable",
                EventLevel.ERROR,
                error=type(error).__name__,
            )
            raise _ApplyFailed(FAILURE_SOURCE_UNAVAILABLE, "FETCH") from error
        # 사본(패치 전)이 소스의 같은 파일과 바이트가 같아야 빌드가 사본의 뜻과 같다.
        compared = sorted({*spec.files, f"{scenario}/{build.dockerfile}"})
        for name in compared:
            relative = name.removeprefix(scenario + "/")
            source_file = source / relative
            if (
                name not in originals
                or not source_file.is_file()
                or originals[name] != source_file.read_bytes()
            ):
                events.add(
                    RunStep.PATCH_VERIFY,
                    "build source does not match scenario copy",
                    EventLevel.ERROR,
                    file=name,
                    sourceRepo=build.source_repo,
                    sourceCommit=build.source_commit,
                )
                raise _ApplyFailed(FAILURE_SOURCE_UNAVAILABLE, "SOURCE_MISMATCH")
        for name in spec.files:
            shutil.copyfile(
                workspace.root / "repo" / name, source / name.removeprefix(scenario + "/")
            )
        events.add(
            RunStep.PATCH_VERIFY,
            "build context ready",
            sourceRepo=build.source_repo,
            sourceCommit=build.source_commit,
        )
        flush()
        self._build_scan_healthz(
            run, source, build, workspace, events, flush, docker_version, trivy_version
        )

    def _build_scan_healthz(
        self,
        run: ClaimedRun,
        source: Path,
        build: ScenarioBuild,
        workspace: _Workspace,
        events: RunEventLog,
        flush: Callable[[], None],
        docker_version: str,
        trivy_version: str,
    ) -> None:
        """빌드 문맥 `source` 를 이미지로 빌드 → Trivy(C-IMG-1 기준) → healthz. push 없음."""
        started = time.monotonic()
        built = self._run(
            [
                "docker",
                "build",
                "--tag",
                workspace.image_tag,
                "--label",
                f"echo.apply-run={run.id}",
                "--file",
                str(source / build.dockerfile),
                str(source),
            ],
            self._budget(run, BUILD_SECONDS),
            {"DOCKER_BUILDKIT": "1"},
        )
        workspace.image_built = True
        if built.returncode != 0:
            events.add(
                RunStep.PATCH_VERIFY,
                "image build failed",
                EventLevel.ERROR,
                exitCode=built.returncode,
                tail=_tail(built.stderr or built.stdout),
            )
            raise _ApplyFailed(FAILURE_IMAGE_BUILD_FAILED, "BUILD")
        events.add(
            RunStep.PATCH_VERIFY,
            "image built",
            image=workspace.image_tag,
            dockerVersion=docker_version,
            seconds=round(time.monotonic() - started, 1),
            pushed=False,
        )
        flush()

        scanned = self._run(
            [
                "trivy",
                "image",
                "--scanners",
                "vuln",
                *(["--list-all-pkgs"] if run.input_snapshot.get("trigger") == "CVE_WATCH" else []),
                "--format",
                "json",
                "--quiet",
                "--exit-code",
                "0",
                workspace.image_tag,
            ],
            self._budget(run, SCAN_SECONDS),
            None,
        )
        report: Any = None
        if scanned.returncode == 0:
            try:
                report = json.loads(scanned.stdout)
            except json.JSONDecodeError:
                report = None
        if not isinstance(report, dict):
            events.add(
                RunStep.PATCH_VERIFY,
                "image scan did not finish",
                EventLevel.ERROR,
                exitCode=scanned.returncode,
                trivyVersion=trivy_version,
                tail=_tail(scanned.stderr),
            )
            raise _ApplyFailed(FAILURE_IMAGE_SCAN_FAILED, "SCAN_ERROR")
        if run.input_snapshot.get("trigger") == "CVE_WATCH":
            from echo_agent.cve_policy import verify_target_report

            try:
                verify_target_report(report, dict(run.input_snapshot))
            except ValueError as exc:
                raise _ApplyFailed(FAILURE_IMAGE_SCAN_FAILED, str(exc)) from exc
            # Check the installed runtime metadata independently of the scanner inventory.
            remediation = run.input_snapshot["remediation"]
            probe = (
                "import importlib.metadata as m,sys; "
                f"sys.exit(0 if m.version({remediation['package']!r}) == "
                f"{remediation['toVersion']!r} else 1)"
            )
            installed = self._run(
                [
                    "docker",
                    "run",
                    "--rm",
                    "--network",
                    "none",
                    "--read-only",
                    "--cap-drop",
                    "ALL",
                    "--security-opt",
                    "no-new-privileges",
                    "--entrypoint",
                    "python",
                    workspace.image_tag,
                    "-c",
                    probe,
                ],
                self._budget(run, 20),
                None,
            )
            if installed.returncode != 0:
                raise _ApplyFailed(FAILURE_IMAGE_SCAN_FAILED, "INSTALLED_VERSION_MISMATCH")
        fixable = count_fixable(report)
        total_fixable = sum(fixable.values())
        events.add(
            RunStep.PATCH_VERIFY,
            "image scanned" if total_fixable == 0 else "image scan found fixable HIGH/CRITICAL",
            EventLevel.INFO if total_fixable == 0 else EventLevel.ERROR,
            trivyVersion=trivy_version,
            fixableHigh=fixable["HIGH"],
            fixableCritical=fixable["CRITICAL"],
            criterion="C-IMG-1: fixable HIGH/CRITICAL == 0",
        )
        flush()
        if total_fixable:
            raise _ApplyFailed(FAILURE_IMAGE_SCAN_FAILED, "FIXABLE_HIGH_CRITICAL")

        self._healthz(run, build, workspace, events)

    def _healthz(
        self, run: ClaimedRun, build: ScenarioBuild, workspace: _Workspace, events: RunEventLog
    ) -> None:
        args = [
            "docker",
            "run",
            "--detach",
            "--name",
            workspace.container,
            "--network",
            "none",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--label",
            f"echo.apply-run={run.id}",
        ]
        for key, value in sorted(build.healthz_env.items()):
            args += ["--env", f"{key}={value}"]
        args.append(workspace.image_tag)
        started = self._run(args, self._budget(run, CLEANUP_SECONDS), None)
        workspace.container_started = True
        if started.returncode != 0:
            events.add(
                RunStep.PATCH_VERIFY,
                "healthz failed",
                EventLevel.ERROR,
                reason="CONTAINER_START",
                tail=_tail(started.stderr),
            )
            raise _ApplyFailed(FAILURE_HEALTHZ_FAILED, "CONTAINER_START")
        probe = (
            "import sys, urllib.request\n"
            f"r = urllib.request.urlopen('http://127.0.0.1:{build.healthz_port}"
            f"{build.healthz_path}', timeout=2)\n"
            "sys.exit(0 if r.status == 200 else 1)\n"
        )
        limit = time.monotonic() + self._budget(run, HEALTHZ_SECONDS)
        attempts = 0
        while True:
            attempts += 1
            done = self._run(
                ["docker", "exec", workspace.container, "python", "-c", probe],
                self._budget(run, 10.0),
                None,
            )
            if done.returncode == 0:
                events.add(
                    RunStep.PATCH_VERIFY,
                    "healthz passed",
                    path=build.healthz_path,
                    attempts=attempts,
                    network="none",
                )
                return
            if time.monotonic() >= limit:
                events.add(
                    RunStep.PATCH_VERIFY,
                    "healthz failed",
                    EventLevel.ERROR,
                    reason="NO_200",
                    path=build.healthz_path,
                    attempts=attempts,
                )
                raise _ApplyFailed(FAILURE_HEALTHZ_FAILED, "NO_200")
            time.sleep(HEALTHZ_POLL_SECONDS)


def process_apply_run(
    client: WasClient,
    run: ClaimedRun,
    heartbeat: HeartbeatLike,
    sender: EventSenderLike,
    *,
    clock: Clock | None = None,
    log: Logger = lambda message: None,
    runner: ApplyRunner | None = None,
) -> tuple[str, str, str | None, bool]:
    """반영 실행 하나를 끝까지 처리한다(run_id, status, failureCode, submitted). 예외를 내지 않는다.

    하트비트·이벤트 보내기는 사전 점검 러너의 것을 그대로 받아 쓴다(`precheck_runner.process_run`
    의 종류 분기 한 곳에서 부름).
    """
    clock = clock or (lambda: datetime.now(UTC))
    runner = runner or ApplyRunner(clock=clock)
    heartbeat.beat()  # 첫 하트비트가 CLAIMED → RUNNING 을 만든다(echo-was AD-2).
    if heartbeat.lost.is_set():
        return run.id, "LOST", None, False
    heartbeat.start()
    try:
        status, failure_code, commit_sha, branch = runner.execute(run, sender.events, sender.flush)
        if heartbeat.lost.is_set():
            return run.id, "LOST", None, False
        if status == "SUCCEEDED" and clock() >= run.deadline_at - DEADLINE_MARGIN:
            sender.events.add(
                RunStep.PATCH_VERIFY, "deadline reached before result", EventLevel.ERROR
            )
            status, failure_code, commit_sha = "FAILED", FAILURE_DEADLINE, None
        sender.flush()
        stored = client.submit_result(
            run, build_apply_result(status, failure_code, commit_sha, branch)
        )
        return run.id, stored or status, failure_code, True
    except RunNotActiveError:
        return run.id, "LOST", None, False
    except ResultAlreadySubmittedError:
        return run.id, "ALREADY_SUBMITTED", None, False
    except (WasError, OSError) as error:
        log(f"apply result failed run={run.id}: {type(error).__name__} {error}")
        return run.id, "FAILED", FAILURE_RUNNER_ERROR, False
    finally:
        heartbeat.stop()
