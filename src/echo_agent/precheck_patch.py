"""규칙 패치 제안(AI 에이전트 5 초안): 규칙 R-PIP-1 로 패치 하나를 만들고 검사해 결과에 올린다.

SPEC `specs/ai-5-rule-patch-proposal.md`. 모델을 쓰지 않으며 `origin: "RULE"` 로 표시한다.

    발동 조건 확인(C-IMG-1 + 시나리오 이미지·서비스) → Dockerfile 변환 → unified diff
    → PATCH_PROPOSE 이벤트("drafted") → 검사(PATCH_APPLIES · POLICY · DOCKERFILE_STATIC
    · DOCKER_BUILD · TRIVY) → PATCH_VERIFY 이벤트

- 고정 시나리오 전용 규칙이다. 대상은 운영 저장소가 아니라 이 저장소의 사본
  `scenarios/demo-app-0ff0d44/Dockerfile` 이고, 변환 결과는 운영에서 사람이 낸 수정
  echo-demo-app `6ac8813` 과 바이트가 같다.
- 검사는 실제로 돌린 것만 `checks` 에 적는다. docker·trivy 를 못 쓰거나 도구 준비가 실패하면
  (시간 초과·trivy 실행 실패·결과를 못 읽음) 그 검사를 넣지 않고 `reason` 에 미실행과 이유를 적는다.
- 패치 단계의 어떤 실패도 실행을 FAILED 로 만들지 않는다. 패치 없이 규칙 결과만 낸다.
"""

import difflib
import hashlib
import json
import os
import re
import shutil
import subprocess
import time
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any

from echo_agent.events import EventLevel, RunEventLog, RunStep
from echo_agent.precheck_rules import TEXT_LIMIT, parse_snapshot
from echo_agent.was_client import ClaimedRun

SCENARIO_ROOT_ENV = "ECHO_SCENARIO_ROOT"
SCENARIO_DIR = "scenarios/demo-app-0ff0d44"
SCENARIO_FILE = f"{SCENARIO_DIR}/Dockerfile"

PATCH_ID = "rule-c-img-1-pip-uninstall"
TRIGGER_CONTROL = "C-IMG-1"
# 발동 조건 3: 사본과 같은 이미지·서비스의 점검일 때만. 출발·도착 중 한쪽 digest 가 목록에 있거나
# 서비스 이름이 목록에 있어야 한다. digest 는 echo-demo-app `0ff0d44` 로 GHCR 에 게시한 이미지
# (`sha-0ff0d44…` 태그, echo-infra `demo-app/base/kustomization.yaml`·`onprem/install.sh` 의 값).
SCENARIO_IMAGE_DIGESTS = frozenset(
    {"sha256:3a8211ce82191fdee4da70d736f4946bf8be84c052bf889f7f5c2e6b596405bd"}
)
# WAS 의 시연 서비스 이름(실제 실행기 이미지는 AR 에서 다시 빌드해 digest 가 다르다).
SCENARIO_SERVICE_NAMES = frozenset({"demo"})
POLICY_VERSION = "rule-patch-policy-2026.11.05"

CHECK_PATCH_APPLIES = "PATCH_APPLIES"
CHECK_POLICY = "POLICY"
CHECK_DOCKERFILE_STATIC = "DOCKERFILE_STATIC"
CHECK_DOCKER_BUILD = "DOCKER_BUILD"
CHECK_TRIVY = "TRIVY"
RESULT_PASS = "PASS"  # noqa: S105 — 판정 값이다(비밀번호 아님)
RESULT_FAIL = "FAIL"

# 이유 코드(이벤트 data.reason).
REASON_NOT_FLAGGED = "C_IMG_1_NOT_FLAGGED"
REASON_OTHER_SERVICE = "SCENARIO_NOT_MATCHED"
REASON_DEADLINE = "DEADLINE_TOO_CLOSE"
REASON_ALREADY_PATCHED = "ALREADY_PATCHED"
REASON_SCENARIO_MISSING = "SCENARIO_MISSING"
REASON_NOT_APPLICABLE = "TRANSFORM_NOT_APPLICABLE"
REASON_PATCH_ERROR = "PATCH_ERROR"

DOCKER_PROBE_SECONDS = 10.0
DOCKER_BUDGET_SECONDS = 180.0
CLEANUP_SECONDS = 30.0
TOOL_MARGIN_SECONDS = 30.0
# docker·trivy 검사를 시작하려면 남아 있어야 하는 시간: 예산 + 탐침 이미지 정리 + 여유.
TOOL_STAGE_SECONDS = DOCKER_BUDGET_SECONDS + CLEANUP_SECONDS + TOOL_MARGIN_SECONDS
TOOL_VERSION_LIMIT = 64
FLAGGED_TEXT_LIMIT = 200

PROBE_IMAGE_PREFIX = "echo-rule-patch-probe"
PROBE_NOTE = "실행 단계 RUN만, 앱 소스 없음"
TRIVY_SCOPE_NOTE = "탐침 범위: base FROM + 실행 단계 첫 RUN, 앱 의존성·소스 미포함"
# pip 모듈이 없으면 0 으로 끝난다.
PIP_ABSENT_CODE = (
    "import importlib.util, sys; sys.exit(1 if importlib.util.find_spec('pip') else 0)"
)

# 6ac8813 과 글자가 같아야 한다(`tests/fixtures/demo-app-6ac8813.Dockerfile` 로 시험).
_PIP_COMMENT_LINES = (
    "# 베이스 이미지의 pip 를 지운다. 앱은 /opt/venv 만 쓰고 실행 중 pip 를 부르지 않는다.\n",
    "# pip 안에 함께 든 msgpack·setuptools·urllib3 가 수정 버전이 있는 HIGH 취약점으로 잡혀\n",
    "# 이미지 보안 검사(Trivy, echo-was C-IMG-1)가 FAIL 이 되기 때문이다.\n",
)
_PIP_UNINSTALL_LINE = "RUN python -m pip uninstall --yes --no-cache-dir pip && \\\n"
_PIP_UNINSTALL = re.compile(r"\bpip3?\s+uninstall\b")
_SHELL_SEPARATOR = re.compile(r"&&|\|\||;|\|")
_PIP_PACKAGE_NAMES = frozenset({"pip", "pip3"})
_RUNTIME_USER = "1001:1001"

_PROTECTED_DIRS = frozenset({"tests", ".github", "security", "specs"})
_PROTECTED_FILES = frozenset({"pyproject.toml", "uv.lock"})

_RUNNER_SECRETS = frozenset({"ANTHROPIC_API_KEY", "ECHO_RUNNER_TOKEN"})

_HUNK_HEADER = re.compile(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@\n")


class DiffApplyError(ValueError):
    """diff 를 원본에 적용할 수 없다(머리·덩어리 모양, 문맥 줄 불일치)."""


class _PatchSkipped(Exception):
    """패치를 내지 않는다. `reason` 은 이벤트에 적는 이유 코드다."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


# ---------------------------------------------------------------- 명령 실행


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str


# (인자 목록, 표준 입력, 시간 제한) → 결과. 시험에서 바꿔 끼운다.
CommandRunner = Callable[[Sequence[str], str | None, float], CommandResult]


def subprocess_runner(args: Sequence[str], stdin: str | None, timeout: float) -> CommandResult:
    """기본 실행기. 셸을 거치지 않고, 러너 비밀을 도구 프로세스에 넘기지 않는다."""
    environment = {k: v for k, v in os.environ.items() if k not in _RUNNER_SECRETS}
    completed = subprocess.run(  # noqa: S603 — 인자 목록으로 부른다(셸 없음)
        list(args),
        input=stdin or "",
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=False,
        env=environment,
    )
    return CommandResult(completed.returncode, completed.stdout)


# ---------------------------------------------------------------- Dockerfile 읽기


@dataclass(frozen=True)
class _Instruction:
    keyword: str  # 대문자
    args: str  # 이어진 줄을 한 줄로 합친 인자
    first_line: int
    raw: str  # 파일에 적힌 줄 그대로


def _split_lines(text: str) -> list[str]:
    """줄 끝을 유지해 나눈다. `\\n` 만 줄 끝으로 본다(바이트 그대로 되돌리려고)."""
    return re.findall(r"[^\n]*\n|[^\n]+\Z", text)


def _parse_instructions(lines: Sequence[str]) -> list[_Instruction]:
    """명령 단위로 읽는다. 주석·빈 줄은 건너뛰고 `\\` 로 이어진 줄은 한 명령으로 합친다."""
    instructions: list[_Instruction] = []
    index = 0
    while index < len(lines):
        stripped = lines[index].strip()
        if not stripped or stripped.startswith("#"):
            index += 1
            continue
        first = index
        parts: list[str] = []
        while index < len(lines):
            current = lines[index].strip()
            index += 1
            if not current or current.startswith("#"):
                continue
            if not current.endswith("\\"):
                parts.append(current)
                break
            parts.append(current[:-1].strip())
        keyword, _, args = " ".join(parts).partition(" ")
        raw = "".join(lines[first:index])
        instructions.append(_Instruction(keyword.upper(), args.strip(), first, raw))
    return instructions


def _stages(text: str) -> list[list[_Instruction]]:
    """`FROM` 으로 단계를 나눈다. 단계의 첫 원소가 그 `FROM` 이다."""
    stages: list[list[_Instruction]] = []
    for instruction in _parse_instructions(_split_lines(text)):
        if instruction.keyword == "FROM":
            stages.append([instruction])
        elif stages:
            stages[-1].append(instruction)
    return stages


def _is_pip_uninstall(instruction: _Instruction) -> bool:
    """`RUN` 이 pip 자신을 지운다(`pip uninstall … pip`). 다른 패키지만 지우면 아니다."""
    if instruction.keyword != "RUN":
        return False
    for match in _PIP_UNINSTALL.finditer(instruction.args):
        rest = instruction.args[match.end() :]
        command = _SHELL_SEPARATOR.split(rest, maxsplit=1)[0]
        packages = {word for word in command.split() if not word.startswith("-")}
        if packages & _PIP_PACKAGE_NAMES:
            return True
    return False


def _signature(stage: Sequence[_Instruction]) -> list[tuple[str, str]]:
    return [(i.keyword, i.args) for i in stage]


def _args_of(stage: Sequence[_Instruction], keyword: str) -> list[str]:
    return [i.args for i in stage if i.keyword == keyword]


def _is_base_stage(from_instruction: _Instruction) -> bool:
    words = from_instruction.args.split()
    return len(words) >= 3 and words[-2].upper() == "AS" and words[-1].lower() == "base"


# ---------------------------------------------------------------- 규칙 R-PIP-1


def flagged_results(raw_snapshot: Mapping[str, Any]) -> Counter[str]:
    """발동 조건 1: `C-IMG-1` 의 PASS 아닌 결과별 건수(비었으면 발동하지 않음)."""
    return Counter(
        finding.result
        for finding in parse_snapshot(raw_snapshot).findings
        if finding.control_id == TRIGGER_CONTROL and finding.result != RESULT_PASS
    )


def scenario_matches(raw_snapshot: Mapping[str, Any]) -> bool:
    """발동 조건 3: 출발·도착 digest 중 하나가 사본 이미지이거나, 서비스 이름이 시연 서비스다."""
    snapshot = parse_snapshot(raw_snapshot)
    digests = {snapshot.source.image_digest, snapshot.target.image_digest}
    if digests & SCENARIO_IMAGE_DIGESTS:
        return True
    service = raw_snapshot.get("service")
    name = service.get("name") if isinstance(service, Mapping) else None
    return isinstance(name, str) and name in SCENARIO_SERVICE_NAMES


def already_patched(source: str) -> bool:
    """발동 조건 2 의 반대: 마지막 단계에 이미 pip 자신을 지우는 `pip uninstall … pip` 이 있다."""
    stages = _stages(source)
    return bool(stages) and any(_is_pip_uninstall(i) for i in stages[-1])


def transform_dockerfile(source: str) -> str:
    """마지막 단계의 첫 `RUN` 앞에 pip 제거를 넣는다. 결정적이다(시각·난수 없음).

    모양이 예상과 다르면 `_PatchSkipped(TRANSFORM_NOT_APPLICABLE)`.
    """
    if "\r" in source or not source.endswith("\n"):
        raise _PatchSkipped(REASON_NOT_APPLICABLE)
    stages = _stages(source)
    first_run = next((i for i in stages[-1] if i.keyword == "RUN"), None) if stages else None
    if first_run is None:
        raise _PatchSkipped(REASON_NOT_APPLICABLE)
    lines = _split_lines(source)
    run_line = lines[first_run.first_line]
    body = run_line.removeprefix("RUN ").lstrip(" ")
    # `RUN --mount=…`·`RUN [..]`·`RUN <<EOF` 앞에는 명령을 이어 붙일 수 없다.
    if not run_line.startswith("RUN ") or not body.strip() or body[0] in "-[<":
        raise _PatchSkipped(REASON_NOT_APPLICABLE)
    return "".join(
        [
            *lines[: first_run.first_line],
            *_PIP_COMMENT_LINES,
            _PIP_UNINSTALL_LINE,
            f"    {body}",
            *lines[first_run.first_line + 1 :],
        ]
    )


def build_diff(original: str, patched: str, path: str) -> str:
    """문맥 3줄 unified diff. `diff --git`·index 줄은 넣지 않는다."""
    return "".join(
        difflib.unified_diff(
            _split_lines(original),
            _split_lines(patched),
            fromfile=f"a/{path}",
            tofile=f"b/{path}",
            n=3,
        )
    )


def patch_hash(diff: str) -> str:
    """결정 PD-14: `sha256:` + diff 문자열 UTF-8 바이트의 해시."""
    return "sha256:" + hashlib.sha256(diff.encode("utf-8")).hexdigest()


def apply_unified_diff(original: str, diff: str, path: str) -> str:
    """파일 하나짜리 unified diff 를 적용한다. 문맥 줄이 다르면 `DiffApplyError`."""
    lines = _split_lines(diff)
    if lines[:2] != [f"--- a/{path}\n", f"+++ b/{path}\n"] or len(lines) < 3:
        raise DiffApplyError("diff header does not match the file")
    source = _split_lines(original)
    output: list[str] = []
    cursor = 0
    index = 2
    while index < len(lines):
        header = _HUNK_HEADER.fullmatch(lines[index])
        if header is None:
            raise DiffApplyError("hunk header expected")
        index += 1
        old_count = int(header[2] or 1)
        new_count = int(header[4] or 1)
        start = int(header[1]) - 1 if old_count else int(header[1])
        if start < cursor or start > len(source):
            raise DiffApplyError("hunk position out of order")
        output.extend(source[cursor:start])
        cursor = start
        old_seen = new_seen = 0
        while index < len(lines) and (old_seen < old_count or new_seen < new_count):
            tag, body = lines[index][:1], lines[index][1:]
            index += 1
            if tag not in (" ", "-", "+"):
                raise DiffApplyError("unknown hunk line")
            if tag != "+":
                if cursor >= len(source) or source[cursor] != body:
                    raise DiffApplyError("context does not match the file")
                cursor += 1
                old_seen += 1
            if tag != "-":
                output.append(body)
                new_seen += 1
        if old_seen != old_count or new_seen != new_count:
            raise DiffApplyError("hunk line count does not match its header")
    output.extend(source[cursor:])
    return "".join(output)


# ---------------------------------------------------------------- 검사: 정적 3개


@dataclass(frozen=True)
class PatchCheck:
    name: str
    result: str
    summary: str
    tool_version: str | None = None
    policy_version: str | None = None

    @property
    def passed(self) -> bool:
        return self.result == RESULT_PASS

    @property
    def label(self) -> str:
        return f"{self.name}={self.result}"

    def to_json(self) -> dict[str, str]:
        check = {"name": self.name, "result": self.result, "summary": self.summary}
        if self.tool_version:
            check["toolVersion"] = self.tool_version[:TOOL_VERSION_LIMIT]
        if self.policy_version:
            check["policyVersion"] = self.policy_version
        return check


def policy_violations(files: Sequence[str]) -> list[str]:
    """POLICY 위반 코드. 비었으면 통과. 보호 이름은 경로 어느 칸에 있어도 위반으로 본다."""
    violations: set[str] = set()
    for path in files:
        parts = path.split("/")
        if path.startswith("/") or "\\" in path or {"", ".", ".."} & set(parts):
            violations.add("UNSAFE_PATH")
        if not path.startswith(f"{SCENARIO_DIR}/"):
            violations.add("OUTSIDE_SCENARIO")
        folded = [part.casefold() for part in parts]
        if (
            _PROTECTED_DIRS & set(folded)
            or folded[-1] in _PROTECTED_FILES
            or (folded[0] == "scenarios" and folded[-1] == "readme.md")
        ):
            violations.add("PROTECTED_FILE")
    return sorted(violations)


def diff_paths(diff: str) -> list[str]:
    """diff 의 `--- a/…`·`+++ b/…` 머리 경로(`a/`·`b/` 를 뗀 값, 순서 유지·중복 없음)."""
    paths: list[str] = []
    for line in _split_lines(diff):
        if line.startswith(("--- ", "+++ ")):
            path = line[4:].rstrip("\n").split("\t", 1)[0]
            if path != "/dev/null":
                path = path.removeprefix("a/") if line[0] == "-" else path.removeprefix("b/")
                if path not in paths:
                    paths.append(path)
    return paths


def touched_paths(files: Sequence[str], diff: str) -> list[str]:
    """POLICY 가 보는 경로: 패치의 `files` 와 diff 머리 경로의 합집합."""
    return list(dict.fromkeys([*files, *diff_paths(diff)]))


def static_problems(original: str, patched: str) -> list[str]:
    """DOCKERFILE_STATIC 위반 코드. 비었으면 통과."""
    before, after = _stages(original), _stages(patched)
    if not after or len(before) != len(after):
        return ["STAGE_COUNT_CHANGED"]
    problems: list[str] = []
    if [stage[0].args for stage in before] != [stage[0].args for stage in after]:
        problems.append("FROM_CHANGED")
    if [_signature(s) for s in before[:-1]] != [_signature(s) for s in after[:-1]]:
        problems.append("OTHER_STAGE_CHANGED")
    last_before, last_after = before[-1], after[-1]
    users = _args_of(last_after, "USER")
    if not users or users[-1] != _RUNTIME_USER or users != _args_of(last_before, "USER"):
        problems.append("USER_CHANGED")
    commands = _args_of(last_after, "CMD")
    if not commands or commands != _args_of(last_before, "CMD"):
        problems.append("CMD_CHANGED")
    uninstall = next((n for n, i in enumerate(last_after) if _is_pip_uninstall(i)), None)
    first_user = next((n for n, i in enumerate(last_after) if i.keyword == "USER"), None)
    if uninstall is None or first_user is None or uninstall > first_user:
        problems.append("PIP_UNINSTALL_NOT_BEFORE_USER")
    return problems


@dataclass(frozen=True)
class _Candidate:
    original: str
    patched: str
    diff: str
    flagged: Counter[str]


def _check_applies(candidate: _Candidate) -> PatchCheck:
    try:
        applied = apply_unified_diff(candidate.original, candidate.diff, SCENARIO_FILE)
    except DiffApplyError as error:
        return PatchCheck(CHECK_PATCH_APPLIES, RESULT_FAIL, f"diff 적용 실패: {error}")
    if applied != candidate.patched:
        return PatchCheck(CHECK_PATCH_APPLIES, RESULT_FAIL, "적용 결과가 변환 결과와 다름")
    return PatchCheck(CHECK_PATCH_APPLIES, RESULT_PASS, "시나리오 사본에 적용, 변환 결과와 같음")


def _check_policy(candidate: _Candidate) -> PatchCheck:
    violations = policy_violations(touched_paths([SCENARIO_FILE], candidate.diff))
    if violations:
        summary = "위반: " + ", ".join(violations)
        return PatchCheck(CHECK_POLICY, RESULT_FAIL, summary, policy_version=POLICY_VERSION)
    return PatchCheck(CHECK_POLICY, RESULT_PASS, "위반 0건", policy_version=POLICY_VERSION)


def _check_static(candidate: _Candidate) -> PatchCheck:
    problems = static_problems(candidate.original, candidate.patched)
    if problems:
        return PatchCheck(CHECK_DOCKERFILE_STATIC, RESULT_FAIL, "위반: " + ", ".join(problems))
    return PatchCheck(
        CHECK_DOCKERFILE_STATIC,
        RESULT_PASS,
        "FROM·USER·CMD 동일, USER 앞 RUN 에 pip 제거, 바뀐 단계는 마지막 하나",
    )


_STATIC_CHECKS: tuple[Callable[[_Candidate], PatchCheck], ...] = (
    _check_applies,
    _check_policy,
    _check_static,
)


# ---------------------------------------------------------------- 검사: docker·trivy


def probe_dockerfile(patched: str) -> str:
    """`base` 의 `FROM` 줄 + 마지막 단계 첫 `RUN` 만으로 탐침을 만든다(빌드 문맥 없음)."""
    stages = _stages(patched)
    base = next((stage[0] for stage in stages if _is_base_stage(stage[0])), None)
    first_run = next((i for i in stages[-1] if i.keyword == "RUN"), None) if stages else None
    if base is None or first_run is None:
        raise ValueError("probe needs a base stage and a RUN in the last stage")
    return base.raw + first_run.raw


def probe_image(run_id: str) -> str:
    return f"{PROBE_IMAGE_PREFIX}:{re.sub(r'[^A-Za-z0-9_]', '_', run_id[:8]) or 'run'}"


def fixable_vulnerabilities(trivy_json: str) -> int:
    """Trivy JSON 에서 수정 버전이 있는 HIGH·CRITICAL 건수. 모양이 다르면 `ValueError`."""
    report = json.loads(trivy_json)
    if not isinstance(report, Mapping):
        raise ValueError("trivy report must be an object")
    return sum(
        1
        for target in report.get("Results") or []
        for vulnerability in target.get("Vulnerabilities") or []
        if vulnerability.get("Severity") in ("HIGH", "CRITICAL")
        and vulnerability.get("FixedVersion")
    )


@dataclass
class _ToolChecks:
    checks: list[PatchCheck] = field(default_factory=list)
    not_run: list[str] = field(default_factory=list)
    probe_removed: bool = True


def _not_run_because(reason: str) -> _ToolChecks:
    return _ToolChecks(
        not_run=[f"{CHECK_DOCKER_BUILD}({reason})", f"{CHECK_TRIVY}({CHECK_DOCKER_BUILD} 미실행)"]
    )


# ---------------------------------------------------------------- 패치 단계


@dataclass(frozen=True)
class RulePatcher:
    """패치 단계 하나. `run_command`·`which` 는 시험에서 바꿔 끼운다."""

    run_command: CommandRunner = subprocess_runner
    which: Callable[[str], str | None] = shutil.which

    def propose(
        self,
        run: ClaimedRun,
        events: RunEventLog,
        remaining: timedelta,
        flush: Callable[[], None],
    ) -> list[dict[str, Any]]:
        """`result.patches`(0개 또는 1개). 어떤 예외도 밖으로 내지 않는다.

        `remaining` 은 마감 여유를 뺀 남은 시간이다. `flush` 는 긴 검사 전에 쌓인 이벤트를
        보낸다. 실행이 닫혀 `flush` 가 실패하면 여기서 멈추고, 부른 쪽의 다음 전송이 다시 알아챈다.
        """
        step = RunStep.PATCH_PROPOSE
        try:
            if remaining.total_seconds() <= 0:
                raise _PatchSkipped(REASON_DEADLINE)
            candidate = _prepare(run.input_snapshot, events)
            if candidate is None:
                return []
            # 아직 결과에 싣지 않았다. 검사를 모두 통과해야 "checks passed" 와 함께 실린다.
            events.add(
                RunStep.PATCH_PROPOSE,
                "rule patch drafted; checks pending",
                patchId=PATCH_ID,
                origin="RULE",
            )
            flush()
            step = RunStep.PATCH_VERIFY
            return self._verify(run.id, candidate, events, remaining.total_seconds())
        except _PatchSkipped as skipped:
            events.add(step, "rule patch skipped", EventLevel.WARN, reason=skipped.reason)
        except Exception as error:  # noqa: BLE001 — 패치 실패로 실행을 실패시키지 않는다
            events.add(
                step,
                "rule patch skipped",
                EventLevel.WARN,
                reason=REASON_PATCH_ERROR,
                error=type(error).__name__,
            )
        return []

    def _verify(
        self, run_id: str, candidate: _Candidate, events: RunEventLog, seconds_left: float
    ) -> list[dict[str, Any]]:
        checks: list[PatchCheck] = []
        for static_check in _STATIC_CHECKS:
            checks.append(static_check(candidate))
            if not checks[-1].passed:
                _report_dropped(events, checks, probe_removed=True)
                return []
        tools = self._tool_checks(run_id, candidate.patched, seconds_left)
        checks.extend(tools.checks)
        if not all(check.passed for check in checks):
            _report_dropped(events, checks, probe_removed=tools.probe_removed)
            return []
        names = {check.name for check in checks}
        events.add(
            RunStep.PATCH_VERIFY,
            "rule patch checks passed",
            checks=[check.label for check in checks],
            dockerChecked=CHECK_DOCKER_BUILD in names,
            trivyChecked=CHECK_TRIVY in names,
            **_cleanup_detail(tools.probe_removed),
        )
        return [_patch_element(candidate, checks, tools.not_run)]

    def _tool_checks(self, run_id: str, patched: str, seconds_left: float) -> _ToolChecks:
        # 탐침 정리(최대 30초)는 예산 밖에서 따로 쓰므로 기준에 함께 넣는다.
        if seconds_left < TOOL_STAGE_SECONDS:
            return _not_run_because("실행 마감이 가까워 건너뜀")
        budget_end = time.monotonic() + DOCKER_BUDGET_SECONDS
        docker_version = self._docker_version()
        if docker_version is None:
            return _not_run_because("docker 를 쓸 수 없음: 없거나 데몬에 접근 권한 없음")
        probe = probe_dockerfile(patched)
        image = probe_image(run_id)
        tools = _ToolChecks()
        try:
            build = self._docker_build_check(image, probe, docker_version, budget_end)
            if isinstance(build, str):
                tools.not_run.extend(_not_run_because(build).not_run)
            else:
                tools.checks.append(build)
            if isinstance(build, PatchCheck) and build.passed:
                if self.which("trivy") is None:
                    tools.not_run.append(f"{CHECK_TRIVY}(trivy 가 PATH 에 없음)")
                else:
                    trivy = self._trivy_check(image, budget_end)
                    if isinstance(trivy, str):
                        tools.not_run.append(f"{CHECK_TRIVY}({trivy})")
                    else:
                        tools.checks.append(trivy)
        finally:
            tools.probe_removed = self._remove_probe(image)
        return tools

    def _docker_version(self) -> str | None:
        """서버 버전. docker 가 없거나 10초 안에 데몬에 닿지 못하면 None."""
        version_command = ("docker", "version", "--format", "{{.Server.Version}}")
        try:
            version = self.run_command(version_command, None, DOCKER_PROBE_SECONDS)
        except (OSError, subprocess.SubprocessError):
            return None
        server = version.stdout.strip()
        return f"docker {server}" if version.returncode == 0 and server else None

    def _timed(self, args: Sequence[str], stdin: str | None, budget_end: float) -> CommandResult:
        remaining = budget_end - time.monotonic()
        if remaining <= 0:
            raise subprocess.TimeoutExpired(list(args), 0)
        return self.run_command(args, stdin, remaining)

    def _docker_build_check(
        self, image: str, probe: str, tool_version: str, budget_end: float
    ) -> PatchCheck | str:
        """판정, 또는 미실행 이유(시간 상한 초과는 패치 탓이 아니라 미실행으로 본다)."""

        def verdict(result: str, summary: str) -> PatchCheck:
            return PatchCheck(
                CHECK_DOCKER_BUILD, result, f"{summary} ({PROBE_NOTE})", tool_version=tool_version
            )

        build_command = ("docker", "build", "--network", "none", "-t", image, "-")
        pip_command = (
            "docker", "run", "--rm", "--network", "none", image, "python", "-c", PIP_ABSENT_CODE,
        )  # fmt: skip
        try:
            if self._timed(build_command, probe, budget_end).returncode != 0:
                return verdict(RESULT_FAIL, "탐침 빌드 실패")
            if self._timed(pip_command, None, budget_end).returncode != 0:
                return verdict(RESULT_FAIL, "탐침 이미지에 pip 가 남아 있음")
        except subprocess.TimeoutExpired:
            return f"시간 상한 {DOCKER_BUDGET_SECONDS:.0f}초 초과"
        return verdict(RESULT_PASS, "탐침 빌드 성공, pip 없음")

    def _trivy_check(self, image: str, budget_end: float) -> PatchCheck | str:
        """판정, 또는 미실행 이유(trivy 준비·실행 실패는 패치 탓이 아니다)."""
        version = self._trivy_version(budget_end)

        def verdict(result: str, summary: str) -> PatchCheck:
            return PatchCheck(
                CHECK_TRIVY, result, f"{summary} ({TRIVY_SCOPE_NOTE})", tool_version=version
            )

        scan_command = (
            "trivy", "image", "--scanners", "vuln", "--severity", "HIGH,CRITICAL",
            "--ignore-unfixed", "--format", "json", "--quiet", image,
        )  # fmt: skip
        try:
            scan = self._timed(scan_command, None, budget_end)
        except subprocess.TimeoutExpired:
            return f"시간 상한 {DOCKER_BUDGET_SECONDS:.0f}초 초과"
        if scan.returncode != 0:
            return "trivy 실행 실패"
        try:
            fixable = fixable_vulnerabilities(scan.stdout)
        except (ValueError, AttributeError, TypeError):
            return "trivy 결과를 읽지 못함"
        result = RESULT_FAIL if fixable else RESULT_PASS
        return verdict(result, f"수정 가능한 HIGH·CRITICAL {fixable}건")

    def _trivy_version(self, budget_end: float) -> str | None:
        try:
            output = self._timed(("trivy", "--version"), None, budget_end)
        except (OSError, subprocess.SubprocessError):
            return None
        found = re.search(r"Version:\s*(\S+)", output.stdout)
        return f"trivy {found[1]}" if output.returncode == 0 and found else None

    def _remove_probe(self, image: str) -> bool:
        """탐침 이미지를 지운다. 실패해도 검사 결과를 바꾸지 않고 이벤트에 적는다."""
        try:
            removal = self.run_command(("docker", "rmi", "-f", image), None, CLEANUP_SECONDS)
        except (OSError, subprocess.SubprocessError):
            return False
        return removal.returncode == 0


def scenario_dockerfile() -> Path:
    """기본은 저장소 루트의 시나리오 사본. `ECHO_SCENARIO_ROOT` 로 바꿀 수 있다(시험용)."""
    root = os.environ.get(SCENARIO_ROOT_ENV)
    directory = Path(root) if root else Path(__file__).resolve().parents[2] / SCENARIO_DIR
    return directory / "Dockerfile"


def _prepare(raw_snapshot: Mapping[str, Any], events: RunEventLog) -> _Candidate | None:
    """발동 조건을 보고 변환·diff 를 만든다. 조건이 거짓이면 이벤트를 남기고 None."""
    flagged = flagged_results(raw_snapshot)
    if not flagged:
        _report_not_applicable(events, REASON_NOT_FLAGGED)
        return None
    if not scenario_matches(raw_snapshot):
        _report_not_applicable(events, REASON_OTHER_SERVICE)
        return None
    try:
        # 줄 끝을 바꾸지 않으려고 바이트로 읽는다.
        original = scenario_dockerfile().read_bytes().decode("utf-8")
    except OSError as error:
        raise _PatchSkipped(REASON_SCENARIO_MISSING) from error
    if already_patched(original):
        _report_not_applicable(events, REASON_ALREADY_PATCHED)
        return None
    patched = transform_dockerfile(original)
    return _Candidate(original, patched, build_diff(original, patched, SCENARIO_FILE), flagged)


def _report_not_applicable(events: RunEventLog, reason: str) -> None:
    events.add(RunStep.PATCH_PROPOSE, "rule patch not applicable", reason=reason)


def _cleanup_detail(probe_removed: bool) -> dict[str, Any]:
    return {} if probe_removed else {"probeRemoved": False}


def _report_dropped(
    events: RunEventLog, checks: Sequence[PatchCheck], *, probe_removed: bool
) -> None:
    failed = next(check for check in checks if not check.passed)
    events.add(
        RunStep.PATCH_VERIFY,
        "rule patch dropped after failed check",
        EventLevel.WARN,
        checks=[check.label for check in checks],
        detail=failed.summary,
        **_cleanup_detail(probe_removed),
    )


def _patch_element(
    candidate: _Candidate, checks: Sequence[PatchCheck], not_run: Sequence[str]
) -> dict[str, Any]:
    """`result.patches[0]`. 키는 SPEC 5절 8개뿐이다(WAS `extra=forbid`)."""
    return {
        "id": PATCH_ID,
        "patchHash": patch_hash(candidate.diff),
        "files": [SCENARIO_FILE],
        "diff": candidate.diff,
        "reason": _reason(candidate.flagged, checks, not_run),
        "touchesProtectedFiles": "PROTECTED_FILE"
        in policy_violations(touched_paths([SCENARIO_FILE], candidate.diff)),
        "checks": [check.to_json() for check in checks],
        "origin": "RULE",
    }


def _reason(flagged: Counter[str], checks: Sequence[PatchCheck], not_run: Sequence[str]) -> str:
    counts = ", ".join(f"{result} {count}건" for result, count in sorted(flagged.items()))
    text = (
        f"근거: 입력 스냅숏의 {TRIGGER_CONTROL} 결과가 PASS 가 아닙니다"
        f"({counts[:FLAGGED_TEXT_LIMIT]}). "
        "수정: 실행 이미지에서 pip 를 지웁니다. 운영 echo-demo-app `6ac8813` 과 같은 수정입니다. "
        f"고정 시나리오 사본({SCENARIO_DIR}) 전용 규칙 R-PIP-1 이 만들었습니다(모델 아님). "
        f"실행한 검사: {', '.join(check.name for check in checks)}. "
        f"미실행 검사: {', '.join(not_run) or '없음'}."
    )
    return text[:TEXT_LIMIT]
