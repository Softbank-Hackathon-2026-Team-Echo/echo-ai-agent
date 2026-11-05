"""규칙 패치 제안(SPEC `specs/ai-5-rule-patch-proposal.md` AC-1~AC-4).

가짜 WAS·가짜 명령 실행기로 돈다. 실제 docker 시험만 마커 `docker` 로 데몬이 있을 때 돈다.
"""

import hashlib
import json
import re
import shutil
import subprocess
import threading
import uuid
from collections.abc import Callable, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from echo_agent import precheck_patch, precheck_runner
from echo_agent.precheck_model import PrecheckReviewer
from echo_agent.precheck_patch import (
    PATCH_ID,
    PIP_ABSENT_CODE,
    POLICY_VERSION,
    SCENARIO_FILE,
    SCENARIO_ROOT_ENV,
    CommandResult,
    DiffApplyError,
    RulePatcher,
    apply_unified_diff,
    build_diff,
    fixable_vulnerabilities,
    patch_hash,
    policy_violations,
    probe_dockerfile,
    probe_image,
    static_problems,
    subprocess_runner,
    transform_dockerfile,
)
from echo_agent.precheck_rules import analyze
from echo_agent.precheck_runner import FAILURE_DEADLINE, build_result, main, process_run, run_loop
from tests.test_precheck_model import FakeCreate, _response
from tests.test_was_client import (
    BASE,
    RUN_ID,
    RUNNER_CRED,
    FakeWas,
    _claimed,
    _client,
    _routes,
    _run_payload,
    fail,
    ok,
)

REPO = Path(__file__).resolve().parents[1]
SCENARIO_DOCKERFILE = REPO / SCENARIO_FILE
FIXED_DOCKERFILE = REPO / "tests/fixtures/demo-app-6ac8813.Dockerfile"

ORIGINAL = SCENARIO_DOCKERFILE.read_bytes().decode()
FIXED = FIXED_DOCKERFILE.read_bytes().decode()

PATCH_KEYS = {
    "id", "patchHash", "files", "diff", "reason", "touchesProtectedFiles", "checks", "origin",
}  # fmt: skip
STATIC_LABELS = ["PATCH_APPLIES=PASS", "POLICY=PASS", "DOCKERFILE_STATIC=PASS"]
PATCH_STEPS = {"PATCH_PROPOSE", "PATCH_VERIFY"}
BASE_STEPS = ["INPUT_LOAD", "CONFIG_DIFF", "ANALYZE"]
DOCKER_VERSION = ["docker", "version", "--format", "{{.Server.Version}}"]
PROBE_TAG = f"echo-rule-patch-probe:{RUN_ID[:8]}"
COMMAND_OUTPUT_CANARY = "raw-build-output-canary"

PLAIN_STAGES = """FROM python:3.13-slim AS base
ENV A=1

FROM base AS runner
RUN echo one && \\
    echo two
USER 1001:1001
CMD ["python", "-m", "app"]
"""


@pytest.fixture(autouse=True)
def _default_scenario_root(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(SCENARIO_ROOT_ENV, raising=False)


class FakeCommands:
    """명령 실행기 자리에 끼운다. 받은 인자를 쌓고 정해 둔 결과를 돌려준다."""

    def __init__(
        self,
        *,
        docker: bool = True,
        version_rc: int = 0,
        build_rc: int = 0,
        pip_rc: int = 0,
        rmi_rc: int = 0,
        trivy_rc: int = 0,
        trivy_json: str = '{"Results": []}',
        on_build: Callable[[], None] | None = None,
    ) -> None:
        self.docker = docker
        self.version_rc = version_rc
        self.build_rc = build_rc
        self.pip_rc = pip_rc
        self.rmi_rc = rmi_rc
        self.trivy_rc = trivy_rc
        self.trivy_json = trivy_json
        self.on_build = on_build
        self.calls: list[tuple[Sequence[str], str | None, float]] = []

    def __call__(self, args: Sequence[str], stdin: str | None, timeout: float) -> CommandResult:
        self.calls.append((args, stdin, timeout))
        tool, verb = args[0], args[1]
        if tool == "docker" and not self.docker:
            raise FileNotFoundError("docker")
        if verb == "version":
            return CommandResult(self.version_rc, "29.8.2\n" if self.version_rc == 0 else "")
        if verb == "build":
            if self.on_build:
                self.on_build()
            return CommandResult(self.build_rc, COMMAND_OUTPUT_CANARY)
        if verb == "run":
            return CommandResult(self.pip_rc, "")
        if verb == "rmi":
            return CommandResult(self.rmi_rc, "")
        if verb == "--version":
            return CommandResult(0, "Version: 0.75.0\nVulnerability DB:\n  Version: 2\n")
        if verb == "image":
            return CommandResult(self.trivy_rc, self.trivy_json)
        raise AssertionError(f"unexpected command: {args}")

    @property
    def argv(self) -> list[list[str]]:
        return [list(args) for args, _, _ in self.calls]


def _no_tool(name: str) -> str | None:
    return None


def _has_trivy(name: str) -> str | None:
    return "/usr/local/bin/trivy" if name == "trivy" else None


def _static_only() -> RulePatcher:
    """샌드박스 VM 처럼 docker·trivy 가 없는 곳."""
    return RulePatcher(FakeCommands(docker=False), which=_no_tool)


def _payload(*results: str, deadline: datetime | None = None) -> dict[str, Any]:
    payload = _run_payload(deadline)
    payload["run"]["inputSnapshot"]["findings"] = [
        {
            "controlId": "C-IMG-1",
            "result": result,
            "source": "trivy",
            "environmentId": "env-source",
            "collectedAt": "2026-11-05T01:00:00Z",
        }
        for result in results
    ]
    return payload


def _was(payload: dict[str, Any], **overrides: Any) -> FakeWas:
    return FakeWas(_routes(**{"runs:claim": lambda p, b: ok(payload)}, **overrides))


def _submit(
    patcher: RulePatcher | None, *results: str, reviewer: PrecheckReviewer | None = None
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    fake = _was(_payload(*results))
    outcome = process_run(
        _client(fake), _claimed(fake), log=lambda m: None, reviewer=reviewer, patcher=patcher
    )
    assert outcome.submitted is True
    return fake.bodies("result")[0], _sent_events(fake)


def _sent_events(fake: FakeWas) -> list[dict[str, Any]]:
    return [event for body in fake.bodies("events") for event in body["events"]]


def _patch_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [event for event in events if event["step"] in PATCH_STEPS]


def _write_scenario(root: Path, text: str, monkeypatch: pytest.MonkeyPatch) -> None:
    (root / "Dockerfile").write_bytes(text.encode())
    monkeypatch.setenv(SCENARIO_ROOT_ENV, str(root))


def _assert_was_accepts_patch(patch: dict[str, Any]) -> None:
    """SPEC 2절에 옮겨 적은 WAS `RunPatchRequest` 검사(+ S1 의 `origin`)."""
    assert set(patch) == PATCH_KEYS
    assert 1 <= len(patch["id"]) <= 64
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", patch["patchHash"])
    assert len(patch["files"]) >= 1
    assert len(patch["diff"].encode()) <= 200_000
    assert len(patch["reason"]) <= 2_000
    assert isinstance(patch["touchesProtectedFiles"], bool)
    assert patch["origin"] in {"RULE", "AI"}
    assert patch["checks"]
    for check in patch["checks"]:
        assert set(check) <= {"name", "result", "toolVersion", "policyVersion", "summary"}
        assert 1 <= len(check["name"]) <= 64
        assert re.fullmatch(r"[A-Z][A-Z0-9_]{0,31}", check["result"])


# ---------------------------------------------------------------- AC-1 발동 → 패치 1개


def test_scenario_copies_are_the_recorded_bytes() -> None:
    assert hashlib.sha256(SCENARIO_DOCKERFILE.read_bytes()).hexdigest() == (
        "5895a31b150508f14f2c153c7e42d0a685e04dcf181230cd40d2e05087a1adc0"
    )
    assert hashlib.sha256(FIXED_DOCKERFILE.read_bytes()).hexdigest() == (
        "704211dcacaa8db269e4e19a7dcb7074e6ddbf24ab7930ffe39c8c1166e2358c"
    )


def test_transform_is_byte_identical_to_6ac8813() -> None:
    assert transform_dockerfile(ORIGINAL) == FIXED


def test_rule_patch_proposed_for_flagged_c_img_1() -> None:
    result, events = _submit(_static_only(), "WARN")

    assert (result["status"], result["failureCode"]) == ("SUCCEEDED", None)
    assert result["simulated"] is False
    assert len(result["patches"]) == 1
    patch = result["patches"][0]
    _assert_was_accepts_patch(patch)
    assert patch["id"] == PATCH_ID
    assert patch["files"] == ["scenarios/demo-app-0ff0d44/Dockerfile"]
    assert patch["origin"] == "RULE"
    assert patch["touchesProtectedFiles"] is False
    expected_hash = hashlib.sha256(patch["diff"].encode()).hexdigest()
    assert patch["patchHash"] == f"sha256:{expected_hash}"

    applied = apply_unified_diff(ORIGINAL, patch["diff"], SCENARIO_FILE)
    assert applied.encode() == FIXED_DOCKERFILE.read_bytes()
    assert [line for line in patch["diff"].split("\n") if line.startswith("@@")] == [
        "@@ -23,7 +23,11 @@"
    ]

    checks = {check["name"]: check for check in patch["checks"]}
    assert set(checks) == {"PATCH_APPLIES", "POLICY", "DOCKERFILE_STATIC"}
    assert all(check["result"] == "PASS" for check in checks.values())
    assert checks["POLICY"]["policyVersion"] == POLICY_VERSION

    assert [event["step"] for event in events] == [*BASE_STEPS, "PATCH_PROPOSE", "PATCH_VERIFY"]
    assert [event["seq"] for event in events] == list(range(1, 6))
    proposed, verified = events[-2:]
    assert (proposed["level"], proposed["message"]) == ("INFO", "rule patch proposed")
    assert proposed["data"] == {"patchId": PATCH_ID, "origin": "RULE"}
    assert (verified["level"], verified["message"]) == ("INFO", "rule patch checks passed")
    assert verified["data"] == {
        "checks": STATIC_LABELS,
        "dockerChecked": False,
        "trivyChecked": False,
    }


def test_generated_diff_is_a_real_unified_diff_for_git_apply(tmp_path: Path) -> None:
    """내부 적용기와 별개로 `git apply` 도 같은 결과를 내는지 본다."""
    diff = build_diff(ORIGINAL, FIXED, SCENARIO_FILE)
    assert diff.startswith(f"--- a/{SCENARIO_FILE}\n+++ b/{SCENARIO_FILE}\n@@ -23,7 +23,11 @@\n")
    assert "diff --git" not in diff and "\nindex " not in diff
    assert all(line.endswith("\n") for line in diff.splitlines(keepends=True))

    target = tmp_path / SCENARIO_FILE
    target.parent.mkdir(parents=True)
    target.write_bytes(ORIGINAL.encode())
    subprocess.run(  # noqa: S603
        ["git", "apply", "-"],  # noqa: S607
        cwd=tmp_path,
        input=diff.encode(),
        check=True,
        capture_output=True,
    )
    assert target.read_bytes() == FIXED_DOCKERFILE.read_bytes()


@pytest.mark.parametrize("flag", ["FAIL", "WARN", "UNKNOWN", "fail"])
def test_any_result_other_than_pass_triggers_the_rule(flag: str) -> None:
    result, _ = _submit(_static_only(), "PASS", flag)
    assert len(result["patches"]) == 1


def test_reason_states_evidence_origin_and_scope() -> None:
    result, _ = _submit(_static_only(), "WARN", "WARN", "FAIL")
    reason = result["patches"][0]["reason"]
    assert "C-IMG-1" in reason and "FAIL 1건, WARN 2건" in reason
    assert "6ac8813" in reason
    assert "고정 시나리오 사본" in reason and "모델 아님" in reason
    assert "PATCH_APPLIES, POLICY, DOCKERFILE_STATIC" in reason


def test_same_input_gives_the_same_patch_hash() -> None:
    first, _ = _submit(_static_only(), "WARN")
    second, _ = _submit(_static_only(), "WARN")
    assert first["patches"][0]["patchHash"] == second["patches"][0]["patchHash"]
    assert first["patches"][0]["patchHash"] == patch_hash(first["patches"][0]["diff"])


# ---------------------------------------------------------------- AC-2 발동 안 함·끄기


@pytest.mark.parametrize("results", [("PASS",), ()], ids=["pass", "absent"])
def test_rule_patch_not_applicable_when_c_img_1_not_flagged(results: tuple[str, ...]) -> None:
    commands = FakeCommands()
    result, events = _submit(RulePatcher(commands, which=_no_tool), *results)
    assert result["patches"] == []
    assert result["status"] == "SUCCEEDED"
    [event] = _patch_events(events)
    assert (event["step"], event["level"]) == ("PATCH_PROPOSE", "INFO")
    assert event["message"] == "rule patch not applicable"
    assert event["data"] == {"reason": "C_IMG_1_NOT_FLAGGED"}
    assert commands.calls == []


def test_other_controls_do_not_trigger_the_rule() -> None:
    payload = _payload()
    payload["run"]["inputSnapshot"]["findings"] = [
        {"controlId": "C-TLS-1", "result": "FAIL", "source": "tls", "environmentId": "env"}
    ]
    fake = _was(payload)
    process_run(_client(fake), _claimed(fake), log=lambda m: None, patcher=_static_only())
    assert fake.bodies("result")[0]["patches"] == []


def test_rule_patch_not_applicable_when_already_patched(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write_scenario(tmp_path, FIXED, monkeypatch)
    result, events = _submit(_static_only(), "WARN")
    assert result["patches"] == []
    assert result["status"] == "SUCCEEDED"
    [event] = _patch_events(events)
    assert event["message"] == "rule patch not applicable"
    assert event["data"] == {"reason": "ALREADY_PATCHED"}


def test_no_patch_flag_keeps_pr14_result() -> None:
    plain, plain_events = _submit(None, "WARN")
    assert plain["patches"] == []
    assert [event["step"] for event in plain_events] == BASE_STEPS

    payload = _payload("WARN")
    expected = build_result(
        analyze(payload["run"]["inputSnapshot"]), status="SUCCEEDED", failure_code=None
    )
    assert plain == expected

    patched, _ = _submit(_static_only(), "WARN")
    assert {**patched, "patches": []} == plain  # 패치 말고 나머지 결과는 같다


def test_main_turns_the_patcher_on_unless_no_patch(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: list[Any] = []

    def fake_loop(client: Any, name: str, **kwargs: Any) -> int:
        captured.append(kwargs["patcher"])
        return 0

    monkeypatch.setattr(precheck_runner, "run_loop", fake_loop)
    monkeypatch.setattr(precheck_runner.signal, "signal", lambda *args: None)
    monkeypatch.setenv("ECHO_WAS_URL", BASE)
    monkeypatch.setenv("ECHO_RUNNER_TOKEN", RUNNER_CRED)

    assert main(["--once", "--no-model"]) == 0
    assert isinstance(captured[-1], RulePatcher)
    assert main(["--once", "--no-model", "--no-patch"]) == 0
    assert captured[-1] is None


def test_run_loop_passes_the_patcher_to_each_run() -> None:
    fake = _was(_payload("WARN"))
    code = run_loop(
        _client(fake),
        "r",
        once=True,
        stop=threading.Event(),
        log=lambda m: None,
        patcher=_static_only(),
    )
    assert code == 0
    assert len(fake.bodies("result")[0]["patches"]) == 1


# ---------------------------------------------------------------- AC-3 실패 시 동작


def _assert_dropped(
    result: dict[str, Any], events: list[dict[str, Any]], labels: list[str]
) -> dict[str, Any]:
    assert result["patches"] == []
    assert (result["status"], result["failureCode"]) == ("SUCCEEDED", None)
    assert result["findings"]  # 규칙 findings 는 그대로
    assert result["configDiff"]
    event = _patch_events(events)[-1]
    assert (event["step"], event["level"]) == ("PATCH_VERIFY", "WARN")
    assert event["message"] == "rule patch dropped after failed check"
    assert event["data"]["checks"] == labels
    return event


@pytest.mark.parametrize(
    "commands",
    [FakeCommands(build_rc=1), FakeCommands(pip_rc=1)],
    ids=["build-fails", "pip-still-there"],
)
def test_rule_patch_dropped_when_check_fails(commands: FakeCommands) -> None:
    commands.calls = []
    result, events = _submit(RulePatcher(commands, which=_has_trivy), "WARN")
    _assert_dropped(result, events, [*STATIC_LABELS, "DOCKER_BUILD=FAIL"])
    assert commands.argv[-1] == ["docker", "rmi", "-f", PROBE_TAG]
    assert not any(args[0] == "trivy" for args in commands.argv)  # 실패 뒤 검사는 돌리지 않는다


def test_rule_patch_dropped_when_path_is_protected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(precheck_patch, "SCENARIO_FILE", "specs/Dockerfile")
    commands = FakeCommands()
    result, events = _submit(RulePatcher(commands, which=_has_trivy), "WARN")
    event = _assert_dropped(result, events, ["PATCH_APPLIES=PASS", "POLICY=FAIL"])
    assert "OUTSIDE_SCENARIO" in event["data"]["detail"]
    assert "PROTECTED_FILE" in event["data"]["detail"]
    assert commands.calls == []


def test_rule_patch_dropped_when_diff_does_not_apply(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        precheck_patch,
        "build_diff",
        lambda original, patched, path: build_diff(original, patched, path).replace(
            " COPY --from=builder", " COPY --from=other", 1
        ),
    )
    commands = FakeCommands()
    result, events = _submit(RulePatcher(commands, which=_no_tool), "WARN")
    _assert_dropped(result, events, ["PATCH_APPLIES=FAIL"])
    assert commands.calls == []


def test_rule_patch_dropped_when_uninstall_would_run_as_app_user(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    text = "FROM python:3.13-slim AS base\nFROM base\nUSER 1001:1001\nRUN echo hi\nCMD x\n"
    _write_scenario(tmp_path, text, monkeypatch)
    result, events = _submit(_static_only(), "WARN")
    labels = ["PATCH_APPLIES=PASS", "POLICY=PASS", "DOCKERFILE_STATIC=FAIL"]
    event = _assert_dropped(result, events, labels)
    assert "PIP_UNINSTALL_NOT_BEFORE_USER" in event["data"]["detail"]


def _assert_skipped(
    result: dict[str, Any], events: list[dict[str, Any]], reason: str, step: str
) -> None:
    assert result["patches"] == []
    assert (result["status"], result["failureCode"]) == ("SUCCEEDED", None)
    assert result["findings"]
    event = _patch_events(events)[-1]
    assert (event["step"], event["level"]) == (step, "WARN")
    assert event["message"] == "rule patch skipped"
    assert event["data"]["reason"] == reason


def test_patch_error_never_fails_run_when_scenario_is_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(SCENARIO_ROOT_ENV, str(tmp_path / "nowhere"))
    result, events = _submit(_static_only(), "WARN")
    _assert_skipped(result, events, "SCENARIO_MISSING", "PATCH_PROPOSE")


@pytest.mark.parametrize(
    "text",
    [
        "FROM python:3.13 AS base\nFROM base\nUSER 1001:1001\nCMD x\n",
        "FROM base\nRUN --mount=type=cache,target=/c echo hi\nCMD x\n",
        'FROM base\nRUN ["echo", "hi"]\nCMD x\n',
        "FROM base\nrun echo hi\nCMD x\n",
        "FROM base\r\nRUN echo hi\r\n",
        "FROM base\nRUN echo hi",
        "# 주석뿐\n",
    ],
    ids=["no-run", "run-flags", "exec-form", "lower-case", "crlf", "no-newline", "no-from"],
)
def test_patch_error_never_fails_run_when_transform_does_not_fit(
    text: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write_scenario(tmp_path, text, monkeypatch)
    result, events = _submit(_static_only(), "WARN")
    _assert_skipped(result, events, "TRANSFORM_NOT_APPLICABLE", "PATCH_PROPOSE")


def test_patch_error_never_fails_run_on_unexpected_exception(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def boom(raw: Any) -> Any:
        raise RuntimeError("boom")

    monkeypatch.setattr(precheck_patch, "flagged_results", boom)
    result, events = _submit(_static_only(), "WARN")
    _assert_skipped(result, events, "PATCH_ERROR", "PATCH_PROPOSE")
    assert _patch_events(events)[-1]["data"]["error"] == "RuntimeError"


def test_patch_error_never_fails_run_when_docker_call_breaks() -> None:
    def broken_build() -> None:
        raise OSError("docker went away")

    commands = FakeCommands(on_build=broken_build)
    result, events = _submit(RulePatcher(commands, which=_no_tool), "WARN")
    _assert_skipped(result, events, "PATCH_ERROR", "PATCH_VERIFY")
    assert commands.argv[-1][:3] == ["docker", "rmi", "-f"]


def test_deadline_after_patch_stage_fails_run_and_drops_patch() -> None:
    now = datetime.now(UTC)
    deadline = now + timedelta(minutes=15)
    clock = {"now": now}

    def move_past_deadline() -> None:
        clock["now"] = deadline

    fake = _was(_payload("WARN", deadline=deadline))
    outcome = process_run(
        _client(fake),
        _claimed(fake),
        clock=lambda: clock["now"],
        log=lambda m: None,
        patcher=RulePatcher(FakeCommands(on_build=move_past_deadline), which=_no_tool),
    )
    result = fake.bodies("result")[0]
    assert (result["status"], result["failureCode"]) == ("FAILED", FAILURE_DEADLINE)
    assert result["patches"] == []
    assert outcome.failure_code == FAILURE_DEADLINE


def test_run_closed_during_patch_stage_stops_before_docker() -> None:
    def events_route(path: str, body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        if any(event["step"] in PATCH_STEPS for event in body["events"]):
            return fail(409, "RUN_NOT_ACTIVE")
        return ok({"acceptedUpTo": body["events"][-1]["seq"]})

    fake = _was(_payload("WARN"), events=events_route)
    commands = FakeCommands()
    outcome = process_run(
        _client(fake),
        _claimed(fake),
        log=lambda m: None,
        patcher=RulePatcher(commands, which=_no_tool),
    )
    assert (outcome.status, outcome.submitted) == ("LOST", False)
    assert fake.bodies("result") == []
    assert commands.calls == []


def test_failed_run_never_reaches_the_patch_stage() -> None:
    payload = _payload("WARN")
    payload["run"]["inputSnapshot"]["schemaVersion"] = 99
    fake = _was(payload)
    commands = FakeCommands()
    process_run(
        _client(fake),
        _claimed(fake),
        log=lambda m: None,
        patcher=RulePatcher(commands, which=_no_tool),
    )
    result = fake.bodies("result")[0]
    assert (result["status"], result["failureCode"]) == ("FAILED", "INPUT_INVALID")
    assert result["patches"] == []
    assert _patch_events(_sent_events(fake)) == []
    assert commands.calls == []


def test_unsupported_kind_never_reaches_the_patch_stage() -> None:
    payload = _payload("WARN")
    payload["run"]["kind"] = "APPLY_PATCH"
    fake = _was(payload)
    process_run(_client(fake), _claimed(fake), log=lambda m: None, patcher=_static_only())
    result = fake.bodies("result")[0]
    assert (result["status"], result["failureCode"]) == ("FAILED", "KIND_UNSUPPORTED")
    assert result["patches"] == []
    assert _patch_events(_sent_events(fake)) == []


def test_rule_patch_does_not_depend_on_model_review() -> None:
    reviewer = PrecheckReviewer(FakeCreate(_response("{bad")))
    result, events = _submit(_static_only(), "WARN", reviewer=reviewer)
    assert result["model"] is None
    assert result["status"] == "SUCCEEDED"
    assert len(result["patches"]) == 1
    messages = [event["message"] for event in events]
    assert messages[-3:] == [
        "model review failed; rule result only",
        "rule patch proposed",
        "rule patch checks passed",
    ]


# ---------------------------------------------------------------- AC-4 docker 검사 정직성


@pytest.mark.parametrize(
    "commands",
    [FakeCommands(docker=False), FakeCommands(version_rc=1)],
    ids=["binary-missing", "no-socket-permission"],
)
def test_docker_check_absent_when_docker_unusable(commands: FakeCommands) -> None:
    commands.calls = []
    result, events = _submit(RulePatcher(commands, which=_has_trivy), "WARN")
    patch = result["patches"][0]
    names = [check["name"] for check in patch["checks"]]
    assert names == ["PATCH_APPLIES", "POLICY", "DOCKERFILE_STATIC"]  # 안 돌린 검사를 적지 않는다
    assert "미실행 검사: DOCKER_BUILD(docker 를 쓸 수 없음" in patch["reason"]
    assert "TRIVY(DOCKER_BUILD 미실행)" in patch["reason"]
    assert commands.argv == [DOCKER_VERSION]
    assert events[-1]["data"]["dockerChecked"] is False


def test_docker_check_timeout_on_version_counts_as_unusable() -> None:
    def hangs(args: Sequence[str], stdin: str | None, timeout: float) -> CommandResult:
        assert timeout == 10.0
        raise subprocess.TimeoutExpired(list(args), timeout)

    result, _ = _submit(RulePatcher(hangs, which=_no_tool), "WARN")
    assert "미실행 검사: DOCKER_BUILD" in result["patches"][0]["reason"]


def test_docker_check_runs_probe_without_shell_or_network_and_cleans_up() -> None:
    commands = FakeCommands()
    result, events = _submit(RulePatcher(commands, which=_no_tool), "WARN")

    patch = result["patches"][0]
    _assert_was_accepts_patch(patch)
    check = patch["checks"][-1]
    assert check["name"] == "DOCKER_BUILD"
    assert check["result"] == "PASS"
    assert check["toolVersion"] == "docker 29.8.2"
    assert "실행 단계 RUN만, 앱 소스 없음" in check["summary"]

    assert all(isinstance(args, tuple | list) for args, _, _ in commands.calls)  # 셸 문자열 아님
    assert commands.argv == [
        DOCKER_VERSION,
        ["docker", "build", "--network", "none", "-t", PROBE_TAG, "-"],
        ["docker", "run", "--rm", "--network", "none", PROBE_TAG, "python", "-c", PIP_ABSENT_CODE],
        ["docker", "rmi", "-f", PROBE_TAG],
    ]
    _, stdin, timeout = commands.calls[1]
    assert stdin == probe_dockerfile(FIXED)
    assert 0 < timeout <= 180.0
    assert events[-1]["data"]["dockerChecked"] is True
    assert events[-1]["data"]["trivyChecked"] is False
    assert "TRIVY(trivy 가 PATH 에 없음)" in patch["reason"]
    assert "DOCKER_BUILD(" not in patch["reason"]


def test_probe_dockerfile_is_base_from_and_first_run_only() -> None:
    assert probe_dockerfile(FIXED) == (
        "FROM python:3.13-slim AS base\n"
        "RUN python -m pip uninstall --yes --no-cache-dir pip && \\\n"
        "    groupadd --system --gid 1001 app && \\\n"
        "    useradd --system --uid 1001 --gid app --no-create-home app\n"
    )


def test_probe_image_tag_uses_the_first_eight_run_id_characters() -> None:
    assert probe_image("33333333-3333") == "echo-rule-patch-probe:33333333"
    assert probe_image("-a/b c:d-e") == "echo-rule-patch-probe:_a_b_c_d"


def test_docker_check_skipped_when_deadline_is_close() -> None:
    commands = FakeCommands()
    deadline = datetime.now(UTC) + timedelta(minutes=1, seconds=120)  # 1분 + 180초보다 적다
    fake = _was(_payload("WARN", deadline=deadline))
    process_run(
        _client(fake),
        _claimed(fake),
        log=lambda m: None,
        patcher=RulePatcher(commands, which=_has_trivy),
    )
    patch = fake.bodies("result")[0]["patches"][0]
    assert commands.calls == []
    assert [check["name"] for check in patch["checks"]] == [
        "PATCH_APPLIES",
        "POLICY",
        "DOCKERFILE_STATIC",
    ]
    assert "DOCKER_BUILD(실행 마감이 가까워 건너뜀)" in patch["reason"]


def test_docker_check_fails_when_time_budget_runs_out() -> None:
    class SlowBuild(FakeCommands):
        def __call__(self, args: Sequence[str], stdin: str | None, timeout: float) -> CommandResult:
            if args[1] == "build":
                self.calls.append((args, stdin, timeout))
                raise subprocess.TimeoutExpired(list(args), timeout)
            return super().__call__(args, stdin, timeout)

    commands = SlowBuild()
    result, events = _submit(RulePatcher(commands, which=_has_trivy), "WARN")
    event = _assert_dropped(result, events, [*STATIC_LABELS, "DOCKER_BUILD=FAIL"])
    assert "시간 상한 180초 초과" in event["data"]["detail"]
    assert commands.argv[-1][:3] == ["docker", "rmi", "-f"]


def test_failed_probe_cleanup_is_reported_but_does_not_change_verdict() -> None:
    result, events = _submit(RulePatcher(FakeCommands(rmi_rc=1), which=_no_tool), "WARN")
    assert len(result["patches"]) == 1
    assert events[-1]["data"]["probeRemoved"] is False


def test_trivy_absent_means_no_trivy_check() -> None:
    commands = FakeCommands()
    result, _ = _submit(RulePatcher(commands, which=_no_tool), "WARN")
    assert "TRIVY" not in [check["name"] for check in result["patches"][0]["checks"]]
    assert not any(args[0] == "trivy" for args in commands.argv)


def test_trivy_check_runs_before_probe_is_removed() -> None:
    commands = FakeCommands()
    result, events = _submit(RulePatcher(commands, which=_has_trivy), "WARN")
    patch = result["patches"][0]
    _assert_was_accepts_patch(patch)
    check = patch["checks"][-1]
    assert (check["name"], check["result"]) == ("TRIVY", "PASS")
    assert check["toolVersion"] == "trivy 0.75.0"
    assert commands.argv[-2:] == [
        [
            "trivy", "image", "--scanners", "vuln", "--severity", "HIGH,CRITICAL",
            "--ignore-unfixed", "--format", "json", "--quiet", PROBE_TAG,
        ],
        ["docker", "rmi", "-f", PROBE_TAG],
    ]  # fmt: skip
    assert "미실행 검사: 없음" in patch["reason"]
    assert events[-1]["data"]["trivyChecked"] is True


@pytest.mark.parametrize(
    "commands",
    [
        FakeCommands(
            trivy_json=json.dumps(
                {"Results": [{"Vulnerabilities": [{"Severity": "HIGH", "FixedVersion": "1.2.3"}]}]}
            )
        ),
        FakeCommands(trivy_rc=1),
        FakeCommands(trivy_json="not json"),
        FakeCommands(trivy_json='{"Results": ["bad"]}'),
    ],
    ids=["fixable-high", "tool-error", "bad-json", "bad-shape"],
)
def test_trivy_failure_drops_patch(commands: FakeCommands) -> None:
    commands.calls = []
    result, events = _submit(RulePatcher(commands, which=_has_trivy), "WARN")
    _assert_dropped(result, events, [*STATIC_LABELS, "DOCKER_BUILD=PASS", "TRIVY=FAIL"])
    assert commands.argv[-1][:3] == ["docker", "rmi", "-f"]


def test_fixable_vulnerabilities_counts_only_fixable_high_and_critical() -> None:
    report = {
        "Results": [
            {
                "Vulnerabilities": [
                    {"Severity": "HIGH", "FixedVersion": "1"},
                    {"Severity": "CRITICAL", "FixedVersion": "2"},
                    {"Severity": "HIGH", "FixedVersion": ""},
                    {"Severity": "MEDIUM", "FixedVersion": "3"},
                ]
            },
            {"Vulnerabilities": None},
        ]
    }
    assert fixable_vulnerabilities(json.dumps(report)) == 2
    assert fixable_vulnerabilities('{"Results": null}') == 0


def test_default_runner_uses_no_shell_and_hides_runner_secrets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: dict[str, Any] = {}

    def fake_run(args: Any, **kwargs: Any) -> subprocess.CompletedProcess[str]:
        seen.update(kwargs, args=args)
        return subprocess.CompletedProcess(args, 0, stdout="ok", stderr=None)

    monkeypatch.setenv("ANTHROPIC_API_KEY", "canary-model")
    monkeypatch.setenv("ECHO_RUNNER_TOKEN", "canary-runner")
    monkeypatch.setenv("PATH_FOR_TOOL", "kept")
    monkeypatch.setattr(subprocess, "run", fake_run)

    outcome = subprocess_runner(("docker", "version"), "stdin text", 10.0)

    assert outcome == CommandResult(0, "ok")
    assert seen["args"] == ["docker", "version"]
    assert seen.get("shell", False) is False
    assert seen["input"] == "stdin text"
    assert seen["timeout"] == 10.0
    assert "ANTHROPIC_API_KEY" not in seen["env"]
    assert "ECHO_RUNNER_TOKEN" not in seen["env"]
    assert seen["env"]["PATH_FOR_TOOL"] == "kept"


@pytest.mark.docker
def test_probe_build_real_docker() -> None:
    """탐침을 실제로 빌드해 pip 가 없음을 확인한다. 대조로 베이스 이미지에는 pip 가 있어야 한다."""
    payload = _payload("WARN")
    payload["run"]["id"] = str(uuid.uuid4())
    image = probe_image(payload["run"]["id"])
    fake = _was(payload)

    process_run(
        _client(fake), _claimed(fake), log=lambda m: None, patcher=RulePatcher(which=_no_tool)
    )

    result = fake.bodies("result")[0]
    events = _patch_events(_sent_events(fake))
    assert len(result["patches"]) == 1, events
    check = result["patches"][0]["checks"][-1]
    assert (check["name"], check["result"]) == ("DOCKER_BUILD", "PASS")
    assert check["toolVersion"].startswith("docker ")
    assert events[-1]["data"]["dockerChecked"] is True
    assert "probeRemoved" not in events[-1]["data"]

    docker = shutil.which("docker")
    assert docker is not None
    inspected = subprocess.run(  # noqa: S603
        [docker, "image", "inspect", image], capture_output=True, check=False, timeout=30
    )
    assert inspected.returncode != 0, "탐침 이미지가 남아 있다"
    control = subprocess.run(  # noqa: S603
        [docker, "run", "--rm", "--network", "none", "python:3.13-slim"]
        + ["python", "-c", PIP_ABSENT_CODE],
        capture_output=True,
        check=False,
        timeout=60,
    )
    assert control.returncode == 1, "베이스 이미지에서는 pip 가 잡혀야 한다"


# ---------------------------------------------------------------- 적용기·정책·정적 검사


def test_diff_applier_rejects_a_changed_context_line() -> None:
    diff = build_diff(ORIGINAL, FIXED, SCENARIO_FILE)
    changed = ORIGINAL.replace("COPY --from=builder", "COPY --from=other")
    assert changed != ORIGINAL
    with pytest.raises(DiffApplyError, match="context"):
        apply_unified_diff(changed, diff, SCENARIO_FILE)


@pytest.mark.parametrize(
    "broken",
    [
        lambda d: d.replace("--- a/", "--- x/", 1),
        lambda d: d.replace("+++ b/scenarios", "+++ b/other", 1),
        lambda d: d.replace("@@ -23,7 +23,11 @@", "@@ nonsense @@", 1),
        lambda d: d.replace("@@ -23,7 +23,11 @@", "@@ -23,8 +23,12 @@", 1),
        lambda d: d.split("@@")[0],
        lambda d: d + "extra line\n",
    ],
    ids=["old-path", "new-path", "hunk-header", "hunk-count", "no-hunk", "trailing-text"],
)
def test_diff_applier_rejects_malformed_diff(broken: Callable[[str], str]) -> None:
    diff = broken(build_diff(ORIGINAL, FIXED, SCENARIO_FILE))
    with pytest.raises(DiffApplyError):
        apply_unified_diff(ORIGINAL, diff, SCENARIO_FILE)


def test_diff_applier_keeps_lines_outside_hunks() -> None:
    original = "".join(f"line {n}\n" for n in range(1, 21))
    patched = original.replace("line 3\n", "line three\n").replace("line 17\n", "")
    diff = build_diff(original, patched, "f")
    assert diff.count("@@ -") == 2
    assert apply_unified_diff(original, diff, "f") == patched


@pytest.mark.parametrize(
    ("files", "expected"),
    [
        (["scenarios/demo-app-0ff0d44/Dockerfile"], []),
        (["scenarios/demo-app-0ff0d44/app/main.py"], []),
        (["Dockerfile"], ["OUTSIDE_SCENARIO"]),
        (["scenarios/other/Dockerfile"], ["OUTSIDE_SCENARIO"]),
        (["scenarios/demo-app-0ff0d44/../../pwn"], ["UNSAFE_PATH"]),
        (["/etc/passwd"], ["OUTSIDE_SCENARIO", "UNSAFE_PATH"]),
        (["tests/test_x.py"], ["OUTSIDE_SCENARIO", "PROTECTED_FILE"]),
        ([".github/workflows/ci.yml"], ["OUTSIDE_SCENARIO", "PROTECTED_FILE"]),
        (["security/README.md"], ["OUTSIDE_SCENARIO", "PROTECTED_FILE"]),
        (["specs/a.md"], ["OUTSIDE_SCENARIO", "PROTECTED_FILE"]),
        (["pyproject.toml"], ["OUTSIDE_SCENARIO", "PROTECTED_FILE"]),
        (["uv.lock"], ["OUTSIDE_SCENARIO", "PROTECTED_FILE"]),
        (["scenarios/demo-app-0ff0d44/README.md"], ["PROTECTED_FILE"]),
        (["scenarios/demo-app-0ff0d44/sub/readme.md"], ["PROTECTED_FILE"]),
        (["scenarios/demo-app-0ff0d44/tests/x.py"], ["PROTECTED_FILE"]),
        (["scenarios/demo-app-0ff0d44/uv.lock"], ["PROTECTED_FILE"]),
    ],
)
def test_policy_violations(files: list[str], expected: list[str]) -> None:
    assert policy_violations(files) == expected


def test_static_check_accepts_the_real_patch() -> None:
    assert static_problems(ORIGINAL, FIXED) == []


@pytest.mark.parametrize(
    ("change", "problem"),
    [
        (lambda t: t.replace("python:3.13-slim", "python:3.12-slim"), "FROM_CHANGED"),
        (lambda t: t.replace("ENV A=1", "ENV A=2"), "OTHER_STAGE_CHANGED"),
        (lambda t: t.replace("USER 1001:1001", "USER root"), "USER_CHANGED"),
        (lambda t: t.replace('CMD ["python", "-m", "app"]', "CMD sh"), "CMD_CHANGED"),
        (lambda t: t.replace("FROM base AS runner\n", ""), "STAGE_COUNT_CHANGED"),
        (lambda t: t.replace("pip uninstall", "pip list"), "PIP_UNINSTALL_NOT_BEFORE_USER"),
        (
            lambda t: t.replace(
                "RUN python -m pip uninstall --yes pip && \\\n    ", "RUN "
            ).replace("CMD", "RUN python -m pip uninstall --yes pip\nCMD"),
            "PIP_UNINSTALL_NOT_BEFORE_USER",
        ),
    ],
    ids=["from", "other-stage", "user", "cmd", "stage-count", "no-uninstall", "after-user"],
)
def test_static_check_rejects(change: Callable[[str], str], problem: str) -> None:
    patched = PLAIN_STAGES.replace(
        "RUN echo one", "RUN python -m pip uninstall --yes pip && \\\n    echo one"
    )
    assert static_problems(PLAIN_STAGES, patched) == []
    assert problem in static_problems(PLAIN_STAGES, change(patched))


def test_pip_uninstall_in_a_comment_does_not_count_as_patched(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    text = ORIGINAL.replace("USER 1001:1001", "# pip uninstall 은 아직\nUSER 1001:1001")
    _write_scenario(tmp_path, text, monkeypatch)
    result, _ = _submit(_static_only(), "WARN")
    assert len(result["patches"]) == 1


def test_pip_uninstall_only_in_an_earlier_stage_does_not_count(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    text = ORIGINAL.replace(
        "WORKDIR /app\nCOPY pyproject", "RUN pip uninstall -y pip\nCOPY pyproject"
    )
    _write_scenario(tmp_path, text, monkeypatch)
    result, _ = _submit(_static_only(), "WARN")
    assert len(result["patches"]) == 1


@pytest.mark.parametrize("build_rc", [0, 1], ids=["passed", "dropped"])
def test_events_stay_short_and_carry_no_command_output(build_rc: int) -> None:
    commands = FakeCommands(build_rc=build_rc)
    result, events = _submit(RulePatcher(commands, which=_no_tool), "WARN")
    for event in _patch_events(events):
        assert len(event["message"]) <= 200
        assert event["message"].isascii()
    sent = json.dumps([result, events], ensure_ascii=False)
    assert COMMAND_OUTPUT_CANARY not in sent
