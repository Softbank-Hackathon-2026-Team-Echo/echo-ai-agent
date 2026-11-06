"""반영 실행 러너(AI 에이전트 5-2). 가짜 docker·trivy·소스 받기 + 가짜 WAS 로 돈다(네트워크 없음).

git 이 필요한 시험은 실제 git 으로 임시 저장소를 만든다(CI ubuntu·로컬 모두 있음).
"""

import difflib
import hashlib
import json
import shutil
import subprocess
import threading
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from echo_agent import apply_runner
from echo_agent.apply_runner import (
    APPLY_REPOSITORY,
    FAILURE_DEADLINE,
    FAILURE_HEALTHZ_FAILED,
    FAILURE_IMAGE_BUILD_FAILED,
    FAILURE_IMAGE_SCAN_FAILED,
    FAILURE_INPUT_INVALID,
    FAILURE_PATCH_APPLY_FAILED,
    FAILURE_PATCH_HASH_MISMATCH,
    FAILURE_PATCH_TARGET_FORBIDDEN,
    FAILURE_SOURCE_UNAVAILABLE,
    FAILURE_VERIFY_UNAVAILABLE,
    ApplyConfigError,
    ApplyRunner,
    CommandResult,
    ScenarioBuild,
    _ApplyFailed,
    apply_file_diff,
    apply_patch_enabled,
    build_apply_result,
    check_real_targets,
    check_target,
    claim_capabilities,
    compute_patch_hash,
    count_fixable,
    parse_apply_input,
    subprocess_runner,
)
from echo_agent.events import RunEventLog
from echo_agent.precheck_runner import main, process_run, run_loop
from echo_agent.was_client import ClaimedRun
from tests.test_was_client import (
    BASE,
    RUN_CRED,
    RUN_ID,
    FakeWas,
    _client,
    _routes,
    ok,
)

SCENARIO = "scenarios/demo-app-test"
DOCKERFILE = f"{SCENARIO}/Dockerfile"
ORIGINAL = (
    "FROM python:3.13-slim AS base\n"
    "\n"
    "FROM base AS runner\n"
    "WORKDIR /app\n"
    "\n"
    "RUN groupadd --system --gid 1001 app\n"
    "\n"
    "COPY app ./app\n"
    "USER 1001:1001\n"
    'CMD ["python", "-m", "app"]\n'
)
PATCHED = ORIGINAL.replace(
    "RUN groupadd --system --gid 1001 app\n",
    "# pip 를 지운다\n"
    "RUN python -m pip uninstall --yes pip && \\\n"
    "    groupadd --system --gid 1001 app\n",
)
TEST_BUILD = ScenarioBuild(
    source_repo="Softbank-Hackathon-2026-Team-Echo/echo-demo-app",
    source_commit="0" * 40,
    dockerfile="Dockerfile",
    healthz_port=8080,
    healthz_path="/healthz",
    healthz_env={"AUTO_MIGRATE": "false"},
)
GIT_AVAILABLE = shutil.which("git") is not None


def _diff(original: str = ORIGINAL, patched: str = PATCHED, name: str = DOCKERFILE) -> str:
    return "".join(
        difflib.unified_diff(
            original.splitlines(keepends=True),
            patched.splitlines(keepends=True),
            fromfile=f"a/{name}",
            tofile=f"b/{name}",
        )
    )


def _snapshot(diff: str | None = None, **overrides: Any) -> dict[str, Any]:
    diff = _diff() if diff is None else diff
    patch = {
        "id": "rule-c-img-1-pip-uninstall",
        "patchHash": compute_patch_hash(diff),
        "files": [DOCKERFILE],
        "diff": diff,
        "origin": "RULE",
    }
    patch.update(overrides.pop("patch", {}))
    snapshot: dict[str, Any] = {
        "schemaVersion": 1,
        "parentRunId": "11111111-1111-1111-1111-111111111111",
        "patch": patch,
        "repo": APPLY_REPOSITORY,
        "branch": f"applied/{RUN_ID}",
    }
    snapshot.update(overrides)
    return snapshot


def _claimed(snapshot: Mapping[str, Any], deadline: datetime | None = None) -> ClaimedRun:
    return ClaimedRun(
        id=RUN_ID,
        kind="APPLY_PATCH",
        org_id="org-1",
        service_id="svc-1",
        source_environment_id="src",
        target_environment_id="dst",
        input_snapshot=snapshot,
        input_hash="sha256:" + "c" * 64,
        scenario_ref=None,
        deadline_at=deadline or datetime.now(UTC) + timedelta(minutes=15),
        lease_until=None,
        run_token=RUN_CRED,
    )


def _apply_payload(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    deadline = datetime.now(UTC) + timedelta(minutes=15)
    return {
        "run": {
            "id": RUN_ID,
            "kind": "APPLY_PATCH",
            "orgId": "org-1",
            "serviceId": "svc-1",
            "sourceEnvironmentId": "src",
            "targetEnvironmentId": "dst",
            "inputSnapshot": dict(snapshot),
            "inputHash": "sha256:" + "c" * 64,
            "scenarioRef": None,
            "deadlineAt": deadline.isoformat().replace("+00:00", "Z"),
            "leaseUntil": None,
        },
        "runToken": RUN_CRED,
    }


def _repo(tmp_path: Path, *, git: bool = False, dockerfile: str = ORIGINAL) -> Path:
    root = tmp_path / "checkout"
    (root / SCENARIO).mkdir(parents=True)
    (root / DOCKERFILE).write_text(dockerfile, encoding="utf-8")
    (root / SCENARIO / "README.md").write_text("사본\n", encoding="utf-8")
    if git:
        _git(root, "init", "--quiet", "--initial-branch", "main")
        _git(root, "add", ".")
        _git(root, "-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-qm", "b")
    return root


def _git(root: Path, *args: str) -> str:
    env = {"GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1", "PATH": "/usr/bin:/bin"}
    git = shutil.which("git") or "git"
    done = subprocess.run(  # noqa: S603 — 시험용 임시 저장소
        [git, "-C", str(root), *args], check=True, env=env, capture_output=True, text=True
    )
    return done.stdout


class FakeTools:
    """docker·trivy 가짜. git 은 실제로 부른다. 부른 인자를 쌓는다."""

    def __init__(
        self,
        *,
        docker: bool = True,
        trivy: bool = True,
        build_rc: int = 0,
        report: Mapping[str, Any] | None = None,
        healthz_rc: int = 0,
    ) -> None:
        self.docker = docker
        self.trivy = trivy
        self.build_rc = build_rc
        self.report = report if report is not None else {"Results": []}
        self.healthz_rc = healthz_rc
        self.calls: list[list[str]] = []
        self.build_context: dict[str, str] = {}
        self._lock = threading.Lock()

    def __call__(
        self, args: Sequence[str], timeout: float, env: Mapping[str, str] | None
    ) -> CommandResult:
        args = list(args)
        if args[0] == "git":
            return subprocess_runner(args, timeout, env)
        with self._lock:
            self.calls.append(args)
        if args[0] == "docker":
            if not self.docker:
                return CommandResult(1, "", "permission denied")
            if args[1] == "version":
                return CommandResult(0, "28.5.1\n", "")
            if args[1] == "build":
                context = Path(args[-1])
                self.build_context = {
                    path.name: path.read_text(encoding="utf-8")
                    for path in context.iterdir()
                    if path.is_file()
                }
                return CommandResult(self.build_rc, "", "step 3 failed" if self.build_rc else "")
            if args[1] == "exec":
                return CommandResult(self.healthz_rc, "", "")
            return CommandResult(0, "", "")
        if args[0] == "trivy":
            if not self.trivy:
                return CommandResult(127, "", "FileNotFoundError")
            if args[1] == "--version":
                return CommandResult(0, json.dumps({"Version": "0.76.1"}), "")
            return CommandResult(0, json.dumps(self.report), "")
        raise AssertionError(f"unexpected command {args}")

    def kinds(self) -> list[str]:
        return [" ".join(call[:2]) for call in self.calls]


def _fetcher(dockerfile: str = ORIGINAL) -> Any:
    def fetch(repo: str, commit: str, dest: Path, timeout: float) -> Path:
        root = dest / f"echo-demo-app-{commit}"
        (root / "app").mkdir(parents=True)
        (root / "Dockerfile").write_text(dockerfile, encoding="utf-8")
        (root / "app" / "__main__.py").write_text("print('hi')\n", encoding="utf-8")
        return root

    return fetch


def _runner(root: Path, tools: FakeTools, **kwargs: Any) -> ApplyRunner:
    return ApplyRunner(
        repo_root=root,
        run_command=tools,
        fetch_source=kwargs.pop("fetch", _fetcher()),
        workspace_parent=root.parent,
        scenario_builds={SCENARIO: TEST_BUILD},
        **kwargs,
    )


def _execute(runner: ApplyRunner, snapshot: Mapping[str, Any]) -> tuple[Any, RunEventLog]:
    events = RunEventLog(RUN_ID)
    outcome = runner.execute(_claimed(snapshot), events, lambda: None)
    return outcome, events


def _messages(events: RunEventLog) -> list[str]:
    return [event.message for event in events.events]


# ---------------------------------------------------------------- 스위치


def test_switch_defaults_off_and_keeps_precheck_only_claim() -> None:
    assert apply_patch_enabled({}) is False
    assert claim_capabilities({}) == ("PRECHECK",)
    assert claim_capabilities({"ECHO_APPLY_PATCH": "off"}) == ("PRECHECK",)
    assert claim_capabilities({"ECHO_APPLY_PATCH": "on"}) == ("PRECHECK", "APPLY_PATCH")


def test_switch_typo_is_config_error_and_never_claims_apply() -> None:
    with pytest.raises(ApplyConfigError):
        apply_patch_enabled({"ECHO_APPLY_PATCH": "yes"})
    assert claim_capabilities({"ECHO_APPLY_PATCH": "yes"}) == ("PRECHECK",)


def test_main_stops_with_exit_2_on_switch_typo(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ECHO_WAS_URL", "http://localhost:8000")
    monkeypatch.setenv("ECHO_RUNNER_TOKEN", "echo_rnr_" + "x" * 32)
    monkeypatch.setenv("ECHO_APPLY_PATCH", "maybe")
    assert main(["--once", "--no-model"]) == 2


# ---------------------------------------------------------------- 입력·해시·대상


def test_patch_hash_is_sha256_of_diff_utf8() -> None:
    diff = _diff()
    assert compute_patch_hash(diff) == "sha256:" + hashlib.sha256(diff.encode()).hexdigest()


@pytest.mark.parametrize(
    ("overrides", "reason"),
    [
        ({"schemaVersion": 2}, "SCHEMA_VERSION"),
        ({"repo": "Softbank-Hackathon-2026-Team-Echo/echo-demo-app"}, "REPO_NOT_ALLOWED"),
        ({"branch": "main"}, "BRANCH_NOT_RUN_ID"),
        ({"patch": {"patchHash": "sha256:short"}}, "PATCH_HASH_FORMAT"),
        ({"patch": {"origin": "HUMAN"}}, "PATCH_ORIGIN"),
        ({"patch": {"files": []}}, "PATCH_FILES"),
    ],
)
def test_bad_input_is_input_invalid(overrides: dict[str, Any], reason: str) -> None:
    with pytest.raises(_ApplyFailed) as error:
        parse_apply_input(_claimed(_snapshot(**overrides)))
    assert (error.value.code, error.value.reason) == (FAILURE_INPUT_INVALID, reason)


@pytest.mark.parametrize(
    ("files", "reason"),
    [
        (["src/echo_agent/agent.py"], "OUTSIDE_SCENARIOS"),
        (["scenarios/../src/x.py"], "UNSAFE_PATH"),
        (["scenarios/demo-app-test/README.md"], "PROTECTED_FILE"),
        (["scenarios/.hidden/Dockerfile"], "UNSAFE_PATH"),
    ],
)
def test_target_outside_scenario_copy_is_forbidden(files: list[str], reason: str) -> None:
    diff = _diff(name=files[0])
    with pytest.raises(_ApplyFailed) as error:
        check_target(files, diff)
    assert (error.value.code, error.value.reason) == (FAILURE_PATCH_TARGET_FORBIDDEN, reason)


def test_target_files_must_match_diff_headers_and_one_scenario() -> None:
    with pytest.raises(_ApplyFailed) as error:
        check_target([f"{SCENARIO}/Other"], _diff())
    assert error.value.reason == "FILES_DIFF_MISMATCH"
    two = _diff() + _diff(name="scenarios/other/Dockerfile")
    with pytest.raises(_ApplyFailed) as error:
        check_target([DOCKERFILE, "scenarios/other/Dockerfile"], two)
    assert error.value.reason == "MULTIPLE_SCENARIOS"
    assert check_target([DOCKERFILE], _diff()) == SCENARIO


# ---------------------------------------------------------------- diff 적용


def test_apply_file_diff_reproduces_patched_bytes() -> None:
    hunks = _diff().split("\n", 2)[2]
    assert apply_file_diff(ORIGINAL, hunks) == PATCHED


def test_apply_file_diff_rejects_changed_context() -> None:
    hunks = _diff().split("\n", 2)[2]
    with pytest.raises(_ApplyFailed) as error:
        apply_file_diff(ORIGINAL.replace("WORKDIR /app", "WORKDIR /srv"), hunks)
    assert (error.value.code, error.value.reason) == (
        FAILURE_PATCH_APPLY_FAILED,
        "CONTEXT_MISMATCH",
    )
    with pytest.raises(_ApplyFailed):
        apply_file_diff(ORIGINAL, "not a hunk\n")


# ---------------------------------------------------------------- Trivy 해석·결과 모양


def test_count_fixable_uses_c_img_1_rule() -> None:
    report = {
        "Results": [
            {
                "Vulnerabilities": [
                    {"Severity": "HIGH", "FixedVersion": "1.2"},
                    {"Severity": "HIGH", "FixedVersion": ""},
                    {"Severity": "HIGH"},
                    {"Severity": "CRITICAL", "FixedVersion": "3.0"},
                    {"Severity": "MEDIUM", "FixedVersion": "1.0"},
                ]
            },
            {"Target": "no vulns"},
        ]
    }
    assert count_fixable(report) == {"HIGH": 1, "CRITICAL": 1}
    assert count_fixable({}) == {"HIGH": 0, "CRITICAL": 0}


def test_result_has_only_contract_fields() -> None:
    ok_result = build_apply_result("SUCCEEDED", None, "a" * 40, f"applied/{RUN_ID}")
    assert ok_result == {
        "status": "SUCCEEDED",
        "failureCode": None,
        "simulated": False,
        "appliedCommitSha": "a" * 40,
        "branch": f"applied/{RUN_ID}",
    }
    failed = build_apply_result("FAILED", "IMAGE_SCAN_FAILED", "a" * 40, f"applied/{RUN_ID}")
    assert failed["appliedCommitSha"] is None and failed["failureCode"] == "IMAGE_SCAN_FAILED"


# ---------------------------------------------------------------- 실행 하나(가짜 도구)


def test_apply_build_scan_healthz_succeeds_without_push(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    tools = FakeTools()
    (status, failure, sha, branch), events = _execute(_runner(root, tools), _snapshot())

    assert (status, failure, branch) == ("SUCCEEDED", None, f"applied/{RUN_ID}")
    assert sha is None  # git 저장소가 아니면 커밋을 만들지 않는다(file-copy)
    assert tools.build_context["Dockerfile"] == PATCHED  # 패치된 Dockerfile 로 빌드
    assert (root / DOCKERFILE).read_text(encoding="utf-8") == ORIGINAL  # 원본은 그대로
    assert tools.kinds() == [
        "docker version",
        "trivy --version",
        "docker build",
        "trivy image",
        "docker run",
        "docker exec",
        "docker rm",
        "docker rmi",
    ]
    run_args = next(call for call in tools.calls if call[:2] == ["docker", "run"])
    assert run_args[run_args.index("--network") + 1] == "none"
    assert not any("push" in call for call in tools.calls)
    assert _messages(events) == [
        "apply input loaded",
        "patch hash verified",
        "apply workspace created",
        "patch applied",
        "build context ready",
        "image built",
        "image scanned",
        "healthz passed",
        "apply checks passed",
        "apply workspace deleted",
    ]
    assert events.events[2].data["mode"] == "file-copy"
    assert not list(tmp_path.glob("echo-apply-*"))  # 작업 공간을 지웠다


@pytest.mark.skipif(not GIT_AVAILABLE, reason="git 이 없음")
def test_git_checkout_gets_local_commit_on_applied_branch(tmp_path: Path) -> None:
    root = _repo(tmp_path, git=True)
    head_before = _git(root, "rev-parse", "HEAD").strip()
    tools = FakeTools()
    (status, failure, sha, branch), events = _execute(_runner(root, tools), _snapshot())

    assert (status, failure) == ("SUCCEEDED", None)
    assert sha is not None and len(sha) == 40 and sha != head_before
    created = next(e for e in events.events if e.message == "apply workspace created")
    assert created.data == {"mode": "git-clone", "baseCommit": head_before, "scenario": SCENARIO}
    applied = next(e for e in events.events if e.message == "patch applied")
    assert applied.data["appliedCommitSha"] == sha and applied.data["pushed"] is False
    # 러너 체크아웃에는 아무것도 쓰지 않았다(브랜치·커밋 없음).
    assert _git(root, "branch", "--list", "applied/*").strip() == ""
    assert (root / DOCKERFILE).read_text(encoding="utf-8") == ORIGINAL


def test_hash_mismatch_fails_before_touching_anything(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    tools = FakeTools()
    snapshot = _snapshot(patch={"patchHash": "sha256:" + "0" * 64})
    (status, failure, sha, _), events = _execute(_runner(root, tools), snapshot)
    assert (status, failure, sha) == ("FAILED", FAILURE_PATCH_HASH_MISMATCH, None)
    assert tools.calls == []
    assert "patch hash mismatch; not applied" in _messages(events)


def test_patch_that_does_not_apply_fails(tmp_path: Path) -> None:
    root = _repo(tmp_path, dockerfile=ORIGINAL.replace("WORKDIR /app", "WORKDIR /srv"))
    tools = FakeTools()
    (status, failure, sha, _), events = _execute(_runner(root, tools), _snapshot())
    assert (status, failure, sha) == ("FAILED", FAILURE_PATCH_APPLY_FAILED, None)
    assert [c for c in tools.calls if c[1] == "build"] == []
    assert events.events[-1].message == "apply workspace deleted"


def test_missing_target_file_fails(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    (root / DOCKERFILE).unlink()
    (status, failure, _, _), events = _execute(_runner(root, FakeTools()), _snapshot())
    assert (status, failure) == ("FAILED", FAILURE_PATCH_APPLY_FAILED)
    assert any(e.data.get("reason") == "TARGET_MISSING" for e in events.events)


# ---------------------------------------------------------------- 심볼릭 링크·실제 경로 탈출


def _symlink_repo(tmp_path: Path, *, kind: str, git: bool) -> tuple[Path, Path]:
    """`scenarios/demo-app-test/Dockerfile` 이 시나리오 밖을 가리키는 체크아웃과 밖 파일."""
    root = tmp_path / "checkout"
    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()
    outside = outside_dir / "Dockerfile"
    outside.write_text(ORIGINAL, encoding="utf-8")
    if kind == "file":
        (root / SCENARIO).mkdir(parents=True)
        (root / DOCKERFILE).symlink_to(outside)
    else:  # 상위 디렉터리(시나리오 폴더)가 밖 폴더의 링크
        (root / "scenarios").mkdir(parents=True)
        (root / SCENARIO).symlink_to(outside_dir, target_is_directory=True)
    if git:
        _git(root, "init", "--quiet", "--initial-branch", "main")
        _git(root, "add", ".")
        _git(root, "-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-qm", "b")
    return root, outside


@pytest.mark.parametrize("git", [True, False])
@pytest.mark.parametrize("kind", ["file", "parent"])
def test_symlinked_target_is_rejected_before_any_write(
    tmp_path: Path, kind: str, git: bool
) -> None:
    if git and not GIT_AVAILABLE:
        pytest.skip("git 이 없음")
    root, outside = _symlink_repo(tmp_path, kind=kind, git=git)
    before = (outside.read_bytes(), outside.stat().st_mtime_ns)
    tools = FakeTools()
    (status, failure, sha, _), events = _execute(_runner(root, tools), _snapshot())

    assert (status, failure, sha) == ("FAILED", FAILURE_PATCH_TARGET_FORBIDDEN, None)
    assert any(e.data.get("reason") == "SYMLINK" for e in events.events)
    assert "patch applied" not in _messages(events)
    assert (outside.read_bytes(), outside.stat().st_mtime_ns) == before  # 밖 파일 쓰기 0
    assert tools.calls == []  # docker·trivy 를 부르기 전에 멈춘다
    assert events.events[-1].message == "apply workspace deleted"


def test_check_real_targets_rejects_links_and_accepts_plain_files(tmp_path: Path) -> None:
    root = tmp_path / "checkout"
    (root / SCENARIO).mkdir(parents=True)
    (root / DOCKERFILE).write_text(ORIGINAL, encoding="utf-8")
    outside = tmp_path / "outside.txt"
    outside.write_text("밖\n", encoding="utf-8")
    (root / SCENARIO / "linked").symlink_to(outside)
    (root / SCENARIO / "inner-link").symlink_to(root / DOCKERFILE)  # 안을 가리켜도 링크는 거부
    (root / SCENARIO / "dir-link").symlink_to(tmp_path, target_is_directory=True)

    # 정상 파일·아직 없는 새 파일은 통과한다(쓰기 없음).
    check_real_targets(root, [DOCKERFILE, f"{SCENARIO}/new-file"])
    assert (root / DOCKERFILE).read_text(encoding="utf-8") == ORIGINAL
    assert not (root / SCENARIO / "new-file").exists()
    for name in [
        f"{SCENARIO}/linked",  # 파일 링크
        f"{SCENARIO}/inner-link",
        f"{SCENARIO}/dir-link/outside.txt",  # 상위 디렉터리 링크
        f"{SCENARIO}/dir-link/not-yet",  # 링크 아래 새 파일
    ]:
        with pytest.raises(_ApplyFailed) as error:
            check_real_targets(root, [DOCKERFILE, name])  # 이름 바꾸기 양쪽처럼 둘 다 검사
        assert (error.value.code, error.value.reason) == (FAILURE_PATCH_TARGET_FORBIDDEN, "SYMLINK")
    assert outside.read_text(encoding="utf-8") == "밖\n"


def test_check_real_targets_rejects_symlinked_scenarios_root(tmp_path: Path) -> None:
    root = tmp_path / "checkout"
    root.mkdir()
    real_scenarios = tmp_path / "elsewhere"
    (real_scenarios / "demo-app-test").mkdir(parents=True)
    (root / "scenarios").symlink_to(real_scenarios, target_is_directory=True)
    with pytest.raises(_ApplyFailed) as error:
        check_real_targets(root, [DOCKERFILE])
    assert (error.value.code, error.value.reason) == (FAILURE_PATCH_TARGET_FORBIDDEN, "SYMLINK")


def test_symlink_check_keeps_normal_git_apply_working(tmp_path: Path) -> None:
    if not GIT_AVAILABLE:
        pytest.skip("git 이 없음")
    root = _repo(tmp_path, git=True)
    (status, failure, sha, _), events = _execute(_runner(root, FakeTools()), _snapshot())
    assert (status, failure) == ("SUCCEEDED", None) and sha is not None
    assert "patch target rejected" not in _messages(events)
    assert (root / DOCKERFILE).read_text(encoding="utf-8") == ORIGINAL


@pytest.mark.parametrize(("docker", "trivy"), [(False, True), (True, False)])
def test_no_docker_or_trivy_is_not_verified(tmp_path: Path, docker: bool, trivy: bool) -> None:
    tools = FakeTools(docker=docker, trivy=trivy)
    (status, failure, sha, _), events = _execute(_runner(_repo(tmp_path), tools), _snapshot())
    assert (status, failure, sha) == ("FAILED", FAILURE_VERIFY_UNAVAILABLE, None)
    assert "image checks unavailable; not verified" in _messages(events)
    assert "docker build" not in tools.kinds()


def test_build_failure_fails_and_cleans_image(tmp_path: Path) -> None:
    tools = FakeTools(build_rc=1)
    (status, failure, _, _), events = _execute(_runner(_repo(tmp_path), tools), _snapshot())
    assert (status, failure) == ("FAILED", FAILURE_IMAGE_BUILD_FAILED)
    assert tools.kinds()[-1] == "docker rmi"
    assert "trivy image" not in tools.kinds()
    built = next(e for e in events.events if e.message == "image build failed")
    assert built.data["tail"] == "step 3 failed"


def test_fixable_high_fails_scan_like_c_img_1(tmp_path: Path) -> None:
    report = {"Results": [{"Vulnerabilities": [{"Severity": "HIGH", "FixedVersion": "2"}]}]}
    tools = FakeTools(report=report)
    (status, failure, sha, _), events = _execute(_runner(_repo(tmp_path), tools), _snapshot())
    assert (status, failure, sha) == ("FAILED", FAILURE_IMAGE_SCAN_FAILED, None)
    scanned = next(e for e in events.events if e.message.startswith("image scan found"))
    assert (scanned.data["fixableHigh"], scanned.data["fixableCritical"]) == (1, 0)
    assert "docker run" not in tools.kinds() and tools.kinds()[-1] == "docker rmi"


def test_unfixed_high_only_passes_scan(tmp_path: Path) -> None:
    report = {"Results": [{"Vulnerabilities": [{"Severity": "HIGH", "FixedVersion": ""}]}]}
    tools = FakeTools(report=report)
    (status, _, _, _), _ = _execute(_runner(_repo(tmp_path), tools), _snapshot())
    assert status == "SUCCEEDED"


def test_healthz_failure_fails_and_removes_container(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(apply_runner, "HEALTHZ_SECONDS", 0.0)
    tools = FakeTools(healthz_rc=1)
    (status, failure, _, _), _ = _execute(_runner(_repo(tmp_path), tools), _snapshot())
    assert (status, failure) == ("FAILED", FAILURE_HEALTHZ_FAILED)
    assert tools.kinds()[-2:] == ["docker rm", "docker rmi"]


def test_source_that_differs_from_scenario_copy_is_not_built(tmp_path: Path) -> None:
    tools = FakeTools()
    runner = _runner(_repo(tmp_path), tools, fetch=_fetcher(dockerfile=PATCHED))
    (status, failure, _, _), _ = _execute(runner, _snapshot())
    assert (status, failure) == ("FAILED", FAILURE_SOURCE_UNAVAILABLE)
    assert "docker build" not in tools.kinds()


def test_deadline_margin_fails_with_deadline(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    events = RunEventLog(RUN_ID)
    run = _claimed(_snapshot(), deadline=datetime.now(UTC) + timedelta(seconds=30))
    status, failure, sha, _ = _runner(root, FakeTools()).execute(run, events, lambda: None)
    assert (status, failure, sha) == ("FAILED", FAILURE_DEADLINE, None)


# ---------------------------------------------------------------- 가짜 WAS 왕복


def _install_fakes(
    monkeypatch: pytest.MonkeyPatch, root: Path, tools: FakeTools, *, switch: str
) -> None:
    monkeypatch.setenv("ECHO_APPLY_PATCH", switch)
    monkeypatch.setenv("ECHO_APPLY_REPO_ROOT", str(root))
    monkeypatch.setattr(apply_runner, "subprocess_runner", tools)
    monkeypatch.setattr(apply_runner, "codeload_fetcher", _fetcher())
    monkeypatch.setattr(apply_runner, "SCENARIO_BUILDS", {SCENARIO: TEST_BUILD})


def test_claim_to_result_round_trip_with_switch_on(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tools = FakeTools()
    _install_fakes(monkeypatch, _repo(tmp_path), tools, switch="on")
    fake = FakeWas(_routes(**{"runs:claim": lambda p, b: ok(_apply_payload(_snapshot()))}))

    code = run_loop(_client(fake), "r", once=True, stop=threading.Event(), log=lambda m: None)

    assert code == 0
    assert fake.bodies("runs:claim") == [
        {"runnerId": "r", "capabilities": ["PRECHECK", "APPLY_PATCH"]}
    ]
    (result,) = fake.bodies("result")
    assert result == {
        "status": "SUCCEEDED",
        "failureCode": None,
        "simulated": False,
        "appliedCommitSha": None,
        "branch": f"applied/{RUN_ID}",
    }
    run_calls = [(path, auth) for path, auth, _ in fake.calls if "runs:claim" not in path]
    assert run_calls and all(auth == f"Bearer {RUN_CRED}" for _, auth in run_calls)
    assert fake.calls[0][0] == "/api/v1/runner/runs:claim"
    steps = [e["step"] for body in fake.bodies("events") for e in body["events"]]
    assert steps[0] == "INPUT_LOAD" and steps[-1] == "SANDBOX_DELETE"
    assert {"SANDBOX_CREATE", "PATCH_VERIFY"} <= set(steps)
    seqs = [e["seq"] for body in fake.bodies("events") for e in body["events"]]
    assert seqs == list(range(1, len(seqs) + 1))
    assert BASE.startswith("https://")


def test_failed_apply_still_submits_failed_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install_fakes(monkeypatch, _repo(tmp_path), FakeTools(), switch="on")
    snapshot = _snapshot(patch={"patchHash": "sha256:" + "f" * 64})
    fake = FakeWas(_routes(**{"runs:claim": lambda p, b: ok(_apply_payload(snapshot))}))
    outcome = process_run(_client(fake), _claimed(snapshot), log=lambda m: None)
    assert (outcome.status, outcome.failure_code, outcome.submitted) == (
        "FAILED",
        FAILURE_PATCH_HASH_MISMATCH,
        True,
    )
    (result,) = fake.bodies("result")
    assert result["appliedCommitSha"] is None and result["failureCode"] == "PATCH_HASH_MISMATCH"


def test_switch_off_keeps_today_behaviour(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    tools = FakeTools()
    _install_fakes(monkeypatch, _repo(tmp_path), tools, switch="off")
    fake = FakeWas(_routes(**{"runs:claim": lambda p, b: ok(_apply_payload(_snapshot()))}))

    run_loop(_client(fake), "r", once=True, stop=threading.Event(), log=lambda m: None)

    assert fake.bodies("runs:claim") == [{"runnerId": "r", "capabilities": ["PRECHECK"]}]
    # WAS 가 그래도 반영 실행을 주면 지금처럼 KIND_UNSUPPORTED 로 닫는다(도구는 부르지 않음).
    (result,) = fake.bodies("result")
    assert (result["status"], result["failureCode"]) == ("FAILED", "KIND_UNSUPPORTED")
    assert "appliedCommitSha" not in result
    assert tools.calls == []


def test_lost_run_on_first_heartbeat_submits_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tools = FakeTools()
    _install_fakes(monkeypatch, _repo(tmp_path), tools, switch="on")
    fake = FakeWas(
        _routes(
            heartbeat=lambda p, b: (409, {"success": False, "code": "RUN_NOT_ACTIVE"}),
        )
    )
    outcome = process_run(_client(fake), _claimed(_snapshot()), log=lambda m: None)
    assert (outcome.status, outcome.submitted) == ("LOST", False)
    assert fake.bodies("result") == [] and tools.calls == []
