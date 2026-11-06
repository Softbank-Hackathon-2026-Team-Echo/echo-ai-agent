"""배포 실패 진단 러너 간단판(SPEC ai-5-diagnosis-simple). 가짜 로그·가짜 모델·가짜 WAS·가짜 docker.

git 은 실제로 부른다(`git apply --check`). 네트워크·모델 호출 없음.
"""

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
    parse_apply_input,
    subprocess_runner,
)
from echo_agent.diagnosis_check import CheckResult
from echo_agent.diagnosis_model import DiagnosisModel
from echo_agent.diagnosis_runner import (
    Diagnoser,
    DiagnosisRunner,
    LocationHint,
    build_diagnosis_result,
    parse_diagnosis_input,
)
from echo_agent.events import RunEventLog
from echo_agent.precheck_runner import main, process_run, run_loop
from echo_agent.was_client import ClaimedRun
from tests.test_diagnosis import Checks
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
        "analysisStatus": "diagnosed",
        "category": "CODE",
        "summary": "app/static/index.html 120번째 줄의 괄호가 닫히지 않았습니다.",
        "evidenceIds": ["EV000005"],
        "sourceEvidenceIds": ["SC000120"],
        "canFix": True,
        "reason": "누락된 괄호를 복구합니다.",
        "limitations": [],
        "edits": [
            {
                "path": HTML,
                "oldText": "renderStatus(data;",
                "newText": "renderStatus(data);",
                "evidenceIds": ["EV000005"],
                "sourceEvidenceIds": ["SC000120"],
            }
        ],
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

    async def __call__(self, **kwargs: Any) -> SimpleNamespace:
        self.calls.append(kwargs)
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


def _diagnose(
    tmp_path: Path,
    create: FakeCreate | None,
    snapshot: Mapping[str, Any] | None = None,
    fetch: Any = None,
    checker: Any = None,
) -> tuple[str, str | None, Any, RunEventLog]:
    model = DiagnosisModel(create) if create is not None else None
    runner = DiagnosisRunner(
        Diagnoser(
            model,
            checker=checker
            or Checks(
                CheckResult(
                    True, False, "v24", ({"path": HTML, "line": 120, "message": "missing )"},)
                ),
                CheckResult(True, True, "v24"),
            ),
        ),
        fetch_source=fetch or _fetcher(),
        workspace_parent=tmp_path,
    )
    events = RunEventLog(RUN_ID)
    status, failure, outcome = runner.execute(
        _claimed(snapshot or _snapshot()), events, lambda: None
    )
    return status, failure, outcome, events


def _messages(events: RunEventLog) -> list[str]:
    return [event.message for event in events.events]


def test_was_snapshot_produces_syntax_verified_patch(tmp_path: Path) -> None:
    fake = FakeCreate()
    status, failure, outcome, _ = _diagnose(tmp_path, fake)
    assert (status, failure) == ("SUCCEEDED", None)
    assert outcome.diagnosis["fixable"]
    assert len(fake.calls) == 1
    assert TOKEN not in json.dumps(fake.calls)
    assert outcome.diagnosis["evidence"][0] == {
        "source": "LOG",
        "line": 5,
        "text": LOG_TAIL[4],
    }
    checks = {item["name"] for item in outcome.patches[0]["checks"]}
    assert {"GIT_APPLY", "JAVASCRIPT_SYNTAX", "POLICY"} <= checks
    assert "+      renderStatus(data);\n" in outcome.patches[0]["diff"]
    assert outcome.transfer is not None and outcome.transfer.request_bytes > 0


@pytest.mark.parametrize("field", ["sourceCommitSha", "environmentId", "deployRequestId"])
def test_was_owns_association_ids(tmp_path: Path, field: str) -> None:
    _, _, outcome, _ = _diagnose(tmp_path, FakeCreate())
    result = build_diagnosis_result(outcome, status="SUCCEEDED", failure_code=None)
    assert field not in result["diagnosis"]
    assert result["findings"] == result["configDiff"] == []


def test_original_pass_does_not_allow_repair(tmp_path: Path) -> None:
    no_fix = _model_output(canFix=False, edits=[], reason="문법 오류가 재현되지 않았습니다.")
    fake = FakeCreate(_response(no_fix))
    _, _, outcome, _ = _diagnose(tmp_path, fake, checker=Checks(CheckResult(True, True, "v24")))
    assert not outcome.patches and not outcome.diagnosis["fixable"]
    assert json.loads(fake.calls[0]["messages"][0]["content"])["canPatch"] is False


def test_failed_repair_never_becomes_approvable(tmp_path: Path) -> None:
    fake = FakeCreate()
    check = CheckResult(True, False, "v24", ({"path": HTML, "line": 120, "message": "syntax"},))
    _, _, outcome, _ = _diagnose(tmp_path, fake, checker=Checks(check))
    assert len(fake.calls) == 2
    assert not outcome.patches and not outcome.diagnosis["fixable"]


def test_model_failure_preserves_transfer_and_error_code(tmp_path: Path) -> None:
    fake = FakeCreate(_response(stop_reason="refusal"))
    status, failure, outcome, _ = _diagnose(tmp_path, fake)
    assert (status, failure) == ("FAILED", "MODEL_REFUSED")
    result = build_diagnosis_result(outcome, status=status, failure_code=failure)
    assert result["processing"]["externalTransferBytes"] > 0
    assert not result["patches"]


@pytest.mark.parametrize("failure", [None, {"logTail": []}])
def test_missing_logs_never_calls_model(tmp_path: Path, failure: Any) -> None:
    fake = FakeCreate()
    _, _, outcome, _ = _diagnose(tmp_path, fake, {**_snapshot(), "failure": failure})
    assert not fake.calls and not outcome.patches
    assert outcome.diagnosis["result"] == "NO_FAILURE_EVIDENCE"


def test_source_unavailable_is_log_only_and_has_no_patch(tmp_path: Path) -> None:
    fake = FakeCreate(
        _response(
            _model_output(
                analysisStatus="insufficient_evidence",
                category=None,
                canFix=False,
                edits=[],
                sourceEvidenceIds=[],
                reason="소스가 필요합니다.",
            )
        )
    )
    _, _, outcome, _ = _diagnose(tmp_path, fake, fetch=_fetcher(fail=True))
    assert outcome.diagnosis["result"] == "INSUFFICIENT_EVIDENCE"
    assert not outcome.patches
    assert json.loads(fake.calls[0]["messages"][0]["content"])["source"] == []


def test_unknown_evidence_is_rejected(tmp_path: Path) -> None:
    fake = FakeCreate(_response(_model_output(evidenceIds=["EV999999"])))
    status, _, outcome, _ = _diagnose(tmp_path, fake)
    assert status == "FAILED" and not outcome.patches


@pytest.mark.parametrize(
    "path",
    [
        ".env",
        "config/.env.prod",
        "key.pem",
        "credentials.json",
        "service-account.json",
        "private_key.txt",
    ],
)
def test_sensitive_sources_are_excluded_before_read(tmp_path: Path, path: str) -> None:
    target = tmp_path / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("DB_PASSWORD=synthetic-review-password\n")
    source = diagnosis_runner.scan_source(tmp_path)
    assert path not in source.files
    with pytest.raises(ValueError, match="SOURCE_PATH_FORBIDDEN"):
        source.read_lines(path)


def test_source_symlink_and_oversized_file_are_excluded(tmp_path: Path) -> None:
    (tmp_path / "big.py").write_bytes(b"x" * (64 * 1024 + 1))
    (tmp_path / "small.py").write_text("x = 1\n")
    (tmp_path / "link.py").symlink_to(tmp_path / "small.py")
    assert diagnosis_runner.scan_source(tmp_path).files == frozenset({"small.py"})


def test_source_and_log_passwords_are_masked_before_model(tmp_path: Path) -> None:
    secret = "synthetic-review-password"  # noqa: S105 — synthetic fixture
    html = _html().replace("<!-- line 118 -->", '<!-- DB_PASSWORD="' + secret + '" -->')
    snapshot = _snapshot(failure={"logTail": [*LOG_TAIL, 'password="' + secret + '"']})
    fake = FakeCreate(
        _response(
            _model_output(
                canFix=False,
                edits=[],
                reason="민감값이 있는 소스는 자동 수정하지 않습니다.",
            )
        )
    )
    _, _, outcome, _ = _diagnose(tmp_path, fake, snapshot, fetch=_fetcher(html))
    assert secret not in json.dumps(fake.calls)
    assert secret not in json.dumps(outcome.diagnosis, ensure_ascii=False)
    assert not outcome.patches


def test_canonical_diff_cannot_reintroduce_masked_token(tmp_path: Path) -> None:
    html = _html().replace("<!-- line 118 -->", "<!-- key=" + TOKEN + " -->")
    source = diagnosis_runner.scan_source(_fetcher(html)(DEMO_REPO, COMMIT, tmp_path / "src", 1))
    with pytest.raises(diagnosis_runner.PatchRejected, match="SECRET_IN_DIFF"):
        diagnosis_runner.verify_model_diff(
            MODEL_DIFF, source, [HTML], tmp_path / "verify", subprocess_runner, 5
        )


def test_diff_with_secret_added_by_model_is_rejected(tmp_path: Path) -> None:
    source = diagnosis_runner.scan_source(_fetcher()(DEMO_REPO, COMMIT, tmp_path / "src", 1))
    with pytest.raises(diagnosis_runner.PatchRejected, match="SECRET_IN_DIFF"):
        diagnosis_runner.verify_model_diff(
            MODEL_DIFF + TOKEN, source, [HTML], tmp_path / "verify", subprocess_runner, 5
        )


def test_log_tail_coordinates_and_shape_are_validated() -> None:
    for tail in (["x"] * 51, ["first\nsecond"], [123]):
        with pytest.raises(diagnosis_runner.DiagnosisInputError):
            parse_diagnosis_input(_snapshot(failure={"logTail": tail}))


def test_no_model_uses_masked_rules_without_patch(tmp_path: Path) -> None:
    _, _, outcome, _ = _diagnose(tmp_path, None)
    assert not outcome.patches and outcome.model is None and outcome.transfer is None
    assert outcome.diagnosis["fixable"] is False


def test_failure_does_not_reclassify_as_precheck(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from tests.test_was_client import fail

    monkeypatch.setenv("ECHO_DIAGNOSIS", "on")
    monkeypatch.setattr(diagnosis_runner, "codeload_fetcher", _fetcher())
    fake = FakeWas(_routes(result=lambda p, b: fail(422, "RESULT_INVALID")))
    diagnoser = Diagnoser(
        DiagnosisModel(FakeCreate()),
        checker=Checks(
            CheckResult(True, False, "v24"),
            CheckResult(True, True, "v24"),
        ),
    )
    outcome = process_run(
        _client(fake), _claimed(_snapshot()), diagnoser=diagnoser, log=lambda _: None
    )
    assert not outcome.submitted
    assert len(fake.bodies("result")) == 1 and "diagnosis" in fake.bodies("result")[0]


def test_claim_and_submit_use_was_contract(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ECHO_DIAGNOSIS", "on")
    monkeypatch.setattr(diagnosis_runner, "codeload_fetcher", _fetcher())
    fake = FakeWas(_routes(**{"runs:claim": lambda p, b: ok(_payload(_snapshot()))}))
    diagnoser = Diagnoser(
        DiagnosisModel(FakeCreate()),
        checker=Checks(
            CheckResult(True, False, "v24"),
            CheckResult(True, True, "v24"),
        ),
    )
    assert (
        run_loop(
            _client(fake),
            "r",
            once=True,
            stop=threading.Event(),
            log=lambda _: None,
            diagnoser=diagnoser,
        )
        == 0
    )
    assert "CHANGE_PROPOSAL" in fake.bodies("runs:claim")[0]["capabilities"]
    result = fake.bodies("result")[0]
    assert result["diagnosis"]["fixable"]
    assert result["diagnosis"]["evidence"][0]["line"] == 5
    assert result["findings"] == []


def test_switch_off_never_claims_or_executes_diagnosis(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ECHO_DIAGNOSIS", raising=False)
    assert claim_capabilities({}) == ("PRECHECK",)
    fake = FakeWas(_routes())
    outcome = process_run(_client(fake), _claimed(_snapshot()), log=lambda _: None)
    assert outcome.failure_code == "KIND_UNSUPPORTED"


def test_invalid_diagnosis_switch_stops_startup(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ECHO_WAS_URL", "https://api.example.test")
    monkeypatch.setenv("ECHO_RUNNER_TOKEN", "echo_rnr_" + "r" * 32)
    monkeypatch.setenv("ECHO_DIAGNOSIS", "maybe")
    assert main(["--once", "--no-model"]) == 2


def test_expired_run_never_fetches_source(tmp_path: Path) -> None:
    def forbidden(*args: Any) -> Path:
        raise AssertionError("expired run fetched source")

    runner = DiagnosisRunner(
        Diagnoser(None),
        fetch_source=forbidden,
        clock=lambda: datetime.now(UTC) + timedelta(hours=1),
    )
    assert runner.execute(_claimed(_snapshot()), RunEventLog(RUN_ID), lambda: None) == (
        "FAILED",
        "DEADLINE",
        None,
    )


def test_revoked_run_stops_at_flush_without_model(monkeypatch: pytest.MonkeyPatch) -> None:
    from types import SimpleNamespace

    from echo_agent.diagnosis_runner import process_diagnosis_run

    lost = threading.Event()
    model = FakeCreate()
    stopped = []
    heartbeat = SimpleNamespace(
        lost=lost, beat=lambda: None, start=lost.set, stop=lambda: stopped.append(True)
    )
    sender = SimpleNamespace(events=RunEventLog(RUN_ID), flush=lambda: None)
    fake = FakeWas(_routes())
    outcome = process_diagnosis_run(
        _client(fake),
        _claimed(_snapshot()),
        heartbeat,
        sender,
        diagnoser=Diagnoser(DiagnosisModel(model)),
    )
    assert outcome[1] == "LOST" and not outcome[3]
    assert not model.calls and not fake.bodies("result") and stopped


@pytest.mark.parametrize("kind", ["symlink", "expanded_size"])
def test_source_archive_rejects_links_and_expansion(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
) -> None:
    import gzip
    import io
    import tarfile

    member = tarfile.TarInfo("repo/file")
    if kind == "symlink":
        member.type = tarfile.SYMTYPE
        member.linkname = "/etc/passwd"
    else:
        member.size = 129 * 1024 * 1024
    body = gzip.compress(member.tobuf() + b"\0" * 1024)
    monkeypatch.setattr(apply_runner.urllib.request, "urlopen", lambda *a, **kw: io.BytesIO(body))
    with pytest.raises(apply_runner._ApplyFailed):
        apply_runner.codeload_fetcher(DEMO_REPO, COMMIT, tmp_path / "source", 1)


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
    """Verified engine output applies through the service-source sandbox pipeline."""
    _, _, outcome, _ = _diagnose(tmp_path, FakeCreate())
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
