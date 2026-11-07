"""#22 evidence, real syntax parsing, model/timeout guards and opt-in runner regression."""

import asyncio
import copy
import hashlib
import json
import shutil
import threading
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import anthropic
import httpx2 as httpx
import pytest

from echo_agent.diagnosis import DiagnosisService, unified_diff
from echo_agent.diagnosis_check import CheckResult, DockerSyntaxChecker, extract_scripts
from echo_agent.diagnosis_cli import local_check
from echo_agent.diagnosis_cli import main as cli_main
from echo_agent.diagnosis_input import (
    ALLOWED_FILE,
    PURPOSE,
    DiagnosisError,
    DiagnosisInput,
    prepare_evidence,
    redact,
    strict_json,
)
from echo_agent.diagnosis_model import DiagnosisModel, validate_answer
from echo_agent.precheck_runner import main, process_run, run_loop
from echo_agent.sandbox import DockerSandbox
from tests.test_was_client import FakeWas, _claimed, _client, _routes, fail, ok

DATA = Path(__file__).parent / "fixtures" / "diagnosis"
BROKEN = (DATA / "broken.html").read_text()
FIXED = (DATA / "fixed.html").read_text()
MODEL_OUTPUT = json.loads((DATA / "model-response.json").read_text())


def snapshot(**changes: Any) -> dict[str, Any]:
    result: dict[str, Any] = {
        "schemaVersion": 1,
        "purpose": PURPOSE,
        "deployRequestId": "fixture-deployment",
        "environment": "fixture",
        "sourceCommit": "1" * 40,
        "simulated": True,
        "sourceFiles": [{"path": ALLOWED_FILE, "content": BROKEN}],
        "allowedFiles": [ALLOWED_FILE],
        "failure": {"code": "BUILD_FAILED", "exitCode": 1},
        "logs": [
            {
                "id": "build",
                "stage": "build",
                "truncated": False,
                "sourceLineStart": None,
                "lines": ["app/static/index.html:5: SyntaxError: Unexpected token ';'"],
            }
        ],
    }
    result.update(changes)
    return result


class FakeModel:
    def __init__(self, *outputs: Any) -> None:
        self.outputs = list(outputs or [copy.deepcopy(MODEL_OUTPUT)])
        self.calls: list[dict[str, Any]] = []

    async def create(self, **kwargs: Any) -> Any:
        self.calls.append(kwargs)
        value = self.outputs[min(len(self.calls) - 1, len(self.outputs) - 1)]
        if isinstance(value, Exception):
            raise value
        return SimpleNamespace(
            stop_reason="end_turn",
            model="model-test",
            content=[SimpleNamespace(type="text", text=json.dumps(value))],
        )


class Parser:
    """Local test adapter: execute fixed Node parser, not customer JavaScript."""

    async def check(self, source: str, seconds: float) -> CheckResult:
        return await asyncio.to_thread(local_check, source)


class Checks:
    def __init__(self, *results: CheckResult) -> None:
        self.results = list(results)
        self.calls = 0

    async def check(self, source: str, seconds: float) -> CheckResult:
        self.calls += 1
        return self.results[min(self.calls - 1, len(self.results) - 1)]


BEFORE = CheckResult(
    True, False, "v24", ({"path": ALLOWED_FILE, "line": 5, "message": "Unexpected token ';'"},)
)
PASS = CheckResult(True, True, "v24")


def no_patch(status: str = "insufficient_evidence") -> dict[str, Any]:
    return {
        **MODEL_OUTPUT,
        "analysisStatus": status,
        "category": None,
        "canFix": False,
        "reason": "More evidence is required.",
        "edits": [],
    }


def test_input_matches_failure_tail_without_inventing_original_line_numbers() -> None:
    request = DiagnosisInput.parse(
        snapshot(
            logs=[],
            failure={
                "logTail": ["error", "details"],
                "logTruncated": True,
                "exitCode": 1,
            },
        )
    )
    evidence = prepare_evidence(request)
    assert [x["sourceLine"] for x in evidence.logs] == [None, None]
    assert "로그가 일부 잘려 있습니다." in evidence.limitations


@pytest.mark.parametrize(
    "changes",
    [
        {"sourceCommit": None},
        {"sourceCommit": "main"},
        {"allowedFiles": ["../private"]},
        {"sourceFiles": [{"path": ".env", "content": "data"}]},
        {"schemaVersion": True},
        {"simulated": "false"},
        {"failure": {"exitCode": True}},
        {"logs": [{"id": "x", "stage": "runtime", "lines": ["first\nsecond"]}]},
    ],
)
def test_invalid_inputs_are_rejected(changes: dict[str, Any]) -> None:
    with pytest.raises(DiagnosisError):
        DiagnosisInput.parse(snapshot(**changes))


def test_secret_redaction_preserves_multiline_locations() -> None:
    raw = "before\n-----BEGIN PRIVATE KEY-----\nsuper-secret\n-----END PRIVATE KEY-----\nafter"
    cleaned = redact(raw)
    assert cleaned.count("\n") == raw.count("\n")
    assert "super-secret" not in cleaned
    assert cleaned.splitlines()[-1] == "after"
    assert "my-password" not in redact("password=my-password")
    assert "private-cookie" not in redact("Cookie: private-cookie")
    assert "user:password@" not in redact("postgres://user:password@localhost/db")
    assert "private-value" not in redact('const apiKey = "private-value";')
    assert "private-value" not in redact('{"SERVICE_TOKEN": "private-value"}')


@pytest.mark.parametrize("raw", ['{"a":1,"a":2}', '{"a":NaN}'])
def test_duplicate_json_and_nonfinite_numbers_rejected(raw: str) -> None:
    with pytest.raises(DiagnosisError):
        strict_json(raw)


def test_exact_edit_and_evidence_produce_real_diff() -> None:
    request = DiagnosisInput.parse(snapshot())
    answer = validate_answer(MODEL_OUTPUT, request, prepare_evidence(request), can_patch=True)
    assert answer.patched == FIXED
    diff = unified_diff(BROKEN, FIXED)
    assert "--- a/app/static/index.html" in diff
    assert "-const counter = ;\n+const counter = 0;" in diff


@pytest.mark.parametrize(
    "mutation",
    [
        "unknown_log",
        "unknown_source",
        "unrelated_source",
        "wrong_path",
        "wrong_context",
        "html_change",
        "injected_secret",
        "script_escape",
        "duplicate_edit",
        "inconsistent_status",
    ],
)
def test_unsupported_model_changes_never_make_a_patch(mutation: str) -> None:
    raw = copy.deepcopy(MODEL_OUTPUT)
    edit = raw["edits"][0]
    if mutation == "unknown_log":
        raw["evidenceIds"] = ["EV999999"]
    elif mutation == "unknown_source":
        edit["sourceEvidenceIds"] = ["SC999999"]
    elif mutation == "unrelated_source":
        edit["sourceEvidenceIds"] = ["SC000001"]
    elif mutation == "wrong_path":
        edit["path"] = "Dockerfile"
    elif mutation == "wrong_context":
        edit["oldText"] = "not present"
    elif mutation == "html_change":
        edit.update(oldText="<!doctype html>", newText="", sourceEvidenceIds=["SC000001"])
    elif mutation == "injected_secret":
        edit["newText"] = 'const token="private-value";'
    elif mutation == "script_escape":
        edit["newText"] = "</script><h1>changed</h1><script>const counter = 0;"
    elif mutation == "duplicate_edit":
        raw["edits"].append(copy.deepcopy(edit))
    else:
        raw["analysisStatus"] = "insufficient_evidence"
    request = DiagnosisInput.parse(snapshot())
    with pytest.raises(DiagnosisError):
        validate_answer(raw, request, prepare_evidence(request), can_patch=True)


@pytest.mark.skipif(shutil.which("node") is None, reason="Node parser is not installed")
def test_real_parser_detects_error_at_html_line_and_never_executes_js() -> None:
    failed, passed = local_check(BROKEN), local_check(FIXED)
    assert failed.available and not failed.passed
    assert failed.issues[0]["line"] == 5
    assert passed.available and passed.passed
    assert local_check("<script>throw new Error('MUST_NOT_EXECUTE');</script>").passed
    assert local_check("<script>while (true) {}</script>").passed


@pytest.mark.parametrize(
    "source",
    [
        "<div>no script</div>",
        '<script src="app.js"></script>',
        '<script type="module">import x from "y"</script>',
        "<script>unclosed",
    ],
)
def test_unsupported_scripts_are_not_marked_verified(source: str) -> None:
    with pytest.raises(DiagnosisError):
        extract_scripts(source)


@pytest.mark.skipif(shutil.which("node") is None, reason="Node parser is not installed")
async def test_full_diagnosis_with_real_parser_and_model_fixture() -> None:
    model = FakeModel()
    result = await DiagnosisService(DiagnosisModel(model.create), Parser()).execute(snapshot())
    assert result["status"] == "SUCCEEDED"
    assert result["diagnosis"]["verification"]["before"]["passed"] is False
    assert result["diagnosis"]["verification"]["after"]["passed"] is True
    patch = result["patches"][0]
    assert patch["diff"] == unified_diff(BROKEN, FIXED)
    assert patch["patchHash"] == "sha256:" + hashlib.sha256(patch["diff"].encode()).hexdigest()
    assert patch["origin"] == "AI"
    assert result["processing"]["dataClasses"] == ["LOGS", "SOURCE_CODE"]
    assert len(model.calls) == 1


async def test_retry_is_bounded_and_uses_original_source() -> None:
    model = FakeModel()
    result = await DiagnosisService(
        DiagnosisModel(model.create), Checks(BEFORE, BEFORE, PASS)
    ).execute(snapshot())
    assert len(model.calls) == 2
    assert len(result["patches"]) == 1
    retry = json.loads(model.calls[1]["messages"][0]["content"])
    assert retry["repairFeedback"]["passed"] is False
    assert retry["source"][4]["text"] == "const counter = ;"


async def test_twice_failed_verification_returns_no_patch() -> None:
    model = FakeModel()
    result = await DiagnosisService(DiagnosisModel(model.create), Checks(BEFORE)).execute(
        snapshot()
    )
    assert len(model.calls) == 2
    assert result["patches"] == []
    assert not result["diagnosis"]["canFix"]


@pytest.mark.parametrize("status", ["insufficient_evidence", "no_failure_evidence"])
async def test_no_fix_diagnoses_are_successful_jobs(status: str) -> None:
    model = FakeModel(no_patch(status))
    result = await DiagnosisService(DiagnosisModel(model.create), Checks(PASS)).execute(snapshot())
    assert result["status"] == "SUCCEEDED"
    assert result["diagnosis"]["analysisStatus"] == status
    assert not result["patches"]


async def test_missing_source_never_calls_checker_or_proposes_patch() -> None:
    checks = Checks(PASS)
    output = no_patch()
    output["sourceEvidenceIds"] = []
    result = await DiagnosisService(DiagnosisModel(FakeModel(output).create), checks).execute(
        snapshot(sourceFiles=[], sourceCommit=None)
    )
    assert checks.calls == 0
    assert not result["patches"]
    assert result["status"] == "SUCCEEDED"


async def test_secret_source_is_redacted_and_cannot_be_modified() -> None:
    model = FakeModel(no_patch())
    checks = Checks(PASS)
    secret_source = BROKEN.replace("const counter = ;", 'const password = "my-password";')
    result = await DiagnosisService(DiagnosisModel(model.create), checks).execute(
        snapshot(sourceFiles=[{"path": ALLOWED_FILE, "content": secret_source}])
    )
    assert checks.calls == 0
    assert "my-password" not in json.dumps(model.calls)
    assert "my-password" not in json.dumps(result)
    assert not result["patches"]


async def test_provider_failure_keeps_transfer_record_without_fake_success() -> None:
    model = FakeModel(RuntimeError("provider secret should not leak"))
    result = await DiagnosisService(DiagnosisModel(model.create), Checks(BEFORE)).execute(
        snapshot()
    )
    assert result["status"] == "FAILED"
    assert result["processing"]["externalTransferBytes"] > 0
    assert "provider secret" not in json.dumps(result)
    assert result["model"] is None


@pytest.mark.parametrize(
    ("status", "code"),
    [
        (400, "MODEL_REQUEST_REJECTED"),
        (401, "MODEL_AUTH_FAILED"),
        (403, "MODEL_PERMISSION_DENIED"),
        (404, "MODEL_NOT_FOUND"),
        (408, "MODEL_TIMEOUT"),
        (429, "MODEL_RATE_LIMITED"),
        (500, "MODEL_UNAVAILABLE"),
        (529, "MODEL_UNAVAILABLE"),
    ],
)
async def test_model_api_errors_are_classified_without_exposing_provider_body(
    status: int, code: str
) -> None:
    response = httpx.Response(status, request=httpx.Request("POST", "https://example.invalid"))
    error = anthropic.APIStatusError(
        "private-provider-value", response=response, body={"secret": "hidden"}
    )
    model = FakeModel(error)
    result = await DiagnosisService(DiagnosisModel(model.create), Checks(BEFORE)).execute(
        snapshot()
    )
    assert result["status"] == "FAILED" and result["failureCode"] == code
    assert result["patches"] == [] and len(model.calls) == 1
    assert result["processing"]["externalTransferBytes"] > 0
    assert "private-provider-value" not in json.dumps(result)
    assert "hidden" not in json.dumps(result)
    assert any("가" <= c <= "힣" for c in result["diagnosis"]["summary"])


@pytest.mark.parametrize("kind", ["timeout", "connection", "async_timeout"])
async def test_model_network_failures_are_distinct_from_total_deadline(kind: str) -> None:
    request = httpx.Request("POST", "https://example.invalid")
    error = (
        anthropic.APITimeoutError(request=request)
        if kind == "timeout"
        else anthropic.APIConnectionError(request=request)
        if kind == "connection"
        else TimeoutError()
    )
    model = FakeModel(error)
    result = await DiagnosisService(DiagnosisModel(model.create), Checks(BEFORE)).execute(
        snapshot()
    )
    expected = "MODEL_CONNECTION_FAILED" if kind == "connection" else "MODEL_TIMEOUT"
    assert result["failureCode"] == expected
    assert result["patches"] == [] and len(model.calls) == 1


async def test_deadline_does_not_call_model_or_claim_success() -> None:
    model = FakeModel()
    result = await DiagnosisService(DiagnosisModel(model.create), Checks(BEFORE)).execute(
        snapshot(), seconds=-1
    )
    assert result["failureCode"] == "DEADLINE"
    assert not model.calls and not result["patches"]


async def test_fixture_replay_has_no_external_transfer_claim() -> None:
    result = await DiagnosisService(
        DiagnosisModel(FakeModel().create, simulated=True), Checks(BEFORE, PASS)
    ).execute(snapshot(simulated=False))
    assert result["simulated"] is True
    assert result["model"] is None
    assert "processing" not in result


def test_claim_does_not_add_diagnosis_by_default() -> None:
    fake = FakeWas(_routes(**{"runs:claim": lambda p, b: ok({"run": None})}))
    assert (
        run_loop(_client(fake), "test", once=True, stop=threading.Event(), log=lambda _: None) == 0
    )
    assert "CHANGE_PROPOSAL" not in fake.calls[0][2]["capabilities"]


def _wired_runtime(monkeypatch: pytest.MonkeyPatch, fake: FakeWas) -> tuple[Any, Any]:
    from echo_agent.diagnosis_runner import Diagnoser
    from tests.test_diagnosis_runner import _fetcher, _snapshot

    monkeypatch.setenv("ECHO_DIAGNOSIS", "on")
    monkeypatch.setattr("echo_agent.diagnosis_runner.codeload_fetcher", _fetcher(BROKEN))
    request = _snapshot(
        failure={"logTail": ["app/static/index.html:5: SyntaxError: Unexpected token ';'"]}
    )
    run = replace(_claimed(fake), kind="CHANGE_PROPOSAL", input_snapshot=request)
    return run, Diagnoser(DiagnosisModel(FakeModel().create), checker=Checks(BEFORE, PASS))


def test_opt_in_runner_submits_diagnosis_without_precheck_findings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeWas(_routes())
    run, service = _wired_runtime(monkeypatch, fake)
    outcome = process_run(_client(fake), run, diagnoser=service, log=lambda _: None)
    assert outcome.submitted and outcome.status == "SUCCEEDED"
    result = fake.bodies("result")[0]
    assert result["diagnosis"]["fixable"] and result["patches"]
    assert result["diagnosis"]["result"] == "DIAGNOSED"
    assert result["diagnosis"]["category"] == "CODE"
    assert result["diagnosis"]["evidence"][0]["line"] == 1
    assert "analysisStatus" not in result["diagnosis"]
    assert result["findings"] == [] and result["configDiff"] == []


def test_invalid_projection_cannot_submit_patch_or_lose_transfer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def reject(result: Any, **kwargs: Any) -> Any:
        raise DiagnosisError("INVALID_DIAGNOSIS_STATE")

    monkeypatch.setattr("echo_agent.diagnosis_runner.to_was_result", reject)
    fake = FakeWas(_routes())
    run, service = _wired_runtime(monkeypatch, fake)
    outcome = process_run(_client(fake), run, diagnoser=service, log=lambda _: None)
    assert outcome.submitted and outcome.status == "FAILED"
    assert outcome.failure_code == "INVALID_DIAGNOSIS_RESULT"
    result = fake.bodies("result")[0]
    assert result["processing"]["externalTransferBytes"] > 0
    assert result["patches"] == []


def test_was_rejection_only_drops_diagnosis_for_explicit_failed_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeWas(_routes(result=lambda p, b: fail(422, "RESULT_INVALID")))
    run, service = _wired_runtime(monkeypatch, fake)
    outcome = process_run(_client(fake), run, diagnoser=service, log=lambda _: None)
    assert not outcome.submitted
    assert len(fake.bodies("result")) == 2
    fallback = fake.bodies("result")[1]
    assert fallback["status"] == "FAILED" and fallback["failureCode"] == "RUNNER_ERROR"
    assert fallback["patches"] == [] and "diagnosis" not in fallback
    assert outcome.status == "UNCONFIRMED"
    assert "diagnosis" in fake.bodies("result")[0]


def test_opt_in_is_required_to_claim_change_proposal(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeWas(_routes(**{"runs:claim": lambda p, b: ok({"run": None})}))
    _, service = _wired_runtime(monkeypatch, FakeWas(_routes()))
    run_loop(
        _client(fake),
        "test",
        once=True,
        stop=threading.Event(),
        log=lambda _: None,
        diagnoser=service,
    )
    assert "CHANGE_PROPOSAL" in fake.calls[0][2]["capabilities"]


def test_no_model_flag_keeps_diagnosis_rules_only(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ECHO_DIAGNOSIS", "on")
    monkeypatch.setenv("ECHO_WAS_URL", "https://api.example.test")
    monkeypatch.setenv("ECHO_RUNNER_TOKEN", "echo_rnr_" + "r" * 32)

    def run(*args: Any, **kwargs: Any) -> int:
        assert kwargs["diagnoser"].model is None and kwargs["reviewer"] is None
        return 0

    monkeypatch.setattr("echo_agent.precheck_runner.run_loop", run)
    assert main(["--once", "--no-model"]) == 0


async def test_expired_empty_request_cannot_succeed() -> None:
    model = FakeModel()
    result = await DiagnosisService(DiagnosisModel(model.create), Checks(PASS)).execute(
        snapshot(logs=[], failure={}), seconds=-1
    )
    assert result["failureCode"] == "DEADLINE" and not model.calls


@pytest.mark.parametrize("phase", ["create", "load"])
async def test_syntax_timeout_waits_for_creation_and_always_cleans(phase: str) -> None:
    class SlowSandbox(DockerSandbox):
        removed = False
        made = False

        async def create(self) -> None:
            if phase == "create":
                await asyncio.sleep(0.03)
            self.made = True

        async def load_files(self, files: Any) -> None:
            await asyncio.sleep(1)

        async def destroy(self) -> None:
            assert self.made
            self.removed = True

    sandbox = SlowSandbox("test")
    checker = DockerSyntaxChecker(factory=lambda *a, **k: sandbox)
    result = await checker.check(BROKEN, 0.01)
    assert sandbox.removed
    assert not result.available and not result.passed


@pytest.mark.docker
async def test_real_isolated_node_container_can_verify_both_versions() -> None:
    checker = DockerSyntaxChecker()
    before = await checker.check(BROKEN, 60)
    after = await checker.check(FIXED, 60)
    assert before.available and not before.passed
    assert after.available and after.passed


def test_cli_input_errors_do_not_expose_file_contents(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("secret invalid input")
    assert cli_main(["diagnose", "--input", str(bad)]) == 2
    assert "secret invalid input" not in capsys.readouterr().err
