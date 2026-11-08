"""Fresh-context review and immutable syntax evidence. Provider is a test double."""

import copy
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from echo_agent.diagnosis import DiagnosisService
from echo_agent.diagnosis_input import DiagnosisError
from echo_agent.diagnosis_model import DiagnosisModel
from echo_agent.diagnosis_result import to_was_result
from echo_agent.independent_review import SYSTEM, freeze_definition
from echo_agent.review_evidence import (
    REVIEW_POLICY,
    approval_digest,
    fingerprint,
    validate_evidence,
)
from tests.test_diagnosis_python import ANSWER, Parser, request


class Provider:
    def __init__(self, verdict: str = "PASS", error: Exception | None = None) -> None:
        self.calls: list[dict[str, Any]] = []
        self.verdict = verdict
        self.error = error

    async def create(self, **kwargs: Any) -> Any:
        self.calls.append(kwargs)
        if len(self.calls) == 1:
            value = copy.deepcopy(ANSWER)
        else:
            if self.error:
                raise self.error
            packet = json.loads(kwargs["messages"][0]["content"])
            value = {
                "verdict": self.verdict,
                "reason": "누락된 괄호만 복구하며 동일 문법 시험을 통과했습니다.",
                "contextHash": packet["contextHash"],
            }
        return SimpleNamespace(
            stop_reason="end_turn",
            model="test-review-model",
            content=[SimpleNamespace(type="text", text=json.dumps(value))],
        )


async def run(tmp_path: Path, provider: Provider, **changes: Any) -> dict[str, Any]:
    snapshot = {**request(), "simulated": False, "reviewPolicy": REVIEW_POLICY, **changes}
    return await DiagnosisService(DiagnosisModel(provider.create), Parser(tmp_path)).execute(
        snapshot
    )


async def test_pass_binds_fixed_test_and_fresh_context(tmp_path: Path) -> None:
    provider = Provider()
    result = await run(tmp_path, provider)
    assert result["status"] == "SUCCEEDED", result
    patch = result["patches"][0]
    evidence = patch["reviewEvidence"]
    validate_evidence(evidence, patch["diff"], "1" * 40, patch["files"])
    assert len(provider.calls) == 2
    author, reviewer = provider.calls
    assert author["system"] != reviewer["system"] == SYSTEM
    assert len(reviewer["messages"]) == 1 and "tools" not in reviewer
    assert reviewer["timeout"] <= 30 and reviewer["max_tokens"] == 1500
    packet = json.loads(reviewer["messages"][0]["content"])
    assert packet["evidence"]["diff"] == patch["diff"]
    assert "repairFeedback" not in packet and "edits" not in packet
    assert evidence["testResults"]["before"]["passed"] is False
    assert evidence["testResults"]["after"]["passed"] is True
    assert result["processing"]["externalTransferBytes"] > len(reviewer["messages"][0]["content"])
    assert to_was_result(result)["patches"][0]["reviewEvidence"] == evidence


@pytest.mark.parametrize("verdict", ["REJECT", "INCONCLUSIVE", "YES", "pass", None])
async def test_non_pass_never_returns_approvable_patch(tmp_path: Path, verdict: str) -> None:
    result = await run(tmp_path, Provider(verdict))
    public = to_was_result(result)
    assert public["patches"] == [] and public["diagnosis"]["fixable"] is False
    assert "독립 검토" in public["diagnosis"]["unfixableReason"]


@pytest.mark.parametrize("error", [DiagnosisError("MODEL_REFUSED"), TimeoutError()])
async def test_refusal_timeout_no_repair_retry(tmp_path: Path, error: Exception) -> None:
    provider = Provider(error=error)
    result = await run(tmp_path, provider)
    assert result["patches"] == [] and len(provider.calls) == 2
    assert result["processing"]["externalTransferBytes"] > 0


@pytest.mark.parametrize("problem", ["context", "extra_edit", "empty_reason", "oversize_reason"])
async def test_invalid_review_response_cannot_authorize(tmp_path: Path, problem: str) -> None:
    provider = Provider()
    create = provider.create

    async def corrupt(**kwargs: Any) -> Any:
        response = await create(**kwargs)
        if kwargs["system"] == SYSTEM:
            answer = json.loads(response.content[0].text)
            if problem == "context":
                answer["contextHash"] = "sha256:" + "0" * 64
            elif problem == "extra_edit":
                answer["edits"] = [{"newText": "bypass"}]
            elif problem == "empty_reason":
                answer["reason"] = ""
            else:
                answer["reason"] = "가" * 1001
            response.content[0].text = json.dumps(answer)
        return response

    result = await DiagnosisService(DiagnosisModel(corrupt), Parser(tmp_path)).execute(
        {**request(), "simulated": False, "reviewPolicy": REVIEW_POLICY}
    )
    assert result["patches"] == []
    assert result["diagnosis"]["reason"] == "REVIEW_INVALID"
    assert len(provider.calls) == 2


async def test_missing_policy_keeps_legacy_one_call(tmp_path: Path) -> None:
    provider = Provider()
    result = await run(tmp_path, provider, reviewPolicy=None)
    assert len(provider.calls) == 1 and result["patches"]
    assert "reviewEvidence" not in result["patches"][0]


async def test_simulated_and_unknown_policy_cannot_get_real_review(tmp_path: Path) -> None:
    provider = Provider()
    result = await run(tmp_path, provider, simulated=True)
    assert result["patches"] == [] and len(provider.calls) == 1
    result = await run(tmp_path, Provider(), reviewPolicy="syntax-review-v2")
    assert result["status"] == "FAILED" and result["failureCode"] == "REVIEW_POLICY_UNSUPPORTED"


@pytest.mark.parametrize("target", ["diff", "commit", "definition", "test", "review", "evidence"])
async def test_tampering_invalidates_binding(tmp_path: Path, target: str) -> None:
    patch = (await run(tmp_path, Provider()))["patches"][0]
    evidence = patch["reviewEvidence"]
    diff, commit = patch["diff"], "1" * 40
    if target == "diff":
        diff += "\n"
    elif target == "commit":
        commit = "2" * 40
    elif target == "definition":
        evidence["testDefinition"]["expectedAfter"] = "always pass"
        evidence["testDefinitionHash"] = fingerprint(evidence["testDefinition"])
    elif target == "test":
        evidence["testResults"]["before"]["passed"] = True
    elif target == "review":
        evidence["review"]["verdict"] = "REJECT"
    else:
        evidence["evidenceHash"] = "sha256:" + "0" * 64
    with pytest.raises(ValueError):
        validate_evidence(evidence, diff, commit, patch["files"])


async def test_checks_and_review_both_bind_approval(tmp_path: Path) -> None:
    patch = (await run(tmp_path, Provider()))["patches"][0]
    original = approval_digest(patch)
    patch["checks"][0]["summary"] += "changed"
    assert approval_digest(patch) != original
    original = approval_digest(patch)
    patch["reviewEvidence"]["review"]["reason"] += "changed"
    assert approval_digest(patch) != original


def test_current_packaged_parser_definitions_match() -> None:
    for path in ("app/main.py", "app/static/index.html"):
        assert freeze_definition(path)["path"] == path


def test_runtime_adapter_canonical_diff_and_apply_share_evidence(tmp_path: Path) -> None:
    from echo_agent.apply_runner import ApplyRunner
    from echo_agent.events import RunEventLog
    from echo_agent.review_evidence import approval_digest
    from tests.test_diagnosis_python import FIXED, TAIL, fetch
    from tests.test_diagnosis_runner import (
        FakeTools,
        _apply_snapshot,
        _claimed,
        _diagnose,
        _snapshot,
    )

    provider = Provider()
    status, failure, outcome, _ = _diagnose(
        tmp_path,
        provider.create,
        _snapshot(failure={"logTail": TAIL}, reviewPolicy=REVIEW_POLICY),
        fetch=fetch,
        checker=Parser(tmp_path),
    )
    assert (status, failure) == ("SUCCEEDED", None)
    assert outcome.diagnosis["fixable"], outcome.diagnosis
    (patch,) = outcome.patches
    spec = _apply_snapshot(patch["diff"], patch["files"])
    spec.update(
        patch=patch, reviewPolicy=REVIEW_POLICY, approvalChecksDigest=approval_digest(patch)
    )
    tools = FakeTools()
    runner = ApplyRunner(
        repo_root=tmp_path, run_command=tools, fetch_source=fetch, workspace_parent=tmp_path
    )
    result = runner.execute(
        _claimed(spec, kind="APPLY_PATCH"), RunEventLog("review-apply"), lambda: None
    )
    assert result[:2] == ("SUCCEEDED", None)
    assert tools.context_files["app/main.py"] == FIXED
    assert not any("push" in command for command in tools.calls)
    # Same diff and model decision cannot authorize a different test/approval bundle.
    spec["approvalChecksDigest"] = "sha256:" + "0" * 64
    tools.calls.clear()
    result = runner.execute(
        _claimed(spec, kind="APPLY_PATCH"), RunEventLog("review-stale"), lambda: None
    )
    assert result[0] == "FAILED" and tools.calls == []


@pytest.mark.docker
async def test_review_with_real_isolated_parser(tmp_path: Path) -> None:
    from echo_agent.diagnosis_check import DockerSyntaxChecker

    provider = Provider()
    result = await DiagnosisService(
        DiagnosisModel(provider.create),
        DockerSyntaxChecker(path="app/main.py"),
    ).execute({**request(), "simulated": False, "reviewPolicy": REVIEW_POLICY})
    assert result["patches"], result
    proof = result["patches"][0]["reviewEvidence"]
    assert proof["testResults"]["before"]["passed"] is False
    assert proof["testResults"]["after"]["passed"] is True
