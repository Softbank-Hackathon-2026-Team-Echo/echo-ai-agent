"""WAS #98's published fields; not a substitute for the unpublished server validator."""

import copy
import json
from typing import Any

import pytest

from echo_agent.diagnosis import DiagnosisService
from echo_agent.diagnosis_input import (
    ALLOWED_FILE,
    DiagnosisError,
    DiagnosisInput,
    prepare_evidence,
)
from echo_agent.diagnosis_model import DiagnosisModel, validate_answer
from echo_agent.diagnosis_result import to_was_result
from tests.test_diagnosis import BEFORE, MODEL_OUTPUT, PASS, Checks, FakeModel, no_patch, snapshot


async def repaired() -> dict[str, Any]:
    return await DiagnosisService(DiagnosisModel(FakeModel().create), Checks(BEFORE, PASS)).execute(
        snapshot()
    )


async def test_was_diagnosed_payload_uses_exact_public_fields_and_existing_patch_shape() -> None:
    internal = await repaired()
    original = copy.deepcopy(internal)
    wire = to_was_result(internal)
    diagnosis = wire["diagnosis"]
    assert set(diagnosis) == {
        "result",
        "category",
        "cause",
        "fixable",
        "unfixableReason",
        "evidence",
    }
    assert diagnosis["result"] == "DIAGNOSED" and diagnosis["category"] == "CODE"
    assert diagnosis["cause"] == internal["diagnosis"]["summary"]
    assert diagnosis["fixable"] is True and diagnosis["unfixableReason"] is None
    assert diagnosis["evidence"] == [
        {
            "source": "LOG",
            "line": None,
            "text": "app/static/index.html:5: SyntaxError: Unexpected token ';'",
        },
        {"source": "FILE", "line": 5, "path": ALLOWED_FILE, "text": "const counter = ;"},
    ]
    assert wire["patches"] == original["patches"] and wire["patches"][0]["origin"] == "AI"
    assert wire["processing"] == original["processing"]
    assert wire["findings"] == [] and wire["configDiff"] == []
    assert internal == original  # Rich local verification/binding trace must stay intact.


@pytest.mark.parametrize("state", ["insufficient_evidence", "no_failure_evidence"])
async def test_no_evidence_has_no_patch_or_invented_category(state: str) -> None:
    output = no_patch(state)
    result = await DiagnosisService(DiagnosisModel(FakeModel(output).create), Checks(PASS)).execute(
        snapshot()
    )
    wire = to_was_result(result)
    assert wire["status"] == "SUCCEEDED" and not wire["patches"]
    assert wire["diagnosis"]["result"] == state.upper()
    assert wire["diagnosis"]["category"] is None
    assert wire["diagnosis"]["fixable"] is False
    assert wire["diagnosis"]["unfixableReason"]


@pytest.mark.parametrize("category", ["CODE", "CONFIG", "BUILD", "RUNTIME", "PLATFORM"])
async def test_supported_categories_for_diagnosis_without_repair(category: str) -> None:
    output = {**no_patch(), "analysisStatus": "diagnosed", "category": category}
    result = await DiagnosisService(
        DiagnosisModel(FakeModel(output).create), Checks(BEFORE)
    ).execute(snapshot())
    wire = to_was_result(result)
    assert wire["diagnosis"]["category"] == category
    assert not wire["diagnosis"]["fixable"] and not wire["patches"]


async def test_was_does_not_invent_log_line_from_tail_offset_or_source_location() -> None:
    result = await repaired()
    evidence = result["diagnosis"]["evidence"][0]
    evidence.update(chunkLine=42, sourceLine=None)
    wire = to_was_result(result)
    assert wire["diagnosis"]["evidence"][0]["line"] is None
    evidence["sourceLine"] = 150
    assert to_was_result(result)["diagnosis"]["evidence"][0]["line"] == 150


async def test_failed_checker_is_unfixable_and_explains_why() -> None:
    result = await DiagnosisService(DiagnosisModel(FakeModel().create), Checks(BEFORE)).execute(
        snapshot()
    )
    wire = to_was_result(result)
    assert not wire["patches"] and not wire["diagnosis"]["fixable"]
    assert "문법 검사" in wire["diagnosis"]["unfixableReason"]


async def test_api_failure_is_not_reported_as_a_completed_cause_diagnosis() -> None:
    result = await DiagnosisService(
        DiagnosisModel(FakeModel(RuntimeError("private-provider-value")).create), Checks(BEFORE)
    ).execute(snapshot())
    wire = to_was_result(result)
    assert wire["status"] == "FAILED"
    assert wire["diagnosis"]["result"] == "INSUFFICIENT_EVIDENCE"
    assert wire["diagnosis"]["evidence"] == []
    assert not wire["diagnosis"]["fixable"] and wire["diagnosis"]["unfixableReason"]
    assert "private-provider-value" not in json.dumps(wire)
    assert wire["processing"]["externalTransferBytes"] > 0


@pytest.mark.parametrize("change", ["unverified", "wrong_category", "failed", "no_evidence"])
async def test_unverified_or_inconsistent_patch_is_never_serialized(change: str) -> None:
    result = await repaired()
    if change == "unverified":
        result["diagnosis"]["verification"]["after"]["passed"] = False
    elif change == "wrong_category":
        result["diagnosis"]["category"] = "CONFIG"
    elif change == "failed":
        result["status"] = "FAILED"
    else:
        result["diagnosis"]["analysisStatus"] = "insufficient_evidence"
    with pytest.raises(DiagnosisError):
        to_was_result(result)


@pytest.mark.parametrize("category", ["UNKNOWN", 1, ["CODE"], None, "CONFIG"])
def test_model_cannot_invent_categories_or_repair_non_code_failures(category: Any) -> None:
    raw = {**MODEL_OUTPUT, "category": category}
    request = DiagnosisInput.parse(snapshot())
    with pytest.raises(DiagnosisError):
        validate_answer(raw, request, prepare_evidence(request), can_patch=True)


async def test_public_evidence_is_masked_bounded_and_has_no_internal_ids() -> None:
    result = await repaired()
    result["diagnosis"]["sourceEvidence"][0]["text"] = 'password="private-value";' + "a" * 3000
    wire = to_was_result(result)
    evidence = wire["diagnosis"]["evidence"][1]
    assert len(evidence["text"]) <= 2000 and "private-value" not in evidence["text"]
    assert set(evidence) == {"source", "line", "path", "text"}
