"""Project validated internal diagnosis to the public WAS #98 result vocabulary.

The server's api-98 runner spec is not published yet. Unknown category/log line stay
null in this preview; their nullability must be confirmed before operational opt-in.
Deployment/environment/commit IDs belong to the server-owned run association, not model output.
"""

from collections.abc import Mapping
from typing import Any

from echo_agent.diagnosis_input import (
    ALLOWED_FILE,
    MAX_SOURCE_BYTES,
    DiagnosisError,
    redact,
    text_field,
)
from echo_agent.diagnosis_model import CATEGORIES

RESULTS = {
    "diagnosed": "DIAGNOSED",
    "insufficient_evidence": "INSUFFICIENT_EVIDENCE",
    "no_failure_evidence": "NO_FAILURE_EVIDENCE",
}
REASONS = {
    "INSUFFICIENT_EVIDENCE": "원인을 확인할 근거가 부족합니다.",
    "PATCH_VERIFICATION_FAILED": "수정본이 문법 검사를 통과하지 못해 패치를 반환하지 않습니다.",
    "CHECK_UNAVAILABLE": "문법 검사 도구를 사용할 수 없어 수정안을 검증하지 못했습니다.",
    "CHECK_TIMEOUT": "문법 검사 시간이 초과되어 수정안을 검증하지 못했습니다.",
    "CHECK_INVALID_OUTPUT": "문법 검사 결과를 읽을 수 없어 수정안을 검증하지 못했습니다.",
    "CHECK_UNSUPPORTED": "현재 문법 검사기가 지원하는 스크립트 형식이 아닙니다.",
}


def _text(value: Any) -> str:
    return redact(text_field(value))


def _evidence(diagnosis: Mapping[str, Any]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for field, kind in (("evidence", "LOG"), ("sourceEvidence", "FILE")):
        for item in diagnosis.get(field, []):
            # A captured log-tail offset or EV id is NOT an original log-file line.
            line = item.get("sourceLine") if kind == "LOG" else item.get("line")
            if line is not None and (type(line) is not int or line < 1):
                raise DiagnosisError("INVALID_EVIDENCE")
            content = redact(text_field(item["text"], limit=MAX_SOURCE_BYTES, empty=True))
            if not content.strip():
                continue
            if len(content) > 2000:
                content = content[:1999] + "…"
            evidence = {"source": kind, "line": line, "text": content}
            if kind == "FILE":
                if item.get("path") != ALLOWED_FILE or line is None:
                    raise DiagnosisError("INVALID_EVIDENCE")
                evidence["path"] = ALLOWED_FILE
            if evidence not in output:
                output.append(evidence)
    return output


def to_was_result(internal: Mapping[str, Any]) -> dict[str, Any]:
    """Keep runner common fields/patches unchanged; send only public diagnosis fields.

    Verification traces, source hashes and EV/SC IDs remain in the local result artifact.
    Patch checks already carry the verification outcome in the existing runner contract.
    """
    result = dict(internal)
    diagnosis = internal.get("diagnosis")
    if not isinstance(diagnosis, Mapping):
        return result
    analysis = diagnosis.get("analysisStatus")
    if not isinstance(analysis, str) or analysis not in RESULTS:
        raise DiagnosisError("INVALID_DIAGNOSIS_STATE")
    category = diagnosis.get("category")
    if category is not None and (not isinstance(category, str) or category not in CATEGORIES):
        raise DiagnosisError("INVALID_DIAGNOSIS_STATE")
    verification = diagnosis.get("verification", {})
    before = verification.get("before") or {}
    after = verification.get("after") or {}
    fixable = bool(
        internal.get("status") == "SUCCEEDED"
        and analysis == "diagnosed"
        and category == "CODE"
        and diagnosis.get("canFix") is True
        and internal.get("patches")
        and before.get("available") is True
        and before.get("passed") is False
        and after.get("available") is True
        and after.get("passed") is True
    )
    # Never let an unverified patch become approvable through serialization.
    if internal.get("patches") and not fixable:
        raise DiagnosisError("INVALID_DIAGNOSIS_STATE")
    failed = internal.get("status") == "FAILED"
    if failed:
        # A partial model response followed by an API/validation failure is not a diagnosis.
        analysis, category = "insufficient_evidence", None
    elif (analysis == "diagnosed") != (category is not None):
        raise DiagnosisError("INVALID_DIAGNOSIS_STATE")
    reason = diagnosis.get("reason")
    if failed:
        reason = diagnosis.get("summary")
    elif isinstance(reason, str):
        reason = REASONS.get(reason, reason)
    if not reason:
        reason = "현재 근거와 허용 범위에서 검증된 수정안을 만들지 못했습니다."
    result["diagnosis"] = {
        "result": RESULTS[analysis],
        "category": category,
        "cause": _text(diagnosis["summary"]),
        "fixable": fixable,
        "unfixableReason": None if fixable else _text(reason),
        "evidence": [] if failed else _evidence(diagnosis),
    }
    return result
