"""Error diagnosis core. Independent of WAS storage and production deployment."""

import asyncio
import difflib
import hashlib
import json
import time
from collections.abc import Callable, Mapping
from dataclasses import replace
from typing import Any, Protocol

from echo_agent.diagnosis_check import CheckResult, DockerSyntaxChecker
from echo_agent.diagnosis_input import (
    ALLOWED_FILE,
    DiagnosisError,
    DiagnosisInput,
    Evidence,
    prepare_evidence,
)
from echo_agent.diagnosis_model import PROMPT_VERSION, DiagnosisModel, validate_answer
from echo_agent.events import RunEventLog, RunStep
from echo_agent.precheck_model import request_body_bytes

MAX_SECONDS = 180.0
EventCallback = Callable[[], None]
FAILURE_MESSAGES = {
    "MODEL_AUTH_FAILED": "모델 API 인증에 실패했습니다. API 키 설정을 확인해 주세요.",
    "MODEL_PERMISSION_DENIED": "모델 호출 권한이 없습니다. 계정과 모델 접근 권한을 확인해 주세요.",
    "MODEL_NOT_FOUND": "요청한 모델을 사용할 수 없습니다. 모델 이름과 접근 권한을 확인해 주세요.",
    "MODEL_RATE_LIMITED": "모델 호출 한도에 도달했습니다. 잠시 뒤 다시 시도해 주세요.",
    "MODEL_TIMEOUT": "모델 응답 시간이 초과되어 진단을 중단했습니다.",
    "MODEL_CONNECTION_FAILED": "모델 API에 연결하지 못했습니다. 네트워크 상태를 확인해 주세요.",
    "MODEL_UNAVAILABLE": "모델 제공 서버에 오류가 발생했습니다. 잠시 뒤 다시 시도해 주세요.",
    "MODEL_REQUEST_REJECTED": "모델 API가 요청을 거절했습니다. 요청 설정을 확인해 주세요.",
    "MODEL_REFUSED": "모델이 진단 요청을 거절하여 수정안을 만들지 못했습니다.",
    "MODEL_INCOMPLETE": "모델 응답이 끝까지 생성되지 않아 수정안을 사용할 수 없습니다.",
    "DEADLINE": "진단 작업의 제한 시간이 초과되었습니다.",
}


class SyntaxChecker(Protocol):
    async def check(self, source: str, seconds: float) -> CheckResult: ...


def unified_diff(original: str, patched: str) -> str:
    lines = difflib.unified_diff(
        original.splitlines(keepends=True),
        patched.splitlines(keepends=True),
        fromfile=f"a/{ALLOWED_FILE}",
        tofile=f"b/{ALLOWED_FILE}",
    )
    return "".join(
        line if line.endswith("\n") else line + "\n\\ No newline at end of file\n" for line in lines
    )


def _empty_diagnosis(request: DiagnosisInput, evidence: Evidence) -> dict[str, Any]:
    return {
        "analysisStatus": "insufficient_evidence",
        "summary": "분석할 실패 근거가 부족합니다.",
        "evidenceIds": [],
        "sourceEvidenceIds": [],
        "canFix": False,
        "reason": "INSUFFICIENT_EVIDENCE",
        "limitations": list(evidence.limitations),
        "inputBinding": {
            "deployRequestId": request.deploy_request_id,
            "sourceCommit": request.commit,
            "sourceSha256": request.source_hash,
            "commitVerification": "caller_supplied",
        },
        "evidence": [],
        "sourceEvidence": [],
        "verification": {"before": None, "after": None},
    }


class DiagnosisService:
    def __init__(
        self,
        model: DiagnosisModel,
        checker: SyntaxChecker | None = None,
        *,
        location: str = "local/development",
    ) -> None:
        self.model = model
        self.checker = checker or DockerSyntaxChecker()
        self.location = location

    async def execute(
        self,
        snapshot: Mapping[str, Any],
        *,
        seconds: float = MAX_SECONDS,
        events: RunEventLog | None = None,
        flush: EventCallback | None = None,
    ) -> dict[str, Any]:
        deadline = time.monotonic() + min(seconds, MAX_SECONDS)
        result: dict[str, Any] = {
            "status": "FAILED",
            "failureCode": "INPUT_INVALID",
            "simulated": False,
            "sandbox": None,
            "model": None,
            "configDiff": [],
            "featureGaps": [],
            "findings": [],
            "patches": [],
            "blockedAttempts": [],
        }

        def emit(step: RunStep, message: str, **data: Any) -> None:
            if events is not None:
                events.add(step, message, **data)
            if flush is not None:
                flush()

        def budget(cap: float) -> float:
            left = deadline - time.monotonic()
            if left <= 0:
                raise DiagnosisError("DEADLINE")
            return min(cap, left)

        try:
            budget(1)
            request = DiagnosisInput.parse(snapshot)
            result["simulated"] = request.simulated or self.model.simulated
            evidence = prepare_evidence(request)
            diagnosis = _empty_diagnosis(request, evidence)
            result["diagnosis"] = diagnosis
            emit(
                RunStep.INPUT_LOAD,
                "diagnosis input prepared",
                logs=len(evidence.logs),
                sourceAvailable=request.source is not None,
            )
            if not any(x["text"].strip() for x in evidence.logs) and not any(
                request.failure.values()
            ):
                result.update(status="SUCCEEDED", failureCode=None)
                return result
            before = None
            if request.source is not None and evidence.source_safe:
                emit(RunStep.SANDBOX_CREATE, "checking original JavaScript syntax")
                before = await self.checker.check(request.source, budget(30))
                diagnosis["verification"]["before"] = before.to_json()
                emit(
                    RunStep.SANDBOX_DELETE,
                    "original syntax checker finished",
                    available=before.available,
                    passed=before.passed,
                )
                if before.available and not before.passed:
                    extra = tuple(
                        {
                            "id": f"EV{len(evidence.logs) + i + 1:06d}",
                            "chunkId": "syntax-before",
                            "stage": "validation",
                            "chunkLine": i + 1,
                            "sourceLine": None,
                            "text": (
                                f"{issue['path']}:{issue['line']}: SyntaxError: {issue['message']}"
                            ),
                        }
                        for i, issue in enumerate(before.issues)
                    )
                    evidence = replace(evidence, logs=(*evidence.logs, *extra))
            can_patch = bool(
                before and before.available and not before.passed and evidence.source_safe
            )
            feedback: dict[str, Any] | None = None
            for attempt in range(1, 3):
                emit(RunStep.ANALYZE, "diagnosis model request", attempt=attempt)
                payload = json.dumps(
                    {
                        **evidence.payload(),
                        "failure": request.failure,
                        "canPatch": can_patch,
                        "repairFeedback": feedback,
                    },
                    ensure_ascii=False,
                )
                model_request = self.model.request(payload, budget(60))
                processing = result.setdefault(
                    "processing",
                    {
                        "location": self.location,
                        "sandbox": False,
                        "modelProvider": "ANTHROPIC",
                        "model": self.model.model,
                        "modelRegion": None,
                        "dataClasses": ["LOGS", *(["SOURCE_CODE"] if evidence.source else [])],
                        "externalTransfer": True,
                        "externalTransferBytes": 0,
                    },
                )
                # Record attempted transfer even if the provider rejects/times out.
                processing["externalTransferBytes"] += request_body_bytes(model_request)
                try:
                    async with asyncio.timeout(budget(60)):
                        raw, actual_model = await self.model.send(model_request)
                except TimeoutError as error:
                    code = "DEADLINE" if time.monotonic() >= deadline else "MODEL_TIMEOUT"
                    raise DiagnosisError(code) from error
                result["model"] = {
                    "id": actual_model,
                    "effort": "medium",
                    "promptVersion": PROMPT_VERSION,
                    "refusal": False,
                }
                answer = validate_answer(raw, request, evidence, can_patch=can_patch)
                diagnosis.update(answer.analysis)
                diagnosis["limitations"] = list(
                    dict.fromkeys(
                        [
                            *evidence.limitations,
                            *answer.analysis["limitations"],
                            "JavaScript 문법만 확인했습니다. 빌드·Trivy·헬스체크·"
                            "브라우저 동작은 별도 검증이 필요합니다.",
                        ]
                    )
                )
                diagnosis["evidence"] = [
                    e for e in evidence.logs if e["id"] in diagnosis["evidenceIds"]
                ]
                diagnosis["sourceEvidence"] = [
                    e for e in evidence.source if e["id"] in diagnosis["sourceEvidenceIds"]
                ]
                if answer.patched is None:
                    if not can_patch:
                        diagnosis["limitations"].append(
                            "수정 가능한 문법 오류를 재현하지 못했거나 소스·검사 도구를 "
                            "사용할 수 없습니다."
                        )
                    break
                emit(
                    RunStep.PATCH_PROPOSE,
                    "diagnosis edit drafted; syntax verification pending",
                    attempt=attempt,
                )
                after = await self.checker.check(answer.patched, budget(30))
                diagnosis["verification"]["after"] = after.to_json()
                emit(
                    RunStep.PATCH_VERIFY,
                    "candidate syntax checker finished",
                    attempt=attempt,
                    available=after.available,
                    passed=after.passed,
                )
                if after.available and after.passed:
                    if request.source is None:
                        raise DiagnosisError("INPUT_INVALID")
                    diff = unified_diff(request.source, answer.patched)
                    digest = hashlib.sha256(diff.encode()).hexdigest()
                    result["patches"] = [
                        {
                            "id": f"diagnosis-{digest[:16]}",
                            "patchHash": f"sha256:{digest}",
                            "files": [ALLOWED_FILE],
                            "diff": diff,
                            "reason": diagnosis["reason"],
                            "touchesProtectedFiles": False,
                            "origin": "AI",
                            "checks": [
                                {
                                    "name": "DIFF_APPLIES",
                                    "result": "PASS",
                                    "summary": "원본 코드에 수정안을 정확히 적용할 수 있습니다.",
                                },
                                {
                                    "name": "POLICY",
                                    "result": "PASS",
                                    "policyVersion": "diagnosis-v1",
                                    "summary": "허용된 기존 inline JavaScript만 변경했습니다.",
                                },
                                {
                                    "name": "JAVASCRIPT_SYNTAX",
                                    "result": "PASS",
                                    "toolVersion": after.version,
                                    "summary": "같은 문법 검사에서 원본은 실패하고 수정본은 "
                                    "통과했습니다.",
                                },
                            ],
                        }
                    ]
                    break
                diagnosis.update(canFix=False, reason=after.reason or "PATCH_VERIFICATION_FAILED")
                if not after.available or attempt == 2:
                    break
                feedback = after.to_json()
            budget(1)
            result.update(status="SUCCEEDED", failureCode=None)
        except DiagnosisError as error:
            result.update(status="FAILED", failureCode=error.code, patches=[])
        except TimeoutError:
            result.update(status="FAILED", failureCode="DEADLINE", patches=[])
        except Exception as error:  # noqa: BLE001 — provider internals/secrets never leave the process
            # WAS lifecycle exceptions are handled by the runner, not converted to a fake diagnosis.
            from echo_agent.was_client import WasError

            if isinstance(error, WasError):
                raise
            result.update(status="FAILED", failureCode="DIAGNOSIS_ERROR", patches=[])
        if self.model.simulated:
            result.pop("processing", None)
            result["model"] = None
        if result["status"] == "FAILED" and "diagnosis" in result:
            result["diagnosis"]["canFix"] = False
            result["diagnosis"]["reason"] = result["failureCode"]
            result["diagnosis"]["summary"] = FAILURE_MESSAGES.get(
                result["failureCode"], "진단을 완료하지 못했습니다. 실패 코드를 확인해 주세요."
            )
        return result
