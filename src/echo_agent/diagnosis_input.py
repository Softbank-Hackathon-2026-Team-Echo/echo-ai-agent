"""#22 앞단 입력과 근거. WAS와 협의 중인 error-diagnosis.v1 계약."""

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from echo_agent.precheck_model import mask_tokens, secret_candidates

PURPOSE = "error-diagnosis.v1"
ALLOWED_FILE = "app/static/index.html"
MAX_SOURCE_BYTES = 64 * 1024
MAX_INPUT_BYTES = 1024 * 1024
_ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
_PRIVATE_KEY = re.compile(
    r"-----BEGIN [^-]*PRIVATE KEY-----.*?(?:-----END [^-]*PRIVATE KEY-----|\Z)", re.S
)
_SECRET_VALUE = re.compile(
    r"(?im)([\"']?\b(?:[a-z0-9_]*(?:password|passwd|secret|token|api_?key|access_key)"
    r"[a-z0-9_]*|pwd)[\"']?\s*[:=]\s*)"
    r"(?:\"[^\"\n]*\"|'[^'\n]*'|[^\s,;}]+)"
)
_AUTH_LINE = re.compile(r"(?im)\b(?:authorization|proxy-authorization|cookie|set-cookie)\s*:[^\n]*")


class DiagnosisError(Exception):
    """원문 입력·모델 출력을 포함하지 않는 오류 코드."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def redact(text: str) -> str:
    """원래 줄 번호를 유지한다. 의심 값은 외부로 보내기 전에 가린다."""
    text = _PRIVATE_KEY.sub(lambda m: "***" + "\n" * m[0].count("\n"), text)
    text = _AUTH_LINE.sub("[REDACTED AUTH]", text)
    text = _SECRET_VALUE.sub(r"\1***", text)
    text = mask_tokens(text)
    return "\n".join(
        "[REDACTED TOKEN]" if secret_candidates(line) else line for line in text.split("\n")
    )


def strict_json(raw: str) -> Any:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise DiagnosisError("INVALID_JSON")
            result[key] = value
        return result

    def invalid(value: str) -> Any:
        raise DiagnosisError("INVALID_JSON")

    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)
    except (ValueError, RecursionError) as error:
        raise DiagnosisError("INVALID_JSON") from error


def text_field(value: Any, *, limit: int = 2000, empty: bool = False) -> str:
    if (
        not isinstance(value, str)
        or "\0" in value
        or len(value) > limit
        or (not empty and not value.strip())
    ):
        raise DiagnosisError("INPUT_INVALID")
    return value


@dataclass(frozen=True)
class DiagnosisInput:
    deploy_request_id: str
    environment: str
    commit: str | None
    source: str | None
    logs: tuple[dict[str, Any], ...]
    failure: dict[str, Any]
    simulated: bool
    source_hash: str | None

    @classmethod
    def parse(cls, raw: Mapping[str, Any]) -> "DiagnosisInput":
        if len(json.dumps(raw).encode()) > MAX_INPUT_BYTES:
            raise DiagnosisError("INPUT_TOO_LARGE")
        if (
            type(raw.get("schemaVersion")) is not int
            or raw["schemaVersion"] != 1
            or raw.get("purpose") != PURPOSE
        ):
            raise DiagnosisError("INPUT_INVALID")
        request = text_field(raw.get("deployRequestId"), limit=128)
        environment = text_field(raw.get("environment"), limit=128)
        if type(raw.get("simulated")) is not bool:
            raise DiagnosisError("INPUT_INVALID")
        if raw.get("allowedFiles") != [ALLOWED_FILE]:
            raise DiagnosisError("PATCH_TARGET_FORBIDDEN")
        files = raw.get("sourceFiles", [])
        commit = raw.get("sourceCommit")
        if commit is not None and (
            not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}", commit)
        ):
            raise DiagnosisError("INPUT_INVALID")
        if not isinstance(files, list) or len(files) > 1:
            raise DiagnosisError("INPUT_INVALID")
        source = None
        if files:
            item = files[0]
            if not isinstance(item, Mapping) or item.get("path") != ALLOWED_FILE or commit is None:
                raise DiagnosisError("INPUT_INVALID")
            source = text_field(item.get("content"), limit=MAX_SOURCE_BYTES)
            if len(source.encode()) > MAX_SOURCE_BYTES:
                raise DiagnosisError("INPUT_TOO_LARGE")
        failure = raw.get("failure", {})
        if not isinstance(failure, Mapping):
            raise DiagnosisError("INPUT_INVALID")
        safe_failure: dict[str, Any] = {}
        for key in ("code", "message", "containerReason", "terminationReason"):
            value = failure.get(key)
            if value is not None:
                safe_failure[key] = redact(text_field(value))
        exit_code = failure.get("exitCode")
        if exit_code is not None and (type(exit_code) is not int or not -255 <= exit_code <= 255):
            raise DiagnosisError("INPUT_INVALID")
        safe_failure["exitCode"] = exit_code
        logs = raw.get("logs", [])
        if not logs and failure.get("logTail"):
            tail = failure["logTail"]
            if (
                not isinstance(tail, list)
                or len(tail) > 50
                or not all(isinstance(x, str) for x in tail)
            ):
                raise DiagnosisError("INPUT_INVALID")
            logs = [
                {
                    "id": "container-tail",
                    "stage": "runtime",
                    "lines": tail,
                    "truncated": failure.get("logTruncated", False),
                    "sourceLineStart": None,
                }
            ]
        if not isinstance(logs, list) or len(logs) > 5:
            raise DiagnosisError("INPUT_INVALID")
        prepared: list[dict[str, Any]] = []
        ids: set[str] = set()
        for chunk in logs:
            if not isinstance(chunk, Mapping):
                raise DiagnosisError("INPUT_INVALID")
            chunk_id = text_field(chunk.get("id"), limit=64)
            stage = chunk.get("stage")
            lines = chunk.get("lines")
            start = chunk.get("sourceLineStart")
            truncated = chunk.get("truncated", False)
            if (
                chunk_id in ids
                or stage not in {"build", "runtime", "validation"}
                or not isinstance(lines, list)
                or len(lines) > 200
                or type(truncated) is not bool
                or (start is not None and (type(start) is not int or not 1 <= start <= 10_000_000))
            ):
                raise DiagnosisError("INPUT_INVALID")
            ids.add(chunk_id)
            clean_lines = [text_field(line, limit=2000, empty=True) for line in lines]
            if any("\n" in line or "\r" in line for line in clean_lines):
                raise DiagnosisError("INPUT_INVALID")
            prepared.append(
                {
                    "id": chunk_id,
                    "stage": stage,
                    "lines": clean_lines,
                    "sourceLineStart": start,
                    "truncated": truncated,
                }
            )
        return cls(
            request,
            environment,
            commit,
            source,
            tuple(prepared),
            safe_failure,
            raw["simulated"],
            hashlib.sha256(source.encode()).hexdigest() if source else None,
        )


@dataclass(frozen=True)
class Evidence:
    logs: tuple[dict[str, Any], ...]
    source: tuple[dict[str, Any], ...]
    limitations: tuple[str, ...]
    source_safe: bool

    def payload(self) -> dict[str, Any]:
        return {
            "logs": list(self.logs),
            "source": list(self.source),
            "limitations": list(self.limitations),
            "sourceSafeToPatch": self.source_safe,
        }


def prepare_evidence(request: DiagnosisInput) -> Evidence:
    logs: list[dict[str, Any]] = []
    source: list[dict[str, Any]] = []
    limitations = ["소스와 커밋의 연결은 요청자가 제공한 정보이며 별도로 검증하지 않았습니다."]
    for chunk in request.logs:
        original = "\n".join(chunk["lines"])
        cleaned = _ANSI.sub("", original)
        cleaned = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", cleaned)
        masked = redact(cleaned)
        if masked != cleaned:
            limitations.append("로그에서 비밀값을 가렸습니다.")
        if chunk["truncated"]:
            limitations.append("로그가 일부 잘려 있습니다.")
        for offset, line in enumerate(masked.split("\n")):
            logs.append(
                {
                    "id": f"EV{len(logs) + 1:06d}",
                    "chunkId": chunk["id"],
                    "stage": chunk["stage"],
                    "chunkLine": offset + 1,
                    "sourceLine": chunk["sourceLineStart"] + offset
                    if chunk["sourceLineStart"]
                    else None,
                    "text": line,
                }
            )
    safe = request.source is not None and redact(request.source) == request.source
    if request.source is not None:
        for offset, line in enumerate(redact(request.source).splitlines()):
            source.append(
                {
                    "id": f"SC{offset + 1:06d}",
                    "path": ALLOWED_FILE,
                    "line": offset + 1,
                    "text": line,
                }
            )
        if not safe:
            limitations.append("소스에 가려진 비밀값이 있어 수정안을 만들지 않습니다.")
    else:
        limitations.append("소스가 없어 수정안을 만들지 않습니다.")
    return Evidence(tuple(logs), tuple(source), tuple(dict.fromkeys(limitations)), safe)
