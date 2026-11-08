"""실행 이벤트(로그) 기록. WAS 계약 부록 A §3.2 의 이벤트 모양을 따른다.

이벤트 하나 = `seq · at · step · level · message · data`.
message 는 고정 문장이고 값은 data 에 둔다.
모델 출력·명령 출력 원문은 message 에 넣지 않고, 전송 사본의 data 전체 길이를 제한한다.
"""

import json
import math
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any


class RunStep(StrEnum):
    """화면의 단계 표시에 쓰는 값(계약 부록 A §7)."""

    SANDBOX_CREATE = "SANDBOX_CREATE"
    INPUT_LOAD = "INPUT_LOAD"
    CONFIG_DIFF = "CONFIG_DIFF"
    ANALYZE = "ANALYZE"
    PATCH_PROPOSE = "PATCH_PROPOSE"
    PATCH_VERIFY = "PATCH_VERIFY"
    SANDBOX_DELETE = "SANDBOX_DELETE"


class EventLevel(StrEnum):
    INFO = "INFO"
    WARN = "WARN"
    ERROR = "ERROR"


# WAS counts the whole serialized data value, not each string.
DATA_TEXT_LIMIT = 2_000
MESSAGE_TEXT_LIMIT = 200


def wire_data(data: dict[str, Any]) -> dict[str, Any]:
    """Bound only the transport copy. Do not alter model evidence or approved diffs."""
    changed = False
    remaining = 2_048

    def clean(value: Any, depth: int = 0) -> Any:
        nonlocal changed, remaining
        remaining -= 1
        if remaining < 0 or depth > 12:
            changed = True
            return "[omitted]"
        if isinstance(value, str):
            text = value.replace("\x00", "\ufffd").encode("utf-8", "replace").decode()
            changed |= text != value
            return text
        if value is None or isinstance(value, bool):
            return value
        if isinstance(value, int) and value.bit_length() <= 1_024:
            return value
        if isinstance(value, float) and math.isfinite(value):
            return value
        if isinstance(value, dict):
            out = {}
            for key, item in value.items():
                if remaining <= 0:
                    changed = True
                    break
                if not isinstance(key, str):
                    changed = True
                    continue
                out[clean(key, depth + 1)] = clean(item, depth + 1)
            return out
        if isinstance(value, (list, tuple)):
            items = []
            for item in value:
                if remaining <= 0:
                    changed = True
                    break
                items.append(clean(item, depth + 1))
            return items
        changed = True
        return "[omitted]"  # Never stringify arbitrary objects/credential wrappers.

    safe = clean(data)
    output = {"sanitized": True, "data": safe} if changed else safe
    encoded = json.dumps(output, ensure_ascii=False, allow_nan=False)
    if len(encoded) <= DATA_TEXT_LIMIT:
        return dict(output)
    preview = {"truncated": True, "reason": "DATA_TOO_LARGE", "preview": ""}
    low, high = 0, min(len(encoded), DATA_TEXT_LIMIT)
    while low < high:
        mid = (low + high + 1) // 2
        preview["preview"] = encoded[:mid]
        if len(json.dumps(preview, ensure_ascii=False)) <= DATA_TEXT_LIMIT:
            low = mid
        else:
            high = mid - 1
    preview["preview"] = encoded[:low]
    return preview


@dataclass(frozen=True)
class RunEvent:
    seq: int
    at: datetime
    step: RunStep
    level: EventLevel
    message: str
    data: dict[str, Any]

    def to_json(self) -> dict[str, Any]:
        return {
            "seq": self.seq,
            "at": self.at.isoformat().replace("+00:00", "Z"),
            "step": self.step.value,
            "level": self.level.value,
            "message": self.message.replace("\x00", "\ufffd")[:MESSAGE_TEXT_LIMIT],
            "data": wire_data(self.data),
        }


@dataclass
class RunEventLog:
    """실행 하나의 이벤트를 순서대로 쌓는다. seq 는 1부터 빈틈없이."""

    run_id: str
    events: list[RunEvent] = field(default_factory=list)

    def add(
        self,
        step: RunStep,
        message: str,
        level: EventLevel = EventLevel.INFO,
        **data: Any,
    ) -> RunEvent:
        event = RunEvent(
            seq=len(self.events) + 1,
            at=datetime.now(UTC),
            step=step,
            level=level,
            message=message,
            data=data,
        )
        self.events.append(event)
        return event

    @property
    def steps(self) -> list[RunStep]:
        return [event.step for event in self.events]
