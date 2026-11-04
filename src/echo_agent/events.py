"""실행 이벤트(로그) 기록. WAS 계약 부록 A §3.2 의 이벤트 모양을 따른다.

이벤트 하나 = `seq · at · step · level · message · data`.
message 는 고정 문장이고 값은 data 에 둔다.
모델 출력·명령 출력 원문은 message 에 넣지 않고, data 에 넣을 때는 길이를 자른다.
"""

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


# data 안 문자열 하나의 최대 길이.
DATA_TEXT_LIMIT = 2_000


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
            "message": self.message,
            "data": self.data,
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
            data={key: _clip(value) for key, value in data.items()},
        )
        self.events.append(event)
        return event

    @property
    def steps(self) -> list[RunStep]:
        return [event.step for event in self.events]


def _clip(value: Any) -> Any:
    if isinstance(value, str) and len(value) > DATA_TEXT_LIMIT:
        return value[:DATA_TEXT_LIMIT] + "…(잘림)"
    return value
