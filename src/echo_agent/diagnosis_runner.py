"""Opt-in CHANGE_PROPOSAL adapter. WAS contract approval is required before enabling."""

import asyncio
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any, Protocol

from echo_agent.diagnosis import DiagnosisService
from echo_agent.diagnosis_input import DiagnosisError
from echo_agent.diagnosis_result import to_was_result
from echo_agent.events import RunEventLog
from echo_agent.was_client import (
    ClaimedRun,
    ResultAlreadySubmittedError,
    RunNotActiveError,
    WasClient,
    WasError,
)

DIAGNOSIS_KIND = "CHANGE_PROPOSAL"


class Beat(Protocol):
    lost: Any

    def beat(self) -> None: ...
    def start(self) -> None: ...
    def stop(self) -> None: ...


class Sender(Protocol):
    events: RunEventLog

    def flush(self) -> None: ...


def process_diagnosis_run(
    client: WasClient,
    run: ClaimedRun,
    service: DiagnosisService,
    beat: Beat,
    sender: Sender,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> tuple[str, str, str | None, bool]:
    def flush() -> None:
        if beat.lost.is_set():
            raise RunNotActiveError(409, "RUN_NOT_ACTIVE")
        sender.flush()

    try:
        beat.beat()
        beat.start()
        seconds = (run.deadline_at - clock()).total_seconds() - 60
        result = asyncio.run(
            service.execute(run.input_snapshot, seconds=seconds, events=sender.events, flush=flush)
        )
        flush()
        if clock() >= run.deadline_at:
            return run.id, "LOST", None, False
        # Never strip diagnosis or re-submit as PRECHECK on schema rejection.
        status = client.submit_result(run, to_was_result(result))
        return run.id, status or str(result["status"]), result["failureCode"], True
    except RunNotActiveError:
        return run.id, "LOST", None, False
    except ResultAlreadySubmittedError:
        return run.id, "ALREADY_SUBMITTED", None, False
    except DiagnosisError:
        # Do not submit an inconsistent patch or stop the long-lived polling runner.
        return run.id, "FAILED", "INVALID_DIAGNOSIS_RESULT", False
    except (WasError, OSError):
        return run.id, "FAILED", "RESULT_SUBMISSION_FAILED", False
    finally:
        beat.stop()
