"""Bounded result delivery, independent of executing a model, patch or remote write.

422 is an explicit validation rejection. Transport errors/5xx and malformed success
responses are ambiguous: only replay the identical payload, never change its outcome.
No new WAS fields/codes. This module does not resume WAS repository/redeploy callbacks.
"""

import copy
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol

from echo_agent.was_client import ClaimedRun, RunNotActiveError, WasClient, WasError, encode_body

MAX_ATTEMPTS = 3


class Lease(Protocol):
    lost: threading.Event


@dataclass(frozen=True)
class Receipt:
    status: str
    failure_code: str | None


def failure_result(run: ClaimedRun, original: Mapping[str, Any]) -> dict[str, Any]:
    """Use existing kind-specific schemas; preserve valid bounded processing metadata."""
    result: dict[str, Any] = {
        "status": "FAILED",
        "failureCode": "RUNNER_ERROR",
        "simulated": original["simulated"],
    }
    if run.kind == "APPLY_PATCH":
        result.update(appliedCommitSha=None, branch=None)
    elif run.kind == "CHANGE_PROPOSAL":
        result.update(model=None, patches=[])
        for field in ("model", "processing"):
            value = original.get(field)
            if isinstance(value, dict):
                try:
                    raw = encode_body(value)
                except (ValueError, TypeError, UnicodeError):
                    continue
                if len(raw) <= 8_192 and b"\\u0000" not in raw:
                    result[field] = value
    else:
        raise ValueError("delivery recovery is only for diagnosis/apply")
    return result


def _remaining(run: ClaimedRun, lease: Lease, clock: Callable[[], datetime]) -> float:
    if lease.lost.is_set():
        raise RunNotActiveError(409, "RUN_NOT_ACTIVE")
    end = run.deadline_at
    lease_until = getattr(lease, "lease_until", run.lease_until)
    if lease_until is not None:
        end = min(end, lease_until)
    left = (end - clock()).total_seconds()
    if left <= 0:
        raise RunNotActiveError(409, "RUN_NOT_ACTIVE")
    return left


def submit_with_recovery(
    client: WasClient,
    run: ClaimedRun,
    result: Mapping[str, Any],
    lease: Lease,
    *,
    clock: Callable[[], datetime],
    log: Callable[[str], None],
    sleep: Callable[[float], None] = time.sleep,
) -> Receipt:
    # Freeze once. A retry must not re-run an agent or rebuild a payload from changing data.
    payload = copy.deepcopy(dict(result))
    uncertain = False
    fallback = False
    delay = 0.0
    for attempt in range(1, MAX_ATTEMPTS + 1):
        left = _remaining(run, lease, clock)
        if delay:
            if left <= delay:
                raise RunNotActiveError(409, "RUN_NOT_ACTIVE")
            sleep(delay)
        left = _remaining(run, lease, clock)
        try:
            status = client.submit_result(run, payload, timeout_seconds=left)
            return Receipt(status, payload.get("failureCode"))
        except WasError as error:
            rejected = error.status == 422 and error.code == "RESULT_INVALID"
            if rejected and not uncertain and not fallback and attempt < MAX_ATTEMPTS:
                payload = failure_result(run, payload)
                fallback, delay = True, 0.0
                log(f"result rejected run={run.id}; submitting minimal FAILED result")
                continue
            transient = error.status == 429 or error.status >= 500 or 200 <= error.status < 300
            if not transient or attempt == MAX_ATTEMPTS:
                raise
        except OSError:
            if attempt == MAX_ATTEMPTS:
                raise
        uncertain = True
        delay = float(attempt)
        log(f"result unconfirmed run={run.id}; identical payload retry={attempt + 1}")
    raise AssertionError("unreachable")
