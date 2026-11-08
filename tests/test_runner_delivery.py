"""Wire-size, partial acknowledgements and ambiguous result-delivery regressions."""

import copy
import json
import threading
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest

from echo_agent.events import DATA_TEXT_LIMIT, RunEventLog, RunStep
from echo_agent.precheck_runner import _EventSender, process_run
from echo_agent.result_delivery import submit_with_recovery
from echo_agent.was_client import (
    MAX_BODY_BYTES,
    ResultAlreadySubmittedError,
    RunNotActiveError,
    WasError,
    encode_body,
)
from tests.test_was_client import FakeWas, _claimed, _client, _routes, fail, ok


@pytest.mark.parametrize(
    "data",
    [
        {"tail": "x" * 2000},
        {"tail": '한글🙂\n\t"\\' * 1000},
        {"items": [{"a": "x" * 500, "b": "y" * 500}] * 5},
        {"x\x00": {"nested": ["nul\x00", "\ud800"]}},
        {"bad": float("inf")},
        {"wide": list(range(10_000))},
    ],
)
def test_event_wire_data_bounded_and_source_unmodified(data: dict[str, Any]) -> None:
    original = copy.deepcopy(data)
    event = RunEventLog("r").add(RunStep.ANALYZE, "test", **data)
    payload = event.to_json()
    encoded = json.dumps(payload["data"], ensure_ascii=False, allow_nan=False)
    assert len(encoded) <= DATA_TEXT_LIMIT
    assert "\\u0000" not in encoded
    assert payload["data"].get("truncated") or payload["data"].get("sanitized")
    assert data == original and event.data == original
    encode_body(payload)  # Surrogates are safe on the wire too.


def test_normal_event_keeps_existing_shape() -> None:
    event = RunEventLog("r").add(RunStep.ANALYZE, "test", count=2, safe="ok")
    assert event.to_json()["data"] == {"count": 2, "safe": "ok"}


def test_client_batches_by_utf8_bytes_as_well_as_count() -> None:
    fake = FakeWas(_routes())
    run = _claimed(fake)
    events = [{"seq": i, "data": {"text": "한" * 180_000}} for i in range(1, 5)]
    assert _client(fake).send_events(run, events) == 4
    batches = fake.bodies("events")
    assert len(batches) == 4  # Two fit by character count but not by UTF-8 bytes.
    assert all(len(encode_body(body)) <= MAX_BODY_BYTES for body in batches)


def test_sender_does_not_replay_acknowledged_batches() -> None:
    count = 0

    def events(path: str, body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        nonlocal count
        count += 1
        if count == 2:
            raise OSError("synthetic network failure")
        return ok({"acceptedUpTo": body["events"][-1]["seq"]})

    fake = FakeWas(_routes(events=events))
    sender = _EventSender(_client(fake), _claimed(fake), lambda _: None)
    for _ in range(201):
        sender.events.add(RunStep.ANALYZE, "test")
    sender.flush()
    assert sender._sent == 100
    sender.flush()
    assert sender._sent == 201
    assert [b["events"][0]["seq"] for b in fake.bodies("events")] == [1, 101, 101, 201]


def test_rejected_event_gets_one_summary_then_next_event_continues() -> None:
    count = 0

    def events(path: str, body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        nonlocal count
        count += 1
        if count == 1:
            return fail(422, "RESULT_INVALID")
        return ok({"acceptedUpTo": body["events"][-1]["seq"]})

    fake = FakeWas(_routes(events=events))
    sender = _EventSender(_client(fake), _claimed(fake), lambda _: None)
    original = sender.events.add(RunStep.ANALYZE, "test", tail="detail")
    sender.flush()
    sender.events.add(RunStep.SANDBOX_DELETE, "test")
    sender.flush()
    sent = fake.bodies("events")
    assert [b["events"][0]["seq"] for b in sent] == [1, 1, 2]
    assert sent[1]["events"][0]["data"] == {"omitted": True, "reason": "RESULT_INVALID"}
    assert original.data == {"tail": "detail"}


def test_repeated_event_rejection_does_not_block_result() -> None:
    fake = FakeWas(_routes(events=lambda p, b: fail(422, "RESULT_INVALID")))
    messages: list[str] = []
    outcome = process_run(_client(fake), _claimed(fake), log=messages.append)
    assert outcome.submitted and outcome.status == "SUCCEEDED"
    assert len(fake.bodies("events")) == 2
    assert len(fake.bodies("result")) == 1
    assert any("events disabled" in message for message in messages)


def test_summary_response_loss_does_not_restart_rejected_original_forever() -> None:
    calls = 0

    def events(path: str, body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        nonlocal calls
        calls += 1
        if calls == 1:
            return fail(422, "RESULT_INVALID")
        raise OSError("summary response lost")

    fake = FakeWas(_routes(events=events))
    outcome = process_run(_client(fake), _claimed(fake), log=lambda _: None)
    assert outcome.submitted and outcome.status == "SUCCEEDED"
    assert len(fake.bodies("events")) == 2
    assert len(fake.bodies("result")) == 1


@pytest.mark.parametrize("ack", [None, True, 0, "1", 2_147_483_648])
def test_invalid_event_ack_does_not_advance_sender(ack: Any) -> None:
    fake = FakeWas(_routes(events=lambda p, b: ok({"acceptedUpTo": ack})))
    sender = _EventSender(_client(fake), _claimed(fake), lambda _: None)
    sender.events.add(RunStep.ANALYZE, "test")
    sender.flush()
    assert sender._sent == 0


def _delivery(fake: FakeWas, kind: str = "CHANGE_PROPOSAL") -> tuple[Any, Any, Any]:
    run = replace(_claimed(fake), kind=kind)
    lease = SimpleNamespace(lost=threading.Event(), lease_until=run.deadline_at)
    clock = SimpleNamespace(now=datetime.now(UTC), sleeps=[])

    def sleep(seconds: float) -> None:
        clock.sleeps.append(seconds)
        clock.now += timedelta(seconds=seconds)

    clock.sleep = sleep
    return run, lease, clock


def _result(kind: str = "CHANGE_PROPOSAL") -> dict[str, Any]:
    if kind == "APPLY_PATCH":
        return {
            "status": "SUCCEEDED",
            "failureCode": None,
            "simulated": False,
            "appliedCommitSha": "a" * 40,
            "branch": "applied/test",
        }
    return {
        "status": "SUCCEEDED",
        "failureCode": None,
        "simulated": True,
        "diagnosis": {"cause": "test"},
        "patches": [{"diff": "approved-test-diff"}],
        "model": {"id": "test-model", "effort": "medium", "refusal": False},
        "processing": {
            "location": "gcp/asia-northeast3",
            "sandbox": False,
            "modelProvider": "ANTHROPIC",
            "model": "test-model",
            "modelRegion": None,
            "dataClasses": ["LOGS", "SOURCE_CODE"],
            "externalTransfer": True,
            "externalTransferBytes": 123,
        },
    }


def _submit(fake: FakeWas, result: dict[str, Any], kind: str = "CHANGE_PROPOSAL") -> Any:
    run, lease, clock = _delivery(fake, kind)
    return submit_with_recovery(
        _client(fake),
        run,
        result,
        lease,
        clock=lambda: clock.now,
        log=lambda _: None,
        sleep=clock.sleep,
    )


@pytest.mark.parametrize("kind", ["CHANGE_PROPOSAL", "APPLY_PATCH"])
def test_explicit_rejection_submits_small_failure_without_reexecuting(kind: str) -> None:
    def result(path: str, body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        return fail(422, "RESULT_INVALID") if body["status"] == "SUCCEEDED" else ok(body)

    fake = FakeWas(_routes(result=result))
    original = _result(kind)
    receipt = _submit(fake, original, kind)
    sent = fake.bodies("result")
    assert len(sent) == 2
    assert (receipt.status, receipt.failure_code) == ("FAILED", "RUNNER_ERROR")
    assert sent[1]["simulated"] is original["simulated"]
    assert "diagnosis" not in sent[1] and not sent[1].get("patches")
    assert not sent[1].get("appliedCommitSha") and not sent[1].get("branch")
    if kind == "CHANGE_PROPOSAL":
        assert sent[1]["processing"] == original["processing"]
        assert sent[1]["model"] == original["model"]
    assert original["status"] == "SUCCEEDED"


@pytest.mark.parametrize("kind", ["CHANGE_PROPOSAL", "APPLY_PATCH"])
def test_both_results_rejected_are_not_reported_submitted(kind: str) -> None:
    fake = FakeWas(_routes(result=lambda p, b: fail(422, "RESULT_INVALID")))
    with pytest.raises(WasError):
        _submit(fake, _result(kind), kind)
    assert len(fake.bodies("result")) == 2


@pytest.mark.parametrize("error", [OSError("synthetic"), 429, 500, 503, "malformed"])
def test_uncertain_response_retries_identical_bytes_then_succeeds(error: Any) -> None:
    count = 0

    def result(path: str, body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        nonlocal count
        count += 1
        if count < 3:
            if isinstance(error, OSError):
                raise error
            if error == "malformed":
                return 200, {}
            return fail(error, "INTERNAL_ERROR")
        return ok({"status": body["status"]})

    fake = FakeWas(_routes(result=result))
    run, lease, clock = _delivery(fake)
    receipt = submit_with_recovery(
        _client(fake),
        run,
        _result(),
        lease,
        clock=lambda: clock.now,
        log=lambda _: None,
        sleep=clock.sleep,
    )
    assert receipt.status == "SUCCEEDED"
    assert clock.sleeps == [1, 2]
    assert len({encode_body(b) for b in fake.bodies("result")}) == 1


def test_422_after_uncertain_delivery_never_changes_original_outcome() -> None:
    count = 0

    def result(path: str, body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        nonlocal count
        count += 1
        return fail(500, "INTERNAL_ERROR") if count == 1 else fail(422, "RESULT_INVALID")

    fake = FakeWas(_routes(result=result))
    with pytest.raises(WasError):
        _submit(fake, _result())
    assert len(fake.bodies("result")) == 2
    assert all(b["status"] == "SUCCEEDED" for b in fake.bodies("result"))


@pytest.mark.parametrize(
    ("status", "code"),
    [
        (401, "RUNNER_TOKEN_INVALID"),
        (403, "FORBIDDEN"),
        (409, "RESULT_ALREADY_SUBMITTED"),
        (409, "RUN_NOT_ACTIVE"),
    ],
)
def test_authority_or_terminal_errors_do_not_retry(status: int, code: str) -> None:
    fake = FakeWas(_routes(result=lambda p, b: fail(status, code)))
    with pytest.raises(WasError):
        _submit(fake, _result())
    assert len(fake.bodies("result")) == 1


def test_lost_success_response_then_409_is_not_a_new_failure() -> None:
    count = 0

    def result(path: str, body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        nonlocal count
        count += 1
        if count == 1:
            raise TimeoutError("stored, response lost")
        return fail(409, "RESULT_ALREADY_SUBMITTED")

    fake = FakeWas(_routes(result=result))
    with pytest.raises(ResultAlreadySubmittedError):
        _submit(fake, _result())
    assert len({encode_body(b) for b in fake.bodies("result")}) == 1


@pytest.mark.parametrize("expires", ["deadline", "lease", "revoked"])
def test_retry_stops_when_deadline_or_lease_is_lost(expires: str) -> None:
    fake = FakeWas(_routes(result=lambda p, b: fail(503, "UNAVAILABLE")))
    run, lease, clock = _delivery(fake)
    if expires == "deadline":
        run = replace(run, deadline_at=clock.now + timedelta(milliseconds=500))
    elif expires == "lease":
        lease.lease_until = clock.now + timedelta(milliseconds=500)
    else:
        clock.sleep = lambda seconds: lease.lost.set()
    with pytest.raises(RunNotActiveError):
        submit_with_recovery(
            _client(fake),
            run,
            _result(),
            lease,
            clock=lambda: clock.now,
            log=lambda _: None,
            sleep=clock.sleep,
        )
    assert len(fake.bodies("result")) == 1


def test_never_exceeds_three_delivery_attempts() -> None:
    fake = FakeWas(_routes(result=lambda p, b: fail(503, "UNAVAILABLE")))
    with pytest.raises(WasError):
        _submit(fake, _result())
    assert len(fake.bodies("result")) == 3


@pytest.mark.parametrize("reply", [{}, {"status": "RUNNING"}, {"status": "FAILED"}])
def test_http_200_without_matching_terminal_receipt_is_not_success(reply: dict[str, Any]) -> None:
    fake = FakeWas(_routes(result=lambda p, b: ok(reply)))
    with pytest.raises(WasError, match="RESULT_RESPONSE_INVALID"):
        _submit(fake, _result())
    assert len(fake.bodies("result")) == 3
