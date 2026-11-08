"""WAS 러너 클라이언트·러너 루프(가짜 WAS). 네트워크·모델·Docker 없이 돈다."""

import json
import threading
import urllib.request
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from echo_agent.precheck_runner import FAILURE_DEADLINE, process_run, run_loop
from echo_agent.was_client import (
    ClaimedRun,
    ResultAlreadySubmittedError,
    RunNotActiveError,
    WasClient,
    WasConfigError,
    WasError,
)
from tests.test_precheck_rules import TARGET_ID, _snapshot

BASE = "https://api.example.test"
RUNNER_CRED = "echo_rnr_" + "r" * 32
RUN_CRED = "echo_run_" + "u" * 32
RUN_ID = "33333333-3333-3333-3333-333333333333"

Handler = Callable[[str, dict[str, Any]], tuple[int, dict[str, Any]]]


class FakeWas:
    """경로별 응답을 정해 두고, 받은 요청(경로·헤더·본문)을 쌓는다."""

    def __init__(self, routes: dict[str, Handler]) -> None:
        self.routes = routes
        self.calls: list[tuple[str, str, dict[str, Any]]] = []
        self._lock = threading.Lock()

    def __call__(self, request: urllib.request.Request, timeout: float) -> tuple[int, bytes]:
        path = request.full_url.removeprefix(BASE)
        assert isinstance(request.data, bytes)
        body = json.loads(request.data)
        with self._lock:
            self.calls.append((path, request.get_header("Authorization") or "", body))
        action = path.rsplit("/", 1)[-1]
        status, envelope = self.routes[action](path, body)
        return status, json.dumps(envelope).encode()

    def bodies(self, action: str) -> list[dict[str, Any]]:
        return [body for path, _, body in self.calls if path.endswith("/" + action)]


def ok(data: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    return 200, {"success": True, "data": data}


def fail(status: int, code: str) -> tuple[int, dict[str, Any]]:
    return status, {"success": False, "code": code, "message": "x"}


def _run_payload(deadline: datetime | None = None) -> dict[str, Any]:
    deadline = deadline or datetime.now(UTC) + timedelta(minutes=15)
    return {
        "run": {
            "id": RUN_ID,
            "kind": "PRECHECK",
            "orgId": "org-1",
            "serviceId": "svc-1",
            "sourceEnvironmentId": "src",
            "targetEnvironmentId": TARGET_ID,
            "inputSnapshot": _snapshot(),
            "inputHash": "sha256:" + "b" * 64,
            "scenarioRef": None,
            "deadlineAt": deadline.isoformat().replace("+00:00", "Z"),
            "leaseUntil": None,
        },
        "runToken": RUN_CRED,
    }


def _routes(**overrides: Handler) -> dict[str, Handler]:
    routes: dict[str, Handler] = {
        "runs:claim": lambda p, b: ok(_run_payload()),
        "heartbeat": lambda p, b: ok(
            {
                "status": "RUNNING",
                "leaseUntil": (datetime.now(UTC) + timedelta(minutes=1)).isoformat(),
            }
        ),
        "events": lambda p, b: ok({"acceptedUpTo": b["events"][-1]["seq"]}),
        "result": lambda p, b: ok({"status": b["status"]}),
    }
    routes.update(overrides)
    return routes


def _client(fake: FakeWas) -> WasClient:
    return WasClient(BASE, RUNNER_CRED, transport=fake)


# ---------------------------------------------------------------- 클라이언트


def test_claim_without_queued_run_returns_none() -> None:
    fake = FakeWas(_routes(**{"runs:claim": lambda p, b: ok({"run": None, "runToken": None})}))
    assert _client(fake).claim("echo-sandbox-runner") is None
    path, auth, body = fake.calls[0]
    assert path == "/api/v1/runner/runs:claim"
    assert auth == f"Bearer {RUNNER_CRED}"
    assert body == {"runnerId": "echo-sandbox-runner", "capabilities": ["PRECHECK"]}


def test_claim_parses_run_and_keeps_token_out_of_repr() -> None:
    fake = FakeWas(_routes())
    client = _client(fake)
    run = client.claim("echo-sandbox-runner")
    assert run is not None
    assert (run.id, run.kind, run.target_environment_id) == (RUN_ID, "PRECHECK", TARGET_ID)
    assert run.deadline_at.tzinfo is not None
    assert run.run_token == RUN_CRED
    assert RUN_CRED not in repr(run)
    assert RUNNER_CRED not in repr(client)


def test_run_calls_use_run_token_and_split_events_by_100() -> None:
    fake = FakeWas(_routes())
    client = _client(fake)
    run = client.claim("r")
    assert run is not None
    events = [
        {"seq": i, "at": "t", "step": "ANALYZE", "level": "INFO", "message": "m", "data": {}}
        for i in range(1, 251)
    ]
    assert client.send_events(run, events) == 250
    assert [len(b["events"]) for b in fake.bodies("events")] == [100, 100, 50]
    client.heartbeat(run)
    auths = {auth for path, auth, _ in fake.calls if "/runs/" in path}
    assert auths == {f"Bearer {RUN_CRED}"}
    assert any(path == f"/api/v1/runner/runs/{RUN_ID}/heartbeat" for path, _, _ in fake.calls)


@pytest.mark.parametrize(
    ("action", "status", "code", "error_type"),
    [
        ("heartbeat", 409, "RUN_NOT_ACTIVE", RunNotActiveError),
        ("result", 409, "RESULT_ALREADY_SUBMITTED", ResultAlreadySubmittedError),
        ("result", 422, "RESULT_INVALID", WasError),
    ],
)
def test_error_envelope_maps_to_exception(
    action: str, status: int, code: str, error_type: type[WasError]
) -> None:
    fake = FakeWas(_routes(**{action: lambda p, b: fail(status, code)}))
    client = _client(fake)
    run = client.claim("r")
    assert run is not None
    call = client.heartbeat if action == "heartbeat" else (lambda r: client.submit_result(r, {}))
    with pytest.raises(error_type) as caught:
        call(run)
    assert (caught.value.status, caught.value.code) == (status, code)
    assert RUN_CRED not in str(caught.value)


def test_from_env_requires_both_variables_without_echoing_values() -> None:
    with pytest.raises(WasConfigError) as caught:
        WasClient.from_env({"ECHO_RUNNER_TOKEN": RUNNER_CRED})
    assert "ECHO_WAS_URL" in str(caught.value)
    assert RUNNER_CRED not in str(caught.value)
    client = WasClient.from_env({"ECHO_WAS_URL": BASE + "/", "ECHO_RUNNER_TOKEN": RUNNER_CRED})
    assert client.base_url == BASE


@pytest.mark.parametrize(
    ("url", "token"),
    [
        ("http://api.example.test", RUNNER_CRED),  # 로컬이 아닌 http
        ("ftp://api.example.test", RUNNER_CRED),
        (BASE + "?x=1", RUNNER_CRED),
        (BASE, "echo_agt_" + "a" * 32),  # 에이전트 토큰은 러너 토큰이 아니다
    ],
)
def test_client_rejects_unsafe_url_or_wrong_token_kind(url: str, token: str) -> None:
    with pytest.raises(WasConfigError):
        WasClient(url, token)


def test_localhost_http_is_allowed_for_development() -> None:
    assert WasClient("http://localhost:8000", RUNNER_CRED).base_url == "http://localhost:8000"


# ---------------------------------------------------------------- 러너


def _claimed(fake: FakeWas) -> ClaimedRun:
    run = _client(fake).claim("r")
    assert run is not None
    return run


def test_process_run_sends_events_then_real_rule_result() -> None:
    fake = FakeWas(_routes())
    client = _client(fake)
    outcome = process_run(client, _claimed(fake), log=lambda m: None)
    assert (outcome.status, outcome.submitted) == ("SUCCEEDED", True)

    actions = [path.rsplit("/", 1)[-1] for path, _, _ in fake.calls]
    assert actions[:2] == ["runs:claim", "heartbeat"]  # 첫 하트비트가 RUNNING 을 만든다
    assert actions[-1] == "result"
    sent = [e for body in fake.bodies("events") for e in body["events"]]
    assert [e["seq"] for e in sent] == [1, 2, 3]
    assert [e["step"] for e in sent] == ["INPUT_LOAD", "CONFIG_DIFF", "ANALYZE"]
    assert all(len(e["message"]) <= 200 for e in sent)

    result = fake.bodies("result")[0]
    assert set(result) == {
        "status", "failureCode", "simulated", "sandbox", "model",
        "configDiff", "featureGaps", "findings", "patches", "blockedAttempts",
    }  # fmt: skip
    assert result["status"] == "SUCCEEDED"
    assert result["failureCode"] is None
    assert result["simulated"] is False
    assert result["model"] is None  # → WAS 가 aiReviewed=false 로 계산
    assert result["sandbox"] is None
    warnings = [f for f in result["findings"] if f["result"] == "WARN"]
    assert len(warnings) >= 1
    assert all(f["origin"] == "RULE" for f in result["findings"])
    assert warnings[0]["suggestedFix"]
    assert {"key": "region", "source": "ap-northeast-1", "target": "asia-northeast3",
            "origin": "RULE", "severity": "INFO"} in result["configDiff"]  # fmt: skip
    assert RUN_CRED not in json.dumps(result)


def test_result_after_deadline_margin_is_failed_deadline() -> None:
    deadline = datetime.now(UTC) + timedelta(seconds=30)  # 마감 1분 전을 이미 지남
    fake = FakeWas(_routes(**{"runs:claim": lambda p, b: ok(_run_payload(deadline))}))
    outcome = process_run(_client(fake), _claimed(fake), log=lambda m: None)
    result = fake.bodies("result")[0]
    assert (result["status"], result["failureCode"]) == ("FAILED", FAILURE_DEADLINE)
    assert result["findings"] == [] and result["configDiff"] == []
    assert outcome.failure_code == FAILURE_DEADLINE


def test_bad_snapshot_is_reported_as_failed_input_invalid() -> None:
    payload = _run_payload()
    payload["run"]["inputSnapshot"] = {"schemaVersion": 99}
    fake = FakeWas(_routes(**{"runs:claim": lambda p, b: ok(payload)}))
    process_run(_client(fake), _claimed(fake), log=lambda m: None)
    result = fake.bodies("result")[0]
    assert (result["status"], result["failureCode"]) == ("FAILED", "INPUT_INVALID")
    assert result["simulated"] is False


def test_cancelled_run_stops_without_result() -> None:
    fake = FakeWas(_routes(heartbeat=lambda p, b: fail(409, "RUN_NOT_ACTIVE")))
    outcome = process_run(_client(fake), _claimed(fake), log=lambda m: None)
    assert (outcome.status, outcome.submitted) == ("LOST", False)
    assert fake.bodies("result") == []


def test_event_failure_does_not_block_result() -> None:
    fake = FakeWas(_routes(events=lambda p, b: fail(422, "RESULT_INVALID")))
    outcome = process_run(_client(fake), _claimed(fake), log=lambda m: None)
    assert outcome.submitted is True
    assert fake.bodies("result")[0]["status"] == "SUCCEEDED"


def test_heartbeat_repeats_while_run_is_processing() -> None:
    beats = threading.Event()
    count = 0

    def heartbeat(path: str, body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        nonlocal count
        count += 1
        if count >= 3:
            beats.set()
        return ok({"status": "RUNNING", "leaseUntil": None})

    def slow_result(path: str, body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        assert beats.wait(5), "heartbeat did not repeat"
        return ok({"status": body["status"]})

    fake = FakeWas(_routes(heartbeat=heartbeat, result=slow_result))
    outcome = process_run(
        _client(fake), _claimed(fake), heartbeat_interval=0.01, log=lambda m: None
    )
    assert outcome.submitted is True
    assert count >= 3


def test_run_loop_once_exits_when_queue_is_empty() -> None:
    fake = FakeWas(_routes(**{"runs:claim": lambda p, b: ok({"run": None, "runToken": None})}))
    code = run_loop(_client(fake), "r", once=True, stop=threading.Event(), log=lambda m: None)
    assert code == 0
    assert len(fake.calls) == 1


def test_run_loop_once_processes_one_run() -> None:
    fake = FakeWas(_routes())
    code = run_loop(_client(fake), "r", once=True, stop=threading.Event(), log=lambda m: None)
    assert code == 0
    assert len(fake.bodies("result")) == 1
