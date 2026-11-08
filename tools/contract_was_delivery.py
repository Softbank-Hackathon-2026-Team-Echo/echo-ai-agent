"""Run as a test in an isolated echo-was checkout (see docs/runner-delivery.md).

Real WAS ASGI routes/auth/schemas and real local PostgreSQL; cloud executors and
the deployment failure fixture are WAS test doubles. Never run against production.
"""

# ruff: noqa: S101 -- this file is a pytest suite run in the WAS checkout.

import asyncio
import threading
import urllib.request
from types import SimpleNamespace
from typing import Any

import pytest
from app.models import AgentRunEvent, DeployRequest, Job
from sqlalchemy import func, select
from tests.integration.migration_support import Migration
from tests.integration.runner_support import add_runner, run_patch, run_row
from tests.integration.test_failed_deploy_diagnosis import (
    DIAGNOSIS_CAPABILITIES,
    _approve,
    _claim,
    _data,
    _failed_deploy,
    _request_diagnosis,
)

from echo_agent.precheck_runner import _EventSender
from echo_agent.result_delivery import submit_with_recovery
from echo_agent.was_client import ResultAlreadySubmittedError, WasClient, _parse_claimed_run


async def prepared(migration: Migration, kind: str) -> Any:
    migration.harness.use_settings(ai_diagnosis_runner_enabled=True, patch_apply_enabled=True)
    runner = await add_runner(migration.harness.session_factory)
    failed = await _failed_deploy(migration)
    created = await _request_diagnosis(migration, failed["id"])
    assert created.status_code == 201
    claimed = await _claim(runner, DIAGNOSIS_CAPABILITIES)
    if kind == "APPLY_PATCH":
        patch = run_patch("fix-1", origin="AI")
        result = diagnosis_result() | {"patches": [patch]}
        result["diagnosis"].update(result="DIAGNOSED", fixable=True, unfixableReason=None)
        submitted = await claimed.post("result", result)
        assert submitted.status_code == 200
        approved = await _approve(migration, claimed.run_id, patch)
        assert approved.status_code == 200
        assert _data(approved)["apply"]["redeployRequestId"] is None
        claimed = await _claim(runner, DIAGNOSIS_CAPABILITIES)
    assert claimed.run["kind"] == kind
    heartbeat = await claimed.post("heartbeat")
    assert heartbeat.status_code == 200
    return claimed


def diagnosis_result() -> dict[str, Any]:
    return {
        "status": "SUCCEEDED",
        "failureCode": None,
        "simulated": False,
        "patches": [],
        "model": None,
        "processing": {
            "location": "gcp/asia-northeast3",
            "sandbox": False,
            "modelProvider": "ANTHROPIC",
            "model": "test-model",
            "modelRegion": None,
            "dataClasses": ["LOGS"],
            "externalTransfer": True,
            "externalTransferBytes": 123,
        },
        "diagnosis": {
            "result": "INSUFFICIENT_EVIDENCE",
            "category": "CODE",
            "cause": "test",
            "fixable": False,
            "unfixableReason": "synthetic fixture",
            "evidence": [],
        },
    }


def client_for(claimed: Any, *, lose_first_result: bool = False) -> tuple[WasClient, list[int]]:
    loop = asyncio.get_running_loop()
    statuses: list[int] = []

    def transport(request: urllib.request.Request, timeout: float) -> tuple[int, bytes]:
        action = request.full_url.rsplit("/", 1)[-1]
        assert isinstance(request.data, bytes)
        response = asyncio.run_coroutine_threadsafe(
            claimed.post_raw(action, request.data), loop
        ).result(timeout=timeout)
        statuses.append(response.status_code)
        if lose_first_result and action == "result" and len(statuses) == 1:
            assert response.status_code == 200
            raise TimeoutError("synthetic response loss after real DB commit")
        return response.status_code, response.content

    # The bridge uses real run-token auth in ClaimedRunFixture, never a production credential.
    return WasClient("http://localhost", "echo_rnr_synthetic", transport=transport), statuses


async def counts(migration: Migration) -> tuple[int, int]:
    async with migration.harness.session_factory() as session:
        return (
            await session.scalar(select(func.count()).select_from(DeployRequest)),
            await session.scalar(select(func.count()).select_from(Job)),
        )


@pytest.mark.parametrize("kind", ["CHANGE_PROPOSAL", "APPLY_PATCH"])
async def test_runner_422_fallback_is_saved_failed_without_redeploy(
    migration: Migration, kind: str
) -> None:
    claimed = await prepared(migration, kind)
    before = await counts(migration)
    client, statuses = client_for(claimed)
    run = _parse_claimed_run(claimed.run, claimed.run_token)
    payload = (
        diagnosis_result()
        if kind == "CHANGE_PROPOSAL"
        else {
            "status": "SUCCEEDED",
            "failureCode": None,
            "simulated": False,
            "appliedCommitSha": "a" * 40,
            "branch": "applied/test",
        }
    )
    payload["invalidField"] = True  # Actual server schema returns 422 before storing a result.
    receipt = await asyncio.to_thread(
        submit_with_recovery,
        client,
        run,
        payload,
        SimpleNamespace(lost=threading.Event(), lease_until=run.lease_until),
        clock=migration.harness.clock.now,
        log=lambda _: None,
    )
    assert statuses == [422, 200]
    assert (receipt.status, receipt.failure_code) == ("FAILED", "RUNNER_ERROR")
    stored = await run_row(migration, claimed.run_id)
    assert (stored.status, stored.failure_code) == ("FAILED", "RUNNER_ERROR")
    assert stored.result.get("patches", []) == []
    assert not stored.result.get("redeployRequestId")
    assert await counts(migration) == before
    if kind == "CHANGE_PROPOSAL":
        assert stored.processing["externalTransferBytes"] == 123


async def test_runner_large_unicode_nul_events_are_saved_with_sequences(
    migration: Migration,
) -> None:
    claimed = await prepared(migration, "CHANGE_PROPOSAL")
    client, statuses = client_for(claimed)
    run = _parse_claimed_run(claimed.run, claimed.run_token)
    sender = _EventSender(client, run, lambda _: None)
    from echo_agent.events import RunStep

    for _ in range(101):
        sender.events.add(RunStep.ANALYZE, "test", tail="한글\n\x00" * 1000)
    await asyncio.to_thread(sender.flush)
    assert statuses == [200, 200]
    assert sender._sent == 101
    async with migration.harness.session_factory() as session:
        rows = (
            await session.scalars(
                select(AgentRunEvent)
                .where(AgentRunEvent.run_id == stored_id(claimed.run_id))
                .order_by(AgentRunEvent.seq)
            )
        ).all()
    assert [row.seq for row in rows] == list(range(1, 102))
    assert all(row.data["truncated"] for row in rows)


def stored_id(value: str) -> Any:
    import uuid

    return uuid.UUID(value)


async def test_runner_lost_receipt_preserves_committed_result(migration: Migration) -> None:
    claimed = await prepared(migration, "CHANGE_PROPOSAL")
    before = await counts(migration)
    client, statuses = client_for(claimed, lose_first_result=True)
    run = _parse_claimed_run(claimed.run, claimed.run_token)
    with pytest.raises(ResultAlreadySubmittedError):
        await asyncio.to_thread(
            submit_with_recovery,
            client,
            run,
            diagnosis_result(),
            SimpleNamespace(lost=threading.Event(), lease_until=run.lease_until),
            clock=migration.harness.clock.now,
            log=lambda _: None,
            sleep=lambda _: None,
        )
    assert statuses == [200, 409]
    assert (await run_row(migration, claimed.run_id)).status == "SUCCEEDED"
    assert await counts(migration) == before
