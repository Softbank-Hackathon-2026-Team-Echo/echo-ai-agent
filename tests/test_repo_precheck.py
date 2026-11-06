"""Existing runner lifecycle and result shape remain intact when repo analysis is enabled."""

import json
import threading
from dataclasses import replace
from typing import Any

from echo_agent.precheck_runner import process_run, run_loop
from echo_agent.repo_model import RepoReviewer
from echo_agent.repo_precheck import RepoPrecheck, merge_result
from echo_agent.repo_source import SourceError
from tests.test_repo_analysis import COMMIT, snapshot
from tests.test_repo_model import Model
from tests.test_was_client import FakeWas, _claimed, _client, _routes, ok


def loader(*args: Any, **kwargs: Any) -> Any:
    return snapshot()


def test_precheck_submits_repository_findings_in_existing_result_fields() -> None:
    fake = FakeWas(_routes())
    run = _claimed(fake)
    run = replace(
        run,
        input_snapshot={
            **run.input_snapshot,
            "repository": {"repo": "team/demo", "commitSha": COMMIT},
        },
    )
    outcome = process_run(
        _client(fake), run, repo_analyzer=RepoPrecheck(loader=loader), log=lambda _: None
    )
    assert outcome.submitted and outcome.status == "SUCCEEDED"
    body = fake.bodies("result")[0]
    repo_findings = [f for f in body["findings"] if f["control"].startswith("repo-")]
    assert len(repo_findings) == 5 and all(f["result"] == "WARN" for f in repo_findings)
    assert body["configDiff"] and body["model"] is None
    assert "repository" not in body and "processing" not in body
    assert "demo-value-never-a-real-credential" not in json.dumps(fake.calls)


def test_default_runner_does_not_fetch_repository_or_change_capabilities() -> None:
    fake = FakeWas(_routes(**{"runs:claim": lambda p, b: ok({"run": None})}))
    assert (
        run_loop(_client(fake), "test", once=True, stop=threading.Event(), log=lambda _: None) == 0
    )
    assert fake.calls[0][2]["capabilities"] == ["PRECHECK"]


def test_missing_or_unavailable_source_is_a_visible_warning_not_a_clean_scan() -> None:
    fake = FakeWas(_routes())
    run = _claimed(fake)
    called = False

    def unavailable(*args: Any, **kwargs: Any) -> Any:
        nonlocal called
        called = True
        raise SourceError("SOURCE_UNAVAILABLE")

    analyzer = RepoPrecheck(loader=unavailable)
    result = analyzer.run(run.input_snapshot, seconds=30)
    assert not called and result["status"] == "UNAVAILABLE"
    assert "REPO_INPUT_MISSING" in result["findings"][0]["reason"]
    raw = {**run.input_snapshot, "repository": {"repo": "team/demo", "commitSha": COMMIT}}
    result = analyzer.run(raw, seconds=30)
    assert called and "SOURCE_UNAVAILABLE" in result["findings"][0]["reason"]


def test_model_source_transfer_is_attached_even_when_model_fails() -> None:
    fake = FakeWas(_routes())
    run = _claimed(fake)
    raw = {**run.input_snapshot, "repository": {"repo": "team/demo", "commitSha": COMMIT}}
    analyzer = RepoPrecheck(
        RepoReviewer(Model(error=True).create), loader=loader, location="gcp/asia-northeast3"
    )
    outcome = process_run(
        _client(fake), replace(run, input_snapshot=raw), repo_analyzer=analyzer, log=lambda _: None
    )
    assert outcome.submitted
    body = fake.bodies("result")[0]
    assert body["model"] is None and body["processing"]["externalTransferBytes"] > 0
    assert "SOURCE_CODE" in body["processing"]["dataClasses"]
    assert all(f["origin"] == "RULE" for f in body["findings"])
    assert "private-provider-body" not in json.dumps(fake.calls)


def test_two_model_calls_combine_transfer_without_losing_existing_findings() -> None:
    fake = FakeWas(_routes())
    run = _claimed(fake)
    raw = {**run.input_snapshot, "repository": {"repo": "team/demo", "commitSha": COMMIT}}
    repo = RepoPrecheck(RepoReviewer(Model().create), loader=loader).run(raw, seconds=90)
    result = {
        "status": "SUCCEEDED",
        "simulated": False,
        "model": None,
        "findings": [{"control": "keep"}] * 99,
        "processing": {
            **repo["processing"],
            "externalTransferBytes": 100,
            "dataClasses": ["CONFIG"],
        },
    }
    expected = repo["processing"]["externalTransferBytes"] + 100
    merge_result(result, repo)
    assert len(result["findings"]) == 100 and result["findings"][0]["control"] == "keep"
    assert result["processing"]["externalTransferBytes"] == expected
    assert "SOURCE_CODE" in result["processing"]["dataClasses"]
    assert result["model"] is not None


def test_deadline_failure_still_records_transfer_but_not_successful_review() -> None:
    fake = FakeWas(_routes())
    run = _claimed(fake)
    raw = {**run.input_snapshot, "repository": {"repo": "team/demo", "commitSha": COMMIT}}
    repo = RepoPrecheck(RepoReviewer(Model().create), loader=loader).run(raw, seconds=90)
    result = {"status": "FAILED", "simulated": False, "model": None, "findings": []}
    merge_result(result, repo)
    assert not result["findings"] and result["model"] is None
    assert result["processing"]["externalTransferBytes"] > 0
