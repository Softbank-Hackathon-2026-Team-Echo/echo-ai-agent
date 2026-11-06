"""Model review adds cited inferences without rewriting observations or leaking secrets."""

import copy
import json
from types import SimpleNamespace
from typing import Any

import pytest

from echo_agent.repo_analysis import to_findings
from echo_agent.repo_model import RepoReviewer, verified_reviews
from tests.test_repo_analysis import report


def reply(identity: str, **changes: Any) -> dict[str, Any]:
    value = {
        "observationId": identity,
        "evidenceIds": [identity],
        "assessment": "NEEDS_CONTEXT",
        "explanation": "대상 클라우드에서도 이 의존성이 필요한지 확인해야 합니다.",
        "recommendation": "API 호출 경로와 권한을 확인하세요.",
    }
    value.update(changes)
    return value


class Model:
    def __init__(self, *, error: bool = False) -> None:
        self.requests: list[dict[str, Any]] = []
        self.error = error

    def create(self, **kwargs: Any) -> Any:
        self.requests.append(kwargs)
        if self.error:
            raise RuntimeError("private-provider-body")
        payload = json.loads(kwargs["messages"][0]["content"])
        identity = payload["observations"][0]["id"]
        return SimpleNamespace(
            stop_reason="end_turn",
            model="fixture-model",
            content=[SimpleNamespace(type="text", text=json.dumps({"reviews": [reply(identity)]}))],
        )


def test_masked_evidence_only_and_static_results_survive_model_review() -> None:
    value = report()
    original = copy.deepcopy(value["observations"])
    model = Model()
    RepoReviewer(model.create).review(value)
    assert value["modelReviewStatus"] == "REVIEWED"
    assert value["observations"] == original
    assert value["suggestions"][0]["certainty"] == "INFERRED"
    assert len(model.requests) == 1
    serialized = json.dumps(model.requests)
    assert "demo-value-never-a-real-credential" not in serialized
    assert "API_TOKEN" in serialized and "***" in serialized
    assert value["processing"]["dataClasses"] == ["SOURCE_CODE", "FINDINGS", "CONFIG"]
    assert value["processing"]["externalTransferBytes"] > 0
    ai = [f for f in to_findings(value, "env") if f["origin"] == "AI"]
    assert len(ai) == 1 and ai[0]["result"] == "WARN"


@pytest.mark.parametrize(
    "changes",
    [
        {"observationId": "invented"},
        {"evidenceIds": ["other"]},
        {"assessment": "SAFE"},
        {"path": "injected.py"},
        {"explanation": ""},
        {"recommendation": 3},
    ],
)
def test_unsupported_reviews_are_discarded(changes: dict[str, Any]) -> None:
    value = report()
    identity = value["observations"][0]["id"]
    assert verified_reviews({"reviews": [reply(identity, **changes)]}, value) == ([], 1)


def test_duplicate_reviews_are_not_counted_twice() -> None:
    value = report()
    item = reply(value["observations"][0]["id"])
    reviews, rejected = verified_reviews({"reviews": [item, item]}, value)
    assert len(reviews) == 1 and rejected == 1


def test_provider_failure_retains_transfer_and_static_findings_without_raw_errors() -> None:
    value = report()
    original = copy.deepcopy(value["observations"])
    RepoReviewer(Model(error=True).create).review(value)
    assert value["modelReviewStatus"] == "FAILED" and not value["suggestions"]
    assert value["observations"] == original and value["model"] is None
    assert value["processing"]["externalTransfer"]
    assert "private-provider-body" not in json.dumps(value)


def test_replay_has_no_fake_model_or_external_transfer_and_no_evidence_skips_call() -> None:
    model = Model()
    value = report()
    RepoReviewer(model.create, simulated=True).review(value)
    assert value["simulated"] and value["model"] is None and "processing" not in value
    clean = report("print('hello')")
    RepoReviewer(model.create).review(clean)
    assert clean["modelReviewStatus"] == "SKIPPED" and len(model.requests) == 1


def test_review_is_not_allowed_to_cite_an_observation_not_sent_to_model() -> None:
    value = report("\n".join(f'R{i} = "us-east-1"' for i in range(30)))
    item = reply(value["observations"][25]["id"])
    assert verified_reviews({"reviews": [item]}, value) == ([], 1)


def test_model_control_characters_are_removed_before_was_serialization() -> None:
    value = report()
    identity = value["observations"][0]["id"]
    reviews, rejected = verified_reviews(
        {"reviews": [reply(identity, explanation="확인\x00필요")]}, value
    )
    assert not rejected and reviews[0]["explanation"] == "확인필요"
