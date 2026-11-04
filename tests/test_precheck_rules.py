"""사전 점검 규칙 비교(순수 함수). WAS·모델·Docker 없이 돈다."""

import copy
from typing import Any

import pytest

from echo_agent.precheck_rules import (
    CONFIG_DIFF_LIMIT,
    TEXT_LIMIT,
    FindingResult,
    Severity,
    SnapshotError,
    analyze,
    flatten_config,
)

SOURCE_ID = "11111111-1111-1111-1111-111111111111"
TARGET_ID = "22222222-2222-2222-2222-222222222222"
DIGEST = "sha256:" + "a" * 64


def _snapshot() -> dict[str, Any]:
    """AWS(도쿄) → GCP(서울) 이전. echo-was AD-9 inputSnapshot v1 모양."""
    return {
        "schemaVersion": 1,
        "service": {"id": "svc-1", "name": "shop", "containerPort": 8080, "healthCheckPath": "/"},
        "source": {
            "environmentId": SOURCE_ID,
            "kind": "aws",
            "config": {
                "region": "ap-northeast-1",
                "cluster_name": "echo-eks",
                "ingress_class": "alb",
            },
            "imageDigest": DIGEST,
            "variableKeys": ["DATABASE_URL", "LOG_LEVEL", "STRIPE_KEY"],
        },
        "target": {
            "environmentId": TARGET_ID,
            "kind": "gcp",
            "config": {
                "region": "asia-northeast3",
                "cluster_name": "echo-gke",
                "project_id": "echo-prod",
            },
            "imageDigest": None,
            "variableKeys": ["DATABASE_URL", "LOG_LEVEL", "GCP_ONLY"],
        },
        "findings": [
            {
                "controlId": "C-IMG-1",
                "result": "FAIL",
                "source": "trivy",
                "environmentId": SOURCE_ID,
            },
            {"controlId": "C-TLS-1", "result": "PASS", "source": "tls", "environmentId": TARGET_ID},
        ],
    }


def _same_snapshot() -> dict[str, Any]:
    snapshot = _snapshot()
    snapshot["target"] = copy.deepcopy(snapshot["source"]) | {"environmentId": TARGET_ID}
    snapshot["findings"] = []
    return snapshot


def test_cross_cloud_snapshot_lists_every_difference_in_order() -> None:
    analysis = analyze(_snapshot())
    rows = [(d.key, d.source, d.target, d.severity) for d in analysis.config_diff]
    assert rows == [
        ("kind", "aws", "gcp", Severity.INFO),
        ("cluster_name", "echo-eks", "echo-gke", Severity.INFO),
        ("ingress_class", "alb", None, Severity.INFO),
        ("project_id", None, "echo-prod", Severity.INFO),
        ("region", "ap-northeast-1", "asia-northeast3", Severity.INFO),
        ("imageDigest", DIGEST, None, Severity.INFO),
        ("variables.STRIPE_KEY", "present", None, Severity.WARN),
        ("variables.GCP_ONLY", None, "present", Severity.INFO),
    ]
    # 계약 §3.3 configDiff 모양 그대로.
    assert analysis.config_diff[0].to_json() == {
        "key": "kind",
        "source": "aws",
        "target": "gcp",
        "origin": "RULE",
        "severity": "INFO",
    }


def test_difference_produces_warning_with_guidance() -> None:
    analysis = analyze(_snapshot())
    config_finding = analysis.findings[0].to_json()
    assert config_finding["control"] == "config-diff"
    assert config_finding["environmentId"] == TARGET_ID
    assert config_finding["result"] == "WARN"
    assert config_finding["origin"] == "RULE"
    assert config_finding["reason"].startswith("설정 차이 8건(경고 1건)")
    guidance = config_finding["suggestedFix"]
    # 경고(빠진 변수)가 맨 앞, 이어서 종류·리전·이미지·도착 전용 변수·그 밖의 설정.
    lines = guidance.split("\n")
    assert lines[0].startswith("- 도착 환경에 없는 변수 1개: STRIPE_KEY")
    assert "aws → gcp" in lines[1]
    assert "ap-northeast-1 → asia-northeast3" in lines[2]
    assert "배포된 이미지가 아직 없습니다" in lines[3]
    assert "GCP_ONLY" in lines[4]
    assert "cluster_name, ingress_class, project_id" in lines[5]
    assert analysis.warning_count >= 1


def test_recent_fail_finding_becomes_second_warning() -> None:
    findings = analyze(_snapshot()).findings
    assert [f.control for f in findings] == ["config-diff", "recent-findings"]
    recent = findings[1]
    assert recent.result is FindingResult.WARN
    assert recent.environment_id == SOURCE_ID  # 도착 환경에는 FAIL·WARN 이 없음
    assert recent.reason == "최근 검사 FAIL 1건 · WARN 0건: C-IMG-1"
    assert recent.suggested_fix is not None


def test_identical_environments_pass_without_guidance() -> None:
    analysis = analyze(_same_snapshot())
    assert analysis.config_diff == ()
    assert len(analysis.findings) == 1
    finding = analysis.findings[0]
    assert finding.result is FindingResult.PASS
    assert finding.suggested_fix is None
    assert analysis.warning_count == 0


def test_same_input_gives_same_output() -> None:
    assert analyze(_snapshot()) == analyze(_snapshot())


def test_secret_named_config_keys_are_not_copied() -> None:
    snapshot = _same_snapshot()
    snapshot["source"]["config"]["db"] = {"secretRef": "projects/x/secrets/a", "port": 5432}
    snapshot["target"]["config"]["db"] = {"secretRef": "projects/x/secrets/b", "port": 5433}
    analysis = analyze(snapshot)
    assert [d.key for d in analysis.config_diff] == ["db.port"]
    assert "projects/x" not in str([d.to_json() for d in analysis.config_diff])


def test_flatten_config_nests_and_serializes_values() -> None:
    flat = flatten_config({"a": {"b": 1, "c": True}, "d": [2, 1], "e": None, "f": {}})
    assert flat == {"a.b": "1", "a.c": "true", "d": "[2,1]", "e": None, "f": "{}"}


def test_long_values_and_many_keys_stay_within_was_limits() -> None:
    snapshot = _same_snapshot()
    snapshot["source"]["config"] = {f"k{i:03}": "x" * 5000 for i in range(300)}
    analysis = analyze(snapshot)
    assert len(analysis.config_diff) == CONFIG_DIFF_LIMIT
    assert all(len(d.source or "") <= TEXT_LIMIT for d in analysis.config_diff)
    finding = analysis.findings[0]
    assert len(finding.reason) <= TEXT_LIMIT
    assert len(finding.suggested_fix or "") <= TEXT_LIMIT
    assert "외 " in finding.reason  # 이름은 8개까지만 늘어놓는다


@pytest.mark.parametrize(
    "mutate",
    [
        lambda s: s.update(schemaVersion=2),
        lambda s: s.pop("source"),
        lambda s: s["target"].pop("environmentId"),
        lambda s: s["source"].update(config=["x"]),
        lambda s: s["source"].update(variableKeys="A"),
        lambda s: s.update(findings={"controlId": "C-IMG-1"}),
    ],
)
def test_bad_snapshot_shape_is_rejected(mutate: Any) -> None:
    snapshot = _snapshot()
    mutate(snapshot)
    with pytest.raises(SnapshotError):
        analyze(snapshot)
