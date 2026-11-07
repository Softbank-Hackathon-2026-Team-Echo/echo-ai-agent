import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from echo_agent.apply_runner import CommandResult
from echo_agent.cve_policy import validate_manifest_change, verify_target_report
from echo_agent.cve_runner import CveRunner
from echo_agent.diagnosis_model import DiagnosisModel
from echo_agent.events import RunEventLog
from echo_agent.sbom import attach_sbom, collect_sbom, validate_sbom
from echo_agent.was_client import ClaimedRun

NOW = datetime(2026, 11, 7, tzinfo=UTC)
MANIFEST = (
    '[project]\nname="demo"\nversion="0.1"\ndependencies=["urllib3==1.26.0", "requests==2.25.0"]\n'
)
LOCK = 'version = 1\n[[package]]\nname="urllib3"\nversion="1.26.0"\nsource={registry="https://pypi.org/simple"}\n'
SBOM = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "components": [{"purl": "pkg:pypi/urllib3@1.26.0"}],
}


@pytest.fixture
def run(monkeypatch):
    monkeypatch.setenv("ECHO_CVE_REMEDIATION", "on")
    monkeypatch.setenv("ECHO_CUSTOMER_IMAGE_PREFIXES", "asia-northeast3-docker.pkg.dev/team/echo")
    snapshot = {
        "schemaVersion": 1,
        "trigger": "CVE_WATCH",
        "sourceCommitSha": "a" * 40,
        "service": {"repo": "team/demo"},
        "imageDigest": "sha256:" + "a" * 64,
        "finding": {
            "advisoryId": "CVE-2023-43804",
            "aliases": ["GHSA-v845-jxx5-vc9f"],
            "synthetic": False,
        },
        "remediation": {
            "ecosystem": "PyPI",
            "package": "urllib3",
            "fromVersion": "1.26.0",
            "toVersion": "2.2.0",
        },
        "packages": [{"ecosystem": "PyPI", "name": "urllib3", "version": "1.26.0"}],
    }
    snapshot["imageRef"] = (
        "asia-northeast3-docker.pkg.dev/team/echo/demo@" + snapshot["imageDigest"]
    )
    snapshot["source"] = {"imageRef": snapshot["imageRef"], "imageDigest": snapshot["imageDigest"]}
    return ClaimedRun(
        "run",
        "CHANGE_PROPOSAL",
        None,
        None,
        None,
        None,
        snapshot,
        None,
        None,
        NOW + timedelta(minutes=15),
        None,
        "echo_run_test",
    )


def fetch(repo, commit, dest, timeout):
    dest.mkdir()
    (dest / "pyproject.toml").write_text(MANIFEST)
    (dest / "uv.lock").write_text(LOCK)
    return dest


class Verifier:
    def __init__(self, fail=False):
        self.calls = []
        self.fail = fail

    def execute(self, run, events, flush):
        self.calls.append(run)
        return (
            ("FAILED", "IMAGE_BUILD_FAILED", None, None)
            if self.fail
            else ("SUCCEEDED", None, "b" * 40, "applied/run")
        )


def resolver(args, timeout, env):
    assert "--no-build" in args and "--no-sources" in args
    path = Path(args[args.index("--project") + 1]) / "uv.lock"
    path.write_text(LOCK.replace("1.26.0", "2.2.0"))
    return CommandResult(0, "", "")


def test_first_rule_success(run):
    verifier = Verifier()
    result = CveRunner(command=resolver, fetch=fetch, verifier=verifier, clock=lambda: NOW).execute(
        run, RunEventLog(run.id), lambda: None
    )
    assert result["patches"][0]["origin"] == "RULE"
    assert set(result["patches"][0]["files"]) == {"pyproject.toml", "uv.lock"}
    assert len(verifier.calls) == 1
    assert "기능 호환성 검증 미실시" in result["patches"][0]["reason"]


@pytest.mark.parametrize("second_success", [True, False])
def test_one_model_correction_only(run, second_success):
    calls = []
    model_calls = []

    async def send(**kwargs):
        model_calls.append(kwargs)

        class Response:
            stop_reason = "end_turn"
            model = "claude-opus-4-1-20250805"

            class Block:
                type = "text"
                text = json.dumps(
                    {
                        "edits": [{"old": "requests==2.25.0", "new": "requests==2.32.4"}],
                        "reason": "충돌 해소",
                    }
                )

            content = [Block()]

        return Response()

    def command(args, timeout, env):
        calls.append(args)
        if len(calls) == 1 or not second_success:
            return CommandResult(1, "", "requests==2.25.0 conflicts with urllib3==2.2.0")
        return resolver(args, timeout, env)

    result = CveRunner(
        DiagnosisModel(send), command=command, fetch=fetch, verifier=Verifier(), clock=lambda: NOW
    ).execute(run, RunEventLog(run.id), lambda: None)
    assert len(calls) == 2 and len(model_calls) == 1
    assert bool(result["patches"]) == second_success
    if second_success:
        assert result["patches"][0]["origin"] == "AI"
    else:
        assert result["diagnosis"]["unfixableReason"]
    assert result["processing"]["externalTransfer"] is True


@pytest.mark.parametrize(
    "field,value", [("ecosystem", "npm"), ("toVersion", "1.0.0"), ("fromVersion", "1.25.0")]
)
def test_unfixable_has_no_patch(run, field, value):
    run.input_snapshot["remediation"][field] = value
    verifier = Verifier()
    result = CveRunner(fetch=fetch, command=resolver, verifier=verifier, clock=lambda: NOW).execute(
        run, RunEventLog(run.id), lambda: None
    )
    assert not result["patches"] and not verifier.calls
    assert result["diagnosis"]["fixable"] is False


def test_deadline_stops_without_patch(run):
    result = CveRunner(fetch=fetch, command=resolver, clock=lambda: run.deadline_at).execute(
        run, RunEventLog(run.id), lambda: None
    )
    assert result["failureCode"] == "DEADLINE" and not result["patches"]


def test_protected_manifest_and_target_removal():
    with pytest.raises(ValueError):
        validate_manifest_change(
            MANIFEST, MANIFEST + '[tool.uv]\nindex-url="https://evil.example"\n', {"urllib3"}
        )
    with pytest.raises(ValueError):
        validate_manifest_change(MANIFEST, MANIFEST.replace('"urllib3==1.26.0", ', ""), {"urllib3"})


def test_advisory_alias_and_complete_inventory(run):
    with pytest.raises(ValueError, match="INSTALLED_VERSION_MISMATCH"):
        verify_target_report({"Results": [{"Vulnerabilities": []}]}, run.input_snapshot)
    with pytest.raises(ValueError, match="TARGET_ADVISORY_REMAINS"):
        verify_target_report(
            {
                "Results": [
                    {
                        "Packages": [{"Name": "urllib3", "Version": "2.2.0"}],
                        "Vulnerabilities": [
                            {"VulnerabilityID": "GHSA-v845-jxx5-vc9f", "PkgName": "urllib3"}
                        ],
                    }
                ]
            },
            run.input_snapshot,
        )


def test_sbom_collection_and_full_result_budget(run):
    def scan(args, timeout, env):
        Path(args[args.index("--output") + 1]).write_text(json.dumps(SBOM))
        assert args[-1] == run.input_snapshot["imageRef"]
        return CommandResult(0, "", "")

    events = RunEventLog(run.id)
    value = collect_sbom(run, events, command=scan, clock=lambda: NOW)
    assert value == SBOM
    result = {"padding": "x" * 1024 * 1024}
    attach_sbom(result, value, events)
    assert "sbom" not in result
    assert events.events[-1].data["reason"] == "RESULT_TOO_LARGE"


@pytest.mark.parametrize(
    "sbom", [{}, {**SBOM, "components": [{}]}, {**SBOM, "padding": "a" * 512 * 1024}]
)
def test_invalid_or_oversized_sbom_is_not_partial(sbom):
    with pytest.raises(ValueError):
        validate_sbom(sbom)


@pytest.mark.parametrize("fault", [None, "hash", "protected", "baseline", "installed"])
def test_apply_rechecks_cve_constraints(run, tmp_path, fault):
    from dataclasses import replace

    from echo_agent.apply_runner import ApplyRunner
    from tests.test_diagnosis_runner import FakeTools

    proposal = CveRunner(
        command=resolver, fetch=fetch, verifier=Verifier(), clock=lambda: NOW
    ).execute(run, RunEventLog(run.id), lambda: None)["patches"][0]
    if fault == "hash":
        proposal["patchHash"] = "0" * 64
    if fault == "protected":
        proposal["files"] = ["Dockerfile"]
    snapshot = {
        **run.input_snapshot,
        "patch": proposal,
        "parentRunId": "a" * 32,
        "repo": "team/demo",
        "branch": f"applied/{run.id}",
        "diagnosis": {"sourceCommitSha": "a" * 40},
    }
    apply_run = replace(run, kind="APPLY_PATCH", input_snapshot=snapshot)
    fake = FakeTools()

    def command(args, timeout, env):
        if args[0:2] == ["trivy", "image"]:
            baseline = "@sha256:" in args[-1]
            vulnerabilities = (
                [{"VulnerabilityID": "CVE-2023-43804", "PkgName": "urllib3"}]
                if baseline and fault != "baseline"
                else []
            )
            report = {
                "Results": [
                    {
                        "Packages": [{"Name": "urllib3", "Version": "2.2.0"}],
                        "Vulnerabilities": vulnerabilities,
                    }
                ]
            }
            return CommandResult(0, json.dumps(report), "")
        if args[:2] == ["docker", "run"] and "--entrypoint" in args and fault == "installed":
            return CommandResult(1, "", "")
        return fake(args, timeout, env)

    def source(repo, sha, dest, timeout):
        root = fetch(repo, sha, dest, timeout)
        (root / "Dockerfile").write_text("FROM python:3.13-slim\n")
        return root

    verifier = ApplyRunner(
        fetch_source=source, run_command=command, clock=lambda: NOW, workspace_parent=tmp_path
    )
    status, failure, commit, _ = verifier.execute(apply_run, RunEventLog(run.id), lambda: None)
    assert (status == "SUCCEEDED") == (fault is None), failure
    if fault is not None:
        assert commit is None
    assert not any("push" in call for call in fake.calls)


def test_pypi_content_hash_is_not_a_secret_but_credentials_still_are():
    from echo_agent.cve_policy import dependency_diff_is_safe

    path = (
        "https://files.pythonhosted.org/packages/aa/bb/"
        + "abc123ef" * 7
        + "abcd"
        + "/demo-1.0-py3-none-any.whl"
    )
    diff = '+++ b/uv.lock\n+url = "' + path + '"\n'
    assert dependency_diff_is_safe(diff)
    assert not dependency_diff_is_safe(diff + '+token = "sensitive"\n')
    assert not dependency_diff_is_safe(diff.replace("demo-1.0-py3-none-any.whl", "ghp_" + "x" * 30))
    assert not dependency_diff_is_safe(diff.replace("b/uv.lock", "b/pyproject.toml"))


def test_sbom_preserves_non_package_os_metadata():
    value = {
        **SBOM,
        "components": [
            *SBOM["components"],
            {"type": "operating-system", "name": "debian", "version": "13"},
        ],
    }
    assert validate_sbom(value) == value
    with pytest.raises(ValueError, match="SBOM_PURL_REQUIRED"):
        validate_sbom({**SBOM, "components": [{"type": "library", "name": "urllib3"}]})
