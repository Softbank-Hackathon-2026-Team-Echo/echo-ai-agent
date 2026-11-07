"""The repeatable demo must distinguish replay from live calls and preserve source."""

import json
from pathlib import Path

import pytest

from echo_agent.diagnosis_demo import BASELINE, main, run_demo
from echo_agent.diagnosis_input import DiagnosisError
from echo_agent.diagnosis_model import DiagnosisModel


@pytest.mark.docker
async def test_demo_replay_uses_real_docker_without_calling_model_api(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def forbidden() -> None:
        pytest.fail("Offline replay must not initialize API credentials")

    monkeypatch.setattr(DiagnosisModel, "from_env", forbidden)
    out = tmp_path / "artifacts"
    summary = await run_demo(BASELINE, out, live=False, location="local/test")
    assert summary["passed"] and summary["realModelCalls"] == 0
    assert summary["mode"] == "replay" and summary["fixedEqualsBaseline"]
    assert not summary["ourContainersRemaining"]
    result = json.loads((out / "result.json").read_text())
    assert result["model"] is None and "processing" not in result
    assert result["diagnosis"]["verification"]["before"]["passed"] is False
    assert result["diagnosis"]["verification"]["after"]["passed"] is True
    wire = json.loads((out / "was-result.json").read_text())
    assert wire["diagnosis"]["result"] == "DIAGNOSED"
    assert wire["diagnosis"]["category"] == "CODE" and wire["diagnosis"]["fixable"]
    assert wire["patches"] == result["patches"]
    assert "verification" not in wire["diagnosis"]
    assert (out / "fixed.html").read_text() == BASELINE
    assert (out.stat().st_mode & 0o777) == 0o700
    for container in json.loads((out / "sandbox-observations.json").read_text()):
        assert container["networkMode"] == "none" and container["readOnlyRoot"]
        assert "ANTHROPIC_API_KEY" not in container["environmentKeys"]
        assert not container["bindMounts"]


async def test_demo_refuses_overwriting_previous_artifacts(tmp_path: Path) -> None:
    (tmp_path / "keep").write_text("untouched")
    with pytest.raises(FileExistsError):
        await run_demo(BASELINE, tmp_path, live=False, location="local/test")
    assert (tmp_path / "keep").read_text() == "untouched"


@pytest.mark.parametrize(
    "source", ["<script>unsupported</script>", BASELINE + "\npassword=private"]
)
async def test_demo_rejects_unsupported_or_sensitive_source_before_creating_artifacts(
    tmp_path: Path, source: str
) -> None:
    out = tmp_path / "new"
    with pytest.raises(DiagnosisError):
        await run_demo(source, out, live=False, location="local/test")
    assert not out.exists()


def test_live_demo_without_key_preserves_source_and_reports_config_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    source = tmp_path / "source.html"
    source.write_text(BASELINE)
    out = tmp_path / "new"
    assert main(["--source", str(source), "--output-dir", str(out), "--live"]) == 2
    assert source.read_text() == BASELINE and not out.exists()
    assert "DEMO_INPUT_OR_CONFIG_ERROR" in capsys.readouterr().out
