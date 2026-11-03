"""샌드박스 설정·경로·출력 자르기(Docker 없이)."""

import asyncio

import pytest

from echo_agent.events import DATA_TEXT_LIMIT, EventLevel, RunEventLog, RunStep
from echo_agent.sandbox import (
    WORKSPACE_IMAGE,
    DockerSandbox,
    SandboxError,
    _read_limited,
    _safe_relative_path,
)


def test_run_args_apply_every_isolation_setting() -> None:
    args = DockerSandbox("run-1").run_args()
    joined = " ".join(args)
    for flag in (
        "--network none",
        "--read-only",
        "--user 65532:65532",
        "--cap-drop ALL",
        "--security-opt no-new-privileges",
        "--pids-limit 128",
        "--memory 512m",
        "--memory-swap 512m",
        "--cpus 1",
    ):
        assert flag in joined
    assert "--privileged" not in args
    assert not any(a.startswith(("-v", "--volume", "--mount", "--env-file")) for a in args)
    assert "/var/run/docker.sock" not in joined
    # 넘기는 환경 변수는 HOME 하나뿐이다.
    env_values = [args[i + 1] for i, a in enumerate(args) if a == "--env"]
    assert env_values == ["HOME=/tmp"]
    assert args[-2:] == [WORKSPACE_IMAGE, "infinity"]
    assert "@sha256:" in WORKSPACE_IMAGE


@pytest.mark.parametrize("run_id", ["", "Run-1", "a" * 41, "run_1", "run 1", "../x"])
def test_run_id_must_be_lowercase_slug(run_id: str) -> None:
    with pytest.raises(SandboxError):
        DockerSandbox(run_id)


@pytest.mark.parametrize(
    ("path", "expected"),
    [("Dockerfile", "Dockerfile"), ("./app/main.py", "app/main.py"), ("a//b", "a/b")],
)
def test_safe_relative_path_normalizes(path: str, expected: str) -> None:
    assert _safe_relative_path(path) == expected


@pytest.mark.parametrize("path", ["", "/etc/passwd", "../x", "a/../../x", ".", "a\\b", "a\x00b"])
def test_safe_relative_path_rejects_escape(path: str) -> None:
    with pytest.raises(SandboxError):
        _safe_relative_path(path)


async def test_read_limited_keeps_head_and_reports_truncation() -> None:
    reader = asyncio.StreamReader()
    reader.feed_data(b"x" * 100)
    reader.feed_eof()
    text, truncated = await _read_limited(reader, 10)
    assert (text, truncated) == ("x" * 10, True)


async def test_read_limited_short_output_is_not_truncated() -> None:
    reader = asyncio.StreamReader()
    reader.feed_data(b"ok")
    reader.feed_eof()
    assert await _read_limited(reader, 10) == ("ok", False)


def test_event_log_numbers_events_and_clips_long_text() -> None:
    log = RunEventLog("run-1")
    log.add(RunStep.SANDBOX_CREATE, "sandbox created")
    event = log.add(RunStep.ANALYZE, "workspace command finished", EventLevel.WARN, out="y" * 5000)
    assert [e.seq for e in log.events] == [1, 2]
    assert len(event.data["out"]) < 5000
    assert event.data["out"].startswith("y" * DATA_TEXT_LIMIT)
    payload = event.to_json()
    assert payload["step"] == "ANALYZE"
    assert payload["level"] == "WARN"
    assert payload["at"].endswith("Z")
