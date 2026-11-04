"""실제 Docker 샌드박스 격리(AI 에이전트 1 SPEC §7·§9 확인 방법). Docker 가 없으면 건너뛴다."""

import asyncio
import os
import secrets
from collections.abc import AsyncIterator

import pytest

from echo_agent.poc import ISOLATION_CHECKS, _leftover_containers, _passed
from echo_agent.sandbox import DockerSandbox, SandboxError, SandboxLimits

pytestmark = pytest.mark.docker


@pytest.fixture
async def sandbox() -> AsyncIterator[DockerSandbox]:
    async with DockerSandbox(f"test-{secrets.token_hex(4)}") as created:
        yield created


async def test_command_runs_inside_workspace(sandbox: DockerSandbox) -> None:
    result = await sandbox.exec("python -c 'print(1)' && pwd")
    assert result.exit_code == 0
    assert result.stdout.split() == ["1", "/workspace"]


@pytest.mark.parametrize("check", ISOLATION_CHECKS, ids=lambda c: c.name)
async def test_isolation_check_holds(sandbox: DockerSandbox, check: object) -> None:
    outcome = await sandbox.exec(check.command, timeout_seconds=15)  # type: ignore[attr-defined]
    assert _passed(check, outcome.exit_code, outcome.stdout)  # type: ignore[arg-type]


async def test_host_secrets_never_reach_the_workspace(monkeypatch: pytest.MonkeyPatch) -> None:
    canary = f"canary-{secrets.token_hex(8)}"
    monkeypatch.setenv("ANTHROPIC_API_KEY", canary)
    monkeypatch.setenv("ECHO_RUNNER_TOKEN", canary)
    async with DockerSandbox(f"test-{secrets.token_hex(4)}") as created:
        result = await created.exec(
            f"env; grep -rs {canary} /proc/1/environ /workspace /tmp; echo done"
        )
    assert canary not in result.stdout
    assert os.environ["ANTHROPIC_API_KEY"] == canary


async def test_files_load_and_read_back(sandbox: DockerSandbox) -> None:
    await sandbox.load_files({"app/main.py": b"print('hi')\n", "Dockerfile": b"FROM x\n"})
    assert await sandbox.read_file("app/main.py") == "print('hi')\n"
    await sandbox.write_file("Dockerfile", "FROM y\n")
    assert await sandbox.read_file("Dockerfile") == "FROM y\n"
    with pytest.raises(SandboxError):
        await sandbox.read_file("../etc/passwd")


async def test_command_is_stopped_at_time_limit(sandbox: DockerSandbox) -> None:
    result = await sandbox.exec("sleep 30", timeout_seconds=2)
    assert result.timed_out
    assert result.duration_seconds < 15


async def test_large_output_is_truncated(sandbox: DockerSandbox) -> None:
    result = await sandbox.exec("head -c 200000 /dev/zero | tr '\\0' 'a'")
    assert result.truncated
    assert len(result.stdout) <= 16_000


async def test_workspace_size_is_limited() -> None:
    limits = SandboxLimits(workspace_size="8m")
    async with DockerSandbox(f"test-{secrets.token_hex(4)}", limits=limits) as created:
        result = await created.exec("head -c 20000000 /dev/zero > big.bin")
    assert result.exit_code != 0


async def test_process_count_is_limited() -> None:
    limits = SandboxLimits(pids=16)
    async with DockerSandbox(f"test-{secrets.token_hex(4)}", limits=limits) as created:
        result = await created.exec("for i in $(seq 1 40); do sleep 5 & done; wait", 20)
    assert result.exit_code != 0 or "fork" in result.stderr.lower()


async def test_sandbox_is_removed_after_run() -> None:
    run_id = f"test-{secrets.token_hex(4)}"
    async with DockerSandbox(run_id) as created:
        await created.exec("true")
        assert await _leftover_containers(run_id) == 1
    assert await _leftover_containers(run_id) == 0


async def test_sandbox_is_removed_even_when_the_run_fails() -> None:
    run_id = f"test-{secrets.token_hex(4)}"
    with pytest.raises(RuntimeError):
        async with DockerSandbox(run_id):
            raise RuntimeError("agent crashed")
    await asyncio.sleep(0)
    assert await _leftover_containers(run_id) == 0
