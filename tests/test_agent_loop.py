"""에이전트 루프·도구(가짜 클라이언트·가짜 샌드박스, 모델 호출 없음)."""

from collections.abc import AsyncIterator
from types import SimpleNamespace
from typing import Any

import pytest
from anthropic.lib.tools import ToolError

from echo_agent.agent import DEFAULT_MODEL, FALLBACK_BETA, run_agent
from echo_agent.events import RunEventLog, RunStep
from echo_agent.sandbox import ExecResult, SandboxError
from echo_agent.tools import build_workspace_tools, format_exec_result


class FakeSandbox:
    def __init__(self) -> None:
        self.commands: list[str] = []
        self.files: dict[str, str] = {"Dockerfile": "FROM python:3.13-slim\n"}

    async def exec(self, command: str, timeout_seconds: int | None = None) -> ExecResult:
        self.commands.append(command)
        return ExecResult(0, "1\n", "", False, False, 0.01)

    async def read_file(self, path: str) -> str:
        if path not in self.files:
            raise SandboxError("file not readable")
        return self.files[path]

    async def write_file(self, path: str, content: str) -> None:
        if path.startswith("/"):
            raise SandboxError("path must be relative to the workspace")
        self.files[path] = content


def message(stop_reason: str, text: str = "", tokens: int = 10) -> SimpleNamespace:
    content = [SimpleNamespace(type="text", text=text)] if text else []
    return SimpleNamespace(
        stop_reason=stop_reason,
        usage=SimpleNamespace(input_tokens=tokens, output_tokens=tokens),
        content=content,
    )


class FakeRunner:
    def __init__(self, messages: list[SimpleNamespace]) -> None:
        self._messages = messages

    def __aiter__(self) -> AsyncIterator[SimpleNamespace]:
        return self._iterate()

    async def _iterate(self) -> AsyncIterator[SimpleNamespace]:
        for item in self._messages:
            yield item


class FakeClient:
    def __init__(self, messages: list[SimpleNamespace]) -> None:
        self.kwargs: dict[str, Any] = {}
        self._messages = messages
        self.beta = SimpleNamespace(messages=SimpleNamespace(tool_runner=self._tool_runner))

    def _tool_runner(self, **kwargs: Any) -> FakeRunner:
        self.kwargs = kwargs
        return FakeRunner(self._messages)


async def test_run_agent_passes_limits_fallback_and_tools() -> None:
    client = FakeClient([message("tool_use"), message("end_turn", "report: printed 1")])
    log = RunEventLog("run-1")
    outcome = await run_agent(client, FakeSandbox(), log, "run it", max_iterations=5)  # type: ignore[arg-type]

    assert client.kwargs["model"] == DEFAULT_MODEL
    assert client.kwargs["max_iterations"] == 5
    assert client.kwargs["fallbacks"] == "default"
    assert client.kwargs["betas"] == [FALLBACK_BETA]
    assert client.kwargs["output_config"] == {"effort": "medium"}
    assert [t.name for t in client.kwargs["tools"]] == ["workspace_exec", "read_file", "write_file"]
    assert outcome.final_text == "report: printed 1"
    assert (outcome.turns, outcome.refused, outcome.input_tokens) == (2, False, 20)
    assert log.events[-1].message == "agent finished"


async def test_run_agent_treats_refusal_as_no_ai_review() -> None:
    client = FakeClient([message("refusal"), message("end_turn", "never read")])
    log = RunEventLog("run-1")
    outcome = await run_agent(client, FakeSandbox(), log, "inspect")  # type: ignore[arg-type]
    assert outcome.refused
    assert outcome.turns == 1
    assert outcome.final_text == ""
    assert any(e.message == "model declined; no AI review for this run" for e in log.events)


async def test_workspace_exec_tool_runs_in_sandbox_and_logs() -> None:
    sandbox = FakeSandbox()
    log = RunEventLog("run-1")
    exec_tool, _, _ = build_workspace_tools(sandbox, log)  # type: ignore[arg-type]
    output = await exec_tool.call({"command": "python -c 'print(1)'"})
    assert sandbox.commands == ["python -c 'print(1)'"]
    assert "exit_code: 0" in str(output)
    assert log.events[-1].step == RunStep.ANALYZE
    assert log.events[-1].data["command"] == "python -c 'print(1)'"


async def test_file_tools_turn_sandbox_errors_into_tool_errors() -> None:
    sandbox = FakeSandbox()
    log = RunEventLog("run-1")
    _, read_tool, write_tool = build_workspace_tools(sandbox, log)  # type: ignore[arg-type]
    assert "FROM python" in str(await read_tool.call({"path": "Dockerfile"}))
    with pytest.raises(ToolError):
        await read_tool.call({"path": "missing.txt"})
    with pytest.raises(ToolError):
        await write_tool.call({"path": "/etc/passwd", "content": "x"})
    await write_tool.call({"path": "Dockerfile", "content": "FROM python:3.13-slim\nUSER 1000\n"})
    assert sandbox.files["Dockerfile"].endswith("USER 1000\n")


def test_format_exec_result_marks_timeout_and_truncation() -> None:
    text = format_exec_result(ExecResult(124, "partial", "", True, True, 2.0))
    assert "timed_out: true" in text
    assert "truncated: true" in text
