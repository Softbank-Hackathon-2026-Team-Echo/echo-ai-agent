"""모델이 쓰는 도구. 모두 작업 공간 컨테이너 안에서만 동작한다.

도구는 실행 하나의 샌드박스·이벤트 기록에 묶어 만든다(`build_workspace_tools`). 도구가 실패하면
`ToolError` 로 고정 문장을 돌려준다(모델이 보고 다음 행동을 고른다). 명령 출력은 길이를 자른다.
"""

from typing import Any

from anthropic import beta_async_tool
from anthropic.lib.tools import BetaAsyncFunctionTool, ToolError

from echo_agent.events import EventLevel, RunEventLog, RunStep
from echo_agent.sandbox import DockerSandbox, ExecResult, SandboxError


def format_exec_result(result: ExecResult) -> str:
    lines = [f"exit_code: {result.exit_code}"]
    if result.timed_out:
        lines.append("timed_out: true (the command was stopped)")
    if result.truncated:
        lines.append("truncated: true (output was cut)")
    lines.append("stdout:")
    lines.append(result.stdout)
    lines.append("stderr:")
    lines.append(result.stderr)
    return "\n".join(lines)


def build_workspace_tools(
    sandbox: DockerSandbox, log: RunEventLog, step: RunStep = RunStep.ANALYZE
) -> list[BetaAsyncFunctionTool[Any]]:
    @beta_async_tool
    async def workspace_exec(command: str) -> str:
        """Run one shell command inside the isolated workspace container and return its output.

        The container has no network access and no credentials. The working directory is
        /workspace, which holds a copy of the application. Each command has a time limit.

        Args:
            command: Shell command to run with `sh -c`, for example `ls -la` or `pip list`.
        """
        result = await sandbox.exec(command)
        log.add(
            step,
            "workspace command finished",
            EventLevel.WARN if result.exit_code != 0 else EventLevel.INFO,
            command=command,
            exit_code=result.exit_code,
            timed_out=result.timed_out,
            duration_ms=round(result.duration_seconds * 1000),
        )
        return format_exec_result(result)

    @beta_async_tool
    async def read_file(path: str) -> str:
        """Read a text file from the workspace copy of the application.

        Args:
            path: Path relative to /workspace, for example `Dockerfile` or `app/main.py`.
        """
        try:
            content = await sandbox.read_file(path)
        except SandboxError as exc:
            log.add(step, "workspace file read rejected", EventLevel.WARN, path=path)
            raise ToolError(str(exc)) from exc
        log.add(step, "workspace file read", path=path, size=len(content))
        return content

    @beta_async_tool
    async def write_file(path: str, content: str) -> str:
        """Create or replace a text file in the workspace copy. Changes never leave the sandbox.

        Args:
            path: Path relative to /workspace.
            content: Full new content of the file.
        """
        try:
            await sandbox.write_file(path, content)
        except SandboxError as exc:
            log.add(step, "workspace file write rejected", EventLevel.WARN, path=path)
            raise ToolError(str(exc)) from exc
        log.add(step, "workspace file written", path=path, size=len(content))
        return f"wrote {len(content)} characters to {path}"

    return [workspace_exec, read_file, write_file]
