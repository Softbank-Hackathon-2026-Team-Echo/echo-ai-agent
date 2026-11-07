"""Fixed, parse-only JS/Python checks in the existing isolated Docker workspace."""

import asyncio
import json
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from html.parser import HTMLParser
from importlib.resources import files
from typing import Any

from echo_agent.diagnosis_input import (
    ALLOWED_FILE,
    PYTHON_FILE,
    REPAIR_FILES,
    DiagnosisError,
    redact,
)
from echo_agent.sandbox import WORKSPACE_IMAGE, DockerSandbox, SandboxError

# Official multi-architecture Node 24 bookworm-slim, resolved 2026-11-07.
NODE_IMAGE = (
    "node:24-bookworm-slim@sha256:01d566e8d94d8c619591d78652babfccd3c6992a3dffa9ed5ab39e11cf6c70e9"
)


@dataclass(frozen=True)
class Script:
    start: int
    end: int
    line_offset: int
    code: str


class _Scripts(HTMLParser):
    def __init__(self, source: str) -> None:
        super().__init__(convert_charrefs=False)
        self.source = source
        self.parts = source.splitlines(keepends=True)
        self.start: int | None = None
        self.scripts: list[Script] = []

    def source_offset(self) -> int:
        line, column = self.getpos()
        return sum(len(part) for part in self.parts[: line - 1]) + column

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag != "script":
            return
        values = dict(attrs)
        if (
            self.start is not None
            or "src" in values
            or values.get("type", "") not in {"", "text/javascript", "application/javascript"}
        ):
            raise DiagnosisError("CHECK_UNSUPPORTED")
        self.start = self.source_offset() + len(self.get_starttag_text() or "")

    def handle_endtag(self, tag: str) -> None:
        if tag != "script":
            return
        if self.start is None:
            raise DiagnosisError("CHECK_UNSUPPORTED")
        end = self.source_offset()
        self.scripts.append(
            Script(
                self.start,
                end,
                self.source[: self.start].count("\n"),
                self.source[self.start : end],
            )
        )
        self.start = None


def extract_scripts(source: str) -> list[Script]:
    parser = _Scripts(source)
    parser.feed(source)
    parser.close()
    if parser.start is not None or not parser.scripts or len(parser.scripts) > 10:
        raise DiagnosisError("CHECK_UNSUPPORTED")
    return parser.scripts


def check_payload(source: str) -> str:
    return json.dumps(
        {
            "scripts": [
                {"path": ALLOWED_FILE, "code": s.code, "lineOffset": s.line_offset}
                for s in extract_scripts(source)
            ]
        }
    )


@dataclass(frozen=True)
class CheckResult:
    available: bool
    passed: bool
    version: str | None
    issues: tuple[dict[str, Any], ...] = ()
    reason: str | None = None

    def to_json(self) -> dict[str, Any]:
        return {
            "available": self.available,
            "passed": self.passed,
            "toolVersion": self.version,
            "issues": list(self.issues),
            "reason": self.reason,
        }


def parse_check(code: int, output: str, path: str = ALLOWED_FILE) -> CheckResult:
    try:
        raw = json.loads(output)
        version, issues = raw["version"], raw["issues"]
        if (
            path not in REPAIR_FILES
            or not isinstance(version, str)
            or not version.startswith("Python 3.13." if path == PYTHON_FILE else "v")
            or not isinstance(issues, list)
            or len(issues) > 10
        ):
            raise ValueError
        cleaned = []
        for issue in issues:
            if (
                issue["path"] != path
                or type(issue["line"]) is not int
                or issue["line"] < 1
                or not isinstance(issue["message"], str)
            ):
                raise ValueError
            cleaned.append(
                {
                    "path": path,
                    "line": issue["line"],
                    "message": redact(issue["message"])[:300],
                }
            )
        if code not in {0, 1} or (code == 0) != (len(issues) == 0):
            raise ValueError
        return CheckResult(True, code == 0, version, tuple(cleaned))
    except (ValueError, KeyError, TypeError):
        return CheckResult(False, False, None, reason="CHECK_INVALID_OUTPUT")


class SyntaxSandbox(DockerSandbox):
    """The pinned tool image must be pre-pulled; a diagnosis never downloads tools."""

    def run_args(self) -> list[str]:
        args = super().run_args()
        return [args[0], "--pull", "never", *args[1:]]


class DockerSyntaxChecker:
    def __init__(
        self, factory: Callable[..., DockerSandbox] = SyntaxSandbox, *, path: str = ALLOWED_FILE
    ) -> None:
        if path not in REPAIR_FILES:
            raise DiagnosisError("PATCH_TARGET_FORBIDDEN")
        self.factory = factory
        self.path = path

    async def _inspect(self, payload: str) -> CheckResult:
        python = self.path == PYTHON_FILE
        sandbox = self.factory(
            f"syntax-{secrets.token_hex(6)}", image=WORKSPACE_IMAGE if python else NODE_IMAGE
        )
        creation = asyncio.create_task(sandbox.create())
        try:
            try:
                # Drain creation before cleanup if cancelled mid-start.
                await asyncio.shield(creation)
            except asyncio.CancelledError:
                await creation
                raise
            script = "diagnosis_python_check.py" if python else "diagnosis_check.cjs"
            command = f"python -I {script} input.json" if python else f"node {script} input.json"
            await sandbox.load_files(
                {
                    script: files("echo_agent").joinpath(script).read_bytes(),
                    "input.json": payload.encode(),
                }
            )
            result = await sandbox.exec(command, timeout_seconds=15)
            if result.timed_out or result.truncated:
                return CheckResult(False, False, None, reason="CHECK_TIMEOUT")
            return parse_check(result.exit_code, result.stdout, self.path)
        finally:
            await sandbox.destroy()

    async def check(self, source: str, seconds: float) -> CheckResult:
        try:
            payload = (
                json.dumps({"path": self.path, "code": source})
                if self.path == PYTHON_FILE
                else check_payload(source)
            )
            async with asyncio.timeout(seconds):
                return await self._inspect(payload)
        except DiagnosisError as error:
            return CheckResult(False, False, None, reason=error.code)
        except (TimeoutError, SandboxError, OSError):
            return CheckResult(False, False, None, reason="CHECK_UNAVAILABLE")
