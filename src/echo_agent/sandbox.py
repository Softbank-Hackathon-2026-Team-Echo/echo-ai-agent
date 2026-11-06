"""작업 공간 샌드박스: 실행 하나마다 새 Docker 컨테이너.

모델이 고른 명령은 이 컨테이너 안에서만 돈다. 컨테이너 설정(AI 에이전트 1 SPEC AD-1):

- 네트워크 없음(`--network none`) → 외부·메타데이터 서버·운영 대역에 닿지 않는다
- 루트 파일 시스템 읽기 전용, 쓸 수 있는 곳은 `/workspace`·`/tmp`(tmpfs, 크기 제한)뿐
- 비루트 사용자, 모든 리눅스 권한 제거(`--cap-drop ALL`), `no-new-privileges`
- 메모리·CPU·프로세스 수 제한, 명령마다 시간 제한
- 환경 변수·볼륨·Docker 소켓을 넘기지 않는다 → 키·토큰이 0
- 실행이 끝나면 컨테이너를 지운다(남는 볼륨 없음)

호스트 쪽은 셸을 거치지 않고 `docker` 를 인자 목록으로 부른다. 모델의 명령 문자열은 컨테이너 안
`sh -c` 에만 들어간다.
"""

import asyncio
import io
import re
import tarfile
import time
from collections.abc import Mapping
from dataclasses import dataclass
from types import TracebackType
from typing import Self

# python:3.13-slim (2026-10-28). 바꿀 때는 digest 를 함께 고친다.
WORKSPACE_IMAGE = (
    "python:3.13-slim@sha256:ae14d4ce8771606477a81446e7ef429edd6762305fc50c84507c1041fa8285d1"
)
WORKDIR = "/workspace"
SANDBOX_USER = "65532:65532"
CONTAINER_PREFIX = "echo-ws-"
SANDBOX_LABEL = "echo.sandbox=workspace"
OUTPUT_LIMIT = 16_000
# 시간 초과 때 coreutils timeout 이 돌려주는 종료 코드.
TIMEOUT_EXIT_CODE = 124

_RUN_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{0,39}$")
_HOST_GRACE_SECONDS = 10


class SandboxError(Exception):
    """샌드박스 조작 실패. 메시지에는 고정 문장과 종료 코드만 넣는다."""


@dataclass(frozen=True)
class SandboxLimits:
    memory: str = "512m"
    cpus: str = "1"
    pids: int = 128
    workspace_size: str = "256m"
    tmp_size: str = "64m"
    command_timeout_seconds: int = 60


@dataclass(frozen=True)
class ExecResult:
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool
    truncated: bool
    duration_seconds: float


class DockerSandbox:
    """`async with DockerSandbox(run_id) as sandbox:` — 나갈 때 늘 지운다."""

    def __init__(
        self,
        run_id: str,
        *,
        image: str = WORKSPACE_IMAGE,
        limits: SandboxLimits | None = None,
        docker: str = "docker",
    ) -> None:
        if not _RUN_ID_PATTERN.fullmatch(run_id):
            raise SandboxError("run id must be lowercase letters, digits, hyphens (max 40)")
        self.run_id = run_id
        self.name = f"{CONTAINER_PREFIX}{run_id}"
        self._image = image
        self._limits = limits or SandboxLimits()
        self._docker = docker
        self._created = False

    async def __aenter__(self) -> Self:
        await self.create()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.destroy()

    def run_args(self) -> list[str]:
        """`docker run` 인자. 시험이 보안 설정을 그대로 확인한다."""
        limits = self._limits
        tmpfs_options = "rw,nosuid,nodev,uid=65532,gid=65532"
        return [
            "run",
            "--detach",
            "--name",
            self.name,
            "--label",
            SANDBOX_LABEL,
            "--label",
            f"echo.run-id={self.run_id}",
            "--network",
            "none",
            "--read-only",
            "--tmpfs",
            f"{WORKDIR}:{tmpfs_options},size={limits.workspace_size},mode=0755",
            "--tmpfs",
            # 컨테이너 안의 /tmp(tmpfs)다. 호스트 임시 디렉터리를 쓰지 않는다.
            f"/tmp:{tmpfs_options},size={limits.tmp_size},mode=1777",  # noqa: S108
            "--user",
            SANDBOX_USER,
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--pids-limit",
            str(limits.pids),
            "--memory",
            limits.memory,
            "--memory-swap",
            limits.memory,
            "--cpus",
            limits.cpus,
            "--env",
            "HOME=/tmp",
            "--workdir",
            WORKDIR,
            "--entrypoint",
            "sleep",
            self._image,
            "infinity",
        ]

    async def create(self) -> None:
        code, _, _ = await self._docker_call(self.run_args(), deadline_seconds=120)
        if code != 0:
            raise SandboxError(f"sandbox create failed (exit {code})")
        self._created = True

    async def load_files(self, files: Mapping[str, bytes]) -> None:
        """파일을 `/workspace` 아래에 넣는다(tar 를 표준 입력으로 넘겨 컨테이너 안에서 푼다)."""
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w") as archive:
            for path, content in sorted(files.items()):
                info = tarfile.TarInfo(name=_safe_relative_path(path))
                info.size = len(content)
                info.mode = 0o644
                archive.addfile(info, io.BytesIO(content))
        args = ["exec", "-i", "--user", SANDBOX_USER, self.name, "tar", "-x", "-C", WORKDIR]
        code, _, _ = await self._docker_call(args, stdin=buffer.getvalue(), deadline_seconds=60)
        if code != 0:
            raise SandboxError(f"sandbox file load failed (exit {code})")

    async def exec(self, command: str, timeout_seconds: int | None = None) -> ExecResult:
        """명령 하나를 컨테이너 안 `sh -c` 로 돌린다. 출력은 앞부분 OUTPUT_LIMIT 자까지만."""
        timeout = timeout_seconds or self._limits.command_timeout_seconds
        args = [
            "exec",
            "--user",
            SANDBOX_USER,
            "--workdir",
            WORKDIR,
            self.name,
            "timeout",
            "--signal=TERM",
            "--kill-after=2",
            str(timeout),
            "sh",
            "-c",
            command,
        ]
        started = time.monotonic()
        try:
            code, stdout, stderr = await self._docker_call(
                args, deadline_seconds=timeout + _HOST_GRACE_SECONDS, limit=OUTPUT_LIMIT
            )
        except TimeoutError:
            return ExecResult(-1, "", "", True, False, time.monotonic() - started)
        out_text, out_cut = stdout
        err_text, err_cut = stderr
        return ExecResult(
            exit_code=code,
            stdout=out_text,
            stderr=err_text,
            timed_out=code == TIMEOUT_EXIT_CODE,
            truncated=out_cut or err_cut,
            duration_seconds=time.monotonic() - started,
        )

    async def read_file(self, path: str) -> str:
        relative = _safe_relative_path(path)
        result = await self.exec(f"cat -- {_sh_quote(relative)}", timeout_seconds=10)
        if result.exit_code != 0:
            raise SandboxError("file not readable")
        return result.stdout

    async def write_file(self, path: str, content: str) -> None:
        relative = _safe_relative_path(path)
        await self.load_files({relative: content.encode()})

    async def destroy(self) -> None:
        if not self._created:
            return
        code, _, _ = await self._docker_call(
            ["rm", "--force", "--volumes", self.name], deadline_seconds=60
        )
        if code != 0:
            raise SandboxError(f"sandbox delete failed (exit {code})")
        self._created = False

    async def _docker_call(
        self,
        args: list[str],
        *,
        stdin: bytes | None = None,
        deadline_seconds: float,
        limit: int = OUTPUT_LIMIT,
    ) -> tuple[int, tuple[str, bool], tuple[str, bool]]:
        process = await asyncio.create_subprocess_exec(
            self._docker,
            *args,
            stdin=asyncio.subprocess.PIPE if stdin is not None else asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            async with asyncio.timeout(deadline_seconds):
                if stdin is not None and process.stdin is not None:
                    process.stdin.write(stdin)
                    await process.stdin.drain()
                    process.stdin.close()
                assert process.stdout is not None and process.stderr is not None  # noqa: S101
                stdout, stderr = await asyncio.gather(
                    _read_limited(process.stdout, limit), _read_limited(process.stderr, limit)
                )
                code = await process.wait()
        except (TimeoutError, asyncio.CancelledError):
            if process.returncode is None:
                process.kill()
            await process.wait()
            raise
        return code, stdout, stderr


async def _read_limited(stream: asyncio.StreamReader, limit: int) -> tuple[str, bool]:
    """앞부분 limit 바이트만 남기고 나머지는 읽어서 버린다(메모리 보호)."""
    kept = bytearray()
    truncated = False
    while chunk := await stream.read(65_536):
        room = limit - len(kept)
        if room > 0:
            kept.extend(chunk[:room])
        if len(chunk) > room:
            truncated = True
    return kept.decode(errors="replace"), truncated


def _safe_relative_path(path: str) -> str:
    """`/workspace` 아래 상대 경로만 받는다(절대 경로·`..`·빈 경로 거부)."""
    if not path or path.startswith("/") or "\\" in path or "\x00" in path:
        raise SandboxError("path must be relative to the workspace")
    parts = [part for part in path.split("/") if part not in ("", ".")]
    if not parts or ".." in parts:
        raise SandboxError("path must stay inside the workspace")
    return "/".join(parts)


def _sh_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"
