"""Bounded immutable source readers. Never checkout, extract or execute customer code."""

import gzip
import hashlib
import io
import os
import re
import subprocess
import tarfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

from echo_agent.precheck_model import mask_tokens, secret_candidates

MAX_FILE = 64 * 1024
MAX_TOTAL = 512 * 1024
MAX_FILES = 100
MAX_ENTRIES = 5000
MAX_ARCHIVE = 8 * 1024 * 1024
MAX_UNPACKED = 32 * 1024 * 1024
_COMMIT = re.compile(r"[0-9a-f]{40}")
_REPOSITORY = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}")
_EXCLUDED = {
    ".git",
    ".github",
    ".venv",
    "venv",
    "node_modules",
    "vendor",
    "dist",
    "build",
    "__pycache__",
    "tests",
    "test",
    "fixtures",
    "docs",
    "migrations",
    "alembic",
}


class SourceError(Exception):
    """Only a fixed code escapes; URLs, git stderr and file contents never do."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def validate_commit(commit: str) -> str:
    if not isinstance(commit, str) or not _COMMIT.fullmatch(commit):
        raise SourceError("COMMIT_REQUIRED")
    return commit


def validate_repository(repository: str) -> str:
    if not isinstance(repository, str) or not _REPOSITORY.fullmatch(repository):
        raise SourceError("REPOSITORY_INVALID")
    if any(p in {".", ".."} or p.endswith(".git") for p in repository.split("/")):
        raise SourceError("REPOSITORY_INVALID")
    return repository


def selected_path(path: str) -> bool:
    """Allowlisted Python/config text only; actual env files and keys are never read."""
    p = PurePosixPath(path)
    if (
        not path
        or len(path) > 240
        or p.is_absolute()
        or str(p) != path
        or any(part in {".", ".."} for part in p.parts)
        or any(ord(c) < 32 or ord(c) == 127 for c in path)
        or "\\" in path
        or mask_tokens(path) != path
        or secret_candidates(path)
    ):
        return False
    lowered = [part.lower() for part in p.parts]
    if any(part in _EXCLUDED or part.startswith(".") for part in lowered):
        return False
    name = lowered[-1]
    if any(x in name for x in ("credential", "secret", "private_key", "service-account")):
        return False
    if name.startswith("test_") or name.endswith("_test.py"):
        return False
    return p.suffix.lower() == ".py" or name in {"requirements.txt", "pyproject.toml", "dockerfile"}


@dataclass(frozen=True)
class SourceFile:
    path: str
    content: str = field(repr=False)


@dataclass(frozen=True)
class RepoSnapshot:
    commit: str
    files: tuple[SourceFile, ...]
    skipped: dict[str, int]
    source: str

    def manifest(self) -> dict[str, Any]:
        digest = hashlib.sha256()
        for item in self.files:
            digest.update(item.path.encode() + b"\0" + item.content.encode() + b"\0")
        return {
            "commitSha": self.commit,
            "source": self.source,
            "contentHash": f"sha256:{digest.hexdigest()}",
            "files": [item.path for item in self.files],
            "skipped": dict(self.skipped),
        }


class Collector:
    def __init__(self) -> None:
        self.files: list[SourceFile] = []
        self.skipped: dict[str, int] = {}
        self.total = 0
        self.seen: set[str] = set()

    def skip(self, reason: str) -> None:
        self.skipped[reason] = self.skipped.get(reason, 0) + 1

    def accepts(self, path: str, size: int, regular: bool) -> bool:
        if path in self.seen:
            raise SourceError("DUPLICATE_PATH")
        self.seen.add(path)
        if not regular or not selected_path(path):
            self.skip("excluded")
            return False
        if size > MAX_FILE:
            self.skip("oversized")
            return False
        if len(self.files) >= MAX_FILES or self.total + size > MAX_TOTAL:
            self.skip("budget")
            return False
        return True

    def add(self, path: str, data: bytes) -> None:
        try:
            text = data.decode("utf-8")
        except UnicodeError:
            self.skip("encoding")
            return
        if "\0" in text or any(len(line) > 4000 for line in text.splitlines()):
            self.skip("binary_or_long_line")
            return
        self.files.append(SourceFile(path, text))
        self.total += len(data)

    def finish(self, commit: str, source: str) -> RepoSnapshot:
        return RepoSnapshot(
            commit, tuple(sorted(self.files, key=lambda f: f.path)), self.skipped, source
        )


def local_snapshot(root: Path, commit: str, *, seconds: float = 30) -> RepoSnapshot:
    """Read Git blobs at an exact commit, ignoring dirty files, hooks and checkout filters."""
    validate_commit(commit)
    deadline = time.monotonic() + min(seconds, 30)
    env = {
        "PATH": os.defpath,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_NO_REPLACE_OBJECTS": "1",
    }

    def git(*args: str) -> bytes:
        left = deadline - time.monotonic()
        if left <= 0:
            raise SourceError("SOURCE_TIMEOUT")
        try:
            result = subprocess.run(  # noqa: S603 — fixed read-only git commands, never shell
                ["git", "-c", "core.fsmonitor=false", "-C", str(root), *args],  # noqa: S607
                env=env,
                capture_output=True,
                check=True,
                timeout=left,
            )
            return result.stdout
        except subprocess.TimeoutExpired as error:
            raise SourceError("SOURCE_TIMEOUT") from error
        except (OSError, subprocess.SubprocessError) as error:
            raise SourceError("SOURCE_UNAVAILABLE") from error

    if git("rev-parse", "--verify", f"{commit}^{{commit}}").decode().strip() != commit:
        raise SourceError("COMMIT_MISMATCH")
    entries = git("ls-tree", "-rlz", commit).split(b"\0")
    if len(entries) > MAX_ENTRIES + 1:
        raise SourceError("TREE_TOO_LARGE")
    collector = Collector()
    for entry in entries:
        if not entry:
            continue
        meta, raw_path = entry.split(b"\t", 1)
        mode, kind, oid, raw_size = meta.split()
        try:
            path = raw_path.decode("utf-8")
        except UnicodeError:
            collector.skip("encoding")
            continue
        regular = mode in {b"100644", b"100755"} and kind == b"blob"
        size = int(raw_size) if regular else 0
        if collector.accepts(path, size, regular):
            data = git("cat-file", "blob", oid.decode())
            if len(data) != size:
                raise SourceError("SOURCE_CHANGED")
            collector.add(path, data)
    return collector.finish(commit, "local-git")


def archive_snapshot(data: bytes, repository: str, commit: str) -> RepoSnapshot:
    """Parse memory only. Links, device entries and paths outside archive root are excluded."""
    validate_repository(repository)
    validate_commit(commit)
    if len(data) > MAX_ARCHIVE:
        raise SourceError("ARCHIVE_TOO_LARGE")
    collector = Collector()
    prefix = f"{repository.split('/')[1]}-{commit}/"
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as zipped:
            unpacked = zipped.read(MAX_UNPACKED + 1)
        if len(unpacked) > MAX_UNPACKED:
            raise SourceError("ARCHIVE_TOO_LARGE")
        with tarfile.open(fileobj=io.BytesIO(unpacked), mode="r:") as archive:
            for index, member in enumerate(archive):
                if index >= MAX_ENTRIES:
                    raise SourceError("TREE_TOO_LARGE")
                if not member.name.startswith(prefix):
                    if member.isdir() and member.name.rstrip("/") == prefix.rstrip("/"):
                        continue
                    raise SourceError("ARCHIVE_PATH_INVALID")
                if member.isdir():
                    continue
                path = member.name[len(prefix) :]
                if collector.accepts(path, member.size, member.isfile()):
                    stream = archive.extractfile(member)  # no extraction to filesystem
                    if stream is None:
                        raise SourceError("SOURCE_UNAVAILABLE")
                    collector.add(path, stream.read(MAX_FILE + 1))
    except (OSError, EOFError, tarfile.TarError) as error:
        raise SourceError("ARCHIVE_INVALID") from error
    return collector.finish(commit, "github-public-archive")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


def github_snapshot(repository: str, commit: str, *, seconds: float = 30) -> RepoSnapshot:
    """Public GitHub only. No ambient GitHub credentials, arbitrary hosts or redirects."""
    validate_repository(repository)
    validate_commit(commit)
    if seconds <= 0:
        raise SourceError("SOURCE_TIMEOUT")
    request = urllib.request.Request(  # noqa: S310 — fixed HTTPS host and validated components
        f"https://codeload.github.com/{repository}/tar.gz/{commit}",
        headers={"User-Agent": "EchoPort-repo-analysis/1"},
    )
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
        with opener.open(request, timeout=min(seconds, 30)) as response:
            deadline = time.monotonic() + min(seconds, 30)
            chunks: list[bytes] = []
            size = 0
            while size <= MAX_ARCHIVE:
                if time.monotonic() >= deadline:
                    raise SourceError("SOURCE_TIMEOUT")
                chunk = response.read(min(64 * 1024, MAX_ARCHIVE + 1 - size))
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
            data = b"".join(chunks)
    except (OSError, urllib.error.URLError) as error:
        raise SourceError("SOURCE_UNAVAILABLE") from error
    return archive_snapshot(data, repository, commit)
