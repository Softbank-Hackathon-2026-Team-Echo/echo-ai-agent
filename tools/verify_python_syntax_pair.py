"""Re-use the pinned Docker parser on two immutable demo commits; no model calls."""

import argparse
import asyncio
import difflib
import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path

from echo_agent.diagnosis_check import DockerSyntaxChecker
from echo_agent.diagnosis_input import PYTHON_FILE


def read_sources(repo: Path, before_sha: str, after_sha: str) -> list[str]:
    if not all(re.fullmatch(r"[a-f0-9]{40}", sha) for sha in (before_sha, after_sha)):
        raise ValueError("full commit SHA required")
    git = shutil.which("git")
    if git is None:
        raise RuntimeError("git is required")
    return [
        subprocess.run(  # noqa: S603 -- fixed command, validated immutable revision
            [git, "-C", str(repo), "show", f"{sha}:{PYTHON_FILE}"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        for sha in (before_sha, after_sha)
    ]


async def verify(repo: Path, before_sha: str, after_sha: str) -> dict[str, object]:
    sources = await asyncio.to_thread(read_sources, repo, before_sha, after_sha)
    checker = DockerSyntaxChecker(path=PYTHON_FILE)
    before = await checker.check(sources[0], 30)
    after = await checker.check(sources[1], 30)
    diff = "".join(
        difflib.unified_diff(
            sources[0].splitlines(keepends=True),
            sources[1].splitlines(keepends=True),
            fromfile=f"a/{PYTHON_FILE}",
            tofile=f"b/{PYTHON_FILE}",
        )
    )
    expected = {"path": PYTHON_FILE, "line": 213, "message": "'(' was never closed"}
    ok = (
        before.available
        and not before.passed
        and expected in before.to_json()["issues"]
        and after.available
        and after.passed
        and before.to_json()["toolVersion"] == after.to_json()["toolVersion"]
    )
    return {
        "ok": ok,
        "sourceCommitSha": before_sha,
        "fixedCommitSha": after_sha,
        "path": PYTHON_FILE,
        "expectedFailure": expected,
        "before": before.to_json(),
        "after": after.to_json(),
        "sourceSha256": [hashlib.sha256(source.encode()).hexdigest() for source in sources],
        "unifiedDiffSha256": hashlib.sha256(diff.encode()).hexdigest(),
        "scope": "same pinned parser; syntax only; no new model/build/deployment execution",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repo", type=Path)
    parser.add_argument("before")
    parser.add_argument("after")
    args = parser.parse_args()
    result = asyncio.run(verify(args.repo, args.before, args.after))
    print(json.dumps(result, ensure_ascii=False))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
