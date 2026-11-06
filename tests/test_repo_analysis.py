"""Immutable reading, risk evidence, redaction, limits and no-execution regressions."""

import gzip
import io
import json
import subprocess
import tarfile
from pathlib import Path
from typing import Any

import pytest

from echo_agent.repo_analysis import analyze, redact_source, to_findings
from echo_agent.repo_source import (
    MAX_FILE,
    RepoSnapshot,
    SourceError,
    SourceFile,
    archive_snapshot,
    github_snapshot,
    local_snapshot,
    selected_path,
)

COMMIT = "1" * 40
SAMPLE = """import boto3
import sqlite3
REGION = "ap-northeast-1"
API_TOKEN = "demo-value-never-a-real-credential"
db = sqlite3.connect("state.db")
with open("cache.json", "w") as stream:
    stream.write("hello")
"""


def snapshot(source: str = SAMPLE) -> RepoSnapshot:
    return RepoSnapshot(COMMIT, (SourceFile("app/main.py", source),), {}, "test-fixture")


def report(source: str = SAMPLE) -> dict[str, Any]:
    return analyze(snapshot(source), "aws", "gcp")


def commit_files(root: Path, files: dict[str, str]) -> str:
    for name, content in files.items():
        file = root / name
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text(content)
    subprocess.run(["/usr/bin/git", "init", "-q", str(root)], check=True)  # noqa: S603, S607
    subprocess.run(["/usr/bin/git", "-C", str(root), "add", "."], check=True)  # noqa: S603, S607
    subprocess.run(  # noqa: S603
        [
            "/usr/bin/git",  # noqa: S607
            "-C",
            str(root),
            "-c",
            "user.name=Fixture",
            "-c",  # noqa: S607
            "user.email=fixture@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "core.hooksPath=/dev/null",
            "commit",
            "-qm",
            "fixture",
        ],
        check=True,
    )
    return subprocess.check_output(  # noqa: S603
        ["/usr/bin/git", "-C", str(root), "rev-parse", "HEAD"],  # noqa: S607
        text=True,  # noqa: S607
    ).strip()


def archive(files: dict[str, bytes], *, extra_link: bool = False) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:") as tar:
        for name, data in files.items():
            info = tarfile.TarInfo(f"demo-{COMMIT}/{name}")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        if extra_link:
            info = tarfile.TarInfo(f"demo-{COMMIT}/leak.py")
            info.type = tarfile.SYMTYPE
            info.linkname = "/etc/passwd"
            tar.addfile(info)
    return gzip.compress(buffer.getvalue())


def test_four_categories_have_real_source_lines_and_no_raw_secrets() -> None:
    result = report()
    observations = result["observations"]
    assert {item["category"] for item in observations} == {
        "REGION",
        "CLOUD_SDK",
        "SECRET",
        "LOCAL_STATE",
    }
    assert {item["location"]["line"] for item in observations} == {1, 3, 4, 5, 6}
    assert all(item["certainty"] == "OBSERVED" for item in observations)
    assert not result["codeExecuted"] and not result["patches"]
    serialized = json.dumps({**result, "findings": to_findings(result, "environment")})
    assert "demo-value-never-a-real-credential" not in serialized
    assert all(f["origin"] == "RULE" and f["result"] == "WARN" for f in to_findings(result, "env"))
    assert "app/main.py:3" in serialized


def test_comments_env_reads_readonly_files_and_similar_package_do_not_become_risks() -> None:
    source = """import os
import boto3_fake
# region ap-northeast-1 and open("x", "w") are just comments
API_TOKEN = os.getenv("API_TOKEN")
PASSWORD = "${PASSWORD}"
with open("config.json", "r") as file:
    pass
"""
    assert report(source)["observations"] == []


def test_cloud_import_aliases_and_sqlite_alias_are_observed() -> None:
    source = 'from google.cloud import storage\nfrom sqlite3 import connect as db\ndb(":memory:")\n'
    assert {o["category"] for o in report(source)["observations"]} == {"CLOUD_SDK", "LOCAL_STATE"}


@pytest.mark.parametrize(
    "path",
    [
        ".env",
        ".env.example",
        "secrets.py",
        "app/credentials.json",
        "private_key.py",
        "id_rsa",
        "key.pem",
        "../app.py",
        "/app.py",
        "a/../app.py",
        "a//app.py",
        "a\\b.py",
        "node_modules/a.py",
        "tests/test_app.py",
        "app.py\n",
        "docs/example.py",
    ],
)
def test_sensitive_and_unsupported_paths_are_not_selected(path: str) -> None:
    assert not selected_path(path)


def test_fixed_git_commit_ignores_dirty_worktree_and_does_not_execute(tmp_path: Path) -> None:
    marker = tmp_path / "executed"
    source = SAMPLE + f'__import__("pathlib").Path({str(marker)!r}).touch()\n'
    sha = commit_files(
        tmp_path,
        {"app/main.py": source, ".env": "password=private", "credentials.py": "SECRET='private'"},
    )
    (tmp_path / "app/main.py").write_text("raise RuntimeError('dirty worktree')")
    result = local_snapshot(tmp_path, sha)
    assert result.files[0].content == source and len(result.files) == 1
    assert not marker.exists()
    assert analyze(result, "aws", "gcp")["observations"]
    assert not marker.exists()
    assert "private" not in repr(result)
    with pytest.raises(SourceError, match="COMMIT_REQUIRED"):
        local_snapshot(tmp_path, "HEAD")


def test_archive_excludes_links_traversal_secrets_oversize_and_never_extracts(
    tmp_path: Path,
) -> None:
    data = archive(
        {
            "app.py": SAMPLE.encode(),
            ".env": b"password=private",
            "../outside.py": b"bad",
            "huge.py": b"x" * (MAX_FILE + 1),
            "binary.py": b"\0secret",
        },
        extra_link=True,
    )
    result = archive_snapshot(data, "team/demo", COMMIT)
    assert [item.path for item in result.files] == ["app.py"]
    assert result.skipped["excluded"] == 3
    assert result.skipped["oversized"] == 1
    assert result.skipped["binary_or_long_line"] == 1
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize(
    "repo,commit",
    [
        ("https://evil.invalid/demo", COMMIT),
        ("a/../b", COMMIT),
        ("a/b?token=x", COMMIT),
        ("a/b", "main"),
        ("a/b.git", COMMIT),
    ],
)
def test_remote_coordinates_are_rejected_before_network(repo: str, commit: str) -> None:
    with pytest.raises(SourceError):
        github_snapshot(repo, commit)


def test_wrong_archive_root_and_invalid_gzip_are_rejected() -> None:
    with pytest.raises(SourceError):
        archive_snapshot(archive({"app.py": b"ok"}), "team/different", COMMIT)
    with pytest.raises(SourceError, match="ARCHIVE_INVALID"):
        archive_snapshot(b"not gzip", "team/demo", COMMIT)


def test_masking_multiline_secrets_preserves_line_numbers() -> None:
    source = 'API_TOKEN = """first-secret\nsecond-secret\n"""\nREGION = "ap-northeast-1"\n'
    masked = redact_source(source)
    assert masked.count("\n") == source.count("\n")
    assert "first-secret" not in masked and "second-secret" not in masked
    serialized = json.dumps(report(source))
    assert "first-secret" not in serialized and "second-secret" not in serialized
    assert report(source)["observations"][-1]["location"]["line"] == 4


def test_known_token_and_private_key_never_appear_in_evidence() -> None:
    key = "AKIA" + "A" * 16
    source = (
        f'AWS_ACCESS_KEY_ID = "{key}"\n'
        'KEY = """-----BEGIN PRIVATE KEY-----\nprivate-data\n-----END PRIVATE KEY-----"""'
    )
    output = json.dumps(report(source))
    assert key not in output and "private-data" not in output
    assert any(o["category"] == "SECRET" for o in report(source)["observations"])


def test_syntax_errors_no_supported_files_and_observation_limits_are_visible() -> None:
    broken = report("def incomplete(")
    assert broken["coverage"]["syntaxErrors"] == 1
    assert any(f["control"] == "repo-coverage" for f in to_findings(broken, "env"))
    empty = analyze(RepoSnapshot(COMMIT, (), {}, "fixture"), "aws", "gcp")
    assert empty["status"] == "NO_SUPPORTED_FILES"
    assert to_findings(empty, "env")[0]["result"] == "WARN"
    many = report("\n".join(f'R{i} = "us-east-1"' for i in range(50)))
    assert len(many["observations"]) == 30 and many["coverage"]["truncatedObservations"] == 20


def test_same_source_manifest_and_observation_ids_are_stable() -> None:
    assert report() == report()
    assert report()["source"]["contentHash"] != report(SAMPLE + "# change")["source"]["contentHash"]


def test_secret_keyword_argument_is_detected_and_masked() -> None:
    value = report('client = configure(api_key="private-argument-value")\n')
    assert [o["category"] for o in value["observations"]] == ["SECRET"]
    assert "private-argument-value" not in json.dumps(value)


def test_uncompressed_archive_budget_is_enforced(monkeypatch: pytest.MonkeyPatch) -> None:
    data = archive({"app.py": SAMPLE.encode()})
    monkeypatch.setattr("echo_agent.repo_source.MAX_UNPACKED", 100)
    with pytest.raises(SourceError, match="ARCHIVE_TOO_LARGE"):
        archive_snapshot(data, "team/demo", COMMIT)
