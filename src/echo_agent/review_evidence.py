"""Versioned, deterministic review binding. Mirrored by WAS; no I/O or model calls.

Hashes bind evidence from an authenticated runner, not attest its honesty. The
review is supplemental to policy, syntax tests, human approval and APPLY checks.
"""

import hashlib
import json
import re
from typing import Any

REVIEW_POLICY = "syntax-review-v1"
REVIEW_PROMPT_HASH = "sha256:adb9c211e3dacbf477e253e79aaa2c9eee42cd3ff84ee23e5a050f96a730aa8a"
MAX_EVIDENCE_BYTES = 16 * 1024
_HASH = re.compile(r"sha256:[0-9a-f]{64}\Z")
# Populated from checked-in parser artifacts, changed only by a policy revision.
PARSER_HASHES: dict[str, str] = {
    "app/main.py": "sha256:490d5ed99802a74f39775bd0520a3155205627f1bd2520d76e45911b42655bda",
    "app/static/index.html": "sha256:"
    "a44361278b1915fa2739eb7f6cfc8ade81e839b3c4f6c5b764a6d082dfcad2bf",
}
IMAGES = {
    "app/main.py": "python:3.13-slim@sha256:"
    "ae14d4ce8771606477a81446e7ef429edd6762305fc50c84507c1041fa8285d1",
    "app/static/index.html": "node:24-bookworm-slim@sha256:"
    "01d566e8d94d8c619591d78652babfccd3c6992a3dffa9ed5ab39e11cf6c70e9",
}


def canonical(value: Any) -> str:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    )


def text_hash(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode()).hexdigest()


def fingerprint(value: Any) -> str:
    return text_hash(canonical(value))


def test_definition(path: str) -> dict[str, Any]:
    if path not in IMAGES:
        raise ValueError("REVIEW_TARGET_UNSUPPORTED")
    return {
        "policy": REVIEW_POLICY,
        "reviewPromptHash": REVIEW_PROMPT_HASH,
        "path": path,
        "image": IMAGES[path],
        "parserHash": PARSER_HASHES[path],
        "command": ["python", "-I", "diagnosis_python_check.py", "input.json"]
        if path == "app/main.py"
        else ["node", "diagnosis_check.cjs", "input.json"],
        "expectedBefore": "available syntax error at the target file",
        "expectedAfter": "available parse-only success; no application behavior claim",
        "limits": {"seconds": 15, "memoryMiB": 512, "cpu": 1, "pids": 128, "network": "none"},
    }


def review_context(evidence: dict[str, Any], diff: str) -> dict[str, Any]:
    return {
        "sourceCommitSha": evidence["sourceCommitSha"],
        "patchHash": evidence["patchHash"],
        "diff": diff,
        "testDefinition": evidence["testDefinition"],
        "testDefinitionHash": evidence["testDefinitionHash"],
        "testResults": evidence["testResults"],
        "testResultsHash": evidence["testResultsHash"],
    }


def _keys(value: Any, names: str) -> None:
    if not isinstance(value, dict) or set(value) != set(names.split()):
        raise ValueError("REVIEW_EVIDENCE_SHAPE")


def validate_evidence(value: Any, diff: str, commit: Any, paths: Any) -> None:
    """Accept only the current fixed test definition and a fully bound PASS."""
    _keys(
        value,
        "version sourceCommitSha patchHash testDefinition testDefinitionHash "
        "testResults testResultsHash review evidenceHash",
    )
    if len(canonical(value).encode()) > MAX_EVIDENCE_BYTES or "\\u0000" in canonical(value):
        raise ValueError("REVIEW_EVIDENCE_SIZE")
    if (
        value["version"] != REVIEW_POLICY
        or not isinstance(commit, str)
        or not re.fullmatch(r"[0-9a-f]{40}", commit)
        or value["sourceCommitSha"] != commit
        or value["patchHash"] != text_hash(diff)
    ):
        raise ValueError("REVIEW_BINDING_MISMATCH")
    definition = value["testDefinition"]
    if (
        not isinstance(definition, dict)
        or not isinstance(definition.get("path"), str)
        or paths != [definition.get("path")]
    ):
        raise ValueError("REVIEW_TARGET_MISMATCH")
    if definition != test_definition(definition["path"]) or value[
        "testDefinitionHash"
    ] != fingerprint(definition):
        raise ValueError("REVIEW_TEST_CHANGED")
    results = value["testResults"]
    _keys(results, "before after")
    for side, passed in (("before", False), ("after", True)):
        result = results[side]
        _keys(result, "available passed toolVersion issues sourceHash")
        if (
            result["available"] is not True
            or result["passed"] is not passed
            or not isinstance(result["toolVersion"], str)
            or not result["toolVersion"]
            or len(result["toolVersion"]) > 128
            or not isinstance(result["sourceHash"], str)
            or not _HASH.fullmatch(result["sourceHash"])
        ):
            raise ValueError("REVIEW_TEST_NOT_PROVEN")
        issues = result["issues"]
        if not isinstance(issues, list) or len(issues) > 10 or bool(issues) == passed:
            raise ValueError("REVIEW_TEST_NOT_PROVEN")
        for issue in issues:
            _keys(issue, "path line message")
            if (
                issue["path"] != definition["path"]
                or type(issue["line"]) is not int
                or not 1 <= issue["line"] <= 1_000_000
                or not isinstance(issue["message"], str)
                or not 1 <= len(issue["message"]) <= 1000
            ):
                raise ValueError("REVIEW_TEST_NOT_PROVEN")
    if (
        results["before"]["toolVersion"] != results["after"]["toolVersion"]
        or results["before"]["sourceHash"] == results["after"]["sourceHash"]
        or value["testResultsHash"] != fingerprint(results)
    ):
        raise ValueError("REVIEW_TEST_CHANGED")
    review = value["review"]
    _keys(review, "verdict reason model contextHash")
    if (
        review["verdict"] != "PASS"
        or not isinstance(review["reason"], str)
        or not 1 <= len(review["reason"]) <= 1000
        or not isinstance(review["model"], str)
        or not re.fullmatch(r"[A-Za-z0-9._:/-]{1,128}", review["model"])
        or review["contextHash"] != fingerprint(review_context(value, diff))
    ):
        raise ValueError("REVIEW_NOT_APPROVED")
    if value["evidenceHash"] != fingerprint(
        {k: v for k, v in value.items() if k != "evidenceHash"}
    ):
        raise ValueError("REVIEW_EVIDENCE_CHANGED")


def approval_digest(patch: dict[str, Any]) -> str:
    """Legacy checks digest unchanged; reviewed patches additionally bind the full bundle."""
    checks = patch.get("checks", [])
    evidence = patch.get("reviewEvidence")
    return fingerprint(
        checks if evidence is None else {"checks": checks, "reviewEvidence": evidence}
    )
