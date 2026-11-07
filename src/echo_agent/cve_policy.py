"""Dependency-only policy. uv owns lock metadata; models may only suggest requirements."""

import copy
import re
import tomllib
from typing import Any, cast

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name, parse_sdist_filename, parse_wheel_filename
from packaging.version import Version

from echo_agent.diagnosis_input import redact
from echo_agent.precheck_model import mask_tokens

FILES = frozenset({"pyproject.toml", "uv.lock"})


def dependency_diff_is_safe(diff: str) -> bool:
    """Public PyPI artifact URLs are inventory, not credentials; all other text stays checked."""

    def public_artifact(match: re.Match[str]) -> str:
        url = match[0]
        if mask_tokens(url) != url:
            return url
        filename = url.rsplit("/", 1)[-1]
        try:
            if filename.endswith(".whl"):
                parse_wheel_filename(filename)
            else:
                parse_sdist_filename(filename)
        except ValueError:
            return url
        return "https://files.pythonhosted.org/public-artifact"

    file = ""
    checked = []
    for line in diff.splitlines(keepends=True):
        if line.startswith("+++ b/"):
            file = line[len("+++ b/") :].strip()
        if file == "uv.lock":
            line = re.sub(
                r"https://files\.pythonhosted\.org/packages/[a-f0-9]{2}/[a-f0-9]{2}/"
                r'[a-f0-9]{60}/[A-Za-z0-9_.+-]+(?:\.whl|\.tar\.gz|\.zip)(?=")',
                public_artifact,
                line,
            )
        checked.append(line)
    text = "".join(checked)
    return redact(text) == text


def project_dependencies(text: str) -> list[str]:
    data = tomllib.loads(text)
    project = data.get("project", {})
    uv = data.get("tool", {}).get("uv", {})
    if any(
        key in uv
        for key in (
            "sources",
            "index",
            "index-url",
            "extra-index-url",
            "find-links",
            "workspace",
            "override-dependencies",
            "constraint-dependencies",
        )
    ):
        raise ValueError("CUSTOM_PACKAGE_SOURCE_UNSUPPORTED")
    if "dependencies" in project.get("dynamic", []):
        raise ValueError("DYNAMIC_DEPENDENCIES_UNSUPPORTED")
    deps = project.get("dependencies", [])
    if not isinstance(deps, list) or not all(isinstance(dep, str) for dep in deps):
        raise ValueError("DEPENDENCIES_INVALID")
    for dep in deps:
        if Requirement(dep).url:
            raise ValueError("CUSTOM_PACKAGE_SOURCE_UNSUPPORTED")
    return deps


def lock_versions(text: str, package: str) -> set[str]:
    data = tomllib.loads(text)
    found = set()
    for item in data.get("package", []):
        source = item.get("source", {})
        if any(
            key in source for key in ("git", "path", "directory", "url", "editable")
        ) and source != {"editable": "."}:
            raise ValueError("CUSTOM_PACKAGE_SOURCE_UNSUPPORTED")
        if "registry" in source and source["registry"] != "https://pypi.org/simple":
            raise ValueError("CUSTOM_PACKAGE_SOURCE_UNSUPPORTED")
        if canonicalize_name(item["name"]) == canonicalize_name(package):
            found.add(item["version"])
    return found


def replace_requirement(text: str, old: str, new: str) -> str:
    before, after = Requirement(old), Requirement(new)
    if (
        canonicalize_name(before.name) != canonicalize_name(after.name)
        or before.extras != after.extras
        or before.marker != after.marker
        or after.url
    ):
        raise ValueError("REQUIREMENT_SCOPE_REJECTED")
    # Preserve TOML formatting and comments; fail rather than guessing ambiguous occurrences.
    tokens = [quote + old + quote for quote in ('"', "'")]
    matches = [token for token in tokens if text.count(token) == 1]
    if len(matches) != 1 or any(c in new for c in ("\n", "\r", "\\", '"', "'")):
        raise ValueError("MANIFEST_EDIT_AMBIGUOUS")
    token = matches[0]
    return text.replace(token, token[0] + new + token[0], 1)


def bump_direct(text: str, package: str, version: str) -> str:
    for dep in project_dependencies(text):
        req = Requirement(dep)
        if canonicalize_name(req.name) == canonicalize_name(package):
            extras = "[" + ",".join(sorted(req.extras)) + "]" if req.extras else ""
            marker = f"; {req.marker}" if req.marker else ""
            text = replace_requirement(text, dep, f"{req.name}{extras}=={version}{marker}")
    return text


def validate_manifest_change(
    original: str, modified: str, allowed: set[str] | frozenset[str]
) -> None:
    before, after = tomllib.loads(original), tomllib.loads(modified)
    before_deps, after_deps = project_dependencies(original), project_dependencies(modified)
    left, right = copy.deepcopy(before), copy.deepcopy(after)
    left.setdefault("project", {}).pop("dependencies", None)
    right.setdefault("project", {}).pop("dependencies", None)
    if left != right or len(before_deps) != len(after_deps):
        raise ValueError("PROTECTED_MANIFEST_CHANGE")
    for old, new in zip(before_deps, after_deps, strict=True):
        if old != new:
            if canonicalize_name(Requirement(old).name) not in allowed:
                raise ValueError("UNRELATED_DEPENDENCY_CHANGE")
            replace_requirement('"' + old + '"', old, new)


def parse_cve(snapshot: dict[str, Any]) -> dict[str, Any]:
    remediation = snapshot.get("remediation", {})
    if snapshot.get("trigger") != "CVE_WATCH" or remediation.get("ecosystem") != "PyPI":
        raise ValueError("ECOSYSTEM_UNSUPPORTED")
    for key in ("package", "fromVersion", "toVersion"):
        if not isinstance(remediation.get(key), str) or not re.fullmatch(
            r"[A-Za-z0-9_.+!-]{1,100}", remediation[key]
        ):
            raise ValueError("REMEDIATION_INVALID")
    if Version(remediation["toVersion"]) <= Version(remediation["fromVersion"]):
        raise ValueError("FIX_VERSION_INVALID")
    if not re.fullmatch(r"[a-f0-9]{40}", str(snapshot.get("sourceCommitSha", ""))):
        raise ValueError("SOURCE_COMMIT_INVALID")
    repo = (snapshot.get("service") or {}).get("repo", "")
    if not isinstance(repo, str) or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
        raise ValueError("SOURCE_REPO_INVALID")
    packages = snapshot.get("packages", [])
    if not any(
        p.get("ecosystem") == "PyPI"
        and canonicalize_name(p.get("name", "")) == canonicalize_name(remediation["package"])
        and p.get("version") == remediation["fromVersion"]
        for p in packages
    ):
        raise ValueError("IMAGE_PACKAGE_MISMATCH")
    return cast(dict[str, Any], remediation)


def target_advisory_present(report: dict[str, Any], finding: dict[str, Any], package: str) -> bool:
    ids = {finding.get("advisoryId"), *finding.get("aliases", [])} - {None, ""}
    results = report.get("Results")
    if not ids or not isinstance(results, list) or not results:
        raise ValueError("SCAN_INCOMPLETE")
    return any(
        v.get("VulnerabilityID") in ids
        and canonicalize_name(v.get("PkgName", "")) == canonicalize_name(package)
        for item in results
        for v in item.get("Vulnerabilities", []) or []
    )


def verify_target_report(report: dict[str, Any], snapshot: dict[str, Any]) -> None:
    remediation = snapshot["remediation"]
    if target_advisory_present(report, snapshot["finding"], remediation["package"]):
        raise ValueError("TARGET_ADVISORY_REMAINS")
    packages = [
        p
        for result in report.get("Results", [])
        for p in result.get("Packages", []) or []
        if canonicalize_name(p.get("Name", "")) == canonicalize_name(remediation["package"])
    ]
    if not packages or any(p.get("Version") != remediation["toVersion"] for p in packages):
        raise ValueError("INSTALLED_VERSION_MISMATCH")
