"""Scan only a WAS-pinned customer image. Never send a truncated inventory."""

import json
import os
import re
import tempfile
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from echo_agent.apply_runner import CommandRunner, subprocess_runner
from echo_agent.events import EventLevel, RunEventLog, RunStep
from echo_agent.was_client import ClaimedRun

MAX_SBOM_BYTES = 512 * 1024
MAX_RESULT_BYTES = 1024 * 1024
IMAGE = re.compile(r"[a-z0-9][a-z0-9./_-]+@sha256:[a-f0-9]{64}")


def checked_image_ref(ref: Any, digest: Any) -> str:
    prefixes = tuple(
        x.strip() for x in os.getenv("ECHO_CUSTOMER_IMAGE_PREFIXES", "").split(",") if x.strip()
    )
    if (
        not isinstance(ref, str)
        or not IMAGE.fullmatch(ref)
        or not isinstance(digest, str)
        or not ref.endswith("@" + digest)
        or not prefixes
        or not any(ref.startswith(prefix.rstrip("/") + "/") for prefix in prefixes)
    ):
        raise ValueError("IMAGE_NOT_ALLOWED")
    return ref


def validate_sbom(value: Any) -> dict[str, Any]:
    if (
        not isinstance(value, dict)
        or value.get("bomFormat") != "CycloneDX"
        or not isinstance(value.get("specVersion"), str)
    ):
        raise ValueError("SBOM_INVALID_FORMAT")
    if len(json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()) > MAX_SBOM_BYTES:
        raise ValueError("SBOM_TOO_LARGE")
    if not isinstance(value.get("components"), list) or not value["components"]:
        raise ValueError("SBOM_EMPTY")
    stack, count = list(value["components"]), 0
    while stack:
        component = stack.pop()
        count += 1
        if count > 5000 or not isinstance(component, dict):
            raise ValueError("SBOM_COMPONENT_LIMIT")
        os_metadata = component.get("type") == "operating-system" and "purl" not in component
        if not os_metadata and (
            not isinstance(component.get("purl"), str)
            or not re.fullmatch(r"pkg:[a-zA-Z0-9.+-]+/[^\s]+@[^\s]+", component["purl"])
        ):
            raise ValueError("SBOM_PURL_REQUIRED")
        children = component.get("components", [])
        if not isinstance(children, list):
            raise ValueError("SBOM_INVALID_COMPONENTS")
        stack.extend(children)
    return value


def collect_sbom(
    run: ClaimedRun,
    events: RunEventLog,
    *,
    command: CommandRunner = subprocess_runner,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> dict[str, Any] | None:
    source = run.input_snapshot.get("source") or {}
    try:
        ref = checked_image_ref(source.get("imageRef"), source.get("imageDigest"))
        remaining = (run.deadline_at - clock()).total_seconds() - 60
        if remaining < 5:
            raise ValueError("SBOM_DEADLINE")
        with tempfile.TemporaryDirectory(prefix="echo-sbom-") as directory:
            output = Path(directory) / "sbom.json"
            result = command(
                [
                    "trivy",
                    "image",
                    "--format",
                    "cyclonedx",
                    "--quiet",
                    "--output",
                    str(output),
                    ref,
                ],
                min(120, remaining),
                None,
            )
            if result.returncode != 0 or not output.is_file():
                raise ValueError("SBOM_SCAN_FAILED")
            if output.stat().st_size > MAX_SBOM_BYTES:
                raise ValueError("SBOM_TOO_LARGE")
            sbom = validate_sbom(json.loads(output.read_text()))
        events.add(
            RunStep.ANALYZE,
            "customer image SBOM collected",
            imageDigest=source["imageDigest"],
            components=len(sbom["components"]),
        )
        return sbom
    except (ValueError, OSError) as exc:
        reason = str(exc) if type(exc) is ValueError else "SBOM_COLLECTION_FAILED"
        events.add(RunStep.ANALYZE, "customer image SBOM omitted", EventLevel.WARN, reason=reason)
        return None


def attach_sbom(result: dict[str, Any], sbom: dict[str, Any] | None, events: RunEventLog) -> None:
    if sbom is None:
        return
    candidate = {**result, "sbom": sbom}
    # Match urllib/json serialization overhead, not just a compact estimate.
    if len(json.dumps(candidate).encode()) > MAX_RESULT_BYTES:
        events.add(
            RunStep.ANALYZE,
            "customer image SBOM omitted",
            EventLevel.WARN,
            reason="RESULT_TOO_LARGE",
        )
        return
    result["sbom"] = sbom
