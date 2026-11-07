"""One-shot demo-app #7 rehearsal: real startup log → Claude → sandbox apply.

No WAS calls, production changes, pushes, or PR merges. Approval is synthetic here.
Requires --live, ANTHROPIC_API_KEY, Docker, Trivy and the pre-pulled Python parser image.
"""

import argparse
import json
import os
import subprocess
import tempfile
import time
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from echo_agent.apply_runner import ApplyRunner, codeload_fetcher, service_build
from echo_agent.diagnosis_input import redact
from echo_agent.diagnosis_model import DiagnosisModel
from echo_agent.diagnosis_runner import Diagnoser, DiagnosisRunner, build_diagnosis_result
from echo_agent.events import RunEventLog
from echo_agent.was_client import ClaimedRun

REPO = "Softbank-Hackathon-2026-Team-Echo/echo-demo-app"
COMMIT = "53997e169a29604b37088b793425b7d72a7946bf"


def command(args: list[str], seconds: int = 60) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 — fixed Docker operations, no shell or model commands
        args,
        capture_output=True,
        text=True,
        timeout=seconds,
        check=True,
        env={**os.environ, "DOCKER_BUILDKIT": "1"},
    )


def save(output: Path, name: str, data: Any) -> None:
    (output / name).write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n")


def claim(snapshot: dict[str, Any], kind: str) -> ClaimedRun:
    run_id = str(uuid.uuid4())
    if kind == "APPLY_PATCH":
        snapshot = {**snapshot, "branch": f"applied/{run_id}"}
    return ClaimedRun(
        id=run_id,
        kind=kind,
        org_id=None,
        service_id=None,
        source_environment_id=None,
        target_environment_id=None,
        input_snapshot=snapshot,
        input_hash=None,
        scenario_ref=None,
        deadline_at=datetime.now(UTC) + timedelta(minutes=15),
        lease_until=None,
        run_token="rehearsal-only-unused",  # noqa: S106 — never sent to a server
    )


def rehearse(output: Path, location: str) -> dict[str, Any]:
    model = DiagnosisModel.from_env()
    output.mkdir(parents=True, mode=0o700, exist_ok=False)
    started = time.monotonic()
    image = "echo-diagnosis-rehearsal:" + uuid.uuid4().hex[:12]
    container = image.replace(":", "-")
    calls: list[dict[str, Any]] = []
    original_create = model.create

    async def observed_create(**kwargs: Any) -> Any:
        began = time.monotonic()
        response = await original_create(**kwargs)
        calls.append(
            {
                "model": response.model,
                "requestId": getattr(response, "_request_id", None),
                "seconds": round(time.monotonic() - began, 3),
                "inputTokens": response.usage.input_tokens,
                "outputTokens": response.usage.output_tokens,
            }
        )
        save(output, "model-calls.json", calls)
        return response

    model.create = observed_create
    with tempfile.TemporaryDirectory(prefix="echo-python-rehearsal-") as temporary:
        root = Path(temporary)
        source = codeload_fetcher(REPO, COMMIT, root / "source", 60)
        try:
            command(["docker", "build", "--tag", image, str(source)], 300)
            dummy_env = [
                part
                for key, value in sorted(service_build(REPO, COMMIT).healthz_env.items())
                for part in ("--env", f"{key}={value}")
            ]
            command(
                [
                    "docker",
                    "run",
                    "--detach",
                    "--name",
                    container,
                    "--network",
                    "none",
                    "--read-only",
                    "--cap-drop",
                    "ALL",
                    "--security-opt",
                    "no-new-privileges",
                    "--memory",
                    "512m",
                    "--cpus",
                    "1",
                    "--pids-limit",
                    "128",
                    *dummy_env,
                    image,
                ]
            )
            exit_code = int(command(["docker", "wait", container], 30).stdout.strip())
            logs = command(["docker", "logs", "--tail", "50", container])
            tail = redact(logs.stdout + logs.stderr).splitlines()[-50:]
            save(output, "startup.json", {"exitCode": exit_code, "logTail": tail})
        finally:
            # Remove only the resources created by this rehearsal, even on interruption.
            for args in (["docker", "rm", "--force", container], ["docker", "rmi", image]):
                subprocess.run(args, capture_output=True, timeout=30)  # noqa: S603
        if exit_code == 0 or not any("SyntaxError" in line for line in tail):
            raise RuntimeError("EXPECTED_STARTUP_SYNTAX_FAILURE_NOT_REPRODUCED")
        snapshot = {
            "schemaVersion": 1,
            "service": {
                "name": "demo-rehearsal",
                "containerPort": 8080,
                "healthCheckPath": "/healthz",
            },
            "deployRequest": {
                "id": "rehearsal-not-a-was-deploy",
                "repo": REPO,
                "commitSha": COMMIT,
                "errorCode": "CONTAINER_START_FAILED",
            },
            "environment": {"kind": "rehearsal"},
            "variableKeys": [],
            "failure": {
                "code": "CONTAINER_START_FAILED",
                "exitCode": exit_code,
                "terminationReason": "Error",
                "logTail": tail,
                "logTruncated": True,
            },
        }
        save(output, "input-snapshot.json", snapshot)
        events = RunEventLog("rehearsal-diagnosis")
        runner = DiagnosisRunner(Diagnoser(model, location=location), workspace_parent=root)
        status, failure, outcome = runner.execute(
            claim(snapshot, "CHANGE_PROPOSAL"),
            events,
            lambda: None,
        )
        result = build_diagnosis_result(outcome, status=status, failure_code=failure)
        # Synthetic run and approval: never submit this object to WAS as real deployment evidence.
        result["simulated"] = True
        save(output, "diagnosis-result.json", result)
        save(output, "diagnosis-events.json", [e.to_json() for e in events.events])
        summary: dict[str, Any] = {
            "sourceRepo": REPO,
            "sourceCommit": COMMIT,
            "location": location,
            "realModelCalls": len(calls),
            "diagnosisStatus": status,
            "diagnosisFailure": failure,
            "startupExitCode": exit_code,
            "syntheticApproval": True,
            "wasConnected": False,
            "pushed": False,
            "redeployed": False,
            "applyStatus": "NOT_RUN",
        }
        if status == "SUCCEEDED" and outcome and len(outcome.patches) == 1:
            patch = outcome.patches[0]
            (output / "fix.diff").write_text(patch["diff"])
            apply = claim(
                {
                    "schemaVersion": 1,
                    "parentRunId": str(uuid.uuid4()),
                    "repo": REPO,
                    "patch": patch,
                    "diagnosis": {
                        "sourceCommitSha": COMMIT,
                        "deployRequestId": "rehearsal-not-a-was-deploy",
                        "environmentId": "rehearsal",
                    },
                },
                "APPLY_PATCH",
            )
            apply_events = RunEventLog(apply.id)
            applied = ApplyRunner(repo_root=root, workspace_parent=root).execute(
                apply,
                apply_events,
                lambda: None,
            )
            summary.update(
                applyStatus=applied[0], applyFailure=applied[1], sandboxCommit=applied[2]
            )
            save(output, "apply-events.json", [e.to_json() for e in apply_events.events])
        summary["seconds"] = round(time.monotonic() - started, 3)
        save(output, "summary.json", summary)
        return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--live", action="store_true", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--location", default="local/development")
    args = parser.parse_args()
    try:
        summary = rehearse(args.output_dir, args.location)
    except subprocess.CalledProcessError as error:
        failure = {
            "status": "FAILED",
            "errorType": type(error).__name__,
            "operation": list(error.cmd[:2]),
            "exitCode": error.returncode,
            "tail": redact(error.stderr or error.stdout or "")[-3000:],
        }
        if args.output_dir.is_dir():
            save(args.output_dir, "command-failure.json", failure)
        print(json.dumps(failure))
        return 2
    except Exception as error:  # noqa: BLE001 — never print command output/credentials
        print(json.dumps({"status": "FAILED", "errorType": type(error).__name__}))
        return 2
    print(json.dumps(summary, ensure_ascii=False))
    return 0 if summary["applyStatus"] == "SUCCEEDED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
