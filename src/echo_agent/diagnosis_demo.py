"""Reproduce a syntax failure, diagnosis and isolated verification; never contact WAS.

Default: offline model replay. --live explicitly enables up to two paid API calls.
Only a synthetic copy is modified. The supplied source and running services stay intact.
"""

import argparse
import asyncio
import hashlib
import json
import shutil
import subprocess
import time
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from echo_agent.apply_runner import apply_patch_to_files
from echo_agent.diagnosis import DiagnosisService
from echo_agent.diagnosis_check import DockerSyntaxChecker, SyntaxSandbox
from echo_agent.diagnosis_input import ALLOWED_FILE, MAX_SOURCE_BYTES, DiagnosisError, redact
from echo_agent.diagnosis_model import DiagnosisModel
from echo_agent.events import RunEventLog
from echo_agent.precheck_model import ModelConfigError

GOOD = "async function fetchJson(url, options, timeoutMs) {"
BAD = "async function fetchJson(url, options, timeoutMs {"
BASELINE = f"""<!doctype html>
<html lang="ko"><body><p>오류 수정 시연용 사본</p>
<script>
{GOOD}
  return {{ url, options, timeoutMs }};
}}
</script>
</body></html>
"""


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def make_source_commit(directory: Path, source: str) -> str:
    """Use a fresh, local-only repo so sourceCommit actually identifies the broken bytes."""
    git = shutil.which("git")
    if git is None:
        raise DiagnosisError("DEMO_GIT_UNAVAILABLE")
    target = directory / ALLOWED_FILE
    target.parent.mkdir(parents=True)
    target.write_text(source, encoding="utf-8")
    for args in (
        ["init", "--quiet", "--template="],
        ["add", ALLOWED_FILE],
        [
            "-c",
            "user.name=Echo diagnosis demo",
            "-c",
            "user.email=demo@example.invalid",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "--quiet",
            "-m",
            "Synthetic syntax failure for local verification",
        ],
    ):
        subprocess.run(  # noqa: S603 — fixed git operations in a new synthetic repo
            [git, *args], cwd=directory, check=True, capture_output=True, timeout=15
        )
    return subprocess.check_output(  # noqa: S603 — read the synthetic commit only
        [git, "rev-parse", "HEAD"], cwd=directory, text=True, timeout=15
    ).strip()


async def docker_output(*args: str) -> bytes:
    process = await asyncio.create_subprocess_exec(
        "docker", *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )
    try:
        stdout, _ = await asyncio.wait_for(process.communicate(), 15)
    except (TimeoutError, asyncio.CancelledError):
        if process.returncode is None:
            process.kill()
        await process.wait()
        raise
    if process.returncode != 0:
        raise DiagnosisError("DEMO_DOCKER_INSPECTION_FAILED")
    return stdout


def replay_model(line: int) -> DiagnosisModel:
    async def create(**kwargs: Any) -> Any:
        answer = {
            "analysisStatus": "diagnosed",
            "summary": "저장된 응답 재생: 닫는 괄호가 없습니다.",
            "evidenceIds": ["EV000001"],
            "sourceEvidenceIds": [f"SC{line:06d}"],
            "canFix": True,
            "reason": "함수 선언의 닫는 괄호를 복구합니다.",
            "limitations": ["모델 응답 재생이며 실제 AI 진단이 아닙니다."],
            "edits": [
                {
                    "path": ALLOWED_FILE,
                    "oldText": BAD,
                    "newText": GOOD,
                    "evidenceIds": ["EV000001"],
                    "sourceEvidenceIds": [f"SC{line:06d}"],
                }
            ],
        }
        return SimpleNamespace(
            stop_reason="end_turn",
            model="fixture-replay",
            content=[SimpleNamespace(type="text", text=json.dumps(answer))],
        )

    return DiagnosisModel(create, simulated=True)


async def run_demo(baseline: str, output: Path, *, live: bool, location: str) -> dict[str, Any]:
    if len(baseline.encode()) > MAX_SOURCE_BYTES or baseline.count(GOOD) != 1:
        raise DiagnosisError("DEMO_SOURCE_UNSUPPORTED")
    if redact(baseline) != baseline:
        raise DiagnosisError("DEMO_SOURCE_CONTAINS_SECRET")
    line = baseline[: baseline.index(GOOD)].count("\n") + 1
    # Validate configuration before creating artifacts or touching Docker.
    model = DiagnosisModel.from_env() if live else replay_model(line)
    await asyncio.to_thread(output.mkdir, mode=0o700, parents=True, exist_ok=False)
    broken = baseline.replace(GOOD, BAD, 1)
    commit = await asyncio.to_thread(make_source_commit, output / "synthetic-source", broken)
    (output / "baseline.html").write_text(baseline, encoding="utf-8")
    (output / "broken.html").write_text(broken, encoding="utf-8")
    containers: list[dict[str, Any]] = []

    class ObservedSandbox(SyntaxSandbox):
        async def create(self) -> None:
            await super().create()
            item = json.loads(await docker_output("inspect", self.name))[0]
            host = item["HostConfig"]
            containers.append(
                {
                    "name": self.name,
                    "image": item["Config"]["Image"],
                    "networkMode": host["NetworkMode"],
                    "readOnlyRoot": host["ReadonlyRootfs"],
                    "user": item["Config"]["User"],
                    "capDrop": host["CapDrop"],
                    "securityOpt": host["SecurityOpt"],
                    "memory": host["Memory"],
                    "nanoCpus": host["NanoCpus"],
                    "pidsLimit": host["PidsLimit"],
                    "bindMounts": host["Binds"],
                    "environmentKeys": [s.split("=", 1)[0] for s in item["Config"]["Env"]],
                }
            )

    checker = DockerSyntaxChecker(factory=ObservedSandbox)
    normal = await checker.check(baseline, 30)
    failed = await checker.check(broken, 30)
    write_json(
        output / "initial-checks.json", {"baseline": normal.to_json(), "broken": failed.to_json()}
    )
    if not normal.available or not normal.passed or not failed.available or failed.passed:
        raise DiagnosisError("DEMO_REPRODUCTION_FAILED")
    request = {
        "schemaVersion": 1,
        "purpose": "error-diagnosis.v1",
        "deployRequestId": "synthetic-diagnosis-demo",
        "environment": location,
        "sourceCommit": commit,
        "simulated": True,
        "allowedFiles": [ALLOWED_FILE],
        "sourceFiles": [{"path": ALLOWED_FILE, "content": broken}],
        "failure": {"code": "SYNTAX_CHECK_FAILED", "exitCode": 1},
        "logs": [
            {
                "id": "real-syntax-check",
                "stage": "validation",
                "sourceLineStart": None,
                "truncated": False,
                "lines": [
                    f"{i['path']}:{i['line']}: SyntaxError: {i['message']}" for i in failed.issues
                ],
            }
        ],
    }
    write_json(output / "request.json", request)
    calls: list[dict[str, Any]] = []
    create = model.create

    async def observed_create(**kwargs: Any) -> Any:
        started = time.monotonic()
        call: dict[str, Any] = {"at": datetime.now(UTC).isoformat(), "mocked": not live}
        calls.append(call)
        try:
            response = await create(**kwargs)
            usage = getattr(response, "usage", None)
            call.update(
                model=response.model,
                requestId=getattr(response, "_request_id", None),
                inputTokens=getattr(usage, "input_tokens", None),
                outputTokens=getattr(usage, "output_tokens", None),
            )
            return response
        except Exception as error:
            call.update(
                errorType=type(error).__name__, httpStatus=getattr(error, "status_code", None)
            )
            raise
        finally:
            call["durationSeconds"] = round(time.monotonic() - started, 3)
            write_json(output / "model-calls.json", calls)

    model.create = observed_create
    events = RunEventLog("synthetic-diagnosis-demo")
    seen = 0

    def flush() -> None:
        nonlocal seen
        for event in events.events[seen:]:
            print(json.dumps(event.to_json(), ensure_ascii=False), flush=True)
        seen = len(events.events)

    started = time.monotonic()
    result = await DiagnosisService(model, checker, location=location).execute(
        request, events=events, flush=flush
    )
    write_json(output / "result.json", result)
    write_json(output / "events.json", [event.to_json() for event in events.events])
    write_json(output / "sandbox-observations.json", containers)
    fixed_equals_baseline = False
    if result["patches"]:
        diff = result["patches"][0]["diff"]
        fixed = apply_patch_to_files({ALLOWED_FILE: broken}, diff)[ALLOWED_FILE]
        (output / "fix.diff").write_text(diff, encoding="utf-8")
        (output / "fixed.html").write_text(fixed, encoding="utf-8")
        fixed_equals_baseline = fixed == baseline
    names = (await docker_output("ps", "-a", "--format", "{{.Names}}")).decode().splitlines()
    remaining = [item["name"] for item in containers if item["name"] in names]
    summary = {
        "at": datetime.now(UTC).isoformat(),
        "mode": "live" if live else "replay",
        "location": location,
        "sourceCommit": commit,
        "baselineSha256": hashlib.sha256(baseline.encode()).hexdigest(),
        "realModelCalls": len(calls) if live else 0,
        "model": result.get("model"),
        "status": result["status"],
        "failureCode": result.get("failureCode"),
        "patchCount": len(result["patches"]),
        "fixedEqualsBaseline": fixed_equals_baseline,
        "verification": result.get("diagnosis", {}).get("verification"),
        "durationSeconds": round(time.monotonic() - started, 3),
        "ourContainersRemaining": remaining,
        "syntheticInput": True,
        "fullAppRuntimeChecked": False,
        "productionChanged": False,
        "passed": result["status"] == "SUCCEEDED" and fixed_equals_baseline and not remaining,
    }
    write_json(output / "summary.json", summary)
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True, help="new private directory")
    parser.add_argument("--source", type=Path, help="optional known-clean echo-demo-app HTML")
    parser.add_argument(
        "--live", action="store_true", help="real paid Claude call; default is replay"
    )
    parser.add_argument(
        "--location", default="local/development", help="actual controller location"
    )
    args = parser.parse_args(argv)
    try:
        baseline = BASELINE
        if args.source:
            with args.source.open("rb") as stream:
                raw = stream.read(MAX_SOURCE_BYTES + 1)
            if len(raw) > MAX_SOURCE_BYTES:
                raise DiagnosisError("DEMO_SOURCE_UNSUPPORTED")
            baseline = raw.decode("utf-8")
        summary = asyncio.run(
            run_demo(baseline, args.output_dir, live=args.live, location=args.location)
        )
        print(json.dumps(summary, ensure_ascii=False, indent=2))
        return 0 if summary["passed"] else 1
    except (
        OSError,
        UnicodeError,
        DiagnosisError,
        ModelConfigError,
        subprocess.SubprocessError,
    ) as error:
        code = error.code if isinstance(error, DiagnosisError) else "DEMO_INPUT_OR_CONFIG_ERROR"
        print(json.dumps({"status": "FAILED", "failureCode": code}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
