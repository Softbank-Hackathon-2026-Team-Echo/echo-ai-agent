"""Local diagnosis and reusable build-time syntax checker; no WAS mutation.

python -m echo_agent.diagnosis_cli check --source app/static/index.html --local-node
python -m echo_agent.diagnosis_cli diagnose --input request.json [--model-response reply.json]
"""

import argparse
import asyncio
import json
import os
import shutil
import subprocess
import sys
from importlib.resources import files
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from echo_agent.diagnosis import DiagnosisService
from echo_agent.diagnosis_check import CheckResult, DockerSyntaxChecker, check_payload, parse_check
from echo_agent.diagnosis_input import (
    MAX_INPUT_BYTES,
    MAX_SOURCE_BYTES,
    DiagnosisError,
    strict_json,
)
from echo_agent.diagnosis_model import DiagnosisModel
from echo_agent.diagnosis_result import to_was_result
from echo_agent.precheck_model import ModelConfigError


def local_check(source: str) -> CheckResult:
    """Explicit build/CI mode: invoke the trusted parser, never run customer JS."""
    node = shutil.which("node")
    if node is None:
        return CheckResult(False, False, None, reason="NODE_UNAVAILABLE")
    payload = check_payload(source)
    script = str(files("echo_agent").joinpath("diagnosis_check.cjs"))
    try:
        completed = subprocess.run(  # noqa: S603 — fixed checker; customer code is stdin JSON
            [node, script],
            input=payload,
            text=True,
            capture_output=True,
            check=False,
            timeout=15,
            env={"PATH": os.path.dirname(node)},
        )
        return parse_check(completed.returncode, completed.stdout)
    except (OSError, subprocess.SubprocessError):
        return CheckResult(False, False, None, reason="CHECK_UNAVAILABLE")


def _read(path: Path, limit: int) -> str:
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise DiagnosisError("INPUT_TOO_LARGE")
    return data.decode("utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    check = commands.add_parser("check", help="fail a build on an inline JavaScript syntax error")
    check.add_argument("--source", type=Path, required=True)
    check.add_argument(
        "--local-node", action="store_true", help="parse only using CI's Node; default is Docker"
    )
    diagnose = commands.add_parser("diagnose", help="read proposed WAS input and write result JSON")
    diagnose.add_argument("--input", type=Path, required=True)
    diagnose.add_argument(
        "--model-response", type=Path, help="offline model replay; always simulated, no API calls"
    )
    diagnose.add_argument(
        "--was-result", action="store_true", help="project output to WAS #98 diagnosis fields"
    )
    args = parser.parse_args(argv)
    try:
        if args.command == "check":
            source = _read(args.source, MAX_SOURCE_BYTES)
            checked = (
                local_check(source)
                if args.local_node
                else asyncio.run(DockerSyntaxChecker().check(source, 30))
            )
            print(json.dumps(checked.to_json(), ensure_ascii=False))
            for issue in checked.issues:
                print(
                    f"{issue['path']}:{issue['line']}: SyntaxError: {issue['message']}",
                    file=sys.stderr,
                )
            return 0 if checked.available and checked.passed else 1
        snapshot = strict_json(_read(args.input, MAX_INPUT_BYTES))
        if not isinstance(snapshot, dict):
            raise DiagnosisError("INPUT_INVALID")
        if args.model_response:
            response = _read(args.model_response, MAX_INPUT_BYTES)

            async def replay(**kwargs: Any) -> Any:
                return SimpleNamespace(
                    stop_reason="end_turn",
                    model="fixture-replay",
                    content=[SimpleNamespace(type="text", text=response)],
                )

            model = DiagnosisModel(replay, simulated=True)
        else:
            model = DiagnosisModel.from_env()
        result = asyncio.run(DiagnosisService(model).execute(snapshot))
        if args.was_result:
            result = to_was_result(result)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0 if result["status"] == "SUCCEEDED" else 1
    except (OSError, UnicodeError, DiagnosisError, ModelConfigError) as error:
        code = error.code if isinstance(error, DiagnosisError) else "LOCAL_INPUT_OR_CONFIG_ERROR"
        print(json.dumps({"status": "FAILED", "failureCode": code}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
