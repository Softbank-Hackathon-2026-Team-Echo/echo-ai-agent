"""Manual real-tool rehearsal, isolated fixture + archive adapter; never a production acceptance.

Requires uv-sync environment, Docker, Trivy and internet. --model adds one real model correction.
ANTHROPIC_API_KEY must already be supplied securely; it is never written or printed.
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

from echo_agent.apply_runner import ApplyRunner, subprocess_runner
from echo_agent.cve_runner import CveRunner
from echo_agent.diagnosis_model import DiagnosisModel
from echo_agent.events import RunEventLog
from echo_agent.was_client import ClaimedRun

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--model", action="store_true")
parser.add_argument("--output-dir", type=Path)
args = parser.parse_args()
root = args.output_dir or Path(tempfile.mkdtemp(prefix="echo-cve-rehearsal-"))
if args.output_dir:
    root.mkdir(parents=True, exist_ok=False)
from_version = "1.26.0" if args.model else "2.5.0"
source = root / "source"
source.mkdir(exist_ok=True)
(source / "pyproject.toml").write_text(
    '[project]\nname="echo-cve-fixture"\nversion="0.1.0"\nrequires-python=">=3.13"\ndependencies=["urllib3==2.5.0"]\n'
)
if args.model:
    manifest = source / "pyproject.toml"
    manifest.write_text(
        manifest.read_text().replace('"urllib3==2.5.0"', '"urllib3==1.26.0", "requests==2.25.0"')
    )
(source / "app.py").write_text(
    "from http.server import BaseHTTPRequestHandler, HTTPServer\nclass Handl"
    "er(BaseHTTPRequestHandler):\n def do_GET(self):\n  self.send_response(20"
    '0 if self.path == "/healthz" else 404); self.end_headers(); self.wfile'
    '.write(b"ok")\nHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()\n'
)
(source / "Dockerfile").write_text(
    "FROM python:3.13-slim AS build\nRUN pip install --no-cache-dir uv==0.8."
    "17\nWORKDIR /app\nCOPY pyproject.toml uv.lock ./\nRUN uv sync --frozen --"
    "no-dev --no-install-project\nFROM python:3.13-slim\nRUN apt-get update &"
    "& apt-get upgrade -y && rm -rf /var/lib/apt/lists/* && python -m pip u"
    "ninstall -y pip\nWORKDIR /app\nCOPY --from=build /app/.venv /opt/venv\nCO"
    'PY app.py ./\nENV PATH="/opt/venv/bin:$PATH"\nUSER 1001\nCMD ["python", "'
    'app.py"]\n'
)


def check(args, timeout=180):
    r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)  # noqa: S603 — fixed tool calls, no shell
    if r.returncode:
        raise RuntimeError(r.stderr[-2000:])
    return r.stdout.strip()


uv = str(Path(sys.executable).parent / "uv")
check(
    [uv, "lock", "--project", str(source), "--python", sys.executable, "--no-build", "--no-sources"]
)
check(["docker", "build", "--pull", "-t", "echo-cve-baseline:local", str(source)], 300)
image_id = check(["docker", "image", "inspect", "--format", "{{.Id}}", "echo-cve-baseline:local"])
archive = root / "baseline.tar"
check(["docker", "save", "-o", str(archive), "echo-cve-baseline:local"])
ref = "fixture.local/cve/baseline@" + image_id
os.environ["ECHO_CVE_REMEDIATION"] = "on"
os.environ["ECHO_CUSTOMER_IMAGE_PREFIXES"] = "fixture.local/cve"
reports = []


def command(args, timeout, env):
    args = list(args)
    if args[:2] == ["trivy", "image"] and args[-1] == ref:
        args = args[:-1] + ["--input", str(archive)]
    r = subprocess_runner(args, timeout, env)
    if args[:2] == ["trivy", "image"] and "--format" in args and "json" in args:
        try:
            data = json.loads(r.stdout)
            name = "baseline-report.json" if "--input" in args else "patched-report.json"
            (root / name).write_text(json.dumps(data))
            reports.append(name)
        except ValueError:
            pass
    return r


def fetch(repo, commit, dest, timeout):
    shutil.copytree(source, dest)
    return dest


now = datetime.now(UTC)
snapshot = {
    "schemaVersion": 1,
    "trigger": "CVE_WATCH",
    "service": {"repo": "fixture/echo-cve"},
    "sourceCommitSha": "a" * 40,
    "imageRef": ref,
    "imageDigest": image_id,
    "finding": {
        "advisoryId": "CVE-2025-66418",
        "aliases": ["GHSA-gm62-xv2j-4w53"],
        "synthetic": False,
    },
    "remediation": {
        "ecosystem": "PyPI",
        "package": "urllib3",
        "fromVersion": from_version,
        "toVersion": "2.8.0",
    },
    "packages": [{"ecosystem": "PyPI", "name": "urllib3", "version": from_version}],
}
run = ClaimedRun(
    "cve-real-local",
    "CHANGE_PROPOSAL",
    None,
    None,
    None,
    None,
    snapshot,
    None,
    None,
    now + timedelta(minutes=15),
    None,
    "local-fixture",
)
events = RunEventLog(run.id)
verifier = ApplyRunner(run_command=command, fetch_source=fetch)
result = CveRunner(
    DiagnosisModel.from_env() if args.model else None, fetch=fetch, verifier=verifier
).execute(run, events, lambda: None)
(root / "result.json").write_text(json.dumps(result, ensure_ascii=False, indent=2))
(root / "events.json").write_text(
    json.dumps([e.to_json() for e in events.events], ensure_ascii=False, indent=2)
)
print(
    json.dumps(
        {
            "outputDirectory": str(root),
            "status": result["status"],
            "patchCount": len(result["patches"]),
            "diagnosis": result["diagnosis"],
            "reports": reports,
        },
        ensure_ascii=False,
    )
)
check(["docker", "rmi", "echo-cve-baseline:local"])
archive.unlink(missing_ok=True)
