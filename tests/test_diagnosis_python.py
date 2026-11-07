"""demo-app #7 startup syntax failure through diagnosis and approved-apply contracts.

Model and Docker build/Trivy/health are fake here; Python parsing and git apply are real.
The separately marked Docker test uses the actual isolated, pinned parser image.
"""

import asyncio
import copy
import json
import subprocess
import sys
from importlib.resources import files
from pathlib import Path
from typing import Any

import pytest

from echo_agent.apply_runner import ApplyRunner, apply_patch_to_files
from echo_agent.diagnosis import DiagnosisService
from echo_agent.diagnosis_check import CheckResult, DockerSyntaxChecker, parse_check
from echo_agent.diagnosis_input import PYTHON_FILE, DiagnosisError, DiagnosisInput, prepare_evidence
from echo_agent.diagnosis_model import DiagnosisModel, validate_answer
from echo_agent.diagnosis_result import to_was_result
from echo_agent.events import RunEventLog
from tests.test_diagnosis import Checks, FakeModel, snapshot
from tests.test_diagnosis_runner import (
    FakeCreate,
    FakeTools,
    _apply_snapshot,
    _claimed,
    _diagnose,
    _fetcher,
    _response,
    _snapshot,
)

BAD = '    return FileResponse(INDEX_HTML, media_type="text/html; charset=utf-8"'
GOOD = BAD + ")"
BROKEN = "# fixture\n" * 211 + "def index():\n" + BAD + "\n"
FIXED = BROKEN.replace(BAD, GOOD)
TAIL = [
    '  File "/app/app/main.py", line 213',
    BAD,
    "                       ^",
    "SyntaxError: '(' was never closed",
]
ANSWER = {
    "analysisStatus": "diagnosed",
    "category": "CODE",
    "summary": "app/main.py 213행의 닫는 괄호가 없어 컨테이너를 시작하지 못했습니다.",
    "evidenceIds": ["EV000004"],
    "sourceEvidenceIds": ["SC000213"],
    "canFix": True,
    "reason": "누락된 닫는 괄호 하나를 복구합니다.",
    "limitations": [],
    "edits": [
        {
            "path": PYTHON_FILE,
            "oldText": BAD,
            "newText": GOOD,
            "evidenceIds": ["EV000004"],
            "sourceEvidenceIds": ["SC000213"],
        }
    ],
}


def request(source: str = BROKEN) -> dict[str, Any]:
    return snapshot(
        allowedFiles=[PYTHON_FILE],
        sourceFiles=[{"path": PYTHON_FILE, "content": source}],
        logs=[],
        failure={"code": "CONTAINER_START_FAILED", "exitCode": 1, "logTail": TAIL},
    )


class Parser:
    """Invoke only our fixed parser; compile never executes customer text."""

    def __init__(self, tmp_path: Path) -> None:
        self.input = tmp_path / "parser-input.json"

    async def check(self, source: str, seconds: float) -> CheckResult:
        self.input.write_text(json.dumps({"path": PYTHON_FILE, "code": source}))
        result = await asyncio.to_thread(
            subprocess.run,
            [
                sys.executable,
                "-I",
                str(files("echo_agent") / "diagnosis_python_check.py"),
                str(self.input),
            ],
            capture_output=True,
            text=True,
            timeout=seconds,
        )
        return parse_check(result.returncode, result.stdout, PYTHON_FILE)


def fetch(repo: str, commit: str, dest: Path, timeout: float) -> Path:
    root = _fetcher()(repo, commit, dest, timeout)
    (root / PYTHON_FILE).write_text(BROKEN)
    return root


async def test_python_failure_produces_verified_was_patch(tmp_path: Path) -> None:
    model = FakeModel(ANSWER)
    result = await DiagnosisService(DiagnosisModel(model.create), Parser(tmp_path)).execute(
        request()
    )
    assert result["status"] == "SUCCEEDED"
    assert result["diagnosis"]["verification"]["before"]["issues"][0]["line"] == 213
    assert result["diagnosis"]["verification"]["after"]["passed"] is True
    public = to_was_result(result, log_tail=True)
    assert public["diagnosis"]["fixable"]
    assert {e["source"] for e in public["diagnosis"]["evidence"]} == {"FILE", "LOG"}
    assert public["diagnosis"]["evidence"][0]["line"] == 4
    (patch,) = public["patches"]
    assert patch["files"] == [PYTHON_FILE]
    assert any(c["name"] == "PYTHON_SYNTAX" for c in patch["checks"])
    assert apply_patch_to_files({PYTHON_FILE: BROKEN}, patch["diff"])[PYTHON_FILE] == FIXED
    assert len(model.calls) == 1


def test_traceback_selects_python_even_when_html_is_present_and_apply_reuses_it(
    tmp_path: Path,
) -> None:
    model = FakeCreate(_response(json.dumps(ANSWER)))
    status, failure, outcome, _ = _diagnose(
        tmp_path,
        model,
        _snapshot(failure={"logTail": TAIL}),
        fetch=fetch,
        checker=Parser(tmp_path),
    )
    assert (status, failure) == ("SUCCEEDED", None)
    (patch,) = outcome.patches
    assert any(c["name"] == "GIT_APPLY" for c in patch["checks"])
    tools = FakeTools()
    runner = ApplyRunner(
        repo_root=tmp_path,
        run_command=tools,
        fetch_source=fetch,
        workspace_parent=tmp_path,
    )
    result = runner.execute(
        _claimed(_apply_snapshot(patch["diff"], [PYTHON_FILE]), kind="APPLY_PATCH"),
        RunEventLog("python-apply"),
        lambda: None,
    )
    assert result[:2] == ("SUCCEEDED", None)
    assert tools.context_files[PYTHON_FILE] == FIXED
    assert "AUTO_MIGRATE=false" in tools.healthz_env
    assert not any("push" in command for command in tools.calls)
    assert not list(tmp_path.glob("echo-apply-*"))


@pytest.mark.parametrize(
    "new",
    [
        "    return None",
        GOOD + "\n    print('extra')",
        GOOD.replace("INDEX_HTML", "OTHER"),
        GOOD + "# skip",
        GOOD.replace("text/html", "text/html)"),
        GOOD + ")))",
        BAD[:-1],
        BAD + "\r)",
    ],
)
def test_python_scope_rejects_replacements_deletions_new_lines_and_extra_code(new: str) -> None:
    parsed = DiagnosisInput.parse(request())
    answer = copy.deepcopy(ANSWER)
    answer["edits"][0]["newText"] = new
    with pytest.raises(DiagnosisError, match="PATCH_TARGET_FORBIDDEN"):
        validate_answer(
            answer, parsed, prepare_evidence(parsed), can_patch=True, repair_lines=frozenset({213})
        )


@pytest.mark.parametrize("lines", [frozenset(), frozenset({212})])
def test_python_edit_must_match_independent_error_line(lines: frozenset[int]) -> None:
    parsed = DiagnosisInput.parse(request())
    with pytest.raises(DiagnosisError, match="PATCH_TARGET_FORBIDDEN"):
        validate_answer(
            ANSWER, parsed, prepare_evidence(parsed), can_patch=True, repair_lines=lines
        )


@pytest.mark.parametrize("paths", [["app/other.py"], ["../app/main.py"], [PYTHON_FILE, "a.py"]])
def test_caller_cannot_expand_allowed_files(paths: list[str]) -> None:
    with pytest.raises(DiagnosisError, match="PATCH_TARGET_FORBIDDEN"):
        DiagnosisInput.parse({**request(), "allowedFiles": paths})


async def test_clean_python_is_not_patched_even_if_model_claims_error(tmp_path: Path) -> None:
    result = await DiagnosisService(
        DiagnosisModel(FakeModel(ANSWER).create), Parser(tmp_path)
    ).execute(
        request(FIXED),
    )
    assert result["failureCode"] == "INVALID_DIAGNOSIS_STATE" and not result["patches"]


async def test_python_secrets_are_masked_and_not_patched() -> None:
    answer = {**ANSWER, "canFix": False, "edits": []}
    model = FakeModel(answer)
    checks = Checks(CheckResult(True, True, "Python 3.13.13"))
    result = await DiagnosisService(DiagnosisModel(model.create), checks).execute(
        request(BROKEN + 'password = "private-test-value"\n'),
    )
    assert checks.calls == 0 and not result["patches"]
    assert "private-test-value" not in json.dumps([model.calls, result])


@pytest.mark.parametrize("docker", [False, pytest.param(True, marks=pytest.mark.docker)])
async def test_python_parser_never_executes_source(tmp_path: Path, docker: bool) -> None:
    checker = DockerSyntaxChecker(path=PYTHON_FILE) if docker else Parser(tmp_path)
    before = await checker.check(BROKEN, 30)
    after = await checker.check(FIXED, 30)
    assert before.available and not before.passed and before.issues[0]["line"] == 213
    assert after.available and after.passed
    # No imports, file IO, or infinite loop from supplied source may run.
    harmless_to_compile = (
        "import nonexistent_customer_library\nraise RuntimeError('never execute')\n"
    )
    assert (await checker.check(harmless_to_compile, 30)).passed
    assert (await checker.check("while True: pass\n", 30)).passed
    assert not (await checker.check("return 1\n", 30)).passed


def test_checker_rejects_wrong_language_or_path_in_output() -> None:
    for version, path in [("v24.0.0", PYTHON_FILE), ("Python 3.13.13", "other.py")]:
        value = {"version": version, "issues": [{"path": path, "line": 213, "message": "missing"}]}
        assert not parse_check(1, json.dumps(value), PYTHON_FILE).available
