"""샌드박스 PoC(AI 에이전트 1 SPEC §9): 샌드박스에서 명령 하나를 실제로 실행하고 격리를 확인한다.

    uv run python -m echo_agent.poc               # 모델 없이: 명령 실행 + 격리 확인
    uv run python -m echo_agent.poc --with-model  # 모델이 명령 실행(API 키 필요, 과금)

결과는 이벤트(JSON 줄)로 출력한다. 격리 확인이 하나라도 실패하면 종료 코드 1.
"""

import argparse
import asyncio
import json
import os
import secrets
import sys
from dataclasses import dataclass

from anthropic import AsyncAnthropic

from echo_agent.agent import run_agent
from echo_agent.events import EventLevel, RunEventLog, RunStep
from echo_agent.sandbox import SANDBOX_LABEL, DockerSandbox

POC_COMMAND = "python -c 'print(1)'"

# 작업 공간에 있어도 되는 환경 변수 이름.
# 기반 이미지(python:3.13-slim)가 넣는 값과 docker 기본값뿐이다.
# GPG_KEY 는 CPython 배포 서명 공개키 지문(비밀 아님)이다. 이 밖의 이름이 보이면 실패다.
ALLOWED_ENV_NAMES = frozenset(
    {"PATH", "HOME", "HOSTNAME", "LANG", "PWD", "PYTHON_VERSION", "PYTHON_SHA256", "GPG_KEY"}
)


@dataclass(frozen=True)
class IsolationCheck:
    name: str
    command: str
    # 격리가 지켜졌을 때 참이 되는 조건(종료 코드·출력으로 판단).
    expect: str


ISOLATION_CHECKS = (
    IsolationCheck(
        "network_blocked",
        'python -c "import urllib.request; '
        "urllib.request.urlopen('https://example.com', timeout=5)\"",
        "nonzero_exit",
    ),
    IsolationCheck(
        "metadata_blocked",
        'python -c "import urllib.request; urllib.request.urlopen('
        "'http://169.254.169.254/computeMetadata/v1/', timeout=3)\"",
        "nonzero_exit",
    ),
    IsolationCheck("root_fs_read_only", "touch /etc/echo-test", "nonzero_exit"),
    IsolationCheck("runs_as_non_root", "id -u", "stdout:65532"),
    IsolationCheck(
        "no_capabilities", "grep CapEff /proc/self/status", "stdout:CapEff:\t0000000000000000"
    ),
    IsolationCheck("only_allowed_env", "env | cut -d= -f1 | sort", "env_names_allowed"),
)


def _passed(check: IsolationCheck, exit_code: int, stdout: str) -> bool:
    if check.expect == "nonzero_exit":
        return exit_code != 0
    if check.expect == "env_names_allowed":
        names = {line.strip() for line in stdout.splitlines() if line.strip()}
        return exit_code == 0 and names <= ALLOWED_ENV_NAMES
    expected = check.expect.removeprefix("stdout:")
    return exit_code == 0 and stdout.strip() == expected


async def _leftover_containers(run_id: str) -> int:
    process = await asyncio.create_subprocess_exec(
        "docker",
        "ps",
        "--all",
        "--quiet",
        "--filter",
        f"label={SANDBOX_LABEL}",
        "--filter",
        f"label=echo.run-id={run_id}",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    stdout, _ = await process.communicate()
    return len(stdout.split())


async def run_poc(with_model: bool) -> int:
    run_id = f"poc-{secrets.token_hex(4)}"
    log = RunEventLog(run_id)
    failures = 0
    async with DockerSandbox(run_id) as sandbox:
        log.add(RunStep.SANDBOX_CREATE, "sandbox created", sandbox=sandbox.name)
        await sandbox.load_files({"README.txt": b"echoport sandbox poc\n"})
        log.add(RunStep.INPUT_LOAD, "workspace files loaded", files=1)

        result = await sandbox.exec(POC_COMMAND)
        ok = result.exit_code == 0 and result.stdout.strip() == "1"
        failures += not ok
        log.add(
            RunStep.ANALYZE,
            "poc command finished",
            EventLevel.INFO if ok else EventLevel.ERROR,
            command=POC_COMMAND,
            exit_code=result.exit_code,
            stdout=result.stdout.strip(),
        )

        for check in ISOLATION_CHECKS:
            outcome = await sandbox.exec(check.command, timeout_seconds=15)
            passed = _passed(check, outcome.exit_code, outcome.stdout)
            failures += not passed
            log.add(
                RunStep.PATCH_VERIFY,
                "isolation check finished",
                EventLevel.INFO if passed else EventLevel.ERROR,
                check=check.name,
                passed=passed,
                exit_code=outcome.exit_code,
            )

        if with_model:
            agent_outcome = await run_agent(
                AsyncAnthropic(),
                sandbox,
                log,
                f"Run `{POC_COMMAND}` in the workspace with the workspace_exec tool and report "
                "the exact output. Do nothing else.",
                effort="low",
                max_iterations=4,
                max_tokens=2_000,
            )
            log.add(RunStep.ANALYZE, "agent report", report=agent_outcome.final_text)

    leftover = await _leftover_containers(run_id)
    failures += leftover != 0
    log.add(
        RunStep.SANDBOX_DELETE,
        "sandbox deleted",
        EventLevel.INFO if leftover == 0 else EventLevel.ERROR,
        leftover_containers=leftover,
    )
    for event in log.events:
        sys.stdout.write(json.dumps(event.to_json(), ensure_ascii=False) + "\n")
    return 1 if failures else 0


def main() -> None:
    parser = argparse.ArgumentParser(description="EchoPort sandbox PoC")
    parser.add_argument("--with-model", action="store_true", help="Tool Runner 로 모델 호출(과금)")
    args = parser.parse_args()
    if args.with_model and not os.environ.get("ANTHROPIC_API_KEY"):
        sys.stderr.write("ANTHROPIC_API_KEY 환경 변수가 없습니다\n")
        raise SystemExit(2)
    raise SystemExit(asyncio.run(run_poc(args.with_model)))


if __name__ == "__main__":
    main()
