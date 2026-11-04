"""에이전트 루프: Anthropic Python SDK Tool Runner 로 작업 공간 도구를 부른다.

AI 에이전트 1 SPEC D-1·D-2.


- Claude 호출은 이 제어 프로세스만 한다. 키는 SDK 기본값(`ANTHROPIC_API_KEY` 환경 변수)으로 읽고,
  작업 공간 컨테이너에는 넘기지 않는다.
- 거절(`stop_reason = refusal`)은 실패가 아니라 "AI 검토 없음"이다.
  서버 측 fallback(`default`)을 켠다.
- 도는 횟수(`max_iterations`)와 출력 토큰(`max_tokens`)에 상한을 둔다(비용 상한, SPEC AD-7).
- 모델의 말은 판정이 아니다. 결과 판단(PASS 금지·기본 WARN)은 WAS 가 한다.
"""

from dataclasses import dataclass
from typing import Literal

from anthropic import AsyncAnthropic

from echo_agent.events import EventLevel, RunEventLog, RunStep
from echo_agent.sandbox import DockerSandbox
from echo_agent.tools import build_workspace_tools

DEFAULT_MODEL = "claude-opus-5-5"
DEFAULT_MAX_ITERATIONS = 12
DEFAULT_MAX_TOKENS = 8_000
FALLBACK_BETA = "server-side-fallback-2026-07-01"

Effort = Literal["low", "medium", "high"]

SYSTEM_PROMPT = """\
You are the EchoPort sandbox agent. You inspect, and when asked fix, a copy of a customer \
application before it is migrated between clouds.

Where you work:
- Every tool runs inside an isolated workspace container: no network, no credentials, \
read-only system files. /workspace holds a copy of the application. Nothing you change \
there reaches production.
- You cannot change production. Real changes happen only after a person reviews and \
approves your proposal.

How to work:
- Base every statement on files you read or commands you ran in the workspace. If you \
could not check something, say it is unknown instead of guessing.
- Never claim something passed unless you ran the check and saw it pass.
- Keep commands short and targeted. Do not try to reach the network.
- Finish with a short report: what you checked, what you found, what you changed (if \
anything), and what remains unknown.
"""


@dataclass(frozen=True)
class AgentOutcome:
    final_text: str
    stop_reason: str | None
    turns: int
    refused: bool
    input_tokens: int
    output_tokens: int


async def run_agent(
    client: AsyncAnthropic,
    sandbox: DockerSandbox,
    log: RunEventLog,
    task: str,
    *,
    step: RunStep = RunStep.ANALYZE,
    model: str = DEFAULT_MODEL,
    effort: Effort = "medium",
    max_iterations: int = DEFAULT_MAX_ITERATIONS,
    max_tokens: int = DEFAULT_MAX_TOKENS,
) -> AgentOutcome:
    tools = build_workspace_tools(sandbox, log, step)
    runner = client.beta.messages.tool_runner(
        model=model,
        max_tokens=max_tokens,
        system=SYSTEM_PROMPT,
        tools=tools,
        messages=[{"role": "user", "content": task}],
        max_iterations=max_iterations,
        output_config={"effort": effort},
        fallbacks="default",
        betas=[FALLBACK_BETA],
    )
    log.add(step, "agent started", model=model, effort=effort, max_iterations=max_iterations)

    turns = 0
    input_tokens = 0
    output_tokens = 0
    final_text = ""
    stop_reason: str | None = None
    refused = False
    async for message in runner:
        turns += 1
        stop_reason = message.stop_reason
        input_tokens += message.usage.input_tokens
        output_tokens += message.usage.output_tokens
        log.add(
            step,
            "model turn finished",
            turn=turns,
            stop_reason=stop_reason,
            input_tokens=message.usage.input_tokens,
            output_tokens=message.usage.output_tokens,
        )
        if stop_reason == "refusal":
            refused = True
            log.add(step, "model declined; no AI review for this run", EventLevel.WARN)
            break
        text = "".join(block.text for block in message.content if block.type == "text")
        if text:
            final_text = text

    log.add(
        step,
        "agent finished",
        turns=turns,
        stop_reason=stop_reason,
        refused=refused,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
    )
    return AgentOutcome(final_text, stop_reason, turns, refused, input_tokens, output_tokens)
