# echo-ai-agent

EchoPort AI 에이전트 러너. 이전 전에 고객 앱 사본을 **격리된 샌드박스**에서 점검·수정하고, 결과를 WAS에 낸다. 판정(PASS 금지·기본 WARN)과 승인은 WAS와 사람이 한다.

- 설계: [`specs/ai-1-sdk-model-sandbox.md`](specs/ai-1-sdk-model-sandbox.md)(SDK·모델·샌드박스), [`specs/ai-2-sandbox-runner.md`](specs/ai-2-sandbox-runner.md)(작업 공간·에이전트 루프), [`specs/ai-4-precheck-model-review.md`](specs/ai-4-precheck-model-review.md)(사전 점검 모델 검토)
- 스택: Python 3.13, Anthropic Python SDK(Tool Runner), Docker, uv

## 구조

```text
src/echo_agent/
├─ sandbox.py   # 작업 공간 컨테이너: 네트워크 없음·읽기 전용·비루트·권한 0·비밀 0, 실행마다 새로 만들고 지운다
├─ tools.py     # 모델 도구: workspace_exec · read_file · write_file (모두 컨테이너 안에서만)
├─ agent.py     # Tool Runner 루프(상한·fallback·거절 처리)
├─ events.py    # 실행 이벤트(seq·at·step·level·message·data)
├─ poc.py       # 샌드박스 PoC: 명령 실행 + 격리 확인 + 정리 확인
├─ was_client.py       # WAS 러너 API 클라이언트(claim·heartbeat·events·result), 표준 라이브러리만
├─ precheck_rules.py   # 사전 점검 규칙 비교(순수 함수): 설정 차이 → configDiff·경고·조치 안내
├─ precheck_model.py   # 사전 점검 모델 검토: Claude 한 번(구조화 출력) → AI WARN·model 칸
└─ precheck_runner.py  # 사전 점검 러너 루프(규칙 비교 → 모델 검토 → 결과 제출)
```

## 실행

```bash
uv sync
uv run ruff check . && uv run ruff format --check . && uv run mypy && uv run pytest   # Docker 시험 포함
uv run python -m echo_agent.poc               # 모델 없이 샌드박스 PoC
ANTHROPIC_API_KEY=… uv run python -m echo_agent.poc --with-model   # 모델이 명령 실행(과금)
```

- Docker 데몬이 없으면 Docker 시험은 건너뛴다.
- API 키는 이 프로세스의 환경 변수로만 넘긴다. 작업 공간 컨테이너에는 들어가지 않는다(시험이 확인).

## 사전 점검 러너 실행법

WAS 사전 점검 실행을 가져가 출발·도착 환경 설정 차이를 규칙으로 비교하고, Claude 를 한 번 불러 경고·조치 안내를 더해 결과로 낸다(AI 에이전트 4). 결과는 `simulated: false`(실제 `inputSnapshot`으로 계산한 값), `sandbox: null`이다. 모델 검토가 되면 `model: {id, effort, promptVersion, refusal}`(WAS가 `aiReviewed: true`로 표시)과 `origin: "AI"` WARN finding 이 붙고, 모델이 실패·거절하거나 마감이 가까우면 규칙 결과만으로 `SUCCEEDED`·`model: null`이다(SPEC [`ai-4`](specs/ai-4-precheck-model-review.md) D-7·D-8·D-9). 계약: [`specs/ai-1-appendix-a-was-runner-contract.md`](specs/ai-1-appendix-a-was-runner-contract.md) §3.2·§3.3. **WAS 쪽 러너 API(echo-was)가 병합·배포돼야 실제로 돈다.**

1. **러너 토큰 발급(WAS 어드민).** WAS 파드에서 한 번 실행한다. 원문은 이때 한 번만 출력된다.

   ```bash
   python -m app.scripts.issue_runner_token --name echo-sandbox-runner   # 철회: --revoke echo-sandbox-runner
   ```

   출력된 원문은 Secret Manager 비밀에 바로 넣고, 채팅·로그·파일에 남기지 않는다. 샌드박스 VM은 그 비밀을 읽기만 한다.

2. **환경 변수로만 넘긴다.** 명령줄 인자·`.env` 커밋으로 넘기지 않는다.

   | 변수 | 값 |
   |---|---|
   | `ECHO_WAS_URL` | 예 `https://api.echoport.uk` (https만, 로컬 개발 `http://localhost`만 예외) |
   | `ECHO_RUNNER_TOKEN` | `echo_rnr_…` 러너 토큰(1번 비밀에서 읽음) |
   | `ECHO_RUNNER_NAME` | 선택. 발급 때 쓴 이름, 기본 `echo-sandbox-runner` |
   | `ANTHROPIC_API_KEY` | 모델 키(VM 은 Secret Manager 비밀에서 읽음). 없으면 러너가 시작하지 않는다(종료 코드 2). `--no-model` 이면 필요 없음 |

3. **실행.**

   ```bash
   uv run python -m echo_agent.precheck_runner --once   # 한 번 가져가 보고 끝(실행이 없으면 종료 코드 0)
   uv run python -m echo_agent.precheck_runner          # 계속: 실행이 없으면 5초 뒤 다시, SIGTERM 으로 멈춤
   uv run python -m echo_agent.precheck_runner --once --no-model   # 모델 없이 규칙만(과금 없음)
   ```

   흐름: `runs:claim` → 첫 하트비트(CLAIMED → RUNNING) → 30초마다 하트비트 → 이벤트 `INPUT_LOAD`·`CONFIG_DIFF`·`ANALYZE` → 모델 검토(`ANALYZE` 이벤트 "model review started/finished") → `result`. 마감 1분 전이 지나면 `FAILED`·`DEADLINE`, 스냅숏 모양이 v1이 아니면 `FAILED`·`INPUT_INVALID`, 그 밖의 예외는 `FAILED`·`RUNNER_ERROR`.

4. **비교 규칙**(`precheck_rules.py`, 순수 함수): 환경 종류 · 설정 키 합집합(중첩은 `a.b`, 이름에 `secret`이 들어간 칸은 옮기지 않음) · 이미지 digest(도착에 없음 포함) · 변수 이름 집합(출발에만 있으면 WARN) · 최근 findings의 FAIL·WARN. 차이가 하나라도 있으면 `config-diff` 경고 1건 + 조치 안내(`suggestedFix`), 없으면 PASS. 최근 findings에 FAIL·WARN이 있으면 `recent-findings` 경고가 하나 더 붙는다.

5. **모델 검토**(`precheck_model.py`, 실행마다 호출 한 번, 과금): `claude-opus-5-5`·effort `medium`·도구 없음·구조화 출력·서버 측 fallback. 보내는 것은 허용 목록으로 새로 만든 입력(서비스·두 환경의 종류·설정·digest·변수 이름·최근 findings·규칙 결과)뿐이고, UUID·토큰·키·비밀 이름 칸은 넣지 않는다. 입력은 `<precheck_input>` 데이터 태그 안에 넣고 그 안의 지시를 따르지 않게 한다. 받은 경고는 모두 `WARN`(AI 는 PASS 를 낼 수 없음)이고 요약은 `ai-summary` finding 하나다.

## 지키는 것

- 모델이 고른 명령은 작업 공간 컨테이너 안 `sh -c`에서만 돈다. 호스트는 셸을 거치지 않는다.
- 작업 공간에는 네트워크·키·토큰·볼륨·Docker 소켓이 없다.
- 의존성은 `exclude-newer` 날짜 이전 배포본만 쓰고, 액션·이미지는 SHA·digest로 고정한다.
