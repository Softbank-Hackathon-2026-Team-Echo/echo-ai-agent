# echo-ai-agent

EchoPort AI 에이전트 러너. 이전 전에 고객 앱 사본을 **격리된 샌드박스**에서 점검·수정하고, 결과를 WAS에 낸다. 판정(PASS 금지·기본 WARN)과 승인은 WAS와 사람이 한다.

- 설계: [`specs/ai-1-sdk-model-sandbox.md`](specs/ai-1-sdk-model-sandbox.md)(SDK·모델·샌드박스), [`specs/ai-2-sandbox-runner.md`](specs/ai-2-sandbox-runner.md)(작업 공간·에이전트 루프)
- 스택: Python 3.13, Anthropic Python SDK(Tool Runner), Docker, uv

## 구조

```text
src/echo_agent/
├─ sandbox.py   # 작업 공간 컨테이너: 네트워크 없음·읽기 전용·비루트·권한 0·비밀 0, 실행마다 새로 만들고 지운다
├─ tools.py     # 모델 도구: workspace_exec · read_file · write_file (모두 컨테이너 안에서만)
├─ agent.py     # Tool Runner 루프(상한·fallback·거절 처리)
├─ events.py    # 실행 이벤트(seq·at·step·level·message·data)
└─ poc.py       # 샌드박스 PoC: 명령 실행 + 격리 확인 + 정리 확인
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

## 지키는 것

- 모델이 고른 명령은 작업 공간 컨테이너 안 `sh -c`에서만 돈다. 호스트는 셸을 거치지 않는다.
- 작업 공간에는 네트워크·키·토큰·볼륨·Docker 소켓이 없다.
- 의존성은 `exclude-newer` 날짜 이전 배포본만 쓰고, 액션·이미지는 SHA·digest로 고정한다.
