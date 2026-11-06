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
├─ apply_runner.py     # 반영 실행(APPLY_PATCH): 승인된 패치 적용·빌드·Trivy·healthz → 결과(스위치 기본 꺼짐)
└─ precheck_runner.py  # 사전 점검 러너 루프(규칙 비교 → 모델 검토 → 결과 제출)
deploy/
├─ echo-precheck-runner.service  # 샌드박스 VM systemd 유닛(전용 사용자·쓰기 금지·죽으면 다시 뜸)
├─ precheck-runner-start.sh      # 시작 스크립트: Secret Manager → 환경 변수 → 러너
└─ runner.env.example            # 비밀 없는 환경 파일(모델 켜기·끄기 포함)
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

WAS 사전 점검 실행을 가져가 출발·도착 환경 설정 차이를 규칙으로 비교하고, Claude 를 한 번 불러 경고·조치 안내를 더해 결과로 낸다(AI 에이전트 4). 결과는 `simulated: false`(실제 `inputSnapshot`으로 계산한 값), `sandbox: null`이다. 모델 검토가 되면 `model: {id, effort, promptVersion, refusal}`(WAS가 `aiReviewed: true`로 표시)과 `origin: "AI"` WARN finding 이 붙고, 모델이 실패·거절하거나 마감이 가까우면 규칙 결과만으로 `SUCCEEDED`·`model: null`이다(SPEC [`ai-4`](specs/ai-4-precheck-model-review.md) D-7·D-8·D-9). 계약: [`specs/ai-1-appendix-a-was-runner-contract.md`](specs/ai-1-appendix-a-was-runner-contract.md) §3.2·§3.3. **WAS 쪽 러너 API(echo-was)가 병합·배포돼야 실제로 돈다.** 모델 API 로 요청을 보냈으면(실패·거절이어도) 레지던시 기록 `processing: {location: "gcp/asia-northeast3", sandbox: false, modelProvider: "ANTHROPIC", model: <요청 모델>, modelRegion: null, dataClasses: ["CONFIG", "FINDINGS"], externalTransfer: true, externalTransferBytes: <요청 본문 바이트>}` 를 싣고(echo-was #77·#80, 비밀값을 안 보내 리전 없는 Anthropic 호출이 조건부 허용), 모델을 부르지 않으면 칸을 뺀다(SPEC [`ai-4`](specs/ai-4-precheck-model-review.md) 9절).

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
   uv run python -m echo_agent.precheck_runner --once --patch      # 규칙 패치 켬(기본은 끔. WAS 가 patches[].origin 을 받는 뒤에만, echo-was #79. VM 서비스는 아래 "규칙 패치 켜기·끄기")
   ```

   규칙 패치는 손 실행·VM 모두 기본이 끔이다. 켰을 때 WAS 가 패치가 실린 결과를 422 `RESULT_INVALID` 로 거절하면 `patches=[]` 로 한 번 다시 내고 WARN 이벤트("result rejected; resent without rule patch")를 남긴다.

   규칙 패치의 대상과 규칙: [시나리오 사본 README](scenarios/demo-app-0ff0d44/README.md).

   흐름: `runs:claim` → 첫 하트비트(CLAIMED → RUNNING) → 30초마다 하트비트 → 이벤트 `INPUT_LOAD`·`CONFIG_DIFF`·`ANALYZE` → 모델 검토(`ANALYZE` 이벤트 "model review started/finished") → `result`. 마감 1분 전이 지나면 `FAILED`·`DEADLINE`, 스냅숏 모양이 v1이 아니면 `FAILED`·`INPUT_INVALID`, 그 밖의 예외는 `FAILED`·`RUNNER_ERROR`.

4. **비교 규칙**(`precheck_rules.py`, 순수 함수): 환경 종류 · 설정 키 합집합(중첩은 `a.b`, 이름에 `secret`이 들어간 칸은 옮기지 않음) · 이미지 digest(도착에 없음 포함) · 변수 이름 집합(출발에만 있으면 WARN) · 최근 findings의 FAIL·WARN. 차이가 하나라도 있으면 `config-diff` 경고 1건 + 조치 안내(`suggestedFix`), 없으면 PASS. 최근 findings에 FAIL·WARN이 있으면 `recent-findings` 경고가 하나 더 붙는다.

5. **모델 검토**(`precheck_model.py`, 실행마다 호출 한 번, 과금): `claude-opus-5-5`·effort `medium`·도구 없음·구조화 출력·서버 측 fallback. 보내는 것은 허용 목록으로 새로 만든 입력(서비스·두 환경의 종류·설정·digest·변수 이름·최근 findings·규칙 결과)뿐이고, UUID·토큰·키·비밀 이름 칸은 넣지 않는다. 입력은 `<precheck_input>` 데이터 태그 안에 넣고 그 안의 지시를 따르지 않게 한다. 받은 경고는 모두 `WARN`(AI 는 PASS 를 낼 수 없음)이고 요약은 `ai-summary` finding 하나다.

## VM 상시 실행 (systemd)

재난 흐름에서는 사람이 화면에서 점검을 만들면 러너가 바로 가져가야 한다. 러너가 꺼져 있으면 점검이 `QUEUED` 에 머물다 15분 뒤 `TIMED_OUT` 이 되고, 승인 단계가 멈춘다(비상구는 C-AI-1 기한부 예외). 그래서 샌드박스 VM `echo-sandbox-runner`(`team-echo-final`, `asia-northeast3-a`, IAP SSH 만)에서 systemd 서비스 `echo-precheck-runner` 로 계속 켜 둔다. 설계: SPEC [`ai-4`](specs/ai-4-precheck-model-review.md) 8절.

- **과금:** 켜져 있고 `ECHO_PRECHECK_MODEL=on` 이면 **점검 실행마다 모델을 1회** 부른다. 실행이 없을 때는 5초마다 WAS 에 claim 만 하고 모델은 부르지 않는다.
- **비밀:** 토큰·키는 시작할 때 VM 서비스 계정으로 Secret Manager(`echo-sandbox-was-runner-token`·`echo-sandbox-anthropic-api-key`)에서 읽어 러너 프로세스의 환경 변수로만 넘긴다. 디스크·로그에 남지 않는다.

```text
/opt/echo-ai-agent/                  root 소유, 서비스는 읽기만
├─ bin/uv                            uv 0.8.17
├─ python/                           uv 가 받은 CPython 3.13
├─ releases/<sha>/                   git archive + .venv(--no-dev) + .deployed-rev
└─ current -> releases/<sha>
/etc/echo-precheck-runner/runner.env 비밀 없는 설정(deploy/runner.env.example)
/etc/systemd/system/echo-precheck-runner.service
/var/lib/echo-precheck-runner/       서비스 전용 쓰기 자리(gcloud 설정)
```

아래 명령은 VM 안에서 친다. Mac 에서 한 번에 치려면 앞에 다음을 붙이고 명령을 `--command '…'` 로 넘긴다.

```bash
gcloud compute ssh echo-sandbox-runner --zone asia-northeast3-a --project team-echo-final --tunnel-through-iap
```

### 켜기·끄기·상태

```bash
sudo systemctl enable --now echo-precheck-runner    # 켜기(VM 이 다시 켜져도 자동 시작)
sudo systemctl stop echo-precheck-runner            # 잠깐 끄기(처리 중인 점검은 끝내고 멈춤, 최대 5분 기다림)
sudo systemctl disable --now echo-precheck-runner   # 계속 끄기(재부팅해도 안 뜸)
sudo systemctl restart echo-precheck-runner         # 다시 시작(설정·새 버전 반영)
systemctl status echo-precheck-runner               # 상태·PID·최근 로그
```

### 모델만 바로 끄기·켜기

러너는 계속 돌리고 모델 호출(과금)만 멈춘다. 끄면 결과는 규칙 비교만(`model=null`, 화면 "AI 검토 없음")이고 C-AI-1 증거는 계속 생긴다.

```bash
# 끄기
sudo sed -i 's/^ECHO_PRECHECK_MODEL=.*/ECHO_PRECHECK_MODEL=off/' /etc/echo-precheck-runner/runner.env \
  && sudo systemctl restart echo-precheck-runner
# 켜기
sudo sed -i 's/^ECHO_PRECHECK_MODEL=.*/ECHO_PRECHECK_MODEL=on/' /etc/echo-precheck-runner/runner.env \
  && sudo systemctl restart echo-precheck-runner
# 확인: 마지막 줄이 "model review: off" 또는 "model review: claude-opus-5-5 medium"
sudo journalctl -u echo-precheck-runner -o cat | grep 'model review:' | tail -1
```

### 규칙 패치 켜기·끄기

기본은 끔(`ECHO_PRECHECK_PATCH=off`, `--no-patch`)이고 켜면 `--patch` 로 돈다. WAS 가 `patches[].origin` 을 받기 전(echo-was #79 배포 전)에 켜면 패치가 실린 결과가 422 가 되는데, 러너가 패치를 빼고 한 번 다시 내므로 C-AI-1 증거는 남는다(그래도 #79 배포 뒤에만 켠다). 발동은 시연 서비스(이미지 digest 가 echo-demo-app `0ff0d44` 이미지이거나 서비스 이름 `demo`)의 점검뿐이다. 이 설정이 생기기 전에 설치한 VM 의 `runner.env` 에는 줄이 없어 `sed` 가 아무것도 바꾸지 않으니, 첫 줄로 먼저 더한다.

```bash
# 줄이 없으면 더하기(한 번)
grep -q '^ECHO_PRECHECK_PATCH=' /etc/echo-precheck-runner/runner.env \
  || echo 'ECHO_PRECHECK_PATCH=off' | sudo tee -a /etc/echo-precheck-runner/runner.env >/dev/null
# 켜기(S1 배포 뒤에만)
sudo sed -i 's/^ECHO_PRECHECK_PATCH=.*/ECHO_PRECHECK_PATCH=on/' /etc/echo-precheck-runner/runner.env \
  && sudo systemctl restart echo-precheck-runner
# 끄기
sudo sed -i 's/^ECHO_PRECHECK_PATCH=.*/ECHO_PRECHECK_PATCH=off/' /etc/echo-precheck-runner/runner.env \
  && sudo systemctl restart echo-precheck-runner
# 확인: 마지막 줄이 "rule patch: on" 또는 "rule patch: off"
sudo journalctl -u echo-precheck-runner -o cat | grep 'rule patch:' | tail -1
# 확인: "active" 여야 한다. 값 오타면 종료 코드 2 로 멈춰 "failed"(다시 띄우지 않음) → runner.env 를 고친다
systemctl is-active echo-precheck-runner
```

### 로그 보기

```bash
sudo journalctl -u echo-precheck-runner -f                          # 실시간
sudo journalctl -u echo-precheck-runner --since '30 min ago' -o cat  # 최근
sudo journalctl -u echo-precheck-runner -o cat | grep 'finished run='  # 처리한 점검: status·model_review
```

한 점검마다 `claimed run=<id>` → `finished run=<id> status=SUCCEEDED … model_review=REVIEWED` 두 줄이 남는다. `model_review` 는 `REVIEWED`(AI 검토됨)·`FAILED`·`REFUSED`·`SKIPPED`(규칙만)·`off`(모델 끔)다. 토큰·키·프롬프트·모델 출력은 로그에 쓰지 않는다.

### 처음 설치 (한 번)

```bash
sudo useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin echo-runner
sudo install -d -m 755 /opt/echo-ai-agent/bin /opt/echo-ai-agent/releases /etc/echo-precheck-runner
sudo install -m 755 ~/.local/bin/uv /opt/echo-ai-agent/bin/uv   # uv 0.8.17(sha256 확인한 것)
# 아래 "새 버전 올리기"로 release 를 하나 올린 뒤
sudo install -m 644 /opt/echo-ai-agent/current/deploy/runner.env.example /etc/echo-precheck-runner/runner.env
sudo systemctl enable --now echo-precheck-runner
```

### 새 버전 올리기·되돌리기

```bash
# Mac, 작업 공간 루트: main 의 고정 커밋을 VM /tmp 로
SHA=$(git -C echo-ai-agent rev-parse --short origin/main)
git -C echo-ai-agent archive "$SHA" | gcloud compute ssh echo-sandbox-runner --zone asia-northeast3-a \
  --project team-echo-final --tunnel-through-iap --command "cat > /tmp/echo-ai-agent-$SHA.tar"

# VM
SHA=<위와 같은 값>; B=/opt/echo-ai-agent; R=$B/releases/$SHA
sudo install -d -m 755 "$R" && sudo tar -x -C "$R" -f "/tmp/echo-ai-agent-$SHA.tar" --no-same-owner
echo "code=$SHA" | sudo tee "$R/.deployed-rev" >/dev/null
(cd "$R" && sudo env UV_PYTHON_INSTALL_DIR=$B/python UV_CACHE_DIR=$B/.uv-cache $B/bin/uv sync --frozen --no-dev)
sudo chmod -R a+rX "$R" && sudo ln -sfn "$R" "$B/current"
sudo install -m 644 "$R/deploy/echo-precheck-runner.service" /etc/systemd/system/ && sudo systemctl daemon-reload
sudo systemctl restart echo-precheck-runner && rm -f "/tmp/echo-ai-agent-$SHA.tar"
cat /opt/echo-ai-agent/current/.deployed-rev   # 지금 도는 버전

# 되돌리기: 이전 release 로 링크를 바꾸고 다시 시작
sudo ln -sfn /opt/echo-ai-agent/releases/<이전 sha> /opt/echo-ai-agent/current && sudo systemctl restart echo-precheck-runner
```

- 유닛 파일(`deploy/echo-precheck-runner.service`)이 바뀐 버전은 위 `install` + `daemon-reload` 줄을 꼭 거친 뒤 다시 시작한다. 링크만 바꾸고 재시작하면 옛 유닛 설정으로 돈다(`systemctl show echo-precheck-runner -p Environment` 로 확인).
- VM 을 멈추면(인프라 `vm_running = false`) 러너도 멈춘다. 다시 켜면 서비스가 자동으로 뜬다.
- 설정 오류(환경 변수·키 없음, 종료 코드 2)면 다시 띄우지 않는다. 그 밖에 죽으면 10초 뒤 다시 뜨고, 5분에 5번을 넘기면 멈춘다(`systemctl status` 로 확인).

## 승인된 패치 반영 (APPLY_PATCH, 기본 꺼짐)

사람이 승인한 패치(WAS `PATCH_APPLY_ENABLED` 가 켜져 있을 때 생기는 `APPLY_PATCH` 실행)를 샌드박스에서 시나리오 사본에 적용하고, 이미지를 빌드해 Trivy(C-IMG-1 기준: 수정 가능한 HIGH·CRITICAL 0)로 보고, 앱을 `--network none` 으로 띄워 `/healthz` 를 본 뒤 결과 `{status, failureCode, simulated, appliedCommitSha, branch}` 를 낸다. **브랜치·이미지를 push 하지 않는다**(샌드박스는 읽기 자격만). 설계·실패 코드·계약 보완 목록: SPEC [`ai-5-2`](specs/ai-5-2-apply-patch-runner.md), 운영 안내 [`docs/apply-patch-runner.md`](docs/apply-patch-runner.md).

- 스위치 `ECHO_APPLY_PATCH=on|off`(기본 off). 꺼져 있으면 claim 이 지금과 같은 `["PRECHECK"]` 이다. 오타면 종료 코드 2. 시작 로그 `apply patch: on|off`.
- docker·trivy 가 없으면 PASS 를 만들지 않고 `FAILED`·`VERIFY_UNAVAILABLE` 로 낸다. 지금 VM 은 러너 사용자에게 docker 권한이 없고 trivy·git 이 없어 켜지 않는다(켜는 절차는 SPEC 10절, 인프라 승인 필요).
- 로컬 확인(가짜 WAS·시나리오 사본이 있는 체크아웃 필요):

  ```bash
  ECHO_WAS_URL=http://localhost:<port> ECHO_RUNNER_TOKEN=echo_rnr_… ECHO_APPLY_PATCH=on \
    ECHO_APPLY_REPO_ROOT=<scenarios/ 가 있는 체크아웃> uv run python -m echo_agent.precheck_runner --once --no-model
  ```

## 지키는 것

- 모델이 고른 명령은 작업 공간 컨테이너 안 `sh -c`에서만 돈다. 호스트는 셸을 거치지 않는다.
- 작업 공간에는 네트워크·키·토큰·볼륨·Docker 소켓이 없다.
- 의존성은 `exclude-newer` 날짜 이전 배포본만 쓰고, 액션·이미지는 SHA·digest로 고정한다.
