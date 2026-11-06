# 오류 진단·수정 시연 (#22)

정상 HTML의 사본에 `)` 한 글자 누락 → 실제 오류 로그 → 진단·diff → 같은 Docker 문법 검사 → 원본 복구 확인을 한 명령으로 실행한다. **기본은 모델 응답 재생이고 `--live`일 때만 Claude를 실제로 부른다.** 실제 호출도 최대 2회다.

## 준비

Python 3.13+, Git, Docker와 저장소 의존성이 필요하다. Docker는 실행 중이어야 한다. 검사 이미지는 아래 digest를 미리 받아 둔다. 실행 중 자동으로 도구를 내려받거나 호스트 Node로 전환하지 않는다.

```bash
uv sync --frozen
docker pull node:24-bookworm-slim@sha256:01d566e8d94d8c619591d78652babfccd3c6992a3dffa9ed5ab39e11cf6c70e9
```

## 1. API 키 없는 재생

```bash
bash deploy/diagnosis-demo.sh --output-dir /tmp/echo-diagnosis-replay-01
```

출력 디렉터리는 매번 새 이름을 사용한다. 기존 디렉터리를 덮어쓰지 않는다. 기본 입력은 도구에 포함된 작은 HTML이다. 실제 demo-app HTML로 확인하려면 `--source /path/to/echo-demo-app/app/static/index.html`을 더한다. `fetchJson(url, options, timeoutMs)` 함수 선언이 정확히 한 번 있는 정상 파일만 지원한다.

## 2. 실제 Claude 호출

이미 `ANTHROPIC_API_KEY`가 환경에 있으면 그대로 사용한다. 없으면 아래처럼 프로젝트를 지정하면 시작 스크립트가 기존 Secret Manager 키를 프로세스 메모리로 읽는다. 키를 터미널에 출력하거나 컨테이너로 전달하지 않는다. `set -x`로 실행하지 않는다.

```bash
ECHO_GCP_PROJECT=team-echo-final bash deploy/diagnosis-demo.sh \
  --live --source /path/to/echo-demo-app/app/static/index.html \
  --output-dir /tmp/echo-diagnosis-live-01
```

모델에는 오류를 넣은 코드와 실제 검사 로그만 보내며 정상 정답은 보내지 않는다. 결과는 한국어로 설명하고, 코드·경로·근거 ID는 유지한다. 소스에 마스킹할 비밀값이 있으면 이 시연은 전송 전에 중단한다.

## 결과 보기

실행 중 단계별 이벤트를 출력하고 마지막에 요약 JSON을 표시한다. 성공 종료 코드 0은 **문법 수정본이 원래 정상 파일과 완전히 일치했고 검사 컨테이너도 정리되었다**는 뜻이다. 종료 코드 1은 진단·복구 조건 미충족, 2는 입력·도구·설정 오류다. 같은 기능을 하는 다른 수정안이라도 원본과 다르면 이 고정 시연은 엄격하게 실패로 표시한다.

| 파일 | 내용 |
|---|---|
| `summary.json` | live/replay, 실제 호출 수, 위치, 소요 시간, 복구 일치, 컨테이너 잔존 |
| `initial-checks.json` | 정상 사본 PASS / 오류 사본 FAIL |
| `result.json` | 진단·근거·수정안·수정 전후 검사 결과 |
| `was-result.json` | WAS #98의 공개 진단 필드에 맞춘 제출용 변환. 상세 runner 스키마 수신 확인은 별도 |
| `fix.diff`, `fixed.html` | 실제 생성된 변경분과 적용 결과. 패치가 있을 때만 생성 |
| `events.json`, `model-calls.json` | 단계·호출 시간·요청 ID·토큰 수. API 키·원문 오류 응답 없음 |
| `sandbox-observations.json` | 실제 컨테이너의 네트워크·권한·자원 제한. 환경 변수는 이름만 |
| `request.json`, `broken.html`, `baseline.html`, `synthetic-source/` | 합성 실패 요청·비교 자료·실패 코드를 정확히 가리키는 로컬 전용 Git 커밋 |

`simulated=true`는 실제 배포 실패가 아닌 **인위적인 오류 입력**이라는 뜻이다. 실제 호출 여부는 `summary.mode=live`, `realModelCalls`, `result.model/processing`으로 구분한다. 재생은 모델·외부 전송 기록이 없다.

`was-result.json`은 `result/category/cause/fixable/unfixableReason/evidence`와 기존 AI 패치를 포함한다. 분류 근거나 원본 로그 줄 번호가 없으면 null로 두므로, 아직 공개되지 않은 WAS 상세 명세에서 null 허용 및 작업 ID 연결 방식을 확인한 뒤 운영 수신을 켜야 한다. 일반 진단 CLI에서도 `diagnose --was-result`로 같은 변환을 사용할 수 있다.

## GCP VM에서 일회성 검증

기존 `echo-precheck-runner`의 release·서비스·환경 설정은 그대로 두고, 검토한 소스를 별도 `/tmp` 디렉터리에 올린 뒤 `echo-runner` 사용자로 실행한다. 예를 들어 `src/`, `deploy/diagnosis-demo.sh`와 정상 `demo.html`을 `/tmp/echo-diagnosis-check/`에 준비했다면:

```bash
sudo -u echo-runner env \
  ECHO_GCP_PROJECT=team-echo-final \
  CLOUDSDK_CONFIG=/var/lib/echo-precheck-runner/gcloud \
  DOCKER_CONFIG=/var/lib/echo-precheck-runner/docker \
  ECHO_DEMO_PYTHON=/opt/echo-ai-agent/current/.venv/bin/python \
  bash /tmp/echo-diagnosis-check/deploy/diagnosis-demo.sh \
  --live --source /tmp/echo-diagnosis-check/demo.html \
  --location gcp/asia-northeast3 --output-dir /tmp/echo-diagnosis-gcp-01
```

새 소스는 `PYTHONPATH`로 선택하며, 현재 release의 Python/동일 SDK 의존성만 재사용한다. 디렉터리를 러너 계정이 읽을 수 있어야 하며, Node 이미지는 러너 계정에서도 사용할 수 있어야 한다. `--location`은 자동 감지하지 않으므로 실행한 제어 프로세스 위치를 정확히 지정한다.

실행 전후 `systemctl is-active echo-precheck-runner`와 현재 release 링크를 비교한다. 증거를 회수한 뒤 **이번에 생성한 임시 디렉터리만** 제거한다. 기존 러너 컨테이너·캐시를 일괄 삭제하지 않는다. 정리 실패·중단 때는 `sandbox-observations.json`에 기록된 이번 컨테이너 이름을 확인한다.

## 실패 표시

| `failureCode` | 의미 |
|---|---|
| `MODEL_AUTH_FAILED` / `MODEL_PERMISSION_DENIED` | API 인증 / 모델 사용 권한 문제 |
| `MODEL_RATE_LIMITED` | 모델 호출 한도 도달 |
| `MODEL_TIMEOUT` / `DEADLINE` | 모델 응답 제한 / 전체 진단 시간 초과 |
| `MODEL_CONNECTION_FAILED` | 모델 API 네트워크 연결 실패 |
| `MODEL_NOT_FOUND` / `MODEL_REQUEST_REJECTED` | 모델 이름·접근 문제 / 요청 형식 등 거절 |
| `MODEL_UNAVAILABLE` | 모델 제공 서버 오류 |
| `MODEL_REFUSED` / `MODEL_INCOMPLETE` | 모델 거절 / 미완성 응답 |

`diagnosis.summary`는 한국어 안내, `diagnosis.reason`은 실패 코드를 담는다. 오류 응답 본문이나 키는 결과에 싣지 않는다. 한도·인증 실패를 자동 재시도로 반복하지 않는다.

## 확인 범위

이 시연은 **JavaScript 문법 검사**다. 고객 JS 실행·브라우저 기능·API/DB 정상 동작·이미지 빌드·Trivy·헬스체크·사람 승인·PR 자동 생성·실제 재배포는 확인하지 않는다. 이 기능의 운영 수신(`ECHO_DIAGNOSIS`)은 WAS 및 후단 연결 합의 전까지 기본 off다.
