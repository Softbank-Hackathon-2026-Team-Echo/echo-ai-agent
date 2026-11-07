# #22 오류 진단·수정 — WAS #101 통합

상태: **#25 연결 구조 + #24 진단 엔진 통합·단독 검증 완료 / 운영 수신 기본 off / 실제 WAS·승인·재배포 종단 확인 남음** (2026-11-07)

- 요청: [AI #22](https://github.com/Softbank-Hackathon-2026-Team-Echo/echo-ai-agent/issues/22)
- 기반: #24 `ed5f399`, #25 `ec809b3`. #25 작성자의 원래 커밋을 병합해 연결·반영 골격을 재사용했다.
- 서버 기준: [WAS #101](https://github.com/Softbank-Hackathon-2026-Team-Echo/echo-was/pull/101) 최종 head `62dfe5e` (병합됨). `docs/api/deploy-diagnosis.md`의 러너 계약.
- 진단·diff는 형래, WAS 작업 생성·실패 로그 제공·저장소 반영/PR·수정 커밋 재배포는 지민 담당 분담을 유지한다.

## 1. 현재 실행 경로

```text
CHANGE_PROPOSAL claim → 하트비트
→ WAS 입력 확인 → 공개 GitHub의 실패 commitSha 소스 조회
→ 민감 파일 제외·로그/소스 비밀값 가림
→ 기존 #24 엔진: 원본 문법 검사 → Claude 근거·수정 제안 → 수정본 문법 검사
→ diff/비밀값 검사 → git apply 확인·정규화 → 엄격한 적용기 결과 대조
→ WAS diagnosis + origin=AI patch + processing 제출 → 임시 작업 공간 정리
```

- 자동 수정은 `app/static/index.html`의 기존 classic inline JavaScript와 `app/main.py`의 닫는 괄호 누락을 지원한다. Python은 독립 문법 검사기가 지목한 한 줄에서 기존 문자를 보존하고 `)`/`]`/`}` 최대 3개를 추가하는 수정 한 건만 허용한다. 코드 삭제·교체·다른 줄/파일 수정은 거절한다. 일반 Python 오류 전체를 고치는 기능은 아니다.
- 실패 로그에서 지원 파일 하나가 특정될 때 그 실패 커밋의 원본을 제공한다. 여러 지원 파일이 섞인 모호한 로그, 소스가 없거나 지원 대상이 아닌 경우는 로그 기반 진단만 가능하며 검증하지 못한 패치는 반환하지 않는다.
- 모델 호출 최대 2회, SDK 재시도 0, 엔진 예산 최대 180초. 수정본 문법 실패 때만 원본 기준으로 재시도한다. Node/Python 공식 고정 digest·Docker network none/read-only/non-root/자원 상한을 재사용한다. Python은 `compile`만 하고 고객 모듈을 import/실행하지 않는다. 검사 도구 이미지가 없으면 자동 다운로드 없이 검증 불가로 처리한다.
- `fixable=true`는 원본 문법 FAIL → 수정본 PASS, 허용된 변경 범위·근거·최종 diff 검사까지 만족해야 한다. 실제 화면/API/DB 정상이나 배포 완료를 뜻하지 않는다.
- `--no-model`은 마스킹된 로그/위치 규칙만 사용하고 패치를 만들지 않는다. 모델 거절·API 실패는 코드별 FAILED이며 전송 기록은 남긴다.

## 2. 실제 WAS 계약과 내부 입력의 구분

외부 `inputSnapshot`은 WAS #101의 `schemaVersion`, `service`, `deployRequest`, `environment`, `variableKeys`, `failure`다. `deployRequest.repo`(owner/name)·`commitSha`(40자리)로 러너가 소스를 읽는다. `failure.logTail`은 최대 50줄이다. 줄 번호를 유지하기 위해 초과/여러 줄 원소는 거절한다. 비공개 저장소용 자격은 사용하지 않는다.

`diagnosis_runner.Diagnoser`가 이를 #24 내부 `error-diagnosis.v1` 입력으로 변환한다. 내부 입력은 로컬 CLI/fixture에서 계속 사용하지만 WAS가 이 내부 형식을 직접 보내야 하는 것이 아니다. 내부 sourceCommit/hash는 소스 바인딩 기록이며 운영 경로의 바이트는 해당 커밋 URL에서 가져온다.

결과는 기존 RunResult + `diagnosis{result,category,cause,fixable,unfixableReason,evidence}`와 기존 patches 형식이다.

- `result`: DIAGNOSED / INSUFFICIENT_EVIDENCE / NO_FAILURE_EVIDENCE.
- `category`: CODE / CONFIG / BUILD / RUNTIME / PLATFORM, 근거 부족이면 null.
- **운영 LOG.line은 failure.logTail의 1부터 위치**, FILE.line은 파일의 실제 줄이다. 내부 문법 검사기가 생성한 로그는 logTail에 있었던 것처럼 번호를 붙여 제출하지 않는다. evidence 최대 20개, 각 text 최대 300자로 정리한다.
- deployRequestId/environmentId/sourceCommitSha는 WAS가 붙인다. 러너 diagnosis에 중복 제출하지 않는다.
- patch checks: DIFF_APPLIES / POLICY / JAVASCRIPT_SYNTAX 또는 PYTHON_SYNTAX / GIT_APPLY. 빌드·Trivy·healthz는 승인 이후 별도 실행이다. 프롬프트·Python 수정 정책 버전은 diagnosis-v1.3이다.
- processing은 실제 모델 전송을 기록하며 실패·거절·결과 변환 실패에도 보존한다. Anthropic 직접 호출이므로 modelRegion=null. 운영 제어 프로세스는 gcp/asia-northeast3, 로컬 검증은 local/development다.
- CHANGE_PROPOSAL은 PRECHECK/C-AI-1 증거로 제출하지 않는다. WAS가 422로 거절하면 필드를 지우거나 PRECHECK로 재전송하지 않는다.
- 로컬 CLI의 `--was-result`는 같은 공개 필드 모양을 출력한다. CLI는 자체 입력 로그의 원본 좌표를 유지하며, logTail 좌표 변환은 운영 어댑터가 명시적으로 선택한다.

## 3. 비밀값·소스 보호

- `.env`, 숨김 경로, 키/credentials/service-account 파일 등을 읽기 전에 제외한다. 심볼릭 링크·루트 밖 경로를 제외하고 선택 파일 100개·파일당 64 KiB·선택 총량 512 KiB·탐색 5,000개 상한을 둔다.
- 기존 토큰 패턴 외에 password/secret/token/API key 할당, 인증 헤더·쿠키와 잔여 고엔트로피 후보도 전송 전에 가린다. 패턴 기반이므로 모든 비밀값 탐지를 보증하지 않는다.
- 원본에 마스킹이 필요한 내용이 있으면 자동 패치를 보류한다. 모델 diff와 원본 문맥에서 재생성한 최종 diff도 재검사하며, 가려야 할 값이 있으면 반환하지 않는다. 적용용 diff의 문맥만 `***`로 바꿔 무결성 검사를 우회하지 않는다.
- 공개 archive는 압축 크기 50 MiB, 확장 크기 128 MiB·10,000개 상한이다. 링크·특수 엔트리를 거절하고 tar data filter로 추출한다.
- 모델 원문/API 오류 본문·키는 이벤트/결과에 쓰지 않는다. 동작 정지·리스 상실은 다음 작업 경계에서 확인하고 임시 파일·검사 컨테이너를 정리한다.

## 4. 승인 이후와 활성화

#25의 서비스 저장소 APPLY_PATCH 모드를 재사용한다: 승인된 patchHash 확인 → 실패 커밋 소스 → 엄격 적용 → 로컬 커밋 → Docker build → Trivy → healthz. 민감 경로·비밀값을 포함한 서비스 패치도 거절한다. 사전 점검의 기존 scenarios 경로는 유지한다.

러너는 push·PR 생성·실제 배포를 하지 않는다. appliedCommitSha는 샌드박스의 로컬 커밋이며 저장소 반영/재배포 완료가 아니다. echo-demo-app의 build/healthz 값은 #25의 기존 상수다. 실제 서비스의 DB 연결·기능 검증은 별도다.

`ECHO_DIAGNOSIS=off`가 기본. on이면 CHANGE_PROPOSAL을 claim한다(`--diagnose` 별칭도 제공). ECHO_PRECHECK_MODEL=off면 규칙만 사용한다. 승인 후 검증에는 ECHO_APPLY_PATCH=on도 필요하다. 운영 release·서버 설정을 실제로 맞추고 켜는 것은 별도 배포 작업이다.

## 5. 직접 검증과 남은 인수

### demo-app #7 실제 시작 실패 검증 — 2026-11-07 17:12 KST

- 전체 **451 passed**, skip 0. 실제 Docker 포함, ruff lint/format·strict mypy·최종 sdist/wheel 빌드 통과. 배포 wheel의 Python/Node 검사기 및 변경 모듈이 소스와 일치한다.
- 실제 GitHub 고정 커밋 `53997e1`을 받아 Docker 이미지를 빌드했다. 컨테이너 시작은 종료 1, `app/main.py:213`의 `SyntaxError: '(' was never closed`를 실제로 재현했다. 이 로그 38줄과 실패 커밋 소스를 WAS #101 어댑터로 전달했다.
- **로컬:** 실제 Claude 1회 10.748초 → 닫는 괄호 한 글자 diff → Python 문법/엄격 diff/git apply → 기존 APPLY_PATCH의 실제 빌드·Trivy(수정 가능한 HIGH/CRITICAL 0)·`/healthz` PASS. 전체 73.3초.
- **GCP 서울 VM:** 별도 임시 소스, 기존 release Python과 echo-runner 계정으로 같은 검증을 수행했다. 실제 Claude 1회 7.093초, 전체 45.348초, 진단/빌드/스캔/healthz 모두 PASS. 임시 디렉터리·컨테이너·이미지 정리, 기존 systemd active·release `82aac70` 유지. Anthropic API 호출이며 모델의 서울 호스팅을 뜻하지 않는다.
- 두 실제 결과 모두 현재 WAS `DiagnosisRunResultRequest`와 정규화에서 `DIAGNOSED/CODE/fixable=true`, 패치 `PROPOSED`를 확인했다. 승인 입력은 리허설이 자체 구성했다. **실제 WAS HTTP·화면·사람 승인·원격 커밋/PR·재배포 완료는 아니다.**
- GCP 일회성 실행은 초기 환경 누락으로 실패했다. 전송 시 release Python 사용, BuildKit 활성화 및 기존 unit의 `TRIVY_CACHE_DIR`를 맞춰 해결했다. 운영 환경 파일이나 보안 스캔 기준은 변경하지 않았다.
- [실행 증거](evidence/ai-22-python-rehearsal-2026-11-07.json), [재현 명령](../docs/error-diagnosis-demo.md). 운영 러너 release/스위치 및 기존 WAS #111 활성화·화면 종단 인수는 남는다.

### 앞선 JavaScript 통합 검증 이력

- 전체 **431 passed**, skip 0. Ruff lint/format·mypy·시작 스크립트 문법 검사 통과. 실제 Docker 회귀 포함.
- 공개 demo-app의 고정 커밋 `d856a1d`을 실제 GitHub에서 받아 제한된 소스 30개와 HTML 368행을 읽었다. sdist/wheel 빌드 및 진단 모듈·Node 검사기 포함 확인.
- WAS #101 최종 head `62dfe5e`의 DiagnosisRunResultRequest와 정규화로 정상 패치·규칙만·거절·로그 없음·근거 부족·입력 오류 6개 결과를 확인. 정상 패치는 PROPOSED다. 실제 HTTP/DB 제출 시험은 아니다.
- 최신 통합 어댑터에 합성 실패 커밋과 실제 Node 오류 로그를 넣어 Claude 1회 **7.677초**, 전체 진단/검증 **9.626초**. 수정본은 정상 원본과 일치, LOG.line=1·FILE.line=160, 최종 실제 결과도 WAS 스키마/정규화 통과. network none·read-only·비루트, 컨테이너 잔존 0.
- 이 검증은 로컬 제어 프로세스 + Docker + Anthropic API다. 소스 전달은 합성 로컬 Git 객체 reader를 주입했다. 실제 GitHub→운영 WAS 요청·사람 승인·고객 앱 빌드/Trivy/healthz·수정 커밋 재배포 전체를 검증한 것이 아니다.
- [통합 실행 증거](evidence/ai-22-was101-integration-2026-11-07.json).
- 남음: demo-app #7의 실제 컨테이너 시작 실패 로그가 운영 WAS 입력으로 전달되는지, 운영 러너 배포/스위치, 화면·승인, WAS 저장소 반영·수정 커밋 재배포 확인. #7은 Python 구문 오류이므로 별도 프론트 빌드 검사기가 필수 선행 작업은 아니다. 본 변경은 DB 네트워크·Vertex·운영 자원을 변경하지 않는다.

## 6. 과거 단독 검증 기록

아래는 이전 커밋 시점의 이력이다. 계약의 현재 상태는 위 1~5절을 따른다.

 (2026-11-07)

- 전체 pytest 354개 통과(실제 Docker 시험 포함, skip 0), ruff lint/format·mypy 통과.
- CLI fixture 재생: 원본 문법 실패 → 수정본 통과 → 패치 1개. simulated=true, 실제 모델 호출 없음.
- 기존 apply parser에 생성 diff를 넣어 예상 수정 파일과 일치 확인.
- 로컬 WAS의 기존 patch/base result 스키마 검사 통과. 새 diagnosis 필드는 아직 extra_forbidden → 계약 확장 전 자동 수신 금지.
- sdist/wheel 빌드 및 Node checker 리소스 포함 확인.
- 실제 Claude 단일 문법 오류 검증은 아래 추가 기록 참고. 운영 WAS·승인·재배포 연결은 미검증이다.

### 실제 Claude + 로컬 Docker 확인 (2026-11-07 01:16 KST)

- 대상: `echo-demo-app` `d856a1d13f19aa219ebba117c29561f838da9fe4`의 HTML 사본. 160행 `async function fetchJson(url, options, timeoutMs) {`에서 닫는 괄호 하나를 제거했다. 원본 저장소와 운영 서비스는 수정하지 않았다.
- 정상 사본 문법 PASS → 오류 사본 실제 문법 FAIL(`Unexpected token '{'`) → 그 로그와 오류 소스를 Claude에 전달 → 실제 diff 생성 → 같은 Docker 문법 검사 PASS.
- 실제 모델 `claude-opus-5-5`, API 1회, 7.448초, 입력 20,872 / 출력 468 토큰. 진단 시작부터 수정본 검사 종료까지 9.286초. 정상 원본이나 샘플 모델 응답을 모델에 주지 않았다.
- 패치를 기존 apply parser로 적용한 결과가 오류 주입 전 원본과 완전히 일치했다. Node v24.22.2. 실제 컨테이너 격리 설정을 inspect로 확인했고 해당 컨테이너 잔존은 0개다.
- 입력의 `simulated=true`는 인위적인 오류·가상 배포 작업을 나타내며 API 응답 재생이 아니다. `model`·`processing`은 실제 호출 기록이다. 정확한 실패 소스 바인딩을 위해 임시 Git 저장소에 합성 커밋을 만들었다.
- Secret Manager 키는 메모리에서만 읽었다. 검사 컨테이너로 전달하지 않았다. 모델 호출은 로컬 제어 프로세스, 문법 검사는 로컬 Docker Desktop이다. GCP VM에서 이 새 기능을 실행한 결과는 아니다.
- 단일 문법 오류의 성공 사례이며 브라우저 동작·빌드·Trivy·헬스체크·WAS/승인/재배포 검증을 포함하지 않는다.
- [실행 증거 JSON](evidence/ai-22-live-model-2026-11-07.json): 실제 요청 식별자·토큰 수·이벤트·검사 결과·diff·컨테이너 설정.

### 마무리 검증 (2026-11-07 01:32 KST)

- 프롬프트 `diagnosis-v1.1`: 진단 summary/reason/limitations는 한국어로 요청하며 코드·경로·근거 ID는 번역하지 않는다. API 인증·권한·모델 접근·호출 한도·연결·응답 시간 초과·서버 오류를 고정 코드와 한국어 안내로 분류한다. 공급자 오류 본문은 반환하지 않는다.
- `diagnosis_demo` + `deploy/diagnosis-demo.sh`: 오류 준비·실제 문법 로그·진단·diff·복구 일치·컨테이너 정리를 재현한다. 기본 replay / 명시적 `--live`, 신규 비공개 출력 디렉터리, 정확한 합성 소스 커밋. 사용법은 [시연 안내](../docs/error-diagnosis-demo.md).
- GCP `echo-sandbox-runner` / `asia-northeast3-a` / `echo-runner` 계정에서 기존 SDK/Python을 사용해 임시 소스를 실행했다. `ECHO_DIAGNOSIS` 및 systemd 서비스 설정을 변경하지 않았다. 별도 Node 검사 이미지를 고정 digest로 준비했다.
- 전체 demo-app HTML 사본의 160행 오류를 실제 Claude **1회**로 수정했다. API **8.213초**, 진단·수정본 검사 **10.013초**. 입력 20,954 / 출력 605 토큰. 한국어 설명·diff 생성·원본 FAIL/수정본 PASS·정상 원본과 완전 일치·검사 컨테이너 잔존 0개.
- [GCP 실행 증거](evidence/ai-22-gcp-live-model-2026-11-07.json)에 입력 기준 커밋, 전송 코드 묶음 SHA-256, 실행 위치, 호출 기록, 컨테이너 설정과 결과를 저장했다. **GCP에 모델을 호스팅한 것이 아니라 GCP 제어 프로세스에서 Anthropic API를 호출한 것**이다.
- 전체 pytest **370 passed**, skip 0. Ruff lint/format·mypy(strict)·쉘 문법·패키지 빌드 통과. Wheel에 `diagnosis_demo.py`·Node 검사 리소스 포함 확인.
- 실행 뒤 기존 러너 active·기존 release `82aac70` 유지 확인. 이번 임시 코드/결과 디렉터리와 전송 파일을 제거했다. 고정 Node 이미지는 이후 검증을 위한 캐시로 남겼다.
- WAS·화면·사람 승인·고객 앱 빌드/Trivy/헬스체크·실제 저장소 반영/재배포는 여전히 통합 확인 대상으로 남는다.

### WAS #98 공개 결과 형식 반영 (2026-11-07 02:18 KST)

- `diagnosis-v1.2`에서 원인 category를 근거와 함께 요청한다. 러너 제출 시 내부 기록을 공개 필드로 변환하고, 기존 AI 패치·processing·공통 결과는 유지한다. CLI `--was-result`, 시연의 `was-result.json`에서도 같은 결과를 확인할 수 있다.
- 근거 부족·실패 없음·다섯 category·검증 실패·API 실패·원본 로그 줄 번호 부재·변환 실패·WAS 422 거절을 시험했다. 공개 이슈의 필드 변환과 FakeWas 회귀 시험이며 실제 WAS validator 통과를 뜻하지 않는다.
- 전체 **392 tests passed**, skip 0. 스키마 표현 수정 후 관련 80개 재확인. Ruff lint/format·mypy·패키지 빌드 통과.
- 실제 API가 nullable enum과 type 배열 조합을 400으로 거절하여 string enum/null을 `anyOf`로 분리했다. 수정 후 Claude **1회, 8.986초**, 진단부터 수정본 검사까지 **10.789초**로 성공했다. 원본 FAIL → 수정본 PASS, 정상 코드와 완전 일치, 컨테이너 잔존 0개.
- 제출용 진단은 `DIAGNOSED / CODE / fixable=true`, 한국어 원인·LOG/FILE 근거·기존 AI 패치로 생성되었다. LOG.line=null, FILE.line=160을 구분했다.
- [실행 증거](evidence/ai-22-was98-live-model-2026-11-07.json). 이번 추가 검증은 **로컬 Docker + Anthropic API**이며 이전 GCP 검증과 구분한다. WAS 상세 명세 부재·null 허용·작업 ID 연결·실제 통합은 여전히 대기 중이다. 운영 자동 수신은 off다.
