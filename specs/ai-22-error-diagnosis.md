# #22 오류 진단·실제 diff 생성 — v1

상태: **앞단 구현·실제 GCP 검증 완료 / WAS #98 공개 결과 필드 반영 / 상세 runner 명세·통합 대기 / 운영 수신 기본 off** (2026-11-07)

- 요청: [echo-ai-agent #22](https://github.com/Softbank-Hackathon-2026-Team-Echo/echo-ai-agent/issues/22)
- 분담·계약 제안: [댓글](https://github.com/Softbank-Hackathon-2026-Team-Echo/echo-ai-agent/issues/22#issuecomment-6688870908)
- 참고: `2026-softbank-1/iris-error-check-agent` `3f3b4d956282899362b30439d02788d329bd3594`의 전처리·근거 ID·진단 상태. 소스 코드는 복사하지 않았으며 그래프·IRIS·별도 HTTP 서버를 도입하지 않는다.

## 1. 범위와 실행

실패 로그·실패 커밋의 전체 HTML → 비밀값 마스킹·EV/SC 근거 → Claude 진단·정확한 문자열 변경 제안 → Python 원본 대조·diff → 격리된 Node 문법 검사.

- v1은 `app/static/index.html`의 기존 classic inline JavaScript만 고친다. HTML 구조·외부 스크립트·module script·다른 파일은 수정하지 않는다.
- SDK·기존 모델 설정·GCP VM·DockerSandbox 재사용. Node 24 공식 이미지의 2026-11-07 조회 digest를 코드에 고정한다. VM/유닛 교체·테스트 DB·Vertex 전환 없음.
- 모델은 명령을 고르거나 실행하지 않는다. Node `vm.Script`는 파싱만 하고 실행 메서드를 호출하지 않는다. 컨테이너는 기존 network none/read-only/non-root/자원 상한을 따른다.
- 모델 호출 최대 2회(자동 SDK 재시도 0), 호출당 최대 60초, 작업 예산 기본 180초. 두 번째 호출은 유효한 수정의 문법 검사 실패 때만 허용하며 원본 소스에 대한 수정안을 다시 받는다. 시간 초과 뒤에도 생성 중인 컨테이너/프로세스 정리는 완료하며, 이 정리 시간은 작업 예산을 넘길 수 있다(기존 Docker 생성 120초/삭제 60초 제한).
- 문법 검사는 화면 기능·API·DB·빌드·Trivy·헬스체크를 대신하지 않는다. 이 앞단 결과를 실제 배포 완료로 표시하지 않는다.

## 2. 제안 계약 — 기존 WAS가 아직 받는다고 가정하지 않는다

작업은 기존 DB에 정의된 `CHANGE_PROPOSAL`을 활성화하는 안이다. 현재 WAS는 이 종류를 claim/상세/승인에 열지 않았으므로 지민 담당 변경이 선행되어야 한다. 기존 `PRECHECK`로 대체하지 않는다(C-AI-1 증거 혼입 방지).

`inputSnapshot`:

```json
{
  "schemaVersion": 1,
  "purpose": "error-diagnosis.v1",
  "deployRequestId": "failed-deploy-id",
  "environment": "aws-tokyo",
  "sourceCommit": "1111111111111111111111111111111111111111",
  "simulated": true,
  "allowedFiles": ["app/static/index.html"],
  "sourceFiles": [{"path": "app/static/index.html", "content": "실패 커밋의 전체 파일"}],
  "failure": {"code": "BUILD_FAILED", "exitCode": 1},
  "logs": [{"id": "build", "stage": "build", "sourceLineStart": null,
            "truncated": false, "lines": ["app/static/index.html:5: SyntaxError: …"]}]
}
```

위 커밋은 문서용 더미이며 실배포 입력에서는 정확한 40자리 SHA가 필요하다. 소스가 없을 때만 `sourceCommit=null`, `sourceFiles=[]`를 허용하며 패치하지 않는다. 소스는 한 파일·UTF-8 64 KiB, 본문은 기존 러너와 같이 1 MiB 이하다. 로그는 최대 5묶음×200줄×2,000자, 한 항목은 실제 한 줄이다. `stage`는 build/runtime/validation이다. tail의 원래 줄 번호를 모르면 null로 유지한다.

WAS #97의 `failure.{code,message,containerReason,terminationReason,exitCode,logTail,logTruncated}`를 받을 수 있다. 별도 `logs`가 없으면 logTail을 runtime 로그로 변환한다. **#97은 컨테이너 로그 수집이다. 이번 프론트 문법 실패는 빌드 검사 로그를 추가 전달해야 한다.** 이미지가 없는 빌드 실패를 지원하고 digest를 요구하지 않는다.

결과는 기존 `RunResult` 공통 칸에 선택 `diagnosis`를 추가한다. **WAS 제출용 결과와 로컬 검증 기록을 구분**한다. [WAS #98 §3](https://github.com/Softbank-Hackathon-2026-Team-Echo/echo-was/issues/98) 및 지민님의 필드 지정 답변에 맞춘 제출용 변환은 다음과 같다:

| 제출 필드 | 의미와 변환 |
|---|---|
| `result` | 내부 analysisStatus를 `DIAGNOSED` / `INSUFFICIENT_EVIDENCE` / `NO_FAILURE_EVIDENCE`로 변환 |
| `category` | 근거에 따라 `CODE` / `CONFIG` / `BUILD` / `RUNTIME` / `PLATFORM`. 분류 근거가 없으면 null |
| `cause` | 한국어 진단 summary |
| `fixable` | CODE 진단이고 실제 원본 문법 FAIL·수정본 PASS·패치 생성까지 확인한 경우에만 true |
| `unfixableReason` | 수정할 수 없거나 검증하지 못한 이유. fixable=true일 때 null |
| `evidence` | 로그는 `source=LOG`, 소스는 `source=FILE`. `line`, `text`, FILE의 `path`를 제공 |

- 모델에 category를 요청하고 허용 enum·진단 상태와의 일관성을 코드로 검사한다. 모델/API 실패는 완료된 원인 분석으로 표시하지 않고 작업 FAILED·INSUFFICIENT_EVIDENCE로 반환한다.
- LOG의 원래 줄 번호가 없으면 `line=null`이다. tail 안의 순번이나 오류 메시지에 표시된 **코드** 줄 번호를 **로그** 줄 번호로 바꾸지 않는다. FILE의 줄 번호는 전달된 소스의 실제 줄 번호다.
- `diagnosis_result.to_was_result`가 제출용 6개 필드만 만든다. 상세 검증·근거 ID·바인딩 기록은 로컬 `result.json`에 보존한다. 변환 후 결과는 `was-result.json`으로 함께 저장한다.
- 로컬 `diagnosis`: analysisStatus, category, summary, evidenceIds/sourceEvidenceIds, canFix, reason, limitations, 인용한 evidence/sourceEvidence, verification.before/after.
- 로컬 `diagnosis.inputBinding`: deployRequestId, sourceCommit, sourceSha256, commitVerification=`caller_supplied`. WAS가 해당 커밋에서 가져온 바이트라는 책임을 진다. 러너는 GitHub 인증·조회·커밋 검증을 임의로 하지 않는다.
- `patches`: 기존 `{id,patchHash,files,diff,reason,touchesProtectedFiles,checks,origin}` 유지. files/diff 경로는 **고객 저장소 기준 `app/static/index.html`**이다. origin=AI. checks는 DIFF_APPLIES/POLICY/JAVASCRIPT_SYNTAX뿐이며 빌드·스캔 통과를 꾸미지 않는다.
- `processing`: 실제 시도한 모델 요청의 LOGS/SOURCE_CODE와 전송량 추정치를 기록. 거절/실패에도 보존. 모델 호출은 컨테이너 밖이므로 sandbox=false, Anthropic 직접 호출이라 modelRegion=null이다. 로컬 CLI는 local/development, VM 러너는 기존 gcp/asia-northeast3로 기록한다.
- 유효한 근거 부족·수정 불가 진단도 작업 자체는 SUCCEEDED이고 patches는 비어 있다. 모델/입력/검증 계약 오류는 FAILED다. 이전의 유효하지 않은 패치는 반환하지 않는다.

**미확정 계약:** 확인 시점 WAS main `30aca36`에 예정된 `specs/api-98-failed-deploy-diagnosis.md`는 없다. #98 §3은 화면 조회 결과 예시이므로 이 변환만으로 실제 runner 제출 스키마 호환을 보장하지 않는다. 다음은 상세 명세에서 확인할 항목이다:

1. 근거가 없는 category와 원본 줄 번호를 모르는 LOG.line의 null 허용 여부. 확인 전에 임의의 분류나 줄 번호를 채우지 않는다.
2. 상세 조회의 deployRequestId/environmentId/sourceCommitSha를 WAS의 작업 연관 정보에서 붙이는지, runner 결과에도 요구하는지. 현재는 제출용 diagnosis에 넣지 않으며 환경 이름으로 environmentId를 추측하지 않는다.
3. 정확한 실패 소스 전달 방식, 기존 공통 결과 필드·processing 수신, 내부 검증 기록의 서버 저장 위치. 현재 inputSnapshot은 위 제안 형태를 유지한다.

WAS가 모르는 결과를 422로 거절하면 결과를 벗기거나 PRECHECK로 재전송하지 않는다. 잘못된 내부 진단 변환도 제출하지 않고 로컬 `INVALID_DIAGNOSIS_RESULT`로 기록하며 폴링 프로세스를 유지한다. 이 경우 서버 작업 완료가 아니라 lease 만료/복구 대상이다. 자동 진단 수신은 운영에서 켜지 않는다.

## 3. 근거·수정 검증

- 마스킹은 여러 줄 비밀의 줄 수를 보존한다. 알려진 토큰/접속 문자열/인증 값/비밀 필드와 고엔트로피 후보를 외부 전송 전에 가린다. 휴리스틱이므로 WAS 수집 단계 마스킹도 유지한다.
- 소스에 마스킹할 내용이 있으면 가린 내용을 진단에만 사용하고 해당 원본의 수정은 금지한다.
- 입력은 지시가 아니라 자료라고 system prompt에 고정한다. 로그/소스 원문을 이벤트에 남기지 않는다.
- 모든 인용 ID의 존재, 수정 대상 줄과 SC 근거의 대응, 정확한 oldText 1회 일치, 변경 구간 비중첩을 코드로 검사한다.
- 모델의 수정 문자열을 원본에 적용하고 Python이 unified diff와 SHA-256을 생성한다. 모델이 임의의 patchHash/경로/검사 결과를 만들 수 없다.
- 원본에서 문법 오류를 재현하지 못했거나 검사 도구를 쓸 수 없으면 패치하지 않는다. 수정본은 같은 검사에 통과해야 한다. 실패 시 최대 한 번 보완한 뒤 패치 없이 사유를 반환한다.
- 일치하는 근거 ID만으로 원인의 의미적 정확성이나 런타임 정상 동작을 보장하지 않는다.

## 4. 로컬 확인 / 빌드에서 재사용

모델 없이 실문법 검사를 확인한다(원본 명령 exit=1, 수정본 exit=0):

```bash
uv run python -m echo_agent.diagnosis_cli check --source tests/fixtures/diagnosis/broken.html --local-node
uv run python -m echo_agent.diagnosis_cli check --source tests/fixtures/diagnosis/fixed.html --local-node
```

`--local-node`는 CI에 설치된 Node로 고정 파서만 실행하는 명시적 옵션이다. 생략하면 Docker다. 실제 진단 서비스는 이 옵션으로 자동 전환하지 않는다.

Docker 이미지 사전 준비와 전체 앞단 재생(모델 API 호출 없음):

```bash
docker pull node:24-bookworm-slim@sha256:01d566e8d94d8c619591d78652babfccd3c6992a3dffa9ed5ab39e11cf6c70e9
uv run python -m echo_agent.diagnosis_cli diagnose \
  --input tests/fixtures/diagnosis/request.json \
  --model-response tests/fixtures/diagnosis/model-response.json
```

fixture의 소스·커밋·로그와 모델 답은 합성 자료다. 재생 결과는 항상 simulated=true, model=null, processing 없음이다. 실제 Node 검사를 사용하지만 실제 Claude 품질이나 운영 통합 성공의 증거는 아니다. `--model-response`를 생략하면 ANTHROPIC_API_KEY가 필요하고 실제 과금 호출이 발생한다. CLI는 결과 JSON만 출력하며 저장·배포·PR 생성을 하지 않는다. `--was-result`를 더하면 로컬 상세 기록 대신 #98 제출용 필드로 변환한 결과를 출력한다.

## 5. 통합 전 인수 조건과 되돌리기

1. 지민: CHANGE_PROPOSAL 작업 생성·claim·결과·상세/승인 계약, 정확한 실패 소스 전달, diagnosis 응답 확장.
2. WAS/데모 앱: 동일한 문법 검사를 빌드에 연결하고 그 실패 로그를 제공. 현재 앱은 정적 HTML이라 /healthz로 프론트 문법 오류를 잡을 수 없다.
3. 후단: 현재 echo-ai-agent scenarios/ 고정 경로와 고정 커밋만 받는 APPLY_PATCH에 이번 고객 파일/커밋을 연결. 앞단은 후단 허용 목록을 해제하지 않는다.
4. 화면: 진단·문법 검사·샌드박스 검증·실제 재배포 상태를 구분. 저장소 반영/재배포는 지민 담당이며 현재 이 변경에는 없다.

위 계약이 배포·통합 검증된 뒤에만 `ECHO_DIAGNOSIS=on` 또는 `--diagnose`로 활성화한다. 기본 off, --no-model과 동시 사용 금지. 끄면 CHANGE_PROPOSAL을 claim하지 않고 기존 PRECHECK/APPLY_PATCH만 처리한다. 이 변경은 운영 VM 설정을 바꾸지 않는다.

## 6. 확인 기록 (2026-11-07)

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
