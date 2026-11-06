# AI 에이전트 22 간단판 — 배포 실패 진단 두뇌(규칙 + 모델 1회) · 진단 패치 반영 (CHANGE_PROPOSAL)

- 상태: Draft (지민 결정 11/7 02:5x 「진단 두뇌, #98, 고친 코드 저장소에 넣기 내가 작업」). **간단판이다 — 형래(ai#22)가 교체할 수 있다**(교체 지점은 5절).
- 이슈: echo-ai-agent #22(형래 담당, 러너 진단). 짝: echo-was #98 / PR #101(`feat/api-98-failed-deploy-diagnosis` `023ee9b`, 진단 실행·러너 계약), echo-was `feat/api-19-apply-commit-to-repo`(승인 패치를 서비스 저장소에 커밋·PR, 재배포를 그 커밋으로).
- 정본 계약: echo-was `docs/api/deploy-diagnosis.md` 「러너 계약 (CHANGE_PROPOSAL)」 + `specs/api-98-failed-deploy-diagnosis.md` 4절. 이 PR 은 계약을 바꾸지 않는다.
- 기준: echo-ai-agent main `82aac70`.

## 1. 목표

시연 시나리오 3(시연 앱 프론트 문법 오류로 배포 실패 → AI 진단 → 승인 → 고친 커밋으로 재배포)의 **러너 쪽 두 칸**을 채운다.

1. `CHANGE_PROPOSAL` 실행을 가져가 실패 로그 + 서비스 저장소(실패 커밋)로 원인·분류·근거·수정 diff 1개를 낸다.
2. 그 패치가 승인되면 오는 `APPLY_PATCH`(입력 `repo` = 서비스 저장소, `diagnosis.sourceCommitSha`)를 **서비스 저장소 기준**으로 기존 샌드박스 절차(적용·빌드·Trivy·healthz) 그대로 검증한다.

**하지 않는다:** push·PR·저장소 쓰기(러너는 읽기 자격뿐 — 저장소 반영은 WAS 가 GitHub App 으로, echo-was api-19), WAS·계약 변경, VM 반영·스위치 켜기, 비공개 저장소 읽기(토큰 없음).

## 2. 흐름

```text
claim(capabilities [PRECHECK, (APPLY_PATCH), CHANGE_PROPOSAL])   ← ECHO_DIAGNOSIS=on 일 때만 CHANGE_PROPOSAL
→ 첫 하트비트, 30초마다 하트비트(사전 점검과 같은 Heartbeat·이벤트 보내기)
→ INPUT_LOAD     입력 v1(service, deployRequest{repo, commitSha…}, failure{logTail ≤ 50줄…})
→ SANDBOX_CREATE 서비스 저장소 commitSha tarball(codeload, 토큰 없음, 반영 러너와 같은 방식). 못 받으면 로그만으로
→ ANALYZE        ① 규칙: 로그에서 파일·줄 후보(Python 역추적 `File "…", line N` · `(file, line N)` · `경로:줄[:칸]`)
                    → 컨테이너 경로 앞 조각을 떼어 저장소 파일과 맞춤(`/app/app/x.py` → `app/x.py`), 줄 수 안인지 확인
                 ② 모델 1회: 후보 파일 ±60줄(최대 2개) + 로그 50줄(줄 번호) + 실패 요약
→ PATCH_PROPOSE  모델이 낸 unified diff 1개
→ PATCH_VERIFY   `git apply --recount --check` → 적용 → difflib 로 diff 다시 만들기(정규화)
                 → 반영 러너의 엄격한 적용기(apply_patch_to_files)로 같은 결과인지 확인
→ SANDBOX_DELETE 작업 공간 지움
→ result RunResult + diagnosis (+ processing: 모델 요청을 보냈으면)
```

## 3. 결과 규칙

| 상황 | diagnosis | patches | model / processing |
|---|---|---|---|
| 모델 DIAGNOSED + diff 검증 통과 | DIAGNOSED·category·cause(모델)·fixable true | 1개 `ai-fix-1`, origin AI, 검사 `GIT_APPLY` PASS(toolVersion = git 버전) | 있음 / 있음 |
| 모델 DIAGNOSED + diff 가 안 맞음(경로가 보낸 파일 아님·문맥 불일치·추가/삭제·숨김 경로) | **INSUFFICIENT_EVIDENCE**, unfixableReason 에 `git apply --check 실패(<사유>)` + AI 추정 원인 | 없음 | 있음 / 있음 |
| 모델 DIAGNOSED + diff 없음 | DIAGNOSED·fixable false·사유(모델) | 없음 | 있음 / 있음 |
| 모델 INSUFFICIENT_EVIDENCE | INSUFFICIENT_EVIDENCE | 없음 | 있음 / 있음 |
| 모델 꺼짐(`--no-model`)·실패·거절·마감 임박 | 규칙만: 위치를 찾았으면 DIAGNOSED·CODE·cause `<경로> <줄>번째 줄에서 (문법 )오류가 났습니다: <오류 줄>`·fixable false, 못 찾았으면 INSUFFICIENT_EVIDENCE | 없음 | null / 요청을 보냈으면 있음 |
| `failure` 없음·로그 꼬리 없음 | NO_FAILURE_EVIDENCE(모델 부르지 않음) | 없음 | null / 없음 |
| 입력 v1 아님 | (빼고 냄) `FAILED`·`INPUT_INVALID` | 없음 | null |

- evidence: LOG(마지막 오류 줄 + 위치 줄, logTail 1부터 번호) + FILE(경로·줄·그 줄 내용), 최대 6개(WAS 상한 20), 문자열은 가리기·300자.
- 결과 칸은 WAS `DiagnosisRunResultRequest` 그대로(모르는 칸 없음). 위 5모양을 echo-was #101 `023ee9b` 의 스키마·정규화로 직접 검사해 모두 통과했다(패치 상태 PROPOSED).

## 4. 모델 입력·마스킹·레지던시

- 입력은 허용 칸만 새로 만든다: 서비스 이름, 배포 오류 코드, failure{code, message, containerReason, terminationReason, exitCode}, logTail[{line, text}], files[{path, focusLine, startLine, content}]. ID·변수 이름·저장소 이름·커밋은 보내지 않는다. `<diagnosis_input>` 태그 안 데이터, `<` 는 `\u003c`.
- 모든 문자열(키 포함)에 사전 점검과 같은 `precheck_model.mask_tokens`(PEM·Bearer·Basic·URL 사용자 정보·GitHub·AWS·GCP·Slack·JWT·Anthropic·sk-·Echo 토큰)를 건다.
- `processing`: location `gcp/asia-northeast3`, sandbox false, ANTHROPIC, 리전 null, dataClasses = CONFIG + (파일 조각 있으면) SOURCE_CODE + (로그 있으면) LOGS + (가린 뒤에도 고엔트로피 후보가 있으면) SECRETS. WAS 는 진단 실행을 C-AI-1·레지던시 요약에 세지 않는다(#101).
- 프롬프트 버전 `diagnosis-simple-v1`, 모델·effort·fallback·타임아웃은 사전 점검과 같은 값(`claude-opus-5-5`, medium). 구조화 출력 `{result, category, cause, fixable, diff, unfixableReason}`.

## 5. 형래(ai#22) 교체 지점

- **`diagnosis_runner.Diagnoser.diagnose(diagnosis_input, source, workspace, *, seconds_left, events, flush) -> DiagnosisOutcome`** 하나만 바꾸면 된다. 입력: 파싱된 입력 사본(`DiagnosisInput`)·받은 소스(`SourceTree` 또는 None)·작업 폴더. 출력: `DiagnosisOutcome{diagnosis, patches, model, transfer}`.
- 러너 골격(claim·하트비트·이벤트·소스 받기·결과 전송·마감)과 `verify_model_diff`(적용 확인·정규화)는 그대로 재사용할 수 있다. 결과 모양은 `build_diagnosis_result` 가 계약대로 만든다.
- 도구 루프·여러 번 호출·작업 공간 컨테이너 안 실행 등은 교체판의 몫이다.

## 6. APPLY_PATCH 서비스 저장소 모드

- 입력에 `diagnosis` 가 있으면: `repo` 는 `owner/name`(echo-ai-agent 자신은 거절), `diagnosis.sourceCommitSha` 40자, branch `applied/<runId>` → 아니면 `INPUT_INVALID`.
- 경로 검사(`check_service_target`): files = diff 머리 경로, 절대 경로·`..`·숨김 경로(`.github/` 등)·안전하지 않은 글자 금지 → `PATCH_TARGET_FORBIDDEN`. 받은 소스에서 심볼릭 링크·저장소 밖 실제 경로 금지.
- 소스: 공개 저장소 tarball(토큰 없음). 엄격 적용(`PATCH_APPLY_FAILED`) → 작업 공간 밖 git 폴더(`--git-dir`)로 기준 커밋 + 패치 커밋(빌드 문맥에 `.git` 없음, push 없음) → docker build(루트 Dockerfile) → trivy(수정 가능 HIGH·CRITICAL 0) → `--network none` healthz.
- 빌드 정보: `SERVICE_BUILDS`(echo-demo-app = 8080·`/healthz`·시나리오와 같은 가짜 DB 주소 환경), 표에 없으면 루트 Dockerfile·8080·`/healthz`.
- 결과는 그대로 `{status, failureCode, simulated:false, appliedCommitSha(로컬 커밋), branch}`. 저장소 브랜치·커밋·PR 은 WAS 가 이 결과를 받은 뒤 GitHub App 으로 만든다(echo-was api-19).

## 7. 스위치·운영

| 스위치 | 기본 | 뜻 |
|---|---|---|
| `ECHO_DIAGNOSIS` | off | on 이면 claim 에 `CHANGE_PROPOSAL`. 오타면 시작 종료 코드 2. 시작 로그 `diagnosis: off / rules only / rules + model` |
| `ECHO_PRECHECK_MODEL` | on | off(`--no-model`)면 진단도 규칙만 |
| `ECHO_APPLY_PATCH` | off | on 이어야 진단 패치 반영(APPLY_PATCH)도 가져간다 |

켜는 순서(별도 작업): 러너 새 release 배포 → `ECHO_DIAGNOSIS=on`·`ECHO_APPLY_PATCH=on` → WAS `AI_DIAGNOSIS_RUNNER_ENABLED=true`(+ `PATCH_APPLY_ENABLED=true`). WAS 를 먼저 켜면 진단 실행이 15분 `QUEUED` 뒤 `TIMED_OUT`.

## 8. 시험

`tests/test_diagnosis_runner.py` 33개(가짜 로그·가짜 모델·가짜 WAS·가짜 docker, git 은 실제):
규칙(위치 후보 3형식·라이브러리 경로 제외·경로 맞추기·입력 v1) / 모델 진단(검증된 AI 패치·모델 1회·마스킹·창 ±60줄·ID 미전송·processing·SECRETS 신고·줄 번호 정규화) / diff 불일치 3종 → INSUFFICIENT_EVIDENCE / diff 없음·모델 근거 부족 / 거절·API 오류 → 규칙 / --no-model·Python 역추적·위치 없음·실패 상세 없음·소스 못 받음·입력 오류 / 스위치·오타 종료 2·claim→결과 왕복·스위치 꺼짐 KIND_UNSUPPORTED / APPLY 서비스 모드(입력·성공·거절 3종·진단 diff → 반영 끝까지).

## 9. 미검증

- 실제 Claude 응답(가짜 모델로만 시험), 실제 VM·실제 WAS 연결, 실제 시연 앱 실패 로그 모양(로그 형식은 가정 — 후보 규칙 3형식으로 덮음), 서비스 저장소 실제 docker build·Trivy(가짜 docker; 기존 시나리오 경로의 docker 시험은 그대로 통과).
