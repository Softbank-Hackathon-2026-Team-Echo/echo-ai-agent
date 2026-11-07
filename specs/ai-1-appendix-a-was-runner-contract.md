# AI 에이전트 1 부록 A: WAS ↔ AI 러너 계약 v1

> **상태:** **v1 승인(2026-11-04, 김형래, 8절 권장안대로).** echo-was 쪽 구현(새 표·리비전·검사기 `require_runner`·감사 SYSTEM)은 echo-was에 PR로 올리고 **echo-was 담당(Saccharine1211 님) 리뷰 뒤에 병합**한다. 그 PR에서 이 내용을 echo-was 문서로 옮긴다(사람 쪽 API는 `docs/api/prechecks.md`, 러너 쪽은 `docs/agent-runner.md`, 가칭). 옮기기 전까지 원본은 이 파일이다. 리뷰에서 바뀌면 이 파일도 같이 고친다.
> **11/7 보완:** APPLY_PATCH의 현재 v1 계약은 4절·6.2절로 정정한다. 검증 상세의 새 필드는 [별도 v1.1 검토안](ai-apply-result-details-v1.1.md)이며 아직 전송하지 않는다.
> **대조 기준:** AI main [fe63df8](https://github.com/Softbank-Hackathon-2026-Team-Echo/echo-ai-agent/tree/fe63df89b84491019c4cdd85d92a3127c900b4c1), WAS main [4a29fb0](https://github.com/Softbank-Hackathon-2026-Team-Echo/echo-was/tree/4a29fb0). 구현 기준이며 운영 적용 여부와는 별개다.
> **작성:** 2026-11-03 23:00 KST 무렵 · Claude Code
> **대상:** 레인 A(echo-was 구현) · 레인 B(echo-ai-agent 러너 구현) · 김도영 님(화면, 계약 4-5)
> **이름:** 모두 가칭이다. 최종 이름은 echo-was 용어 사전에 먼저 적는다.

## 1. 한눈에

```text
사람(개발자)  ──POST 사전 점검──▶  WAS  ──(실행 행 QUEUED)
                                   ▲  │
러너(샌드박스 VM, 제어 프로세스)        │  │ ① 실행 가져가기: 러너 토큰
   │  ② 작업 공간 컨테이너에서 점검·수정   │  ▼
   │  ③ 진행 이벤트·결과 제출: 실행 토큰 ──┘
   └─ 모델이 운영을 읽을 때만: 에이전트 토큰(GET·HEAD만, 쓰기는 403 + 감사)
```

- **러너가 WAS를 폴링한다(pull).** 샌드박스는 들어오는 연결이 0이다. WAS는 러너를 부르지 않는다.
- **자격 증명은 세 가지이고, 서로 섞지 않는다.**

| 자격 증명 | 누가 가짐 | 할 수 있는 것 | 모델(AI)이 쓰나 |
|---|---|---|---|
| **러너 토큰** `echo_rnr_…` (새로) | 제어 프로세스(결정적 코드) | 실행 가져가기만 | **아니요.** 도구로 노출하지 않는다 |
| **실행 토큰** `echo_run_…` (새로, 실행마다) | 제어 프로세스 | 그 실행 하나의 이벤트·결과 제출·임대 연장. 결과를 내거나 마감이 지나면 무효 | **아니요** |
| **에이전트 토큰** `echo_agt_…` (기존) | 제어 프로세스. 모델의 `platform_request` 도구가 이것으로 호출 | 그 조직 읽기만(GET·HEAD). 쓰기는 403 `AGENT_READ_ONLY` + 감사 | **예**(읽기 전용) |

- **경계는 서버가 지킨다.** 모델 도구는 메서드를 걸러내지 않고 그대로 WAS로 보낸다. 쓰기 시도는 WAS가 403으로 거부하고 감사에 남긴다. 이것이 시연 장면 "운영 변경 시도 거부"다. 서버 거부는 이미 구현돼 있다(`app/auth/guards.py`).
- 세 토큰 모두 WAS에는 SHA-256 해시만 저장한다(기존 `app/auth/tokens.py` 방식). 원문은 발급 응답에서 한 번만 준다.

## 2. 실행(Run)

### 2.1 종류

| `kind` | 하는 일 | 결과 |
|---|---|---|
| `PRECHECK` | 출발·도착 환경 차이 분석 + 시나리오 대상 점검 + 수정안 생성·검증 | 3.1절 결과 전체 |
| `APPLY_PATCH` | 승인한 diff를 샌드박스 사본에 적용·로컬 커밋·빌드·Trivy·healthz 검증. push 없음. 입력 해시와 승인 지문 재확인 | `{status, failureCode, simulated, appliedCommitSha, branch}` (4절) |
| `CHANGE_PROPOSAL` | 배포 실패 진단·수정안. WAS #101 구현, 러너 AI #24/#25 병합·적용은 별도 확인 | WAS는 `RunResult` 공통 칸과 `diagnosis`를 받음. APPLY_PATCH와 별개 |

### 2.2 상태

`QUEUED → CLAIMED → RUNNING → SUCCEEDED | FAILED | TIMED_OUT | CANCELLED`

- 상태는 조건부 UPDATE로만 바꾼다(WAS 규칙).
- 실행 하나에는 **마감**(`deadlineAt`, 기본 15분, 가칭)과 **임대**(`leaseUntil`, 60초, 하트비트로 연장)가 있다.
- 임대가 끝나면 WAS가 `TIMED_OUT`으로 바꾸고 실행 토큰을 무효로 한다. 다시 시도는 사람이 새 실행을 만드는 방식으로 한다(자동 재시도 없음).
- 같은 서비스에서 열린 실행(QUEUED·CLAIMED·RUNNING)은 하나만 둔다(부분 unique).

### 2.3 저장 (기반 스키마 A1-1에 포함)

`agent_runs`(가칭) 칸: `id, organization_id, service_id, kind, status, source_environment_id, target_environment_id, scenario_ref, input_snapshot(JSONB, 비밀 없음), input_hash, requested_by_user_id, claimed_by_runner_id, run_token_hash, lease_until, deadline_at, started_at, finished_at, failure_code, result(JSONB), model_id, prompt_version, simulated, created_at, updated_at`

- 이벤트(로그)는 별도 표 `agent_run_events`: `run_id, seq, at, step, level, message, data`. message는 고정 문장 + data.
- 패치 승인은 별도 표: 4절.

## 3. API

모든 응답은 기존 `ApiResponse[T]` 봉투를 쓴다. 경로 접두어는 `/api/v1`.

### 3.1 사람 쪽 — 계약 4-5 (기존 검사기 사용)

| 메서드·경로 | 검사기 | 하는 일 |
|---|---|---|
| `POST /api/v1/orgs/{org_id}/prechecks` `{serviceId, targetEnvironmentId}` | `HumanDeveloperAccess` | 실행 생성(QUEUED). WAS가 `input_snapshot`을 만든다: 두 환경 설정(비밀 참조만), 서비스 연결, 이미지 digest, 최근 findings(Trivy·TLS), 시나리오 ref. **이 시점에 비밀 가리기를 거친다** |
| `GET /api/v1/orgs/{org_id}/prechecks/{id}` | `ViewerAccess` | 상태 + 결과(계약 4-5 모양 + 수정안의 `checks[]`·`patchHash`·`blockReason`) |
| `GET …/prechecks/{id}/logs?after=` | `ViewerAccess` | 이벤트 목록(seq 이후) |
| `POST …/prechecks/{id}/cancel` | `HumanDeveloperAccess` | 열린 실행 취소, 실행 토큰 무효 |
| `POST …/prechecks/{id}/patches/{patchId}/approve` · `/reject` `{reason?}` | `HumanDeveloperAccess` | 4절 |

### 3.2 러너 쪽 (새 검사기 `require_runner`)

- **러너 토큰 / 실행 토큰 전용 검사기를 새로 만든다.** 사람 쿠키·에이전트 토큰으로는 거부(403)한다.
- `test_every_route_has_guards`·역할 표 시험에 새 검사기를 넣는다.

| 메서드·경로 | 자격 | 요청 | 응답 |
|---|---|---|---|
| `POST /api/v1/runner/runs:claim` | 러너 토큰 | `{runnerId, capabilities: ["PRECHECK"]}` | 200 `{run: {id, kind, orgId, serviceId, inputSnapshot, inputHash, scenarioRef, deadlineAt}, runToken}` · 가져갈 실행이 없으면 200 `{run: null}` |
| `POST /api/v1/runner/runs/{id}/heartbeat` | 실행 토큰 | `{}` | 200 `{leaseUntil}` · 마감 지남·취소됨이면 409 `RUN_NOT_ACTIVE` |
| `POST /api/v1/runner/runs/{id}/events` | 실행 토큰 | `{events: [{seq, at, step, level, message, data}]}` (한 번에 최대 100개) | 200 `{acceptedUpTo}` · 같은 seq는 무시(멱등) |
| `POST /api/v1/runner/runs/{id}/result` | 실행 토큰 | 3.3절 `RunResult` | 200 `{status}` → 실행 토큰 즉시 무효 · 두 번째 제출은 409 `RESULT_ALREADY_SUBMITTED` |

- **가져가기:** `FOR UPDATE SKIP LOCKED` + 임대(기존 jobs 방식)로 하나만 준다.
- **실행 토큰:** 가져가기 때 새로 만들어 해시만 저장한다. 그 실행 ID에만 쓸 수 있다. 결과 제출·마감·취소 때 무효가 된다.
- **러너 토큰 발급:** 어드민이 하는 명령(`python -m app.scripts.issue_runner_token`, 가칭)으로만 한다. API로는 발급하지 않는다(P0). 원문은 한 번만 출력하고, 샌드박스 VM의 제어 프로세스에만 둔다.

### 3.3 PRECHECK 결과 스키마 `RunResult`

다음은 공통 결과 구조를 설명하는 축약 예다. APPLY_PATCH는 4.3절의 별도 5개 필드를 사용한다.

```json
{
  "status": "SUCCEEDED",
  "failureCode": null,
  "simulated": false,
  "sandbox": {"id": "sbx-…", "startedAt": "…", "finishedAt": "…", "network": "none", "deletedAt": "…"},
  "model": {"id": "claude-opus-5-5", "effort": "medium", "promptVersion": "precheck-v1", "refusal": false},
  "configDiff": [{"key": "ingress.className", "source": "alb", "target": "gce", "origin": "RULE", "severity": "INFO"}],
  "featureGaps": [{"source": "ALB Ingress", "target": "GCLB Ingress", "gap": "…", "action": "…", "hasReplacement": true, "severity": "WARN", "origin": "AI"}],
  "findings": [{"control": "policy", "environmentId": "…", "result": "WARN", "title": "…", "reason": "…", "origin": "AI", "suggestedFix": "…"}],
  "patches": [{
    "id": "p1", "patchHash": "sha256:…", "files": ["Dockerfile"], "diff": "--- a/Dockerfile\n+++ b/Dockerfile\n…",
    "reason": "…", "touchesProtectedFiles": false,
    "checks": [{"name": "TESTS", "result": "PASS", "toolVersion": "pytest 8.x", "summary": "19 passed"},
               {"name": "TRIVY", "result": "PASS", "toolVersion": "trivy 0.75.0", "summary": "HIGH 0 / CRITICAL 0"},
               {"name": "GITLEAKS", "result": "PASS", "toolVersion": "8.24.3"},
               {"name": "POLICY", "result": "PASS", "policyVersion": "sec-rules-2026.11.04"}]
  }],
  "blockedAttempts": [{"action": "POST /api/v1/orgs/…/services/…/deploy-requests", "target": "service …", "at": "…", "reason": "AGENT_READ_ONLY"}]
}
```

**WAS가 받을 때 지키는 것**
1. 스키마를 엄격히 검사한다(모르는 칸 거부). 크기 제한: diff 하나 200KB, 패치 10개, findings 100개, 이벤트 message 1~200자·data JSON 2,000자.
2. `mask_secrets()`를 한 번 더 거친다(기존 함수).
3. **AI 결과로는 PASS를 만들지 않는다.**
   - `origin`이 AI인 finding의 `result`는 WARN·FAIL·UNKNOWN만 받는다(PASS면 422).
   - 저장할 때는 `confirmation = UNCONFIRMED`로 둔다.
4. **패치 상태는 WAS가 다시 계산한다.**
   - `checks` 중 하나라도 PASS가 아니거나 `touchesProtectedFiles`가 true면 `BLOCKED`(`blockReason`)다.
   - 그 밖은 `PROPOSED`(승인 대기)다.
   - 러너가 보낸 상태값은 믿지 않는다.
5. **`blockedAttempts`를 확인한다.** 러너가 보낸 것과 WAS `audit_logs`의 같은 실행 시간대 AGENT 403 기록을 맞춰 `auditLogId`를 붙인다. WAS에 기록이 없는 시도는 "확인 안 됨"으로 표시한다.
6. `simulated`는 결과를 모의로 만들었는지 표시하는 필수 값이다. 실제 샌드박스 검사는 모델 없이도 false일 수 있다. `model = null`은 AI 검토 없음이며 simulated와 별개다. 모의 결과는 true로 보내고 화면·게이트에서 실제 검증과 구분한다.

## 4. AI 패치 승인·샌드박스 반영

### 4.1 승인과 실행 신원

- `agent_patch_approvals`: `run_id, patch_id, patch_hash, checks_digest, policy_version, decision, decided_by_user_id, reason, decided_at`.
- 개발자 이상의 사람만 승인한다. 에이전트 토큰은 403이며, 자기 승인은 조직의 `allow_self_approval`을 따른다.
- 승인 지문은 `patch_hash + checks_digest + policy_version`이다. 바뀌면 409 `PATCH_STALE`, `BLOCKED` 패치는 409 `PATCH_BLOCKED`다.
- WAS가 승인된 내용으로 `APPLY_PATCH` 입력 사본을 만든다. 러너는 입력의 diff 해시를 다시 계산하고, WAS도 성공 결과를 받을 때 승인 행·입력 사본·diff를 대조한다.
- **러너에는 저장소 쓰기용 배포 키를 주지 않는다.** 패치 적용·로컬 커밋·빌드·스캔·healthz는 샌드박스에서 한다. 브랜치·이미지는 러너가 push하지 않는다. 기존의 “배포 키로 시나리오 브랜치에 커밋” 문구는 이 규칙으로 정정한다.

### 4.2 현재 입력 사본 v1

PRECHECK가 제안한 시나리오 패치의 입력은 다음 모양이다. diff·해시는 구조를 설명하기 위해 축약했다.

```json
{
  "schemaVersion": 1,
  "parentRunId": "11111111-1111-4111-8111-111111111111",
  "patch": {
    "id": "p1",
    "patchHash": "sha256:<diff UTF-8 바이트의 SHA-256>",
    "files": ["scenarios/demo-app-0ff0d44/Dockerfile"],
    "diff": "--- a/scenarios/demo-app-0ff0d44/Dockerfile\n+++ b/scenarios/demo-app-0ff0d44/Dockerfile\n...",
    "origin": "RULE"
  },
  "repo": "Softbank-Hackathon-2026-Team-Echo/echo-ai-agent",
  "branch": "applied/22222222-2222-4222-8222-222222222222"
}
```

- `branch`는 **반영 실행 ID**로 만든다. 부모 실행 ID가 아니다.
- 시나리오 경로의 파일·상위 디렉터리 링크, 사본 밖 경로, `files`와 diff 경로 불일치는 거부한다. 형식은 `parse_apply_input`, 검사 범위는 `check_target`과 `check_real_targets`의 현재 구현을 따른다.
- 시나리오 v1 입력에는 기준 커밋·대상 이미지 digest가 없다. 러너 체크아웃과 `SCENARIO_BUILDS`의 고정 소스/healthz 설정을 사용한다. 이를 임의의 고객 이미지에 묶인 검증이라고 해석하지 않는다.
- **배포 실패 진단의 별도 경로:** WAS #101은 `repo`를 서비스 저장소로 바꾸고 `diagnosis{deployRequestId, environmentId, sourceCommitSha}`를 더한다. WAS 쪽에는 구현됐지만 이 문서의 러너 main 기준에서는 아직 처리하지 않는다. 러너 구현은 진행 중인 [AI #24](https://github.com/Softbank-Hackathon-2026-Team-Echo/echo-ai-agent/pull/24)·[#25](https://github.com/Softbank-Hackathon-2026-Team-Echo/echo-ai-agent/pull/25)로 인수한다. 시나리오 전용 main 러너가 이 입력을 받아도 된다는 뜻이 아니다.
- 입력에 없는 digest를 새 결과 필드만으로 승인 지문에 추가할 수는 없다. 기준 커밋·이미지·설정 바인딩은 WAS 입력 생성과 승인 지문을 함께 바꾸는 별도 후속이다.

### 4.3 현재 전송 계약: `ApplyPatchResult` 5개 필드

`POST /api/v1/runner/runs/{id}/result`에 보낸다. PRECHECK의 `RunResult`와 별개다.

```json
{
  "status": "SUCCEEDED",
  "failureCode": null,
  "simulated": false,
  "appliedCommitSha": "0123456789abcdef0123456789abcdef01234567",
  "branch": "applied/22222222-2222-4222-8222-222222222222"
}
```

| 필드 | 현재 WAS 수신 규칙 | 의미 |
|---|---|---|
| `status` | 필수, `SUCCEEDED` 또는 `FAILED` | 반영 실행 결과. `TIMED_OUT`·`CANCELLED`는 서버 상태 전이이며 러너 결과 값이 아니다 |
| `failureCode` | 성공이면 null, 실패이면 필수. `^[A-Z][A-Z0-9_]{0,31}$` | 6.2절의 실패 원인. 성공에서는 생략 시 null |
| `simulated` | 필수 bool | 모의 실행 여부. true는 실제 검증 성공 근거가 아니다 |
| `appliedCommitSha` | 소문자 40자리 hex 또는 null. 실패이면 반드시 null. 생략 시 null | 러너가 만든 **로컬 커밋**. 원격에 존재하거나 배포 가능하다는 보증이 아니다 |
| `branch` | 성공이면 1~255자 문자열이며 입력 사본과 일치. 실패이면 null/생략 또는 같은 길이 제한의 문자열, 입력과 대조하지 않음 | 러너 작업 사본의 브랜치 식별자. 실제 원격 브랜치 생성 여부와 별개 |

null 허용과 성공 의미:

| 상황 | `status` / `simulated` | SHA / branch | 해석 |
|---|---|---|---|
| 실제 검사 통과·git 작업 사본 | `SUCCEEDED` / false | 로컬 SHA / 입력 branch | 샌드박스 검증 완료 |
| 실제 검사 통과·git 없는 사본 | `SUCCEEDED` / false | null / 입력 branch | 검증은 끝났지만 커밋 산출물 없음 |
| 입력 해석 전 실패 | `FAILED` / false | null / null 가능 | `INPUT_INVALID` 등. 검증 완료 아님 |
| 패치 적용·검사 도중 실패 | `FAILED` / false | null / 입력 branch 가능 | 먼저 커밋했더라도 실패 결과의 SHA는 null |
| 모의 성공 | `SUCCEEDED` / true | 형식에 맞는 SHA 또는 null / 입력 branch | 호환상 수신할 수 있지만 실제 검사·수정본 확보 증거가 아님 |

실패 전송 예:

```json
{
  "status": "FAILED",
  "failureCode": "IMAGE_SCAN_FAILED",
  "simulated": false,
  "appliedCommitSha": null,
  "branch": "applied/22222222-2222-4222-8222-222222222222"
}
```

현재 러너는 성공·실패 모두 5개 필드를 보낸다. 현재 WAS에는 반영 결과의 `checks`·`artifacts`·`nextStep`·`processing`·`sandbox`·`model`·결과 `patchHash` 필드가 없으며, 보내면 422 `RESULT_INVALID`다. **PRECHECK에서 `processing`을 받는다는 사실을 APPLY_PATCH 수용으로 해석하지 않는다.**

성공 결과에서 WAS는 승인 행의 `patchHash`와 입력 diff의 해시를 재확인하고 branch를 대조한다. 불일치는 422이며 결과를 저장하지 않는다. 임대·마감 만료는 이 지문 검사보다 먼저 처리하여 `TIMED_OUT`을 커밋한 뒤 409 `RUN_NOT_ACTIVE`로 끝낸다. 유효한 실패 결과를 받는 HTTP 응답은 200일 수 있다. HTTP 성공은 작업 성공과 다르다.

### 4.4 “성공”과 저장소·배포 경계

[11/7 합의](https://github.com/Softbank-Hackathon-2026-Team-Echo/echo-ai-agent/issues/5#issuecomment-6693323096)에 따라, 실제 APPLY_PATCH의 `SUCCEEDED`는 **승인된 패치의 샌드박스 적용·빌드·Trivy·healthz 검증 완료를 러너가 보고한 것**이다. 모델 사용 여부와는 무관하다. WAS가 빌드·스캔을 독립적으로 다시 수행했다거나 원격 반영·프로덕션 배포가 끝났다는 뜻은 아니다.

| 단계 | 담당과 근거 | 구분해서 표시할 상태 |
|---|---|---|
| 승인된 diff 적용·실제 검사 | 러너 결과와 같은 실행의 이벤트 | 샌드박스 검증 완료 / 실패 / 모의 결과 |
| 원격 저장소 커밋·PR | 별도 WAS 제어 코드의 GitHub 결과 | 저장소 반영 완료 / 실패 / 미수행 |
| 그 수정 커밋의 실제 배포 | 해당 deploy request와 배포 결과 | 배포 진행 / 완료 / 실패 / 미수행 |

WAS #105는 진단 반영에 대해 별도 GitHub App으로 저장소 커밋·PR을 만드는 기능을 추가했다(`AI_APPLY_COMMIT_ENABLED`, 기본 off). 켜진 실제 경로에서는 서버가 저장 결과의 `appliedCommitSha`·`branch`를 원격 값으로 바꾸고, 원래 로컬 값은 내부 `sandboxCommitSha`·`sandboxBranch`에 보관한다. 이는 **러너 POST 요청 스키마의 확장이 아니며**, 내부 필드 전부가 공개 응답으로 노출된다는 뜻도 아니다.

이 기능과 실제 운영 적용은 별개다. 현재 코드에는 스위치 off 또는 simulated일 때 원래 실패 커밋으로 재배포하는 경로도 남아 있다([WAS #101 보안 후속](https://github.com/Softbank-Hackathon-2026-Team-Echo/echo-was/pull/101#issuecomment-6693320688)). 이를 “검증한 수정본을 배포했다”는 증거로 사용하지 않는다. 원격 쓰기·배포를 연결할 때는 승인 내용, 실제 검증 대상, 원격 커밋, 배포 ref의 일치를 별도로 확인해야 한다.

### 4.5 이벤트·네트워크·후속 확장

반영 전용 step을 새로 만들지 않고 기존 값을 유지한다.

| step | 반영 실행에서 기록하는 것 |
|---|---|
| `INPUT_LOAD` | 입력·승인 diff 해시·대상 검사와 해당 실패 |
| `SANDBOX_CREATE` | 작업 사본 생성 |
| `PATCH_VERIFY` | 패치 적용·로컬 커밋·빌드·Trivy·healthz 결과와 실패 |
| `SANDBOX_DELETE` | 정리 결과. 정리 시도와 성공을 구분 |

message는 1~200자, data는 JSON 2,000자 제한을 따른다. 도구 버전·실패 코드·검사 수치만 남기고 토큰·환경 변수 값·원본 로그를 결과에 싣지 않는다.

현재 시나리오 빌드는 이미지·의존성을 받기 위해 Docker 기본 네트워크를 사용하고, 앱 healthz 컨테이너는 `--network none`을 사용한다. 두 경계를 혼동하지 않는다. 이 문구는 빌드 단계의 소켓·비밀·메타데이터 접근 차단까지 운영에서 검증했다는 승인이 아니다([infra #78 보안 조건](https://github.com/Softbank-Hackathon-2026-Team-Echo/echo-infra/pull/78)). `precheck_runner.py`의 종류 분기와 `apply_runner.py`의 제어 흐름은 유지한다.

구조화된 검증 결과·산출물·다음 행동·processing의 구체적인 추가안은 [APPLY_PATCH 결과 확장안](ai-apply-result-details-v1.1.md)에 있다. **검토안이며 현재 전송 계약이 아니다.** WAS 수신·저장·조회와 옛 5개 필드 호환을 먼저 배포한 뒤 러너 전송과 화면을 연결한다.

## 5. 감사

| 행동 | 행위자 | 비고 |
|---|---|---|
| 사전 점검 생성·취소, 패치 승인·거절 | USER | 결과 SUCCEEDED |
| 실행 가져가기·결과 제출·시간 초과 | SYSTEM, `component = ai-runner` | 러너 토큰·실행 토큰은 결정적 코드만 쓴다. **SYSTEM 중에서도 이 신원은 실행 가져가기·결과 제출만 할 수 있고**, 사전 승인 DR 같은 다른 SYSTEM 권한은 없다 |
| 모델이 부른 운영 읽기·쓰기 시도 | AGENT | 쓰기는 이미 403 DENIED로 기록된다(기존). 읽기 성공을 기록할지는 P1 |
| 패치 BLOCKED 판정 | SYSTEM, `component = was` | 사유 포함 |

감사 줄에는 `runId`를 붙여 한 실행의 사람·AI·SYSTEM 행동을 이어 본다(계약 4-8 수정안).

## 6. HTTP 오류와 실행 실패 코드

### 6.1 API 응답 오류

| 코드 | HTTP | 언제 |
|---|---|---|
| `RUNNER_TOKEN_INVALID` | 401 | 러너·실행 토큰 없음·형식 오류·무효 |
| `RUNNER_FORBIDDEN` | 403 | 러너 경로에 사람·에이전트 자격으로 접근 |
| `RUN_NOT_ACTIVE` | 409 | 마감 지남·취소·끝난 실행에 하트비트·이벤트 |
| `RESULT_ALREADY_SUBMITTED` | 409 | 결과 두 번째 제출 |
| `RESULT_INVALID` | 422 | 스키마·크기·AI PASS 위반 |
| `PRECHECK_IN_PROGRESS` | 409 | 같은 서비스에 열린 실행이 있음 |
| `PATCH_STALE` · `PATCH_BLOCKED` | 409 | 4절 |

### 6.2 반영 실행의 `failureCode` (현재 이름 유지)

다음은 HTTP 오류 코드가 아니라, 정상 수신된 `status: "FAILED"` 결과의 원인이다. WAS는 형식만 검사하므로 이 표를 닫힌 서버 enum으로 오해하지 않는다. 이름을 바꾸거나 같은 실패를 새 코드로 중복 분류하지 않는다.

| 구분 | 코드 | 실패 조건 / 이벤트 |
|---|---|---|
| 반영 전용 | `PATCH_HASH_MISMATCH` | 승인된 diff 해시와 재계산 값 불일치 / INPUT_LOAD |
| 반영 전용 | `PATCH_TARGET_FORBIDDEN` | 허용 경로 밖·링크 탈출·files/diff 불일치 등 / INPUT_LOAD |
| 반영 전용 | `PATCH_APPLY_FAILED` | 파일 없음·문맥 불일치·diff 적용 실패 / PATCH_VERIFY |
| 반영 전용 | `VERIFY_UNAVAILABLE` | 필요한 docker·trivy·시나리오 검사 설정 없음 / PATCH_VERIFY |
| 반영 전용 | `SOURCE_UNAVAILABLE` | 고정 소스 다운로드 실패·시나리오 사본과 원본 불일치 / PATCH_VERIFY |
| 반영 전용 | `IMAGE_BUILD_FAILED` | 이미지 빌드 실패 / PATCH_VERIFY |
| 반영 전용 | `IMAGE_SCAN_FAILED` | 스캔 오류 또는 수정 가능한 HIGH/CRITICAL 취약점 발견 / PATCH_VERIFY |
| 반영 전용 | `HEALTHZ_FAILED` | 컨테이너 시작 실패 또는 제한 내 healthz 200 미확인 / PATCH_VERIFY |
| 공통 | `INPUT_INVALID` | 입력 형식·지원하지 않는 repo·branch / INPUT_LOAD |
| 공통 | `DEADLINE` | 마감 1분 전까지 결과를 낼 수 없음 / PATCH_VERIFY |
| 공통 | `RUNNER_ERROR` | 위 코드로 분류하지 못한 실행 예외 / PATCH_VERIFY |

`LEASE_EXPIRED`·`DEADLINE_EXCEEDED`는 WAS가 실행을 만료시킬 때 기록하는 코드이며 러너의 `FAILED/DEADLINE`과 구분한다. `REPO_…`는 WAS #105의 원격 저장소 후처리 코드다. 이 표의 샌드박스 검사 실패로 바꾸지 않는다.

## 7. 러너 쪽 약속 (레인 B)

- 러너 토큰·실행 토큰·에이전트 토큰·Anthropic 키는 **제어 프로세스에만** 둔다. 작업 공간·검사 컨테이너에는 넣지 않는다.
- 모델 도구 목록(P0)

  | 도구 | 하는 일 |
  |---|---|
  | `workspace_exec(cmd)` | 작업 공간 컨테이너에서 명령 실행. 네트워크 없음, 시간·출력 제한 |
  | `read_file` / `write_file` | 작업 공간 파일만 |
  | `platform_request(method, path, body?)` | 에이전트 토큰으로 WAS 호출. 메서드를 걸러내지 않음. 경계는 서버 |
  | `submit_patch(files)` | 수정안 확정 → 제어 프로세스가 새 검사 컨테이너에서 고정 검사 |

- **고정 검사**는 모델이 아니라 제어 프로세스가 돌린다.
  - 보호 파일 목록(테스트·검사 설정·CI·정책 파일)에 닿는 패치는 `touchesProtectedFiles = true`로 표시한다.
- 이벤트 `step` 값: `SANDBOX_CREATE · INPUT_LOAD · CONFIG_DIFF · ANALYZE · PATCH_PROPOSE · PATCH_VERIFY · SANDBOX_DELETE`. 화면의 단계 표시는 이것을 쓴다(프론트 시뮬레이션의 `SANDBOX · CONFIG_DIFF · FEATURE_GAPS · PATCH_VERIFY · APPROVAL`과 대응표를 프론트 안내서에 적는다).
- 마감 1분 전까지 결과를 내지 못하면 `status = FAILED`, `failureCode = DEADLINE`으로 낸다.

## 8. 결정 (2026-11-04, 김형래: 권장안대로 승인)

1. 러너 행동의 감사 행위자는 **SYSTEM + `component=ai-runner`**로 한다. 새 행위자 종류 `RUNNER`는 만들지 않는다(enum·계약 4-8을 덜 바꾼다). 이 신원은 실행 가져가기·결과 제출만 할 수 있다(5절).
2. **당시 결정은 현재 구현으로 대체:** C-AI 게이트가 켜져 있으면 PLANNED·EMERGENCY 모두 승인·시작 때 최근 PRECHECK를 확인한다. 실시간 AI를 DR 실행 경로에서 호출하는 것과는 다르다. 유효기간은 24시간이다. 동일 조직·서비스·출발·도착의 최신 REAL 선택 보완은 [WAS #108](https://github.com/Softbank-Hackathon-2026-Team-Echo/echo-was/pull/108)로 별도 진행 중이며 아직 병합·운영 적용된 정책이라고 표시하지 않는다.
3. 제한 값: 실행 마감 **15분**, 임대 **60초**(하트비트로 연장), 결과 크기는 3.3절 값(diff 하나 200KB, 패치 10개, findings 100개, 이벤트 message 200자·data JSON 2,000자).
