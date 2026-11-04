# AI 에이전트 1 부록 A: WAS ↔ AI 러너 계약 v1

> **상태:** **v1 승인(2026-11-04, 김형래, 8절 권장안대로).** echo-was 쪽 구현(새 표·리비전·검사기 `require_runner`·감사 SYSTEM)은 echo-was에 PR로 올리고 **echo-was 담당(Saccharine1211 님) 리뷰 뒤에 병합**한다. 그 PR에서 이 내용을 echo-was 문서로 옮긴다(사람 쪽 API는 `docs/api/prechecks.md`, 러너 쪽은 `docs/agent-runner.md`, 가칭). 옮기기 전까지 원본은 이 파일이다. 리뷰에서 바뀌면 이 파일도 같이 고친다.
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
| `APPLY_PATCH` | 사람이 승인한 패치를 echo-ai-agent의 시나리오 사본 브랜치 `applied/<runId>`에 커밋(P0 반영). 승인 때의 `patchHash`와 다시 계산한 해시가 같을 때만 | `{appliedCommitSha, branch}` |
| `CHANGE_PROPOSAL` | (P1) 지정한 finding 하나에 대한 수정안만 | `patches`만 |

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

### 3.3 결과 스키마 `RunResult`

```json
{
  "status": "SUCCEEDED",
  "failureCode": null,
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
1. 스키마를 엄격히 검사한다(모르는 칸 거부). 크기 제한: diff 하나 200KB, 패치 10개, findings 100개, 이벤트 message 2KB(가칭).
2. `mask_secrets()`를 한 번 더 거친다(기존 함수).
3. **AI 결과로는 PASS를 만들지 않는다.**
   - `origin`이 AI인 finding의 `result`는 WARN·FAIL·UNKNOWN만 받는다(PASS면 422).
   - 저장할 때는 `confirmation = UNCONFIRMED`로 둔다.
4. **패치 상태는 WAS가 다시 계산한다.**
   - `checks` 중 하나라도 PASS가 아니거나 `touchesProtectedFiles`가 true면 `BLOCKED`(`blockReason`)다.
   - 그 밖은 `PROPOSED`(승인 대기)다.
   - 러너가 보낸 상태값은 믿지 않는다.
5. **`blockedAttempts`를 확인한다.** 러너가 보낸 것과 WAS `audit_logs`의 같은 실행 시간대 AGENT 403 기록을 맞춰 `auditLogId`를 붙인다. WAS에 기록이 없는 시도는 "확인 안 됨"으로 표시한다.
6. `simulated`: 실제 샌드박스에서 실제 모델로 돌았으면 false다. 러너의 가짜 모드(개발용)면 true이고, 화면에 배지를 단다.

## 4. AI 패치 승인

- **표 `agent_patch_approvals`(가칭):** `run_id, patch_id, patch_hash, checks_digest, policy_version, decision(APPROVED|REJECTED), decided_by_user_id, reason, decided_at`
- **승인할 수 있는 사람:** 개발자 이상의 사람만. 에이전트 토큰은 403이다.
  - 실행을 요청한 사람이 스스로 승인하는 것은 조직의 `allow_self_approval`을 따른다(기존 규칙과 같음).
- **지문:** `patch_hash + checks_digest + policy_version`. 승인 때 다시 계산해서 다르면 409 `PATCH_STALE`이다.
- **`BLOCKED` 패치는 승인할 수 없다**(409 `PATCH_BLOCKED`).
- **반영:** 승인하면 WAS가 `APPLY_PATCH` 실행을 만든다. P0 반영 대상은 echo-ai-agent의 시나리오 사본 브랜치뿐이고, 운영 저장소·운영 환경에는 쓰지 않는다. 운영 고객 저장소로의 PR(PR 봇)은 P1이다.
- **배포 키:** 반영에 쓰는 GitHub 배포 키는 echo-ai-agent 저장소 하나에만 쓰기 권한이 있다. Secret Manager에 두고 제어 프로세스만 가진다(모델 도구로 노출하지 않음).

## 5. 감사

| 행동 | 행위자 | 비고 |
|---|---|---|
| 사전 점검 생성·취소, 패치 승인·거절 | USER | 결과 SUCCEEDED |
| 실행 가져가기·결과 제출·시간 초과 | SYSTEM, `component = ai-runner` | 러너 토큰·실행 토큰은 결정적 코드만 쓴다. **SYSTEM 중에서도 이 신원은 실행 가져가기·결과 제출만 할 수 있고**, 사전 승인 DR 같은 다른 SYSTEM 권한은 없다 |
| 모델이 부른 운영 읽기·쓰기 시도 | AGENT | 쓰기는 이미 403 DENIED로 기록된다(기존). 읽기 성공을 기록할지는 P1 |
| 패치 BLOCKED 판정 | SYSTEM, `component = was` | 사유 포함 |

감사 줄에는 `runId`를 붙여 한 실행의 사람·AI·SYSTEM 행동을 이어 본다(계약 4-8 수정안).

## 6. 오류 코드 (가칭)

| 코드 | HTTP | 언제 |
|---|---|---|
| `RUNNER_TOKEN_INVALID` | 401 | 러너·실행 토큰 없음·형식 오류·무효 |
| `RUNNER_FORBIDDEN` | 403 | 러너 경로에 사람·에이전트 자격으로 접근 |
| `RUN_NOT_ACTIVE` | 409 | 마감 지남·취소·끝난 실행에 하트비트·이벤트 |
| `RESULT_ALREADY_SUBMITTED` | 409 | 결과 두 번째 제출 |
| `RESULT_INVALID` | 422 | 스키마·크기·AI PASS 위반 |
| `PRECHECK_IN_PROGRESS` | 409 | 같은 서비스에 열린 실행이 있음 |
| `PATCH_STALE` · `PATCH_BLOCKED` | 409 | 4절 |

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
2. 계획 이전(PLANNED) 계획을 만들 때 최신 사전 점검을 **필수**로 한다. 재난 자동 이전(EMERGENCY)에는 적용하지 않는다(AI는 DR 실행 경로에서 제외). 유효기간은 팀 결정 D01로 따로 정한다.
3. 제한 값: 실행 마감 **15분**, 임대 **60초**(하트비트로 연장), 결과 크기는 3.3절 값(diff 하나 200KB, 패치 10개, findings 100개, 이벤트 message 2KB).
