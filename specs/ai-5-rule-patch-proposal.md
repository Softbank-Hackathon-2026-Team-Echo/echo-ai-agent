# AI 에이전트 5 초안 — 러프 사전 점검 러너의 규칙 패치 제안 1개 (S2)

- 상태: Confirmed (지민 결정 B-1 ⑦A, 11/5 15:20). 형래님 리뷰 대상(Draft PR, 병합은 형래님).
- 이슈: https://github.com/Softbank-Hackathon-2026-Team-Echo/echo-ai-agent/issues/5 (수정안 생성·검증 중 "규칙 패치" 부분만)
- 기준: echo-ai-agent main `5fd3341`(#14 러프 러너 + #15 모델 검토 병합 뒤, 11/5 15시대). #15가 이미 main에 있으므로 병합 충돌은 없다. 그래도 형래님 코드(`precheck_runner.py`·`precheck_model.py`)는 연결 줄만 만진다.
- 근거: 계약 부록 A v1(`specs/ai-1-appendix-a-was-runner-contract.md`) 2.1·3.3·4절, AI-1 SPEC(`specs/ai-1-sdk-model-sandbox.md`) D-8·AD-2·AD-3·10절, echo-was `app/schemas/runner.py` `RunPatchRequest`, `app/services/run_result.py` `patch_block_reason`.

## 1. 목표

러프 러너가 사전 점검 결과의 `patches[]`에 **규칙으로 만든 패치 1개**를 올린다. 대상은 운영 echo-demo-app이 아니라 이 저장소의 시나리오 사본 `scenarios/demo-app-0ff0d44/Dockerfile`이다. 패치 내용은 운영에서 사람이 실제로 낸 수정 echo-demo-app `6ac8813`(실행 이미지에서 pip 제거, 수정 가능한 HIGH 5건 제거)과 같다. 모델은 쓰지 않으며 `origin: "RULE"`로 정직하게 표시한다.

하지 않는다: 모델 수정안(AI #5 본편), 패치 반영(`APPLY_PATCH`, S3), 배포 키, WAS 변경(S1), 운영 echo-demo-app 수정, `precheck_model.py`·`precheck_rules.py`·`was_client.py` 수정. `README.md`는 러너 실행법 절에 `--no-patch` 한 줄과 시나리오 사본 링크만 더한다.

## 2. 확인된 사실 (요약)

- `build_result(analysis, *, status, failure_code, review=None)`는 지금 `"patches": []` 고정. `process_run(…, reviewer=None)`은 규칙 분석(`_analyze_with_events`) → 모델 검토 한 번(`_review_with_events`, `--no-model`이면 없음) → 마감 1분 여유 검사 → 제출 순서다. 이벤트 단계 `RunStep.PATCH_PROPOSE`·`PATCH_VERIFY`는 이미 있다.
- WAS `RunPatchRequest` = `{id(1~64), patchHash(^sha256:[0-9a-f]{64}$), files[1+], diff(≤200KB), reason(≤2,000자), touchesProtectedFiles, checks[{name(1~64), result(^[A-Z][A-Z0-9_]{0,31}$), toolVersion?, policyVersion?, summary?}]}`, `extra=forbid`. WAS는 checks가 비었거나 PASS 아닌 것이 있거나 보호 파일이면 BLOCKED로 다시 계산한다.
- **`origin` 칸은 지금 WAS main에 없다**(보내면 결과 전체 422). S1이 선택 칸 `origin: RULE|AI`(빠지면 AI)를 더한다 → S1 배포 전에는 `--no-patch`로 돌린다.
- `patchHash` 정의(결정 PD-14): `"sha256:" + sha256(diff 문자열의 UTF-8 바이트).hexdigest()`.
- 시나리오 사본 폴더는 아직 없다. 0ff0d44 Dockerfile(blob `a2e023c906db9107da0b03900f5695e55ceb78d4`)에 pip 제거가 없고, `6ac8813`(부모 0ff0d44)이 Dockerfile 한 덩어리 `@@ -23,7 +23,11 @@`(+5/−1)로 고쳤다.
- 입력 스냅숏 최근 findings 모양: `{controlId, result, source, environmentId, collectedAt}`. 첫 실제 실행(11/5)에서 `C-IMG-1` WARN 1건이 있었다.
- 샌드박스 VM: docker 20.10은 있으나 러너 실행 사용자가 docker 그룹이 아니라 소켓 권한이 없다. trivy·git 없음. → VM 러너에서는 docker·Trivy 검사가 돌지 않는다(정적 검사만, 결과에 그렇게 적음).

## 3. 만드는 것

| 파일 | 내용 |
|---|---|
| `scenarios/demo-app-0ff0d44/Dockerfile` (새) | echo-demo-app `0ff0d44:Dockerfile` 바이트 그대로 |
| `scenarios/demo-app-0ff0d44/README.md` (새) | 출처(저장소·커밋·blob 해시), 이 사본을 고치지 않는다는 규칙(반영은 `applied/<runId>` 브랜치 = S3), 운영은 `6ac8813`으로 이미 고쳤다는 사실, 규칙 R-PIP-1 한 문단, 앱 소스는 넣지 않았다는 점 |
| `src/echo_agent/precheck_patch.py` (새) | 규칙·diff·검사·결과 원소 만들기 전부 |
| `src/echo_agent/precheck_runner.py` (연결만) | import 1, `build_result(…, patches=…)`(기본 빈 목록), `process_run`에서 패치 단계 호출 1(규칙 분석·모델 검토 뒤, 마감 검사 앞), `run_loop`·`main`에 `--no-patch` 전달. 목표 추가 30줄 이하 |
| `README.md` (한 줄 수준) | 러너 실행법에 `--no-patch`(S1 배포 전 WAS에 대고 돌릴 때) + 시나리오 사본 README 링크 |
| `tests/test_precheck_patch.py` (새) | AC 시험 전부. 기존 시험 파일은 고치지 않는다(필요한 가짜 WAS는 import하거나 새로 만든다) |
| `tests/fixtures/demo-app-6ac8813.Dockerfile` (새) | echo-demo-app `6ac8813:Dockerfile` 바이트 그대로(기대값) |
| `specs/ai-5-rule-patch-proposal.md` | 이 SPEC(해시 고정, 고치지 않음) |

## 4. 규칙 R-PIP-1 정의

**발동 조건(둘 다 참일 때만):**
1. 입력 스냅숏 `findings[]`에 `controlId == "C-IMG-1"`이고 `result != "PASS"`인 항목이 하나 이상 있다(FAIL·WARN·UNKNOWN 등).
2. 시나리오 사본 Dockerfile의 마지막 단계(마지막 `FROM` 뒤)에 `pip uninstall`이 없다(이미 고쳐진 사본이면 내지 않는다).

`scenarioRef`는 지금 늘 null이라 보지 않는다. 규칙은 **고정 시나리오 전용**이다(사본 경로·변환이 0ff0d44 Dockerfile에 맞춰져 있음). 이 점을 `reason`과 README에 적는다.

**변환(결정적, 시각·난수 없음):** 마지막 단계의 첫 `RUN` 명령 앞에 6ac8813과 글자가 같은 주석 3줄을 넣고, 그 `RUN ` 을 `RUN python -m pip uninstall --yes --no-cache-dir pip && \` + 줄바꿈 + 공백 4칸 + 원래 명령 본문으로 바꾼다. 결과 파일은 `tests/fixtures/demo-app-6ac8813.Dockerfile`과 바이트가 같아야 한다. 마지막 단계에 `RUN`이 없거나 모양이 다르면 패치를 내지 않는다(이유 코드 `TRANSFORM_NOT_APPLICABLE`).

**diff:** `difflib.unified_diff`(문맥 3줄), 머리 `--- a/scenarios/demo-app-0ff0d44/Dockerfile` / `+++ b/scenarios/demo-app-0ff0d44/Dockerfile`, 줄 끝 `\n`. `diff --git`·index 줄은 넣지 않는다. 덩어리 머리는 `@@ -23,7 +23,11 @@`, 덩어리 본문은 6ac8813 덩어리와 같다.

## 5. 패치 원소 모양 (`result.patches[0]`)

키는 정확히 이 8개(그 밖의 칸 금지 — WAS `extra=forbid`):

| 칸 | 값 |
|---|---|
| `id` | `rule-c-img-1-pip-uninstall` |
| `patchHash` | `sha256:` + diff UTF-8 해시(64자 소문자) |
| `files` | `["scenarios/demo-app-0ff0d44/Dockerfile"]` |
| `diff` | 4절 diff |
| `reason` | 한국어, 2,000자 이하: 근거(C-IMG-1 결과·건수), "운영 echo-demo-app `6ac8813`과 같은 수정", "고정 시나리오 사본 전용 규칙(모델 아님)", 실행한 검사 이름과 **실행하지 않은 검사(docker build·Trivy)와 이유** |
| `touchesProtectedFiles` | 6절 POLICY 판정으로 계산(이 패치는 false) |
| `checks` | 6절에서 **실제로 돌린 검사만**(안 돌린 검사를 PASS로 적지 않는다) |
| `origin` | `"RULE"` |

## 6. 검사 단계 (PATCH_VERIFY)

제어 프로세스(러너)가 돌린다. 순서대로, 하나라도 PASS가 아니면 그 뒤 검사는 돌리지 않는다.

| 이름 | 언제 | 무엇 | PASS 기준 |
|---|---|---|---|
| `PATCH_APPLIES` | 늘 | 모듈 안 작은 unified diff 적용기로 diff를 원본(시나리오 사본)에 적용(문맥 줄이 다르면 실패) | 적용 결과 == 변환 결과 |
| `POLICY` | 늘 | 파일 경로가 모두 `scenarios/demo-app-0ff0d44/` 아래이고 `..`·절대 경로가 없으며 보호 패턴(`tests/`·`.github/`·`security/`·`specs/`·`pyproject.toml`·`uv.lock`·`scenarios/**/README.md`)에 닿지 않음. `policyVersion: "rule-patch-policy-2026.11.05"` | 위반 0 (위반이면 `touchesProtectedFiles=true`) |
| `DOCKERFILE_STATIC` | 늘 | 패치된 Dockerfile을 명령 단위로 읽어: `FROM` 줄 동일, 마지막 단계 `USER 1001:1001`·`CMD` 동일, `pip uninstall`이 마지막 단계 `USER` 앞의 `RUN`에 있음, 바뀐 단계는 마지막 단계 하나 | 모두 참 |
| `DOCKER_BUILD` | docker를 쓸 수 있을 때만(`docker version` 이 10초 안에 성공) | 패치된 Dockerfile의 `base` `FROM` 줄 + 패치된 마지막 단계 첫 `RUN` 명령만으로 탐침 Dockerfile을 만들어 `docker build --network none -t echo-rule-patch-probe:<runId 앞 8자> -`(표준 입력, 빌드 문맥 없음) → `docker run --rm --network none <이미지> python -c "<pip 모듈이 없으면 0으로 끝남>"` → 끝나면 `docker rmi -f`. 셸을 거치지 않고 인자 목록으로 부른다. `summary`에 "실행 단계 RUN만, 앱 소스 없음" | 빌드 성공 + pip 없음 |
| `TRIVY` | `trivy`가 PATH에 있고 `DOCKER_BUILD`가 PASS일 때만 | `trivy image --scanners vuln --severity HIGH,CRITICAL --ignore-unfixed --format json --quiet <탐침>` | 수정 가능한 HIGH·CRITICAL 0 |

- docker 검사 전체 시간 상한 180초(넘으면 FAIL). 실행 마감까지 남은 시간이 `DEADLINE_MARGIN + 180초`보다 적으면 docker 검사를 건너뛴다(정적 검사만으로 결정, `reason`에 적음).
- 각 check에 `toolVersion`을 알 수 있으면 넣는다(`docker version` 서버 버전, `trivy --version`).
- 결과는 검사 이름·결과·요약만 남긴다. 명령 출력 원문은 결과에 넣지 않는다(이벤트 `data`도 짧게).

## 7. 실패 시 동작

- **패치 단계의 어떤 실패도 실행을 FAILED로 만들지 않는다.** 규칙 findings·configDiff는 그대로 `SUCCEEDED`로 낸다.
- 검사 하나라도 PASS가 아니면: **패치를 내지 않는다**(`patches: []`), 이벤트 `PATCH_VERIFY` WARN `"rule patch dropped after failed check"`(data: `checks` 이름=결과 목록).
- 패치 단계 안 예외(파일 없음·docker 호출 오류 등): 패치를 내지 않고 이벤트 WARN `"rule patch skipped"`(data: `reason` 코드 — `SCENARIO_MISSING`·`TRANSFORM_NOT_APPLICABLE`·`PATCH_ERROR`).
- 발동 조건이 거짓: 패치 없음, 이벤트 `PATCH_PROPOSE` INFO `"rule patch not applicable"`(data: `reason` = `C_IMG_1_NOT_FLAGGED` 또는 `ALREADY_PATCHED`).
- `--no-patch`: 패치 단계를 아예 돌리지 않는다. 결과·이벤트가 지금 main(#15) 동작과 같다(PATCH_* 이벤트 0, `patches: []`). S1(`origin` 칸) 배포 전 WAS에 대고 돌릴 때 쓴다. `--no-model`과 함께 쓸 수 있다.
- 성공: 이벤트 `PATCH_PROPOSE` INFO `"rule patch proposed"`(data: `patchId`, `origin: "RULE"`) → `PATCH_VERIFY` INFO `"rule patch checks passed"`(data: `checks`, `dockerChecked`, `trivyChecked`). 메시지는 고정 영어 200자 이하.
- 실행 종류가 PRECHECK가 아니거나 분석이 실패한 경우(기존 FAILED 경로)·하트비트가 실행을 잃은 경우에는 패치 단계를 돌리지 않는다. 패치 단계 뒤 마감 검사에 걸려 FAILED·DEADLINE이 되면 패치도 버린다(`patches: []`).
- 모델 검토 결과와 패치는 서로 독립이다(모델이 실패해도 규칙 패치는 낸다).

## 8. 명령줄·설정

- `--no-patch`: 규칙 패치를 끈다(기본은 켜짐).
- 시나리오 루트: 기본은 저장소 루트(`precheck_patch.py` 기준 `parents[2]`)의 `scenarios/demo-app-0ff0d44/`. 환경 변수 `ECHO_SCENARIO_ROOT`로 바꿀 수 있다(시험용).
- 새 의존성 없음(표준 라이브러리만: `difflib`·`hashlib`·`subprocess`·`shutil`).

## 9. 수용 기준 (AC)

| # | 기준 | 시험 |
|---|---|---|
| AC-1 | **발동 → 패치 1개**: C-IMG-1 WARN이 든 스냅숏 + 시나리오 사본으로 가짜 WAS에 `process_run` → 제출된 결과 `patches`가 1개, 키가 정확히 5절 8개, `files`·`origin=RULE`·`touchesProtectedFiles=false`, `patchHash == "sha256:"+sha256(diff)`, diff를 원본에 적용한 결과가 `tests/fixtures/demo-app-6ac8813.Dockerfile`과 바이트가 같음, 덩어리 머리 `@@ -23,7 +23,11 @@`, checks에 `PATCH_APPLIES`·`POLICY`·`DOCKERFILE_STATIC`이 모두 PASS(docker는 가짜로 "없음"), 실행 `SUCCEEDED`, 이벤트 순서 … ANALYZE → PATCH_PROPOSE → PATCH_VERIFY | `test_rule_patch_proposed_for_flagged_c_img_1` 등 |
| AC-2 | **발동 안 함·끄기**: C-IMG-1 PASS·없음 → `patches: []`, 이미 pip 제거된 사본(`ECHO_SCENARIO_ROOT`로 6ac8813 사본) → `[]`, `--no-patch`(또는 `process_run`의 끄기 인자) → `[]`이고 PATCH_* 이벤트 0, 나머지 결과는 지금 main과 같음 | `test_rule_patch_not_applicable_*`, `test_no_patch_flag_keeps_pr14_result` |
| AC-3 | **실패 시 동작**: 검사 하나 FAIL(가짜 docker가 빌드 실패 / 보호 경로) → `patches: []`, 실행 `SUCCEEDED`, PATCH_VERIFY WARN 이벤트. 패치 모듈 안 예외(사본 파일 없음 포함) → 실행 `SUCCEEDED`, 규칙 findings 그대로 | `test_rule_patch_dropped_when_check_fails`, `test_patch_error_never_fails_run` |
| AC-4 | **docker 검사 정직성**: docker 없음 → checks에 `DOCKER_BUILD`·`TRIVY` 없음 + `reason`에 미실행과 이유; 가짜 docker 있음 → `DOCKER_BUILD` PASS, 인자에 `--network none`, 셸 없음, 끝에 `rmi`; trivy 없음 → `TRIVY` 없음. 실제 docker 시험(마커 `docker`, 데몬 없으면 건너뜀)은 탐침을 실제로 빌드해 pip가 없음을 확인한다 | `test_docker_check_*`, `test_probe_build_real_docker`(docker 마커) |

품질 기준(모두 필수): `uv sync --frozen`, `uv run ruff check .`, `uv run ruff format --check .`, `uv run mypy`(strict), `uv run pytest -q -rs` 전부 통과. 기존 시험 삭제·수정 0. 새 의존성 0.

## 10. 위임한 세부사항

모듈 안 함수·데이터클래스 이름, 작은 diff 적용기 구현, 가짜 docker 주입 방식(명령 실행 함수 인자), 이벤트 data 칸 이름의 세부, 시험 파일 안 도우미 구성.

## 11. 위험·남은 일

- 운영 이미지가 6ac8813 뒤로 다시 검사돼 C-IMG-1이 PASS가 되면 시연 실행에서 규칙이 패치를 내지 않는다(설계대로). 시연 직전 입력의 C-IMG-1 값을 확인한다.
- WAS S1(`origin` 칸) 배포 전에는 이 러너가 패치를 내면 결과 전체가 422 → 그때까지 `--no-patch`.
- VM 러너는 docker 권한·Trivy가 없어 정적 검사 3개로만 PASS를 낸다. docker 검사를 VM에서 돌리려면 러너 사용자 docker 그룹 추가(인프라 변경, 별도 승인)와 베이스 이미지 미리 받기(AD-3)가 필요하다.
- 패치 반영(`APPLY_PATCH`, `applied/<runId>` 브랜치 커밋)은 S3.
