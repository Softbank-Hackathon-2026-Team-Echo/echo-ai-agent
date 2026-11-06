# AI 에이전트 5-2 초안 — 러너가 승인된 패치를 샌드박스에서 적용·빌드·스캔해 결과를 낸다 (S2-apply)

- 상태: Draft (지민 결정 11/6 10:5x "P2 지금 진행"). 형래님 영역이라 Draft PR, 병합은 형래님.
- 이슈: https://github.com/Softbank-Hackathon-2026-Team-Echo/echo-ai-agent/issues/6 (패치 승인·반영의 러너 쪽)
- 기준: echo-ai-agent main `db53d1c`(#17 병합 뒤). 지민 Draft PR #18(`feat/rule-patch-proposal` `4da7587`, 규칙 패치 제안)은 미병합 — 이 PR 은 #18 이 고치는 줄을 건드리지 않는다(아래 7절, `git merge-tree` 충돌 0 확인).
- 근거(정본): 계약 부록 A v1 [`ai-1-appendix-a-was-runner-contract.md`](ai-1-appendix-a-was-runner-contract.md) 2.1절(`APPLY_PATCH` 결과 `{appliedCommitSha, branch}`)·4절(반영 대상은 echo-ai-agent 시나리오 사본 브랜치 `applied/<runId>` 뿐, 운영 저장소·운영 환경에는 쓰지 않음)·7절(제어 프로세스만 토큰을 가짐, 마감 1분 전 `FAILED·DEADLINE`). 반영 실행 입력 모양은 echo-was SPEC `api-10-patch-approval.md` PD-6(#79 배포됨, 스위치 `PATCH_APPLY_ENABLED` 꺼짐). `patchHash` 정의는 #18 SPEC PD-14.
- 짝: echo-was S3(claim 종류 확장·`ApplyPatchResult` 받기·`patchHash` 재계산) — 같은 계약으로 병행 구현 중(별도 PR). 이 러너는 리얼 WAS 에 붙여 보지 않았다(S3 미배포).

## 1. 목표

러너가 WAS 에서 `APPLY_PATCH` 실행을 가져가, 사람이 승인한 패치를 샌드박스 안에서 ① 시나리오 사본에 적용하고 ② 컨테이너 이미지를 빌드하고 ③ Trivy 로 스캔하고(C-IMG-1 과 같은 기준) ④ 앱을 띄워 healthz 를 본 뒤, 결과를 `runs/<id>/result` 로 낸다.

**하지 않는다:** 브랜치 push·이미지 push·운영 변경·고객 저장소 쓰기(샌드박스는 읽기 자격만, 배포 키 없음 — 설계 유지), WAS 변경, 계약에 없는 결과 칸 추가, VM systemd·시작 스크립트 변경, 운영 VM 반영.

## 2. 흐름

```text
claim(capabilities [PRECHECK, APPLY_PATCH])  ← ECHO_APPLY_PATCH=on 일 때만 APPLY_PATCH 를 싣는다
→ 첫 하트비트(CLAIMED → RUNNING), 30초마다 하트비트
→ INPUT_LOAD   입력 v1 검사 · patchHash 재계산(승인 값과 다르면 중단) · 대상 검사(scenarios/ 아래만)
→ SANDBOX_CREATE 작업 사본: git 체크아웃이면 로컬 clone(origin 지움) + applied/<runId> 브랜치, 아니면 파일 복사
→ PATCH_VERIFY  패치 적용(엄격) → (git 이면) 로컬 커밋 → 빌드 문맥(공개 소스 고정 커밋 + 패치된 파일)
               → docker build → trivy image → docker run --network none + docker exec healthz
→ SANDBOX_DELETE 컨테이너·이미지·작업 공간 지움
→ result {status, failureCode, simulated:false, appliedCommitSha, branch}
```

## 3. 입력 (`inputSnapshot` v1, PD-6 그대로)

`{schemaVersion: 1, parentRunId, patch: {id, patchHash, files[], diff, origin}, repo, branch}`

| 검사 | 실패 |
|---|---|
| `schemaVersion == 1`, `parentRunId`·`patch.id` 문자열, `patchHash` `^sha256:[0-9a-f]{64}$`, `files` 1개 이상, `diff` 비어 있지 않음, `origin` `RULE`·`AI`(없으면 `AI`) | `INPUT_INVALID` |
| `repo == Softbank-Hackathon-2026-Team-Echo/echo-ai-agent`, `branch == applied/<이 실행 id>` | `INPUT_INVALID` |
| `"sha256:" + sha256(diff UTF-8)` == `patchHash` (계약 2.1 "같을 때만") | `PATCH_HASH_MISMATCH` |
| `files` == diff `---`/`+++` 머리 경로 집합, 모두 같은 `scenarios/<이름>/` 아래, `..`·절대·숨김 경로·시나리오 `README.md` 없음 (계약 4절 "시나리오 사본뿐") | `PATCH_TARGET_FORBIDDEN` |

## 4. 검사 (제어 프로세스가 돌림, 모델 없음)

| 순서 | 무엇 | PASS 기준 | 실패 |
|---|---|---|---|
| 1 | 패치 적용: 표준 라이브러리 unified diff 적용기(문맥·지울 줄이 한 글자라도 다르면 실패). 원본은 git 이면 clone 의 HEAD, 아니면 러너 체크아웃 파일 | 모든 덩어리가 맞음 | `PATCH_APPLY_FAILED` |
| 2 | (git 체크아웃일 때만) 작업 사본에서 `applied/<runId>` 브랜치에 로컬 커밋. 작성자 `Echo AI Runner <echo-ai-runner@echoport.invalid>`, 훅·서명 끔, **origin 지움·push 없음** | 커밋 SHA | `RUNNER_ERROR` |
| 3 | 도구 확인: `docker version`(서버)·`trivy --version`, 시나리오 빌드 정보 있음 | 셋 다 있음. **없으면 PASS 를 만들지 않는다** | `VERIFY_UNAVAILABLE` |
| 4 | 빌드 문맥: 시나리오 빌드 정보의 공개 소스(echo-demo-app `0ff0d44f…`)를 GitHub tarball 로 받음(토큰 없음) → 패치 전 사본 파일과 소스 파일이 바이트 같음 확인 → 패치된 파일로 바꿔 넣음 | 받기 성공·바이트 같음 | `SOURCE_UNAVAILABLE` |
| 5 | `docker build --tag echo-apply-<id12>:local --label echo.apply-run=<id> --file … <문맥>` (BuildKit) | 종료 0 | `IMAGE_BUILD_FAILED` |
| 6 | `trivy image --scanners vuln --format json --quiet --exit-code 0 <이미지>` → 수정 가능한(FixedVersion 있음) HIGH·CRITICAL 세기(`image-scan.yml` 요약·C-IMG-1 과 같은 기준) | 0건 | `IMAGE_SCAN_FAILED` |
| 7 | `docker run --detach --network none --cap-drop ALL --security-opt no-new-privileges` + 시나리오 env(닿지 않는 가짜 DB 주소, `AUTO_MIGRATE=false`) → `docker exec … python -c <urllib GET 127.0.0.1:8080/healthz>` 를 45초 안에 반복 | 200 | `HEALTHZ_FAILED` |

- 단계마다 시간 상한(빌드 420초·스캔 300초·소스 60초·healthz 45초)과 "마감 1분 전까지 남은 시간" 중 작은 값을 쓴다. 남은 시간이 없으면 `DEADLINE`. 그 밖의 예외는 `RUNNER_ERROR`.
- 외부 명령은 셸 없이 인자 목록으로만 부른다. 토큰은 명령·작업 공간에 넣지 않는다(빌드·스캔·컨테이너는 토큰을 모른다).
- 실패해도 정리(컨테이너 `rm -f`·이미지 `rmi -f`·작업 공간 삭제)는 늘 한다.

## 5. 결과 (`ApplyPatchResult`) — 칸을 더하지 않는다

```json
{"status": "SUCCEEDED", "failureCode": null, "simulated": false,
 "appliedCommitSha": "<40자 또는 null>", "branch": "applied/<runId>"}
```

- `appliedCommitSha`·`branch`: 계약 2.1절. `status`·`failureCode`·`simulated`: 모든 결과에 WAS 가 요구하는 공통 칸(`docs/agent-runner.md` "필수"). 실패면 `appliedCommitSha = null`.
- `appliedCommitSha` 는 **샌드박스 작업 사본의 로컬 커밋**이고 push 하지 않는다(원격에 없다). 러너 체크아웃이 git 이 아니면(VM 은 `git archive` 배포) `null` 이다.
- 빌드·스캔·healthz 결과는 계약에 칸이 없어 **이벤트 `data`** 에만 남긴다(`image built`·`image scanned {fixableHigh, fixableCritical, trivyVersion}`·`healthz passed`).

## 6. 스위치

- `ECHO_APPLY_PATCH=on|off`, 기본 off(#18 `ECHO_PRECHECK_PATCH` 관례). 꺼져 있으면 claim `capabilities` 가 지금과 같은 `["PRECHECK"]` 이고, 혹시 `APPLY_PATCH` 실행을 받아도 지금처럼 `FAILED·KIND_UNSUPPORTED` 로 닫는다(도구를 부르지 않음).
- 값 오타는 시작 때 종료 코드 2(`config error`). 시작 로그 `apply patch: on|off`.
- 시작 스크립트는 고치지 않는다. systemd `EnvironmentFile`(`runner.env`) 값이 그대로 러너 프로세스 환경으로 간다. `deploy/runner.env.example` 에는 `ECHO_APPLY_PATCH=off` 한 줄만 더한다.
- `ECHO_APPLY_REPO_ROOT`: 시나리오 사본을 읽을 저장소 루트(기본 = 러너 설치 루트). 시험·로컬 실행용.

## 7. #18 과의 관계

- 새 모듈 `src/echo_agent/apply_runner.py` 에 전부 둔다. `precheck_runner.py` 는 import 1묶음 + 종류 분기 1곳(`process_run` 첫 줄) + claim 인자 1줄 + 시작 때 스위치 검사 5줄만. #18 이 고치는 줄(docstring 8–10, import 23·36, `build_result`, `process_run` 시그니처·패치 단계, `run_loop` 시그니처·호출, `main` 의 `--patch`)은 건드리지 않았다. `git merge-tree HEAD origin/feat/rule-patch-proposal` 충돌 0.
- `README.md` 는 #18 이 고치는 두 곳(실행법 3번·"규칙 패치 켜기·끄기") 밖의 새 절, `runner.env.example` 은 #18 이 덧붙이는 끝이 아닌 중간에 한 줄.
- 반영 대상 `scenarios/demo-app-0ff0d44/` 는 #18 이 더한다. **#18 병합 전 main 에는 사본이 없어 실제 반영은 `PATCH_APPLY_FAILED`(`TARGET_MISSING`)** 다. 시험은 임시 사본을 만든다.
- `patchHash` 계산은 #18 과 같은 정의를 이 모듈에 따로 둔다(#18 모듈을 import 하지 않음 — 병합 순서 무관).

## 8. 계약 보완 필요 (이 PR 에서 칸·값을 지어내지 않고 남김)

1. 반영의 정의: 계약은 "시나리오 사본 브랜치 `applied/<runId>` 에 커밋(배포 키)"인데 샌드박스는 읽기 자격만 있다 → push 하지 않는 로컬 커밋으로 둠. 브랜치를 실제로 만들지(배포 키), 로컬 검증만으로 `SUCCEEDED` 를 볼지 정해야 한다.
2. `ApplyPatchResult` 전체 모양: 공통 칸(`status`·`failureCode`·`simulated`)을 같이 싣는지, 실패·git 없음일 때 `appliedCommitSha: null` 허용, `sandbox`·`model`·`processing` 을 싣는지.
3. 빌드·스캔·healthz 결과 칸이 없다(이벤트에만). 화면에 보이려면 칸이 필요하다.
4. 반영 실패 코드 목록(`PATCH_HASH_MISMATCH`·`PATCH_TARGET_FORBIDDEN`·`PATCH_APPLY_FAILED`·`VERIFY_UNAVAILABLE`·`SOURCE_UNAVAILABLE`·`IMAGE_BUILD_FAILED`·`IMAGE_SCAN_FAILED`·`HEALTHZ_FAILED`)이 계약에 없다(형식 `^[A-Z][A-Z0-9_]{0,31}$` 만 맞춤).
5. 이벤트 `step` 에 반영 단계 값이 없다 → `INPUT_LOAD`·`SANDBOX_CREATE`·`PATCH_VERIFY`·`SANDBOX_DELETE` 를 빌려 씀.
6. 반영 기준 커밋(base): 입력에 없다 → 러너 체크아웃 HEAD(VM 은 `.deployed-rev`, 커밋 불가).
7. 빌드 문맥(앱 소스 저장소·커밋)·healthz 경로·포트·env 가 입력에 없다 → 시나리오별 러너 상수 `SCENARIO_BUILDS`.
8. 빌드 중 네트워크: 빌드는 베이스 이미지·의존성을 받아야 해서 docker 기본 네트워크를 쓴다(앱 실행·healthz 는 `--network none`). 계약 7절 "작업 공간 네트워크 없음"은 모델 작업 공간 기준이라 빌드에 대한 규칙이 없다.

## 9. 수용 기준·시험

| # | 기준 | 시험(`tests/test_apply_runner.py`) |
|---|---|---|
| AC-1 | 스위치 기본 off·오타 종료 2·claim 인자 | `test_switch_*`, `test_main_stops_with_exit_2_on_switch_typo` |
| AC-2 | 입력·해시·대상 검사 | `test_bad_input_is_input_invalid`(6), `test_patch_hash_*`, `test_target_*`(5), `test_hash_mismatch_fails_before_touching_anything` |
| AC-3 | 패치 적용 성공·실패 | `test_apply_file_diff_*`, `test_patch_that_does_not_apply_fails`, `test_missing_target_file_fails` |
| AC-4 | Trivy 해석(C-IMG-1 기준)·결과 모양 | `test_count_fixable_uses_c_img_1_rule`, `test_result_has_only_contract_fields`, `test_fixable_high_fails_scan_like_c_img_1`, `test_unfixed_high_only_passes_scan` |
| AC-5 | 빌드·스캔·healthz·정리·push 없음 | `test_apply_build_scan_healthz_succeeds_without_push`, `test_git_checkout_gets_local_commit_on_applied_branch`, `test_no_docker_or_trivy_is_not_verified`(2), `test_build_failure_*`, `test_healthz_failure_*`, `test_source_that_differs_*`, `test_deadline_margin_*` |
| AC-6 | 가짜 WAS claim→result 왕복·스위치 꺼짐 동작 불변·실행 잃음 | `test_claim_to_result_round_trip_with_switch_on`, `test_failed_apply_still_submits_failed_result`, `test_switch_off_keeps_today_behaviour`, `test_lost_run_on_first_heartbeat_submits_nothing` |
| AC-7 | 로컬 `--once` 실제 빌드 1회(docker·trivy 있을 때, pytest 밖) | PR 본문에 결과 |

품질: `uv run ruff check .`·`ruff format --check .`·`mypy`(strict)·`pytest`(건너뜀 0). 새 의존성 0. 기존 시험 수정 0.

## 10. VM 반영 절차(이 PR 은 실행하지 않음)

11/5 기준 VM 은 docker 20.10 은 있으나 러너 사용자에게 소켓 권한이 없고 trivy·git 이 없다(#18 SPEC 2절). 이대로 켜면 반영 실행은 전부 `VERIFY_UNAVAILABLE` 이다. 켜려면: (1) 이 PR·S3 병합·배포, (2) 인프라 승인 뒤 러너 사용자 docker 그룹·trivy 설치·`TRIVY_CACHE_DIR` 쓰기 자리(`/var/lib/echo-precheck-runner`), (3) 새 release 올리기(README "새 버전 올리기"), (4) `runner.env` 에 `ECHO_APPLY_PATCH=on` → 재시작 → 로그 `apply patch: on`, (5) WAS `PATCH_APPLY_ENABLED=true`. 끄기는 (4) 를 `off` 로.
