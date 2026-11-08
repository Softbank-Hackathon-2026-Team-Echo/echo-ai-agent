# 반영 실행(APPLY_PATCH) 러너 안내

러너가 WAS 의 반영 실행을 처리하는 방법이다. 설계·근거는 SPEC [`specs/ai-5-2-apply-patch-runner.md`](../specs/ai-5-2-apply-patch-runner.md), 계약은 부록 A v1 2.1·4절. 코드: `src/echo_agent/apply_runner.py`.

> **2026-11-07 계약 정정:** 현재 5개 결과 필드·null 허용·샌드박스 성공 의미·실패 코드는 [부록 A 4절·6.2절](../specs/ai-1-appendix-a-was-runner-contract.md#4-ai-패치-승인샌드박스-반영)을 따른다. [결과 상세 v1.1](../specs/ai-apply-result-details-v1.1.md)은 WAS 선배포가 필요한 검토안이다. 현재 러너에 새 필드를 추가해 보내지 않는다.

## 켜기 전에

| 필요 | 이유 | 없으면 |
|---|---|---|
| WAS S3(claim 종류 확장·반영 결과 받기) 배포 + `PATCH_APPLY_ENABLED=true` | [WAS #85](https://github.com/Softbank-Hackathon-2026-Team-Echo/echo-was/pull/85)에 수신이 구현됐고 [AI #5](https://github.com/Softbank-Hackathon-2026-Team-Echo/echo-ai-agent/issues/5#issuecomment-6680448569)에 E2E 성공이 보고됐다. 실행할 배포 버전·스위치는 별도로 확인한다 | 러너가 켜져 있어도 받을 실행이 없다 |
| 시나리오 사본 `scenarios/demo-app-0ff0d44/`(#18) | 반영 대상 | `FAILED`·`PATCH_APPLY_FAILED`(`TARGET_MISSING`) |
| 러너 사용자의 docker 권한 + trivy | 빌드·스캔 없이 PASS 를 만들지 않는다 | `FAILED`·`VERIFY_UNAVAILABLE` |
| 유닛의 `DOCKER_CONFIG`·`TRIVY_CACHE_DIR` 가 상태 폴더(`/var/lib/echo-precheck-runner`) 아래 | 러너 HOME 이 `/nonexistent`·`ProtectSystem=strict` 라 BuildKit 원격 이미지 인증(토큰 seed)과 trivy DB 받기가 쓸 곳이 없다 | `IMAGE_BUILD_FAILED`(`mkdir /nonexistent: read-only file system`)·`IMAGE_SCAN_FAILED` |
| GitHub(codeload) 읽기 + 빌드용 레지스트리·PyPI 접근 | 빌드 문맥(echo-demo-app `0ff0d44`)·베이스 이미지·의존성 | `SOURCE_UNAVAILABLE`·`IMAGE_BUILD_FAILED` |
| (선택) git 체크아웃 | 로컬 커밋 SHA. VM 은 `git archive` 배포라 없다 | `appliedCommitSha: null` |

## 결과 예

로컬 `--once`(가짜 WAS, colima docker 29.5.2, trivy 0.76.1, 11/6) 실제 값:

```json
{"status": "SUCCEEDED", "failureCode": null, "simulated": false,
 "appliedCommitSha": "3ff5b6d512ab80ca7df7d38340df28708b08bc8f",
 "branch": "applied/ebca686b-06fa-4415-8d67-3a142a8159ef"}
```

이벤트(같은 실행):

| seq | step | message | data(요약) |
|---|---|---|---|
| 1 | INPUT_LOAD | apply input loaded | patchId, origin RULE, files, branch |
| 2 | INPUT_LOAD | patch hash verified | patchHash, scenario |
| 3 | SANDBOX_CREATE | apply workspace created | mode git-clone, baseCommit |
| 4 | PATCH_VERIFY | patch applied | appliedCommitSha, committed true, pushed false |
| 5 | PATCH_VERIFY | build context ready | echo-demo-app `0ff0d44f…` |
| 6 | PATCH_VERIFY | image built | dockerVersion, seconds, pushed false |
| 7 | PATCH_VERIFY | image scanned | trivyVersion 0.76.1, fixableHigh 0, fixableCritical 0 |
| 8 | PATCH_VERIFY | healthz passed | /healthz, network none |
| 9 | PATCH_VERIFY | apply checks passed | appliedCommitSha, branch, pushed false |
| 10 | SANDBOX_DELETE | apply workspace deleted | containerRemoved, imageRemoved |

대조: 같은 소스의 패치 전 이미지(0ff0d44 원본)는 같은 기준으로 수정 가능한 HIGH 5건(msgpack 2·setuptools 1·urllib3 2)이었다.

## 실패 코드

| 코드 | 언제 | 이벤트 step |
|---|---|---|
| `INPUT_INVALID` | 입력 v1 모양·`repo`·`branch` 가 다름 | INPUT_LOAD |
| `PATCH_HASH_MISMATCH` | 다시 계산한 `patchHash` ≠ 승인 값 | INPUT_LOAD |
| `PATCH_TARGET_FORBIDDEN` | `scenarios/<이름>/` 밖·README·`..`·여러 시나리오·files ≠ diff 머리 | INPUT_LOAD |
| `PATCH_APPLY_FAILED` | 대상 파일 없음·문맥 다름·diff 모양 틀림 | PATCH_VERIFY |
| `VERIFY_UNAVAILABLE` | docker·trivy·시나리오 빌드 정보 중 하나라도 없음 | PATCH_VERIFY |
| `SOURCE_UNAVAILABLE` | 빌드 소스 받기 실패 또는 사본과 바이트가 다름 | PATCH_VERIFY |
| `IMAGE_BUILD_FAILED` · `IMAGE_SCAN_FAILED` · `HEALTHZ_FAILED` | 빌드 실패 · 수정 가능한 HIGH/CRITICAL ≥ 1 또는 스캔 실패 · 200 없음 | PATCH_VERIFY |
| `DEADLINE` · `RUNNER_ERROR` | 마감 1분 전 · 그 밖의 예외(git 실패 포함) | PATCH_VERIFY |

모든 실패의 마지막 PATCH_VERIFY·INPUT_LOAD 이벤트는 `"apply failed; nothing pushed"`(data `failureCode`·`reason`, `DEADLINE` 만 `"deadline reached before result"`)이고, 정리 이벤트 `SANDBOX_DELETE` 가 뒤따른다(작업 공간을 만들기 전 실패 제외).
