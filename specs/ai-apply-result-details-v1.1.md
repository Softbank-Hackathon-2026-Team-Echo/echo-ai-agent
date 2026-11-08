# APPLY_PATCH 결과 상세 v1.1 — WAS 수용을 위한 검토안

> 상태: **계약 확장 검토안, 현재 WAS·러너 미구현**(2026-11-07). 기존 v1 5개 필드는 그대로 유지한다. 이 문서만 병합해도 새 필드를 전송할 수 있는 것은 아니다.
> 근거: [AI #5의 합의](https://github.com/Softbank-Hackathon-2026-Team-Echo/echo-ai-agent/issues/5#issuecomment-6693323096), [WAS #85의 7개 보완 항목](https://github.com/Softbank-Hackathon-2026-Team-Echo/echo-was/pull/85), [현재 계약 4절](ai-1-appendix-a-was-runner-contract.md#4-ai-패치-승인샌드박스-반영).
> 담당 순서: 형래 계약 → 지민 WAS 검토·수신/저장/조회 → 러너 전송 → 도영 화면·종단 인수. 기존 진단·저장소 반영 PR을 다시 구현하지 않는다.

## 1. 범위와 호환

현재 `ApplyPatchResult`는 `status, failureCode, simulated, appliedCommitSha, branch`만 받는다. **아래 4개 필드는 현재 보내면 422다.** 새 필드는 모두 선택이고, 기존 요청·응답의 이름과 의미를 바꾸지 않는다. 결과 envelope의 `schemaVersion`을 갑자기 추가하지 않는다(`inputSnapshot.schemaVersion`과 별개다).

| 추가 필드 | 형식·기본값 | 의미 |
|---|---|---|
| `checks` | 아래 3개 항목의 배열 또는 null, 생략 시 null | 실제 실행한 빌드·Trivy·healthz의 요약 |
| `artifacts` | 3절 객체 또는 null, 생략 시 null | 검증한 소스·diff·로컬 이미지 식별과 공개 여부 |
| `nextStep` | 4절 enum 또는 null, 생략 시 null | 사람이 이어서 할 일. 실행 명령이 아님 |
| `processing` | 기존 WAS `RunProcessingRequest` 또는 null, 생략 시 null | 반영 실행 자체의 처리 위치·외부 전송 기록 |

옛 5개 필드만 오면 실행 결과는 계속 수용하되 검증 상세·산출물·레지던시는 **미제공**으로 저장·표시한다. 누락된 검사를 PASS로 채우거나 처리 위치를 추정하지 않는다. 이 변경은 기한부 예외나 보안 게이트를 자동 통과시키는 새 경로가 아니다.

## 2. `checks`

객체마다 `name`·`result`가 필수다. 배열을 제공하면 **BUILD·TRIVY·HEALTHZ가 각각 한 번씩, 정확히 3개** 있어야 한다. 부분 실행은 항목을 빼지 않고 NOT_RUN으로 표현한다. 빈 배열·중복·알 수 없는 이름은 422다.

| 필드 | 값·제한 |
|---|---|
| `name` | `BUILD` · `TRIVY` · `HEALTHZ` |
| `result` | `PASS` · `FAIL` · `UNKNOWN` · `NOT_RUN` |
| `toolVersion` | 문자열 최대 128자 또는 null, 생략 시 null |
| `policyVersion` | 문자열 최대 128자 또는 null, 생략 시 null |
| `summary` | 문자열 최대 500자 또는 null, 생략 시 null. 고정 요약·수치만, 원본 출력 금지 |

- PASS: 실제 도구가 성공 조건을 확인했다. BUILD는 빌드 성공, TRIVY는 적용 정책의 수정 가능 HIGH/CRITICAL 0, HEALTHZ는 허용 시간 내 HTTP 200이다.
- FAIL: 확인 가능한 실패 또는 취약점·비정상 상태를 발견했다.
- UNKNOWN: 도구 오류·시간 초과·결과 해석 실패로 확인하지 못했다. 성공으로 계산하지 않는다.
- NOT_RUN: 선행 단계 실패·입력 거부 등으로 시도하지 않았다.
- `checks`를 제공한 SUCCEEDED 결과는 3개 모두 PASS여야 한다. FAILED 결과는 검사 이후의 마감·정리 오류도 표현할 수 있으므로 반드시 특정 검사 하나를 FAIL로 바꾸도록 강제하지 않는다.
- simulated=true이면 PASS 표시가 있어도 화면·게이트에서 실제 검증 근거로 사용하지 않는다. WAS는 보고 형식과 일관성을 검사할 뿐 도구를 직접 실행한 것으로 취급하지 않는다.
- 모든 단계의 상세 원인은 기존 이벤트에 남긴다. 상태·실패 코드와 모순되는 요약을 만들지 않는다.

## 3. `artifacts`

객체를 제공하면 아래 키를 모두 포함한다. nullable 필드의 모르는 값은 null이며, 기본 이미지 digest나 임의 SHA로 채우지 않는다. 입력 거부 등으로 승인된 patchHash를 확인하지 못했다면 artifacts 자체를 null/생략한다.

| 필드 | 형식·검사 |
|---|---|
| `sourceCommitSha` | 소문자 40자리 hex 또는 null. 실제 빌드 소스 기준 커밋. 진단 입력에 `diagnosis.sourceCommitSha`가 있으면 null일 수 없고 그 값과 일치해야 한다 |
| `patchHash` | `sha256:` + 64자리 소문자 hex. 승인된 diff와 일치해야 하며 WAS가 입력 사본·승인 행으로 재확인 |
| `imageId` | `sha256:` + 64자리 소문자 hex 또는 null. 검증한 로컬 이미지 ID |
| `imageDigest` | `sha256:` + 64자리 소문자 hex 또는 null. 실제 확인한 해당 산출물의 manifest digest만. 모르면 null |
| `commitPublished` | false 고정. 러너는 원격 저장소에 쓰지 않음 |
| `imagePublished` | false 고정. 러너는 레지스트리에 push하지 않음 |

로컬 imageId와 배포 대상 manifest digest를 동일시하지 않는다. 로컬 커밋은 기존 `appliedCommitSha`에 남기며, 실패 결과는 여전히 null이다. 이미지·작업 사본은 종료 시 정리되므로 식별자가 남았다고 산출물을 내려받거나 재배포할 수 있는 것은 아니다.

시나리오 입력 v1에는 기준 커밋·이미지 digest가 없다. 결과에 보고한 값을 승인 때 이미 바인딩된 값으로 소급 해석하지 않는다. 임의 고객 이미지와의 digest/config 바인딩은 입력 생성·승인 지문을 함께 확장하는 별도 작업이다. WAS #105의 `repoCommitted`·원격 SHA·PR URL은 서버 후처리 정보이며 러너가 보고하는 이 객체와 분리한다.

## 4. `nextStep`과 `processing`

| nextStep | 화면 의미 |
|---|---|
| `REVIEW_FOR_PUBLISH` | 실제 샌드박스 검증 완료. 승인 내용과 배포 가능한 수정본을 확인한 뒤 저장소 반영 검토 |
| `FIX_AND_RETRY` | 패치·소스·검사 실패를 고친 뒤 새 실행 |
| `RETRY_VERIFICATION` | 도구·접근·시간 제한을 확인한 뒤 새 검증 |
| `SIMULATED_ONLY` | 모의 결과. 실제 검증 필요 |

nextStep은 안내 값이며 자동 커밋·배포·이관 실행의 입력으로 사용하지 않는다. 제공한 경우 SUCCEEDED+simulated=false는 REVIEW_FOR_PUBLISH, simulated=true는 SIMULATED_ONLY다. 실제 FAILED는 FIX_AND_RETRY 또는 RETRY_VERIFICATION이다. null이면 “다음 행동 미제공”으로 표시한다.

processing은 PRECHECK의 기존 타입·제한을 재사용하되 **이 APPLY_PATCH 실행 자체**를 기록한다. 부모 PRECHECK의 모델 호출·외부 전송 값을 복사하지 않는다. 모델을 호출하지 않았다면 NONE·빈 dataClasses·externalTransfer=false 규칙을 지킨다. WAS는 전용 `agent_runs.processing` 칸에 저장하고 기존 레지던시 조회와 연결한다. 없으면 NULL이다.

## 5. 확장 결과 예 — 지금 전송하지 않음

값은 형식을 설명하는 예시다. 현재 endpoint에서는 추가 필드 때문에 거절되어야 한다.

```json
{
  "status": "SUCCEEDED",
  "failureCode": null,
  "simulated": false,
  "appliedCommitSha": null,
  "branch": "applied/22222222-2222-4222-8222-222222222222",
  "checks": [
    {"name": "BUILD", "result": "PASS", "toolVersion": null, "policyVersion": null, "summary": "image build completed"},
    {"name": "TRIVY", "result": "PASS", "toolVersion": null, "policyVersion": null, "summary": "fixable HIGH 0 / CRITICAL 0"},
    {"name": "HEALTHZ", "result": "PASS", "toolVersion": null, "policyVersion": null, "summary": "HTTP 200"}
  ],
  "artifacts": {
    "sourceCommitSha": null,
    "patchHash": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    "imageId": null,
    "imageDigest": null,
    "commitPublished": false,
    "imagePublished": false
  },
  "nextStep": "REVIEW_FOR_PUBLISH",
  "processing": null
}
```

## 6. 적용 순서와 완료 기준

1. 지민 WAS 검토에서 필드·제한·저장/조회 방식을 확정한다. 변경되면 이 문서도 함께 수정한다.
2. WAS가 먼저 새 선택 필드를 검사·저장·조회할 수 있게 구현하고 배포한다. 옛 5개 필드 요청도 그대로 받는 시험을 둔다.
3. 모든 수신 파드의 수용을 확인한 뒤 러너가 새 필드를 전송한다. 그전에는 기존 5개 필드와 이벤트를 유지한다. 옛 WAS의 422를 피하려고 검증 실패 필드만 지우고 성공으로 재제출하지 않는다.
4. 화면은 샌드박스 검증·원격 반영·실제 배포, 모의/실제, 상세 미제공/NOT_RUN/UNKNOWN을 구분한다.
5. 되돌릴 때는 러너의 새 필드 전송을 먼저 끄고 WAS를 되돌린다. 저장된 상세는 보존한다.

| 인수 범위 | 확인할 것 |
|---|---|
| 호환 | 옛 5개 필드 성공·실패·null SHA 수용, 새 필드 null/생략 수용, 모르는 필드 거부 |
| 검사 요약 | 3개 PASS 성공, 실패·UNKNOWN·NOT_RUN 보존, 중복/누락·성공과 불일치 거부 |
| 출처·산출물 | simulated 배제, 다른 승인 patchHash/진단 sourceCommitSha 거부, local ID와 manifest digest 구분, published=true 거부 |
| 레지던시 | 반영 실행 자체의 processing 저장·조회, 미제공 NULL, 부모 기록을 복사하지 않음 |
| 종단 | 같은 실행의 이벤트·결과·화면 일치, 원격 반영/배포 상태와 분리, 실제 WAS↔러너 왕복 |
| 롤링/되돌리기 | WAS 선배포 뒤 러너 전송, 옛 러너 호환, 새 필드 전송 중단 후 WAS 되돌리기 |

## 7. 기존 요청 처리 대응표

| WAS #85 / AI #19 요청 | 이번 계약 정리 | 남은 구현·의존성 |
|---|---|---|
| 5개 필드·SHA null·성공 해석 | 부록 A 4.3·4.4에 현재 v1 명시 | 런타임 변경 없음 |
| 빌드·스캔·healthz·산출물·nextStep | 이 문서 1~5절의 구체적인 확장안 | WAS 리뷰/수용 → 러너 → 화면 |
| 입력 digest·기준 커밋 | 현재 누락과 진단 sourceCommitSha 경로 구분 | 승인 지문과의 바인딩은 별도 후속 |
| 반영 event step | 부록 A 4.5: 기존 4개 step 재사용 | 새 step enum 불필요 |
| APPLY_PATCH processing | 이 문서 4절: 기존 타입 재사용 | 현재 반영 결과는 아직 거부. 수신·저장·조회 필요 |
| 로컬 커밋·배포 키 | 부록 A 4.1·4.4: 러너 push 없음, WAS 별도 신원 | 실제 원격 반영/수정 커밋 배포의 운영 인수([WAS #105](https://github.com/Softbank-Hackathon-2026-Team-Echo/echo-was/pull/105)) |
| 실패 코드 | 부록 A 6.2: 전용 8종·공통 3종 유지 | 이름 변경 없음 |
| 빌드/healthz 설정·네트워크 | 시나리오 상수·빌드 기본 네트워크와 앱 network none을 분리 | 소켓·비밀·메타데이터 차단의 실제 검증은 [infra #78](https://github.com/Softbank-Hackathon-2026-Team-Echo/echo-infra/pull/78) 후속 |
