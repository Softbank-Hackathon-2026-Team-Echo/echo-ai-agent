# 독립 검토와 시험·승인 결속 계약 — syntax-review-v1

AI #22 댓글의 선택 후속 범위를 구현한 후보. 기본 OFF, 미병합·미배포다.

## 적용 흐름

새 실제 CHANGE_PROPOSAL 입력에 WAS가 `reviewPolicy: "syntax-review-v1"`을 고정한다. `AI_PATCH_REVIEW_REQUIRED=false`가 기본이며, 켜도 과거 실행/승인을 소급 변경하지 않는다. 같은 실패 배포의 기존 진단은 기존 멱등 조회 의미를 유지한다. 새 검토를 시험하려면 새 실패 배포에서 새 진단을 만든다. 모의 진단은 실제 검토 증거로 인정하지 않는다.

1. 작성 모델 호출 **전에** 고정 검사 정의를 선택한다. 대상·파서/어댑터 파일 SHA-256·이미지 digest·명령·정상/실패 조건·격리 한도·검토 프롬프트 지문을 포함한다. 패키지 파일과 manifest가 다르면 중단한다.
2. 기존 동일 파서로 원본 실패 → 최소 수정 → 수정본 통과를 검사한다. Python 닫는 괄호/기존 inline JavaScript라는 기존 범위와 보호 파일 제한을 유지한다.
3. 기존 모델 제공자에 별도 system + 단일 user 문맥으로 **최대 1회, 30초** 검토한다. 작성자의 대화/추론/피드백은 전달하지 않는다. 전체 diff, 정상 조건, 전후 검사와 기준 커밋을 준다. 쓰기·tools·운영 권한 없음. 입력 최대128KiB, 출력1500 tokens, 전체 진단180초/기존 실행15분 상한 안이다.
4. `PASS`만 패치를 반환한다. 거부/불명/응답 오류/비밀값/시간 초과에는 패치 없이 고정 사유와 이벤트를 남긴다. 검토 실패 때문에 수정/검토를 반복하지 않는다. 작성 모델의 기존 최대2회는 유지한다.
5. 엄격한 git 적용 검증 뒤 diff가 달라졌다면 기존 검토를 재사용하지 않는다. 통과한 패치와 증거만 WAS에 낸다.
6. 화면에서 검토 사유와 증거 지문을 보여준다. 사람이 승인할 때 그 화면의 `reviewEvidenceHash`를 보낸다. 서버가 받은 최신 지문으로 임의 교체하지 않는다.
7. WAS 승인 행의 기존 `patch_hash`, `checks_digest`, `policy_version`에 결속한다. 검토 대상의 checks_digest는 `{checks, reviewEvidence}` 전체의 해시이고 policy_version은 syntax-review-v1이다. 기존 패치는 기존 checks 해시/정책 의미를 유지한다. 새 DB 칼럼·마이그레이션 없음.
8. APPLY 입력에 승인된 증거·checks·approvalChecksDigest를 함께 싣는다. 러너는 실행 전 재검증하고 실제 내려받은 원본과 패치 후 파일 해시도 대조한다. WAS는 성공 결과 수락 및 원격 커밋 직전에 승인 행을 다시 대조한다. 증거 칸 삭제도 검토 승인 행의 정책으로 차단한다. 빌드·Trivy·healthz 및 실제 재배포 절차는 유지한다.

## 필드

`patches[].reviewEvidence` (선택/null; 제공되면 엄격한 키/크기/현재 정의 검사):

- `version`, `sourceCommitSha`, `patchHash`
- `testDefinition`, `testDefinitionHash`: 코드가 선택한 고정 검사 정의
- `testResults`: before/after 각각 available, passed, toolVersion, issues(path/line/message), sourceHash
- `testResultsHash`: 전후 결과 묶음 해시
- `review`: verdict(PASS), reason(마스킹된 최대1000자), model(실제 응답 모델), contextHash
- `evidenceHash`: evidenceHash 자신을 제외한 위 전체 해시

지문은 UTF-8 문자열의 SHA-256, JSON은 정렬 키·공백 없는 구분자·ensure_ascii=false·NaN 금지다. raw diff 해시는 기존 patchHash 그대로다. reviewer context는 기준 커밋·patchHash·전체diff·시험정의/결과/각 지문이다. WAS와 러너의 순수 검사기 및 golden fixture를 같은 bytes로 유지한다. 총 증거16KiB, 기존 결과1MiB·문자열 제한도 적용한다. 알려지지 않은 키/정책이나 다른 시험 도구/원본 성공/수정본 실패/다른 모델 context/해시 불일치는 거부한다.

승인/거절 요청에 선택 `reviewEvidenceHash` 추가. 검토된 패치의 **승인**에는 필수이고 기존 응답/요청에는 없어도 된다. 승인 재요청도 증거 결속을 검사한다. 누락·변경 시 409 PATCH_STALE, 결과 입력 결속 실패 시 422 RESULT_INVALID. 기존 불명 결과/재전송 정책은 바꾸지 않는다.

## 보안·의미·비용

- 해시는 인증된 러너가 보낸 기록의 일치성 검사이며 악의적인 러너에 대한 서명/원격 증명은 아니다. 별도 문맥은 서로 다른 모델이라는 뜻이 아니며 같은 모델의 오류가 반복될 수 있다.
- 검토 AI가 단위·기능 시험이나 보안 게이트를 대신하지 않는다. “문법 시험 통과/독립 검토 통과”만 표시하며 전체 기능 호환성·실제 배포 성공으로 확대하지 않는다.
- 고객 소스/로그는 기존 마스킹 경계를 재사용한다. 추가 검토의 시도 전송량도 processing.externalTransferBytes에 합산한다. 거절한 검토를 model 성공/검토 완료로 표시하지 않는다. reviewer 모델 ID는 bundle에 기록한다.
- 기존 Anthropic API/샌드박스만 사용한다. API 검토 최대1회 추가분과 검사 시간 비용이 발생할 수 있으며 새 클라우드 자원·권한·회사 계정은 추가하지 않는다.

## 출고·호환

WAS 수신/저장 → 러너 → 프론트 소비를 배포한 뒤 별도로 새 정책을 켠다. 구현·브랜치 출고는 운영 활성화가 아니다. 필수 검토 입력을 구러너가 받으면 결과를 422로 거부해 검토 없는 패치를 승인시키지 않는다. 안전한 FAILED/no-patch 결과는 제출 가능하다. 구프론트는 검토된 패치의 승인을 409로 거절받으므로 프론트 선행 준비가 필요하다.

WAS #135/#138의 Draft 변경은 포함하지 않는다. 공용 설정/dependencies, diagnosis/approval/result/commit 서비스의 병합 접점이 있으므로 각 담당이 별도 인수한다. CVE #27·GAR 권한·DB 연결·자동복구 기능은 이번 범위 밖이다.

## 후속

기능 오류의 고정 회귀 시험, 고객 단위/API/E2E, 시험 범위를 넓히는 승인 정책은 별도다. 검토 실패 진단 재실행 API와 정책 구버전의 단계적 폐기는 별도 설계한다. 실제 고객 서비스에서 새 정책을 켠 사람 승인→배포 종단 인수는 배포 후 별도로 수행한다.
