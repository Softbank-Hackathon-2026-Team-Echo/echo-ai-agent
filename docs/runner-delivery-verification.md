# 러너 전송 안정화 검증 — 2026-11-08 KST

코드 커밋 `9fb1cfc57d2806389dac1d80649345a6e2317664`, branch `fix/runner-delivery`, base `0d10ac1`. 사용자 최종 지시로 **브랜치 커밋·푸시·관련 댓글만** 수행하며 PR 병합·운영 전환은 하지 않는다.

## 판정

러너의 큰 이벤트·확정 결과 거절·응답 유실 처리는 구현/영향 회귀 PASS다. **‘사용자 승인부터 같은 화면 실제 재배포 성공’ 전체 인수는 미완료**다. #135의 프론트 소비가 아직 없고 이번 버전의 새 운영 종단 배포를 하지 않았기 때문이다. 기존 기록을 새 종단 시험 성공으로 대신하지 않는다. #138 자동복구는 제외한다.

| 검증 | 실제 결과 | 범위 |
|---|---|---|
| 로컬 러너 전체 | 490 PASS, 0 FAIL/ERROR/SKIP | PRECHECK·진단·APPLY_PATCH, 실제 Docker, 보호 경로/hash/미재현 거절, 전송 경계 |
| GCP 동일 러너 사용자·별도 후보 | 488 PASS, 0 FAIL/ERROR, 2 SKIP | 운영 release 전환 없음. 호스트 Node 없는 로컬 전용 parser 2건은 skip; 동일 2건은 로컬 전체에서 PASS |
| WAS main 87966f7 전체 | 2,947 PASS, 0 FAIL/ERROR/SKIP | 새 runner 계약 4건 포함. 전용 로컬 PostgreSQL, 클라우드/GitHub executor 대역 |
| WAS #135 정확 head 053df94 관련 | 216 PASS, 0 FAIL/ERROR/SKIP | 후속 상태·승인·역할/조직·기존 저장소/재배포 경계 |
| WAS #135 + 새 runner 계약 | 4 PASS, 0 FAIL/ERROR/SKIP | 실제 ASGI·인증·스키마·PG 저장; main에서도 동일4건 PASS(위2947에 포함) |
| frontend main c179ed4 기존 전체 | 366 PASS, 타입 검사·빌드 PASS | Node22.23.4. #106 기존 재배포 화면 포함, 새 followUp UI 시험 아님 |
| Python 문법 전후 재검증 | 예상한 FAIL→PASS | 53997e16의 app/main.py:213 괄호 누락 → d387b612, 동일 Python3.13.18 고정 이미지 |
| 원장 연결 | patchHash 일치 | sha256:7f8e94bc9b8f1dc843b6ab28a08e9daf9e8ada40c3dd9a119d5db61a74b4dab6 |

집합에 중복이 있으므로 위 수를 단순 합쳐 고유 시험 수로 말하지 않는다. ruff check/format/mypy는 로컬·GCP PASS. 새 source/helper 파일 수에 따라 format 표시 수가 달라지며 린트 대상에 의존성 캐시는 포함하지 않는다.

## 새 계약 시험이 확인한 내용

- 큰 Unicode/NUL 로그 101개가 실제 WAS 이벤트 스키마를 통과하고 순번이 연속 저장된다.
- 진단/적용 결과가 확정 422로 거절되면 작은 FAILED/RUNNER_ERROR가 저장된다. 새 배포 요청·Job은 생성되지 않는다.
- 성공을 DB에 저장한 뒤 응답이 유실되면 동일 결과만 재전송하고 409에서 멈춘다. 기존 결과를 FAILED로 덮거나 새 후속 작업을 중복 생성하지 않는다.
- 이미 수락한 이벤트 묶음 보존, 반복 거절 시 이벤트 채널 종료/결과 제출 계속, 429/5xx/네트워크/임대/기한/불명 응답 경계는 단위 시험으로 확인한다.
- 두 실제 WAS 버전이 새 러너와 호환된다. #135가 최신 main과 병합된 조합을 검증했다는 의미는 아니다.

## 실패와 수정 기록

1. 기존 진단 422 시험이 ‘제출 한 번’을 기대해 첫 전체 실행에서 실패했다(488 PASS/1 FAIL). 새 계약의 원본+작은 FAILED 두 제출·원본 불변·최종 미확인 기대값으로 수정했다. 최종490 PASS.
2. 프론트 Node22.12는 undici가 요구하는 >=22.19 API가 없어 worker 시작 전 실패했다. 기존 설치된 Node22.23.4로 재실행해366 PASS/빌드 PASS. package/lock/프론트 제품 변경 없음.
3. GCP 초기 린트가 검증용 uv 캐시 내부 의존성까지 검사했다. 캐시를 소스 폴더 밖으로 옮겨 ruff/format/mypy PASS 후488 PASS/2 SKIP. 제품 코드 검사 우회 없음.
4. pnpm wrapper가 Vitest 출력 인수를 소비한 명령 오류는 `pnpm exec vitest`로 정정했다.

## 운영 읽기 확인과 기존 시연 연결

API/worker 이미지 `sha256:a68ce238f4690f9b41b73e41bbe4889cdb2b168e0dca87279e6c6651e4bece67`, 실제 진단·패치 적용·수정 커밋 반영 on, simulate off. 조회 시 열린 AgentRun 0. 운영 러너 release `0d10ac1` active 유지. GCP 후보 시험은 같은 사용자/도구에서 실행했으나 systemd의 모든 서비스 가두기를 재현한 운영 실행은 아니다. Secret/런너 토큰·모델 키 없이 시험했고 추가 모델 호출·실서비스 배포는 없다.

기존 11/7 18:28 시연: 실패 배포 2809ecbf → 진단 cbc09cf4 → 승인/APPLY cedadb42 → 수정 커밋 d387b612 → [demo-app PR #10](https://github.com/Softbank-Hackathon-2026-Team-Echo/echo-demo-app/pull/10) → 재배포 7d7e462c 성공. 기존 승인 원장의 patchHash/checksDigest/연결 ID와 새 문법 전후 재생 결과를 대조했다. 이는 새 모델 호출이나 새 운영 종단 시험이 아니다. 공개 증거 스키마 변경도 아니다.

## 미완료·인계

- 도영의 followUp 소비·지연/불명/구버전/401·403·404/늦은 응답/모의 원본 재배포 구분 인수, 지민 #135 계약 배포는 별도. 상세 [화면 인수표](runner-delivery-handoff.md).
- 실제 지정 demo-app에서 새 진단→사람 승인→샌드박스→수정 커밋→동일 화면 재배포→healthz/대표 페이지는 아직 새 버전에서 수행하지 않았다. 기능 전체 호환성 보장 아님.
- #138 eacbc77은 소유권 상실 시 기존 callback의 가용성 변화를 포함하므로 함께 반영하지 않는다. 자동 예약/worker/중단 복구 완료 아님.
- CVE #27/GAR 읽기 권한/테스트DB/별도 AI 검토는 범위 밖이다.
- GitHub CI는 branch push만으로 실행되지 않는 workflow여서 새 CI PASS라고 쓰지 않는다. 로컬·GCP에서 해당 lint/type/pytest를 직접 실행한 결과다.

기계 판독 근거와 JUnit 원문 SHA256: [evidence/runner-delivery-20261108.json](evidence/runner-delivery-20261108.json). 원문 JUnit과 초기 실패 로그는 공통 작업 공간 notes/evidence 및 전용 /private/tmp에 보존했다.
