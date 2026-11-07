# AI #27 — PR·권한 적용 보류 기록

2026-11-07. 구현 커밋 `d010056`에 대한 후속 검증 기록이다. SBOM/CVE 구현은 로컬에 보존하고, 사용자 요청에 따라 문제와 재개 조건을 #27에 기록한다. 운영 적용이나 보안 예외 승인이 아니다.

## 어떤 작업에서 발견했는가

PRECHECK의 고객 이미지 SBOM 수집과 CVE 원본 이미지 검사에 필요한 GAR 읽기 권한을 준비했다. VM 서비스 계정에 저장소 단위 `roles/artifactregistry.reader` 1건을 추가하는 plan이다. 적용 전 실제 샌드박스의 빌드 경계를 시험하다 메타데이터 접근을 확인했다. 이 변경이 접근 경로를 새로 만든 것은 아니지만, 권한 추가는 노출 가능한 VM 신원의 접근 범위를 넓힌다.

## 검사 대상·위치·결과

| 검사 | 무엇을, 어디에서 검사하는가 | 이번 결과 |
|---|---|---|
| C-IAM-2 자동 검사 | WAS worker가 시작/기본 6시간 주기로 일회용 AGENT 토큰을 만들어 같은 프로세스의 ASGI 앱에 쓰기·승인 API를 호출한다. 모두 403 AGENT_READ_ONLY인지 확인한다. `app/services/platform_self_test.py` | 이번 문제를 탐지한 검사가 아니다. VM 메타데이터·Docker 빌드 격리는 검사 범위 밖이다. 관련 정규화/API 경계 회귀는 76 passed |
| C-CFG-1 설정 검사 | 로컬에서 Trivy로 기존/후보 Terraform을 검사하고 WAS 정규화 함수로 비교 | 둘 다 WARN 9건(MEDIUM7/LOW2), 새 위반 0 |
| 이번 실제 빌드 격리 시험 | GCP 샌드박스 VM의 echo-runner로 운영과 같은 기본 BuildKit 빌드를 실행하고 Dockerfile RUN 안에서 비밀값 없는 메타데이터 hostname 경로의 응답 상태만 확인 | **HTTP 200. 빌드 단계에서 메타데이터 접근 차단 안 됨.** network=none 빌드와 health 런타임 대조군은 접근 실패 |

즉, **C-IAM-2 FAIL로 자동 차단된 것이 아니라 [infra #78 보안 검토 댓글](https://github.com/Softbank-Hackathon-2026-Team-Echo/echo-infra/pull/78#issuecomment-6693317245)의 고객 코드 메타데이터 차단 조건을 직접 시험해서 미충족을 확인했다.** 상위 과제는 [infra #24 신원 분리·최소 권한](https://github.com/Softbank-Hackathon-2026-Team-Echo/echo-infra/issues/24)다.

토큰·Secret·메타데이터 응답 본문은 수집하지 않았다. HTTP 200은 hostname 경로 접근 증거이며 실제 토큰 탈취 시험은 아니다. 설정/API 테스트 성공을 VM 신원 격리 성공으로 확대하지 않는다.

## 보류와 재개

- PR·reader apply·운영 활성화는 보류한다. 기본 기능 스위치 off를 유지한다. 빌드 경계 보완 자체는 아직 구현하지 않았다.
- 제어 프로세스의 이미지 읽기와 고객 코드 실행 권한을 분리하고 빌드 중 메타데이터·내부망 접근을 차단한다. 필요한 패키지 다운로드는 유지해야 하므로 network=none만 바로 적용하지 않는다.
- 같은 VM에서 차단/허용 다운로드 대조 및 빌드·Trivy·healthz 회귀 → reader plan 재검토/사용자 확인 → 운영 인수 순서다.

[비밀값 없는 시험 근거](evidence/ai-27-reader-security-20261107.json). 운영 runner `0d10ac1` active 유지, 임시 시험 자원 정리 완료. 운영 finding/예외·고객 배포는 변경하지 않았다. 초기 시험 실패/skip은 최종 재실행 결과로 대체했고 성공 근거로 세지 않았다.
