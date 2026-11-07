# 러너 전송 거절·응답 유실 처리

WAS #123의 러너 보완 요청과 AI #22의 기존 검증 재사용에 대한 구현이다. 공개 API/DB/실패 코드, 모델·샌드박스·사람 승인 권한은 바꾸지 않는다. WAS #135의 followUp 계산이나 #138의 저장소/재배포 자동복구는 포함하지 않는다.

## 이벤트

- 원본 근거와 diff는 그대로 두고 전송 사본의 `data`만 처리한다. JSON 전체가 2,000자 이하이며 UTF-8·NUL·비정상 JSON 값도 검사한다. 생략/정규화 표시를 남긴다.
- 요청당 최대 100건 및 실제 UTF-8 JSON 본문 1MiB. 확인된 앞 묶음은 다시 보내지 않는다.
- `422 RESULT_INVALID`에는 같은 seq의 작은 요약을 한 번 보낸다. 그 응답도 거절되거나 확인되지 않으면 해당 실행의 이벤트 전송을 중단하고 로컬에 원인을 남긴다. 최종 결과 제출은 계속한다.
- 원본 묶음의 일시적 실패는 다음 flush에서 다시 보낼 수 있다. 인증/권한/실행 종료는 중단한다. 이벤트 수락은 `acceptedUpTo`로 확인한다.

## 최종 결과

`CHANGE_PROPOSAL`, `APPLY_PATCH`는 `result_delivery.submit_with_recovery`를 공유한다.

| 응답 | 처리 |
|---|---|
| 결과 status와 일치하는 정상 수락 봉투 | submitted=True |
| 저장 불명 이력 없는 명시적 422 RESULT_INVALID | 기존 스키마의 작은 FAILED/RUNNER_ERROR를 한 번 제안. simulated·유효한 모델 처리 기록 유지, patches/진단/성공 커밋 제거 |
| 네트워크/timeout/429/5xx/잘못된 2xx | 최초와 동일한 결과만 재전송. 전체 최대 3회, 대기 1·2초, 실행 기한·임대 안에서만 |
| 저장 불명 이후 422 | 다른 결과로 바꾸지 않고 종료 |
| 409 / 인증·권한 / 임대·기한 상실 | 추가 제출 중단 |
| 마지막까지 수락 미확인 | 로컬 UNCONFIRMED, submitted=False. 서버 실패/성공을 단정하지 않음 |

최초 제출·축소 실패 제출·재시도를 합쳐 최대 3회다. 결과 전송을 위해 모델/샌드박스/GitHub 쓰기를 재실행하지 않는다. 409를 받은 경우 기존 결과가 저장됐을 수 있지만 후속 GitHub·재배포 완료까지 증명하지 않는다. 일반 PRECHECK 결과의 기존 패치 제외 재제출 정책은 유지한다.

## 재현

```sh
uv run ruff check .
uv run ruff format --check .
uv run mypy
uv run pytest
```

Docker가 있어야 실제 격리 시험이 실행된다. skip을 성공으로 세지 않는다. 주요 전송 경계는 `tests/test_runner_delivery.py`다.

`tools/contract_was_delivery.py`는 WAS의 실제 ASGI·인증·스키마·PostgreSQL 저장을 쓰는 교차 저장소 계약 시험이다. WAS main `87966f7`의 **격리 checkout**에 `tests/integration/test_runner_delivery_contract.py`로 복사하고, 그 checkout의 venv에서 이 러너 패키지와 의존성을 import할 수 있게 구성한 뒤 실행한다. 기존 팀원의 checkout이나 운영 DB를 사용하지 않는다. WAS `tests/conftest.py`가 만드는 `_test` DB도 반드시 전용 로컬 DB로 한정한다.

```sh
DATABASE_URL=postgresql+asyncpg://echo_delivery_test@127.0.0.1:55561/echo_delivery_test \
  .venv/bin/pytest -q tests/integration/test_runner_delivery_contract.py
```

시험 4건: 진단 거절 후 FAILED 저장, 적용 거절 후 FAILED 저장, 큰 로그 101건 분할 저장, DB 저장 후 응답 유실→409 기존 결과 보존. 두 실패 경로는 DeployRequest/Job이 늘지 않는 것을 확인한다. 배포 fixture는 가짜 executor이고 실제 GitHub/클라우드 장애 복구 시험은 아니다. PostgreSQL 프로세스 강제 종료/내구성 시험도 아니다.

## 기존 문법 오류 증거 재사용

```sh
uv run python tools/verify_python_syntax_pair.py /path/to/echo-demo-app \
  53997e169a29604b37088b793425b7d72a7946bf \
  d387b612d83f97c0d77be660ffddfeb7f18751e4
```

고정 Python 이미지의 동일 검사기를 사용하며 원본 `app/main.py:213`의 `'(' was never closed` 오류와 수정본 통과를 확인한다. 시험 조건·검사 도구는 모델 입력의 수정 대상이 아니다. 승인 hash 검사는 기존 코드/회귀 시험을 유지한다. 출력 diff SHA는 이 도구가 다시 만든 diff의 SHA이므로 승인 원장의 patchHash와 실제 일치하는지 별도로 대조한다.

## 배포·완료 경계

CI 통과 커밋을 기존 README의 고정 release 배포 절차로 배포한다. 진행 작업을 확인하고 기존 프로세스가 종료된 후 링크를 바꾼다. 유닛·모델·스위치·권한은 유지한다. 문제가 있으면 이전 `0d10ac1` release로 되돌린다.

이 코드의 시험/배포 완료는 사용자 화면의 전체 인수 완료가 아니다. #135 계약 소비, 같은 화면의 실제 수정 커밋 재배포·최종 성공·/healthz·대표 페이지를 별도 확인한다. 전체 기능 호환성을 보장하지 않는다.
