# AI #22 진단 간단판의 통합 후 상태

#25 `ec809b3`의 연결 골격을 #24의 검증된 진단 엔진과 통합했다. 현재 정본은 [ai-22-error-diagnosis.md](ai-22-error-diagnosis.md)다. #25 원래 간단판은 Git 이력에 보존된다.

## 재사용한 부분

- WAS #101 입력, 공개 실패 커밋 소스 확보, CHANGE_PROPOSAL claim·하트비트·이벤트·결과 제출.
- 서비스 저장소 APPLY_PATCH: 실패 커밋 적용·로컬 커밋·빌드·Trivy·healthz. 저장소 push는 WAS 담당.
- `Diagnoser.diagnose(...) -> DiagnosisOutcome` 교체 지점과 strict apply 호환 확인.

## 교체·보완한 부분

- 단일 모델 diff 생성 대신 #24 DiagnosisService를 사용한다. EV/SC 근거 검사와 격리된 Node 문법 검사에서 원본 FAIL → 수정본 PASS를 확인한 패치만 반환한다. 자동 수정은 기존 demo HTML의 classic inline JS 범위다.
- 소스 파일 ±60줄을 보내던 간단판 대신, 지원 파일의 전체 소스를 64 KiB 이내에서 가려 제공한다. 로그가 지원 파일을 가리키지 않으면 로그만 분석하고 자동 수정하지 않는다.
- 알려진 토큰 외 일반 비밀번호/인증 값도 가리고 민감 파일을 먼저 제외한다. 최종 정규화 diff의 주변 문맥에서 비밀값이 복원되는 경우도 거절한다.
- LOG.line은 WAS logTail 내 1부터 번호, evidence 최대 20개. 내부 검사 로그를 logTail 원문으로 가장하지 않는다.
- 기본 off 유지. 모델 off는 규칙만, API 실패·거절은 실패 코드와 전송 기록을 보존한다.

## 검증 경계

전체 431개 테스트 및 실제 Claude + 로컬 격리 문법 검사, WAS #101 최종 스키마/정규화 통과. 실제 WAS·화면·사람 승인·서비스 저장소 빌드/Trivy/healthz·수정 커밋 재배포 종단 확인은 별도다. 운영 release는 변경하지 않았다.
