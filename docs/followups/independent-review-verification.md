# 독립 검토·증거 결속 검증 (2026-11-08)

구현 후보이며 **PR 생성·병합·운영 활성화 없음**. 기본 OFF. 계약은 [ai-independent-review.md](../../specs/ai-independent-review.md)를 따른다.

- 러너 전체 **514 PASS / 실패0 / skip0**. 실제 Docker 원본 실패/수정본 성공·엄격 git 적용·기존 PRECHECK·진단·APPLY·전송 복구 포함.
- 거부/불명/시간 초과/다른 context/추가 edit/빈·긴 사유는 승인 패치 없음. 커밋·diff·검사 정의·검사 결과·검토 판정·증거/승인 지문 변조 차단. 기존 정책 없는 진단은 추가 모델 호출 없음.
- GCP 임시 경로에서 실제 **claude-opus-5-5** 2호출(작성1, 독립 검토1) 성공. 합성 `return str(123` 원본의 `SyntaxError: '(' was never closed`가 Python3.13.18 동일 Docker 검사에서 재현되고 수정본 통과. 검토 PASS·context/evidence 지문 검증 완료. 입력3526/출력714 tokens. 고객 서비스 소스/운영 API/실제 커밋·PR·재배포 시험은 아니다.
- [실제 모델 시험 근거](../evidence/independent-review-live-20261108.json)에 정책·정의·전후 검사·실제 검토 모델·판정·지문·전송량을 저장했다. 인증 값 없음.
- 임시 VM 소스/결과 제거 후 기존 서비스 PID147223·재시작0·active·운영 release7bb0ee3 유지 확인. 서비스 설정/권한/스위치 변경0.
- WAS 실제 PostgreSQL/API 인수 및 FE 전체 검증은 각 저장소 `specs/ai-independent-review-verification.md`와 루트 원장에 기록한다. 통합 진단→승인→샌드박스→진짜 저장소→실제 배포의 **새 정책 운영 종단 인수는 배포 후 남아 있다**.

## 최초 실패와 처리

로컬 PostgreSQL 임시 클러스터의 SQL_ASCII 때문에 한글 JSON 시험9건이 실패했다. UTF-8 전용 임시 클러스터로 재생성해 통과했다. Node22.12의 개발 도구 API 부재는 지원 범위22.23.4로 실행해 해결했다(잠금파일 변경0). 새 화면 시험의 권한 조회 대기 누락과 추가 시험 import 오타를 수정했다. VM 수동 실행의 HOME=/nonexistent 때문에 키 읽기가 실패했으며 기존 서비스의 CLOUDSDK_CONFIG 경로를 지정해 해결했다. 권한 추가 없음. 선택적 infra 계약의 첫 실패는 오래된 로컬 체크아웃을 지정한 탓이며 최신 infra main3bf3060의 임시 사본으로 통과했다.
