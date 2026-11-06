# #23 고객 저장소의 이전 위험 분석

상태: 분석기·CLI·선택 PRECHECK 단계 구현, 단독 검증 완료. WAS의 고객 저장소/커밋 입력 연결 및 실제 화면 통합은 남아 있다. 운영은 기본 off.

## 목적과 범위

[AI #23](https://github.com/Softbank-Hackathon-2026-Team-Echo/echo-ai-agent/issues/23)의 읽기 전용 분석이다. 고객 코드를 설치·빌드·실행하지 않고 **고정 커밋**의 Python 소스와 제한된 설정 파일에서 관측을 만든다. 모델은 마스킹된 근거를 받아 한국어 설명·권고를 추가한다. 패치 생성·승인·재배포와 DB 네트워크 변경은 이번 범위에 없다.

| 분류 | 정적 관측 | 증명하지 않는 것 |
|---|---|---|
| REGION | Python 문자열 리터럴 또는 설정 파일의 AWS/GCP 리전 패턴 | 실제 사용 여부·대상 리전의 가용성 |
| CLOUD_SDK | boto3/botocore/google.cloud/azure import 또는 SDK 의존성 이름 | API 실제 호출·권한·연결 실패 |
| SECRET | 알려진 자격 증명/개인 키 패턴, 비밀 이름에 직접 지정한 문자열·인자 | 유효한 실제 키인지, 이미 폐기됐는지 |
| LOCAL_STATE | sqlite3.connect, shelve.open, open/io.open 쓰기 모드 | 외부 마운트·복제 여부, 실제 데이터 손실 |

관측은 `origin=RULE / certainty=OBSERVED`, 모델 설명은 `origin=AI / certainty=INFERRED`다. 확정은 **코드 패턴의 존재**를 뜻한다. 이전 장애를 확정하는 뜻이 아니다. 발견 항목은 모두 WARN이며 모델이 보안 승인·PASS/FAIL을 결정하지 않는다. 지역/SDK가 코드에 있다는 사실만으로 이관을 차단하지 않는다.

## 입력과 파일 수집

- CLI는 로컬 Git 저장소 또는 **공개 GitHub** `owner/name`과 40자리 commitSha를 받는다. branch/main/HEAD를 입력으로 받지 않는다.
- 로컬 Git은 rev-parse, ls-tree, cat-file만 사용한다. 작업 폴더의 수정, checkout filter, 설치 스크립트, 고객 Python import를 사용하지 않는다.
- 공개 GitHub는 고정 codeload HTTPS 주소를 사용한다. 임의 URL·리다이렉트·프록시·GitHub 인증 값을 받지 않는다. 비공개 저장소는 자동 다운로드를 지원하지 않으며 실패를 명시한다. 운영 인증 경로는 WAS와 별도로 연결해야 한다.
- 압축은 메모리에서만 읽는다. 심볼릭/하드 링크·특수 파일·경로 이탈을 분석 대상에서 제외하며 파일시스템에 압축을 풀지 않는다.
- 허용 파일: `.py`, `requirements.txt`, `pyproject.toml`, `Dockerfile`. `.env`와 예시 `.env`, 키·자격 증명 파일, 숨김 경로, 의존성/빌드 폴더, 테스트/fixture/문서/마이그레이션은 제외한다.
- 상한: 파일 64 KiB·100개, 선택 소스 합계 512 KiB, 트리 5,000개 항목, 압축 8 MiB/압축 해제 32 MiB, 한 줄 4,000자. 제외·용량·인코딩·구문 오류를 보고한다.
- source에 커밋·선택 파일 목록·내용 hash를 기록한다. 로컬은 Git 객체에서 읽고 원격은 해당 커밋을 지정한 GitHub 응답에 의존한다. 내용 hash는 출처 인증이나 전체 코드 검증을 대신하지 않는다.

## 마스킹과 모델

원문은 정적 관측과 마스킹을 위한 프로세스 메모리에서만 다룬다. 실제 .env/키 파일은 내용을 읽지 않는다. 알려진 토큰·URL 자격 증명·개인 키·비밀 이름 할당을 가리고 줄 번호를 보존한다. 의심스러운 고엔트로피 줄도 가린다. 출력·모델에는 선택된 관측의 **마스킹한 한 줄 근거**만 보낸다. 전처리는 휴리스틱이며 모든 종류의 비밀을 탐지한다고 주장하지 않는다.

Claude는 최대 1회, 요청당 최대 60초, 자동 재시도 0이다. 기존 SDK·모델·Anthropic API를 재사용한다. 관측 최대 30개 중 앞의 20개를 보내고, 최대 20개 설명을 받는다. 모델은 파일이나 관측을 새로 추가하거나 정적 관측을 지울 수 없다.

모델의 observationId/evidenceIds가 실제 **보낸** 관측과 일치해야 한다. 없는 근거·추가 필드·중복·잘못된 분류는 버린다. `POTENTIAL_RISK` 또는 `NEEDS_CONTEXT`로 표시한다. ID 검증은 자연어 주장의 의미적 정확성까지 보장하지 않으므로 사람이 검토해야 한다. 거절·오류·근거 없음 때 정적 관측은 보존한다.

실제 요청 시 성공·실패 모두 processing에 SOURCE_CODE/FINDINGS/CONFIG, 추정 바이트 수를 기록한다. 모델 호출은 컨테이너 밖 제어 프로세스, Anthropic 직접 호출, modelRegion=null이다. 기존 설정 검토와 함께 호출하면 실제 전송량과 자료 종류를 합친다. 모델 원문 오류·키는 이벤트에 넣지 않는다.

## PRECHECK 연결

새 서비스/API/작업 종류를 만들지 않고 기존 PRECHECK에 선택 단계로 붙였다. `ECHO_REPO_ANALYSIS=on` 또는 `--repo-analysis`로 켠다. 기본 off. `--no-model`과 함께 사용하면 정적 분석만 한다. 모델 켜짐이면 기존 설정 검토 외 **최대 1회 추가 호출**이다.

현재 WAS의 PRECHECK 입력에는 고객 저장소/배포 커밋이 없다. 다음 두 칸을 묶은 **선택 입력 제안**을 받도록 구현했다. 실제 WAS의 확정된 입력이라고 주장하지 않는다.

```json
{
  "schemaVersion": 1,
  "service": {"기존": "그대로"},
  "source": {"environmentId": "uuid", "kind": "aws"},
  "target": {"environmentId": "uuid", "kind": "gcp"},
  "findings": [],
  "repository": {
    "repo": "owner/name",
    "commitSha": "현재 이전 대상 빌드를 만든 정확한 40자리 SHA"
  }
}
```

WAS가 **현재 배포 이미지와 연결된 빌드의 저장소·커밋**을 넣어야 한다. main의 최신 커밋이나 AI 시나리오 저장소를 대신 분석하지 않는다. 값이 없거나 읽지 못하면 `repo-coverage` WARN을 남기고 기존 설정 점검은 계속한다. 입력이 없는 상태를 분석 성공으로 꾸미지 않는다.

출력은 기존 RunFindingRequest 그대로다. `control=repo-region/repo-cloud-sdk/repo-secret/repo-local-state`, `title`에 분류·위험도, `reason`에 파일:줄·마스킹한 근거·관측 범위, `suggestedFix`에 권고를 넣는다. 모델 설명은 `repo-ai-review`·origin AI·WARN이다. 별도 미승인 결과 필드를 보내지 않아 기존 WAS 수신 모델로 검사할 수 있다. 총 findings 100개 상한에서는 기존 항목을 우선한다.

구조화된 전체 관측은 CLI JSON에 있다. 기존 UI에서 source 위치를 텍스트로 표시하는 것과 파일 링크/구조화 필터를 지원하는 것은 별개다. 실제 화면 확인은 아직 하지 않았다.

## 검증 및 남은 연결

- 독립 main 기준 브랜치에서 전체 pytest **356 passed**, skip 0. 신규 51개 시험, Ruff lint/format·mypy·쉘 문법·패키지 빌드 및 모듈 포함 검사 통과. #22 PR의 미병합 테스트를 포함한 숫자가 아니다.
- 합성 Python 서비스 한 개에서 네 분류·정적 관측 5건 검출. fake credential은 결과·모델 입력에서 가림.
- 실제 Claude 1회: 17.815초, 입력 2,253/출력 1,812 토큰. 기존 근거를 인용한 한국어 추정·권고 5건. 운영 고객 코드나 서비스를 변경하지 않았다.
- 공개 demo-app `d856a1d13f19aa219ebba117c29561f838da9fe4`를 실제 수집해 11개 파일 분석. 이번 제한된 규칙에 해당하는 관측은 0건이며 안전 판정을 뜻하지 않는다. 시연은 별도의 합성 fixture로 재현한다.
- 로컬 echo-was `RunResultRequest`로 실제 모델 결과 + 기존 findings 10건 검증 통과. HTTP/운영 수신·화면 연결 시험과 구분한다.
- 증거: [ai-23-live-review-2026-11-07.json](evidence/ai-23-live-review-2026-11-07.json).
- 남음: WAS PRECHECK 저장소/커밋 입력 연결, 필요 시 비공개 저장소 제공 방식, 실제 화면 확인, PR 병합 및 운영 스위치 반영. #22 자동 수정으로 이어지는 선택 기능은 제외했다.

## 참고

`2026-softbank-1/iris-code-analyzer-agent` `593cd15606b3bad84b19bf7548b95f984fc1d4f6`의 README·모델 검토/근거 검증 문서를 읽었다. 고정 소스·실행 금지·관측/추정 분리·근거 검증 아이디어만 참고했다. 소스 복사, OpenCode, tree-sitter, 배포 구성 추출 기능은 도입하지 않았다.
