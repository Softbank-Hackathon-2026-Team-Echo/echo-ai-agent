# 시나리오 사본: echo-demo-app `0ff0d44`

사전 점검 러너의 규칙 패치(AI 에이전트 5 초안, [`specs/ai-5-rule-patch-proposal.md`](../../specs/ai-5-rule-patch-proposal.md))가 대상으로 삼는 고정 사본이다.

## 출처

| 항목 | 값 |
|---|---|
| 저장소 | `Softbank-Hackathon-2026-Team-Echo/echo-demo-app` |
| 커밋 | `0ff0d44f64e43d6eb65db63ab4f7844642638562` |
| 파일 | `Dockerfile` (blob `a2e023c906db9107da0b03900f5695e55ceb78d4`, 바이트 그대로) |

앱 소스는 넣지 않았다. `Dockerfile` 하나뿐이라 이 폴더만으로는 전체 이미지를 빌드할 수 없다.

## 이 사본을 고치지 않는다

패치는 제안만 하고 이 파일에 직접 반영하지 않는다. 사람이 승인한 패치의 반영은 `applied/<runId>` 브랜치에 커밋하는 별도 단계(S3)다.

운영 echo-demo-app은 `6ac8813`(실행 이미지에서 pip 제거, 수정 가능한 HIGH 5건 제거)으로 이미 고쳤다. 이 사본은 고치기 전 상태를 시연하려고 그대로 둔다.

## 규칙 R-PIP-1

입력 스냅숏의 `findings[]`에 `controlId`가 `C-IMG-1`이고 결과가 PASS가 아닌 항목이 있고, 이 사본의 마지막 단계에 `pip uninstall`이 없으면 발동한다. 마지막 단계의 첫 `RUN` 앞에 pip를 지우는 명령과 주석 3줄을 넣는 패치 하나를 만들며, 그 결과는 `6ac8813`의 `Dockerfile`과 바이트가 같다. 모델을 쓰지 않으므로 `origin: "RULE"`로 표시한다. 변환이 이 Dockerfile에 맞춰져 있어 **이 고정 시나리오 전용**이고, 다른 앱에는 쓸 수 없다.
