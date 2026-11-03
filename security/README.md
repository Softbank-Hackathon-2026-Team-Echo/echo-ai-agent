# 이미지 검사 대상

`.github/workflows/image-scan.yml`이 이 폴더의 `scan-targets.json`에 적힌 이미지를 매일 Trivy로 검사하고, 원문을 산출물로 남긴다. 판정은 echo-was 보안 규칙표가 한다.

## 대상을 바꿀 때

- 운영에 배포한 이미지 digest가 바뀌면(`echo-infra` `demo-app/base/kustomization.yaml`) 이 파일의 `ref`를 같은 digest로 바꾸는 PR을 연다. main에 반영되면 바로 한 번 검사한다.
- `ref`는 반드시 `<저장소>@sha256:<64자>` 형식이다. 태그(`:latest` 등)는 받지 않는다.
- 급하면 Actions에서 `image-scan`을 수동 실행하고 `image_ref`에 digest 참조 하나를 넣는다.

## 산출물

| 파일 | 내용 |
|---|---|
| `trivy-image.json` | 취약점·비밀 검사 원문(Trivy JSON) |
| `meta.json` | 대상 이미지·digest·Trivy 버전·취약점 DB 시각·실행 번호·커밋 |

- 산출물 이름은 `image-scan-<digest 앞 12자>`, 보관 30일이다.
- 비밀 검사 원문에는 가려진 일부 문자열이 들어 있을 수 있다. 수집기는 규칙 ID·파일·줄만 남기고 나머지는 버린다.
