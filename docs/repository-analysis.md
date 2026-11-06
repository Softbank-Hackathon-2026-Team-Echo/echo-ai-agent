# 저장소 이전 위험 분석 사용법

설치된 Python 3.13+/Git과 프로젝트 의존성을 사용한다. 대상 코드를 설치·실행하지 않는다. 기본은 정적 분석이고 `--model`을 지정할 때만 실제 Claude를 최대 한 번 호출한다.

## 고정 커밋 읽기

```bash
uv sync --frozen
uv run python -m echo_agent.repo_cli \
  --github-repo Softbank-Hackathon-2026-Team-Echo/echo-demo-app \
  --commit d856a1d13f19aa219ebba117c29561f838da9fe4 \
  --source-cloud aws --target-cloud gcp
```

GitHub 자동 수집은 공개 저장소만 지원한다. 로컬 Git 사본은 `--github-repo` 대신 `--local-repo /path/to/repo`를 쓴다. `--commit`은 늘 40자리 SHA다. 작업 폴더가 수정돼 있어도 해당 Git 커밋의 파일만 읽는다.

이 demo-app 버전에서는 현재의 제한된 규칙으로 관측 0건이었다. 이는 안전 인증이 아니다. 네 가지 분류를 보여 주는 합성 입력은 아래에서 재현한다.

## 합성 시연

```bash
demo_dir=$(mktemp -d)
mkdir "$demo_dir/app"
cp tests/fixtures/repo-analysis/app/main.py "$demo_dir/app/main.py"
git -C "$demo_dir" init -q
git -C "$demo_dir" add app/main.py
git -C "$demo_dir" -c user.name=Demo -c user.email=demo@example.invalid \
  -c commit.gpgsign=false -c core.hooksPath=/dev/null commit -qm fixture
demo_commit=$(git -C "$demo_dir" rev-parse HEAD)
uv run python -m echo_agent.repo_cli --local-repo "$demo_dir" \
  --commit "$demo_commit" --source-cloud aws --target-cloud gcp > "$demo_dir/report.json"
```

fixture에는 사용 불가능한 가짜 비밀 문자열과 의도적으로 넣은 위험 패턴이 있다. **fixture를 실행하거나 운영에 배포하지 않는다.** 정적 관측은 다섯 건, 분류는 리전·SDK·비밀값 패턴·로컬 상태 네 종류다.

실제 모델 검토는 기존 `ANTHROPIC_API_KEY`를 프로세스 환경에 준비하고 마지막 명령에 `--model`을 더한다. 키를 소스·인자·출력 파일에 넣지 않는다. 모델은 마스킹된 근거만 받고 한국어 설명을 더한다.

## 결과 읽기

- `source`: 커밋·선택 파일·내용 hash·제외 이유별 개수.
- `observations`: RULE/OBSERVED, 실제 파일·줄·가린 근거·위험도·권고. 확정된 것은 소스 패턴의 존재다.
- `suggestions`: AI/INFERRED. 관측을 인용한 추정이며, 실제 오류나 보안 승인을 확정하지 않는다.
- `findings`: 기존 WAS 사전 점검에 넣을 수 있는 표시 형식. 모두 WARN이다.
- `coverage`, `limitations`: 지원 언어·문법 오류·상한과 검증하지 못한 내용.
- `processing`: 모델을 실제로 호출했을 때만 생기는 전송 기록. 실패해도 남는다.

CLI 종료 코드 0은 지원 소스를 분석한 것이며 ‘이전 가능’ 판정이 아니다. 1은 지원 파일 부재 또는 모델 검토 실패, 2는 소스/설정 오류다. 현재 정규식/AST 범위 밖의 동적 import·메모리 세션·JS/Java·복잡한 설정 연결은 분석하지 않는다.

운영 러너는 WAS 입력 연결 뒤 `ECHO_REPO_ANALYSIS=on`으로 활성화한다. 지금은 기본 off다. 상세 계약·범위는 [명세](../specs/ai-23-repository-analysis.md)를 따른다.
