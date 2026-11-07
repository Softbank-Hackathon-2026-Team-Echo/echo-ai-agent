#!/usr/bin/env bash
# echo-precheck-runner.service 의 시작 스크립트.
# Secret Manager 에서 비밀을 읽어 이 프로세스의 환경 변수로만 넘기고 러너로 바꿔 탄다(exec).
# 비밀 값은 출력하지 않는다. 이 파일에 `set -x` 를 넣지 않는다.
set -euo pipefail

: "${ECHO_WAS_URL:?missing ECHO_WAS_URL}"
: "${ECHO_GCP_PROJECT:?missing ECHO_GCP_PROJECT}"
APP_DIR="$(cd "$(dirname "$0")/.." && pwd)"

# 값 검사를 비밀 읽기보다 먼저 한다. 오타면 Secret Manager 를 부르기 전에 종료 코드 2 로 멈춘다
# (서비스는 2 를 설정 오류로 보고 다시 띄우지 않는다).
args=()
case "${ECHO_PRECHECK_MODEL:-on}" in
  on)
    use_model=1
    ;;
  off)
    use_model=0
    args+=(--no-model)
    ;;
  *)
    echo "ECHO_PRECHECK_MODEL must be on or off" >&2
    exit 2
    ;;
esac
case "${ECHO_PRECHECK_PATCH:-off}" in
  on)
    args+=(--patch)
    ;;
  off)
    args+=(--no-patch)
    ;;
  *)
    echo "ECHO_PRECHECK_PATCH must be on or off" >&2
    exit 2
    ;;
esac

case "${ECHO_DIAGNOSIS:-off}" in
  on)
    export ECHO_DIAGNOSIS=on
    ;;
  off) ;;
  *)
    echo "ECHO_DIAGNOSIS must be on or off" >&2
    exit 2
    ;;
esac

read_secret() {
  gcloud secrets versions access latest --secret="$1" --project="$ECHO_GCP_PROJECT" --quiet
}

ECHO_RUNNER_TOKEN="$(read_secret echo-sandbox-was-runner-token)"
export ECHO_RUNNER_TOKEN
if [ "$use_model" = 1 ]; then
  ANTHROPIC_API_KEY="$(read_secret echo-sandbox-anthropic-api-key)"
  export ANTHROPIC_API_KEY
fi

exec "$APP_DIR/.venv/bin/python" -m echo_agent.precheck_runner "${args[@]}"
