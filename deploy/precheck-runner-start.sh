#!/usr/bin/env bash
# echo-precheck-runner.service 의 시작 스크립트.
# Secret Manager 에서 비밀을 읽어 이 프로세스의 환경 변수로만 넘기고 러너로 바꿔 탄다(exec).
# 비밀 값은 출력하지 않는다. 이 파일에 `set -x` 를 넣지 않는다.
set -euo pipefail

: "${ECHO_WAS_URL:?missing ECHO_WAS_URL}"
: "${ECHO_GCP_PROJECT:?missing ECHO_GCP_PROJECT}"
APP_DIR="$(cd "$(dirname "$0")/.." && pwd)"

read_secret() {
  gcloud secrets versions access latest --secret="$1" --project="$ECHO_GCP_PROJECT" --quiet
}

ECHO_RUNNER_TOKEN="$(read_secret echo-sandbox-was-runner-token)"
export ECHO_RUNNER_TOKEN

args=()
case "${ECHO_PRECHECK_MODEL:-on}" in
  on)
    ANTHROPIC_API_KEY="$(read_secret echo-sandbox-anthropic-api-key)"
    export ANTHROPIC_API_KEY
    ;;
  off)
    args+=(--no-model)
    ;;
  *)
    echo "ECHO_PRECHECK_MODEL must be on or off" >&2
    exit 2
    ;;
esac

exec "$APP_DIR/.venv/bin/python" -m echo_agent.precheck_runner "${args[@]}"
