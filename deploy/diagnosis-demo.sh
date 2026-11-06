#!/usr/bin/env bash
# One-off demo. Never starts the polling runner or changes production settings.
# Do not enable shell tracing: a live run reads the API key into process memory.
set +x
set -euo pipefail

APP_DIR="$(cd "$(dirname "$0")/.." && pwd)"
live=0
for arg in "$@"; do
  if [ "$arg" = --live ]; then live=1; fi
done
if [ "$live" = 1 ] && [ -z "${ANTHROPIC_API_KEY:-}" ]; then
  : "${ECHO_GCP_PROJECT:?set ECHO_GCP_PROJECT for Secret Manager access}"
  ANTHROPIC_API_KEY="$(gcloud secrets versions access latest \
    --secret=echo-sandbox-anthropic-api-key --project="$ECHO_GCP_PROJECT" --quiet)"
  export ANTHROPIC_API_KEY
fi
export PYTHONPATH="$APP_DIR/src"
export PYTHONDONTWRITEBYTECODE=1
exec "${ECHO_DEMO_PYTHON:-$APP_DIR/.venv/bin/python}" -m echo_agent.diagnosis_demo "$@"
