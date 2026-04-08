#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"

export MAYA_TAIPY_API_BASE="${MAYA_TAIPY_API_BASE:-http://127.0.0.1:8900}"
export MAYA_TAIPY_REQUEST_TIMEOUT_SECS="${MAYA_TAIPY_REQUEST_TIMEOUT_SECS:-2.0}"
export MAYA_TAIPY_HOST="${MAYA_TAIPY_HOST:-127.0.0.1}"
export MAYA_TAIPY_PORT="${MAYA_TAIPY_PORT:-5000}"
export MAYA_TAIPY_DARK_MODE="${MAYA_TAIPY_DARK_MODE:-true}"
export MAYA_TAIPY_RELOADER="${MAYA_TAIPY_RELOADER:-false}"

if [[ -n "${MAYA_DASHBOARD_TOKEN:-}" && -z "${MAYA_TAIPY_DASHBOARD_TOKEN:-}" ]]; then
  export MAYA_TAIPY_DASHBOARD_TOKEN="$MAYA_DASHBOARD_TOKEN"
fi

cd "$ROOT_DIR/taipy_dashboard"
python3 app.py
