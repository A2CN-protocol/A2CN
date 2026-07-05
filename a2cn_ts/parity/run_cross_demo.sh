#!/usr/bin/env bash
# Cross-language two-process demo: runs the A2CN negotiation with one side in
# Python and the other in TypeScript, in both directions, asserting that the
# independently derived record hashes match at the wire level.
#
# Direction A: TypeScript buyer  <-> Python supplier
# Direction B: Python buyer      <-> TypeScript supplier
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TS_DIR="$(cd "$HERE/.." && pwd)"
ROOT_DIR="$(cd "$TS_DIR/.." && pwd)"
PY_DIR="$ROOT_DIR/reference-implementation/python"
PY_DEMO_DIR="$ROOT_DIR/demos/two_process"
TS_DEMO_DIR="$TS_DIR/demos/two_process"

SUPPLIER_LOG="$(mktemp)"
BUYER_LOG="$(mktemp)"
SUPPLIER_PID=""
BUYER_PID=""

cleanup() {
  if [[ -n "${SUPPLIER_PID:-}" ]]; then kill "$SUPPLIER_PID" 2>/dev/null || true; fi
  if [[ -n "${BUYER_PID:-}" ]]; then kill "$BUYER_PID" 2>/dev/null || true; fi
}

print_logs_on_failure() {
  exit_code=$?
  if [[ $exit_code -ne 0 ]]; then
    echo
    echo "--- supplier log ---"
    cat "$SUPPLIER_LOG" 2>/dev/null || true
    echo
    echo "--- buyer log ---"
    cat "$BUYER_LOG" 2>/dev/null || true
  fi
  rm -f "$SUPPLIER_LOG" "$BUYER_LOG"
  exit "$exit_code"
}

trap print_logs_on_failure ERR EXIT

wait_for_health() {
  for url in "http://127.0.0.1:8002/demo/health" "http://127.0.0.1:8001/demo/health"; do
    deadline=$((SECONDS + 20))
    until curl -sf -o /dev/null "$url"; do
      if (( SECONDS > deadline )); then
        echo "Timed out waiting for $url" >&2
        return 1
      fi
      sleep 0.2
    done
  done
}

run_direction() {
  local label="$1" supplier_cmd="$2" buyer_cmd="$3"
  echo
  echo "=== $label ==="
  : >"$SUPPLIER_LOG"
  : >"$BUYER_LOG"

  bash -c "$supplier_cmd" >"$SUPPLIER_LOG" 2>&1 &
  SUPPLIER_PID=$!
  bash -c "$buyer_cmd" >"$BUYER_LOG" 2>&1 &
  BUYER_PID=$!

  wait_for_health
  (cd "$TS_DIR" && npx tsx "$TS_DEMO_DIR/run_demo_client.ts" "http://127.0.0.1:8001")

  cleanup
  SUPPLIER_PID=""
  BUYER_PID=""
  sleep 0.5
}

run_direction \
  "Direction A: TypeScript buyer <-> Python supplier" \
  "cd '$PY_DIR' && uv run python '$PY_DEMO_DIR/supplier_agent.py' --port 8002" \
  "cd '$TS_DIR' && npx tsx '$TS_DEMO_DIR/buyer_agent.ts' --port 8001"

run_direction \
  "Direction B: Python buyer <-> TypeScript supplier" \
  "cd '$TS_DIR' && npx tsx '$TS_DEMO_DIR/supplier_agent.ts' --port 8002" \
  "cd '$PY_DIR' && uv run python '$PY_DEMO_DIR/buyer_agent.py' --port 8001"

echo
echo "=== Cross-language demo passed in both directions ==="
