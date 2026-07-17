#!/usr/bin/env bash
set -euo pipefail

DEMO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TS_DIR="$(cd "$DEMO_DIR/../.." && pwd)"

cd "$TS_DIR"

SUPPLIER_LOG="$(mktemp)"
BUYER_LOG="$(mktemp)"

cleanup() {
  if [[ -n "${SUPPLIER_PID:-}" ]]; then kill "$SUPPLIER_PID" 2>/dev/null || true; fi
  if [[ -n "${BUYER_PID:-}" ]]; then kill "$BUYER_PID" 2>/dev/null || true; fi
  rm -f "$SUPPLIER_LOG" "$BUYER_LOG"
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
  exit "$exit_code"
}

trap print_logs_on_failure ERR
trap cleanup EXIT

npx tsx "$DEMO_DIR/supplier_agent.ts" --port 8002 >"$SUPPLIER_LOG" 2>&1 &
SUPPLIER_PID=$!

npx tsx "$DEMO_DIR/buyer_agent.ts" --port 8001 >"$BUYER_LOG" 2>&1 &
BUYER_PID=$!

for url in "http://127.0.0.1:8002/demo/health" "http://127.0.0.1:8001/demo/health"; do
  deadline=$((SECONDS + 15))
  until curl -sf -o /dev/null "$url"; do
    if (( SECONDS > deadline )); then
      echo "Timed out waiting for $url" >&2
      exit 1
    fi
    sleep 0.2
  done
done

npx tsx "$DEMO_DIR/run_demo_client.ts" "http://127.0.0.1:8001"
