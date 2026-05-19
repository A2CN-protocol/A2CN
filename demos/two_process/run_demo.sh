#!/usr/bin/env bash
set -euo pipefail

DEMO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$DEMO_DIR/../.." && pwd)"
PY_DIR="$ROOT_DIR/reference-implementation/python"

cd "$PY_DIR"

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

uv run python "$DEMO_DIR/supplier_agent.py" --port 8002 >"$SUPPLIER_LOG" 2>&1 &
SUPPLIER_PID=$!

uv run python "$DEMO_DIR/buyer_agent.py" --port 8001 >"$BUYER_LOG" 2>&1 &
BUYER_PID=$!

uv run python - <<'PY'
import time
import urllib.request

for url in ("http://127.0.0.1:8002/demo/health", "http://127.0.0.1:8001/demo/health"):
    deadline = time.time() + 15
    while True:
        try:
            with urllib.request.urlopen(url, timeout=1) as response:
                if response.status == 200:
                    break
        except Exception:
            if time.time() > deadline:
                raise RuntimeError(f"Timed out waiting for {url}")
            time.sleep(0.2)
PY

uv run python - <<'PY'
import json
import urllib.request

request = urllib.request.Request("http://127.0.0.1:8001/demo/run", data=b"{}", method="POST")
with urllib.request.urlopen(request, timeout=20) as response:
    result = json.loads(response.read().decode("utf-8"))

print("A2CN two-process HTTP demo")
print("==========================")
print(f"session_id: {result['session_id']}")
print()
for item in result["transcript"]:
    step = item["step"]
    if "amount" in item:
        print(f"- {step}: {item['amount']} ({item['message_id']})")
    elif step == "buyer_acceptance":
        print(f"- {step}: accepted {item['accepted_offer_id']}")
    elif step == "session_ack":
        print(f"- {step}: {item['session_id']}")
    else:
        print(f"- {step}")

buyer_hash = result["buyer_record"]["record_hash"]
supplier_hash = result["supplier_record"]["record_hash"]
print()
print("Transaction records")
print("-------------------")
print(f"buyer_record.record_hash:    {buyer_hash}")
print(f"supplier_record.record_hash: {supplier_hash}")
print(f"hashes_match: {result['record_hashes_match']}")

if not result["record_hashes_match"]:
    raise SystemExit(1)
PY
