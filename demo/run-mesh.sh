#!/usr/bin/env bash
# meshmcp live mesh demo — one gateway (4 different MCP servers) + four agent
# apps (each its own mesh identity) + the Control Room.
# Requires: Go, and a REUSABLE NetBird setup key in $NB_SETUP_KEY.
#   export NB_SETUP_KEY=<key>   # app.netbird.io -> Setup Keys
#   ./demo/run-mesh.sh
set -euo pipefail
cd "$(dirname "$0")/.."   # repo root

[ -n "${NB_SETUP_KEY:-}" ] || { echo "Set NB_SETUP_KEY to a reusable NetBird setup key first." >&2; exit 1; }

echo "==> building binaries"
go build -o meshmcp .
go build -o cmd/mcpserver/mcpserver ./cmd/mcpserver

mkdir -p demo
[ -f demo/secrets.json ] || printf '{"stripe_key":"sk_live_demo_PLACEHOLDER"}' > demo/secrets.json
rm -f demo/audit.jsonl demo/trace.jsonl

PIDS=()
cleanup() { echo; echo "==> stopping"; for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT INT TERM

echo "==> starting gateway (fs · web · payments · customer-db)"
./meshmcp serve --config examples/demo-mesh.yaml >demo/gateway.out 2>demo/gateway.log &
PIDS+=($!)

# Wait for the gateway's mesh IP.
IP=""
for _ in $(seq 1 60); do
  sleep 0.75
  IP=$(grep -oE 'mesh peer up:[[:space:]]*[0-9.]+' demo/gateway.log 2>/dev/null | grep -oE '[0-9.]+$' | head -1 || true)
  [ -n "$IP" ] && break
done
[ -n "$IP" ] || { echo "gateway didn't report a mesh IP — see demo/gateway.log" >&2; exit 1; }
echo "==> gateway mesh IP: $IP"

echo "==> Control Room -> http://127.0.0.1:9900"
./meshmcp room --audit demo/audit.jsonl --addr 127.0.0.1:9900 --title "meshmcp live mesh demo" >demo/room.out 2>demo/room.log &
PIDS+=($!)
sleep 1
( command -v xdg-open >/dev/null && xdg-open http://127.0.0.1:9900 ) 2>/dev/null || \
( command -v open >/dev/null && open http://127.0.0.1:9900 ) 2>/dev/null || true

echo "==> starting agent apps (each its own mesh identity)"
./meshmcp agent --role reader  --device-name agent-reader  --nb-config demo/agent-reader-nb.json  --interval 3s "$IP:9101" >demo/agent-reader.out  2>demo/agent-reader.log  & PIDS+=($!)
./meshmcp agent --role fetcher --device-name agent-fetcher --nb-config demo/agent-fetcher-nb.json --interval 4s "$IP:9102" >demo/agent-fetcher.out 2>demo/agent-fetcher.log & PIDS+=($!)
./meshmcp agent --role billing --device-name agent-billing --nb-config demo/agent-billing-nb.json --interval 5s "$IP:9103" >demo/agent-billing.out 2>demo/agent-billing.log & PIDS+=($!)
./meshmcp agent --role analyst --device-name agent-analyst --nb-config demo/agent-analyst-nb.json --interval 4s "$IP:9104" >demo/agent-analyst.out 2>demo/agent-analyst.log & PIDS+=($!)

echo
echo "LIVE — watch the Control Room. Ctrl+C stops everything."
while true; do sleep 2; done
