#!/bin/sh
# End-to-end demo:
#   1. create a demo project with a fake Cloudflare token
#   2. start the abracadabra API (Touch ID gate active)
#   3. a "dapp" pulls the token over HTTP (Touch ID prompt appears)
#   4. abra run injects the same token into a wrangler-style command
#   5. cleanup
#
# Usage: sh demo/demo.sh

set -e
cd "$(dirname "$0")/.."

PROJ=abra-demo
KEY=CLOUDFLARE_API_TOKEN

echo "── 1. creating demo project"
node dist/index.js project rm "$PROJ" >/dev/null 2>&1 <<< y || true
node dist/index.js project new "$PROJ"
printf "cf-demo-token-123456" | node dist/index.js set "$PROJ" "$KEY" --stdin

echo
echo "── 2. starting API on 127.0.0.1:7331"
ABRA_SKIP_BIOMETRICS=${ABRA_SKIP_BIOMETRICS:-0} node dist/index.js serve &
SERVE_PID=$!
sleep 1.5

cleanup() {
  kill "$SERVE_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

echo
echo "── 3. dapp asks for the secret (approve the Touch ID dialog)"
node demo/dapp-client.mjs "$PROJ" "$KEY"

echo
echo "── 4. injecting into a deploy-style command"
node dist/index.js run -p "$PROJ" -k "$KEY" -- sh -c 'echo "wrangler would deploy with CLOUDFLARE_API_TOKEN=${CLOUDFLARE_API_TOKEN:0:8}…"'

echo
echo "── 5. cleanup"
kill "$SERVE_PID" 2>/dev/null || true
wait "$SERVE_PID" 2>/dev/null || true
node dist/index.js project rm "$PROJ" <<< y

echo
echo "✓ demo complete — run 'abra' to explore the TUI"
