#!/usr/bin/env bash
# w1r3hound Web GUI — one command:
# builds the CLI binary if needed, builds the GUI and serves it on 127.0.0.1:8737.
set -euo pipefail

cd "$(dirname "$0")/.."   # repo root

# ── CLI ──
if [[ ! -x ./w1r3hound ]] || [[ -n "$(find main.go internal -type f -newer ./w1r3hound -print -quit 2>/dev/null)" ]]; then
  echo "[run.sh] building w1r3hound…"
  VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
  go build -ldflags="-X main.version=${VERSION}" -o w1r3hound .
fi

# ── Web GUI ──
if [[ ! -x ./webui/w1r3hound-webui ]] || [[ -n "$(find webui -maxdepth 2 -type f \( -name '*.go' -o -name '*.html' -o -name '*.css' -o -name '*.js' \) -newer ./webui/w1r3hound-webui -print -quit 2>/dev/null)" ]]; then
  echo "[run.sh] building webui…"
  go build -o webui/w1r3hound-webui ./webui
fi

URL="http://127.0.0.1:8737"
echo "[run.sh] opening $URL"
( sleep 1; xdg-open "$URL" >/dev/null 2>&1 || open "$URL" >/dev/null 2>&1 || true ) &

exec ./webui/w1r3hound-webui
