#!/usr/bin/env bash
# Hermetic webui for the Playwright smoke: it runs the real webui binary but
# against a throwaway repo-root skeleton so the login store starts EMPTY (open
# mode, no sign-in gate) and the developer's real webui/auth is never touched.
#
# findRepoRoot() only needs main.go + go.mod + internal as markers (the SPA
# assets are embedded in the binary), so we symlink those and drop a stub
# `w1r3hound` to satisfy the binPath check. No scan is ever launched by the smoke.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT_REAL="$(cd "$HERE/../.." && pwd)"

# Always rebuild so the smoke exercises the CURRENT tree (the SPA assets are
# embedded into the webui binary at build time). Zero third-party deps.
(cd "$ROOT_REAL" && go build -o webui/w1r3hound-webui ./webui)
[ -x "$ROOT_REAL/w1r3hound" ] || (cd "$ROOT_REAL" && go build -o w1r3hound .)

SKEL="$(mktemp -d)"
cleanup() { rm -rf "$SKEL"; }
trap cleanup EXIT INT TERM

ln -s "$ROOT_REAL/main.go"   "$SKEL/main.go"
ln -s "$ROOT_REAL/go.mod"    "$SKEL/go.mod"
ln -s "$ROOT_REAL/internal"  "$SKEL/internal"
printf '#!/bin/sh\nexit 0\n' > "$SKEL/w1r3hound"
chmod +x "$SKEL/w1r3hound"
mkdir -p "$SKEL/webui"

exec env W1R3HOUND_ROOT="$SKEL" "$ROOT_REAL/webui/w1r3hound-webui"
