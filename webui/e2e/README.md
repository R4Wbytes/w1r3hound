# webui e2e — dev-only Playwright smoke

This directory is **not part of the shipped build**. The w1r3hound web console
stays zero-dependency (Go standard library + vanilla JS); everything here is a
local/CI QA aid and is gitignored (`node_modules/`, browser binaries, reports).

## Run

```bash
# 1) install the dev deps + a headless Chromium (one time)
cd webui/e2e
npm install
npx playwright install chromium

# 2) run the smoke — it starts its OWN hermetic webui (open mode) via
#    serve-hermetic.sh, so no accounts and no sign-in gate; nothing touches the
#    real webui/auth. It rebuilds the binaries so the embedded SPA is current.
npm test                          # or: npx playwright test
```

To point the smoke at an already-running console instead of launching its own
(e.g. to test a specific instance), set `W1R3HOUND_UI_REUSE=1` — note that a
login-enabled console will show the sign-in gate and fail the open-mode smoke:

```bash
W1R3HOUND_UI_REUSE=1 W1R3HOUND_UI_URL=http://127.0.0.1:8737 npm test
```

### Hermetic server (serve-hermetic.sh)

The smoke runs the real `webui/w1r3hound-webui` binary against a throwaway
repo-root skeleton (`W1R3HOUND_ROOT` → a `mktemp -d` with symlinks to
`main.go`/`go.mod`/`internal`, plus a stub `w1r3hound`). The login store is
therefore empty → **open mode** (no sign-in), and the developer's real
`webui/auth` is never read or written. No scan is launched by the smoke.

## What the smoke covers (automated)

- Strict-CSP-clean load: no `Content-Security-Policy` console violations, no
  page errors, no failed self-hosted `.css`/`.js` (guards the reskin against a
  regression that would need a looser CSP).
- Same-origin API wiring: `GET /api/modules` from the page returns 21 modules.
- Six-page navigation: Overview / Scans / Findings / Console / Account / Settings.
- New-scan modal opens with the target input and the authorized-use gate.
- New-scan modal exposes the CLI-parity **Advanced options** (dir-brute wordlist
  & extensions, custom headers, resolver/resolvers, wayback/crawl/js caps, TLS
  verification and private-egress toggles), with TLS-verify defaulting off.
- Server-status LED reflects the loopback backend.

The scan -> SSE stream -> report -> Findings pipeline is validated at the API
level (`webui/*_test.go`) and end-to-end (`make e2e-juiceshop`, loopback
portscan), so the smoke does not re-drive a full scan through the browser.

## Residual manual QA checklist (TEST_PLAN.md §3.2)

Items that are not cost-effective to automate; verify by hand on a fresh build:

- Overview: stat cards, severity breakdown, donut and recent scans populate
  from `/api/scans`; date renders; "View all" navigates to Scans.
- Scans: status badges; status/search filters and sort toggle; row -> Console;
  "view findings"; cancel on a running scan.
- Findings: scan selector defaults to the newest completed scan;
  severity/triage/search filters; detail panel (module/WSTG/description/data);
  triage select persists to `localStorage` and survives reload; CSV export.
- Console: New Scan modal options; authorized gate blocks submit; live SSE
  terminal with severity coloring; progress; cancel; scan tabs; clear log;
  download log/json/md.
- Settings: token save to `localStorage` and used on scan/cancel; clear-local
  triage; authorized-use banner.
- Cross-cutting: Escape closes modal/panel; empty states; server-unreachable
  LED (stop the backend); responsive down to a narrow window.
