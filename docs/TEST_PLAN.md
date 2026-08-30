# Test & QA Plan

How to verify w1r3hound end to end: the engine (CLI), the web backend, and the
reskinned frontend. The overarching principle from the existing audit still
holds: **tests are hermetic — no traffic leaves the host.** Anything that needs
a live target uses a loopback mock or a locally-run vulnerable app.

## 0. Tooling & conventions

- `go test ./...` — unit/table tests (existing + new).
- `go test -race ./...` — the job/SSE concurrency must be race-clean.
- `net/http/httptest` — exercise the webui handlers without binding a socket.
- The `TestHelperProcess` pattern — test `jobs.go` without the real scanner:
  set `Manager.binPath` to `os.Args[0]` and args to `-test.run=TestHelperProcess`
  gated by an env var, so the "subprocess" is a controlled Go test that can emit
  canned stdout/stderr and a chosen exit code. This avoids a shell and avoids
  any network.
- Loopback mock for target-hitting flows: a throwaway HTTP server on
  `127.0.0.1` (mirrors the audit's `/tmp/lab` approach) serving crafted
  `robots.txt`, headers, HTML, and `/api-docs`.
- Fixtures live under `internal/modules/testdata/` and (new) `webui/testdata/`.

## 1. Engine / CLI tests

### 1.1 What exists (keep, extend)
17 files / ~97 funcs across `internal/core`, `internal/report`,
`internal/modules` (see [PROJECT_STATE.md](PROJECT_STATE.md) §7), including DNS
wire-parser tests, `*_audit_test.go` accuracy tests, and an integration test.

### 1.2 CLI flag functional matrix (add where missing)
For each flag, assert parsing + effect (via a hermetic run or a unit check):

- `-t/-target`: host, IPv4, IPv6, CIDR, http(s) URL accepted; garbage rejected.
- `-m/-protocols`: alias and internal names both resolve; unknown rejected;
  `all` runs the full set; `-passive` drops active modules.
- `-c`, `-rate`, `-timeout`: bounds honored; `-rate 0` = unlimited.
- `-p`: `top100` / `1-1024` / `full` select the expected port set
  (`selectPorts`).
- `-w`, `-dir-wordlist`, `-dir-ext`: wordlists load; extensions appended.
- `-header/-H`: headers reach `cfg.RequestHeaders` and are sent on requests.
- `-skip-tls-verify` (default true) and `-block-private-egress` (default false):
  verify the dialer honors both (egress guard blocks private IP dials when on).
- `-resolver` / `-resolvers`: single resolver vs raw-UDP pool selection.
- `-wayback-limit`, `-crawl-pages`, `-js-files`: caps enforced.
- `-o`: writes `<base>.json` + `<base>.md`; `-v`: verbose lines emitted.

### 1.3 Module-level correctness
Per-module expected-findings fixtures (see
[FALSE_POSITIVES_NEGATIVES.md](FALSE_POSITIVES_NEGATIVES.md)) drive FP/FN
regression. Highest-value first: `metafiles`, `headers`, `content`, `api`,
`crawler`, `takeover`, `discovery` (cors/cloud/dirbrute), `portscan`.

## 2. webui backend tests (currently ZERO — top gap)

New file(s): `webui/validate_test.go`, `webui/server_test.go`,
`webui/jobs_test.go`.

### 2.1 `validate.go` — table tests
- `validateTarget`: table of valid (host/IP/IPv6/CIDR/URL) and invalid
  (spaces, control chars, `-x`, `--output=`, `userinfo@`, `>2048`, bad scheme).
- `normalizeModules`: alias+internal resolve, dedupe, catalog order, unknown →
  error, "too many" → error, empty → `nil` (all).
- `resolveWordlist`: in-dir file OK; absolute outside, `../` traversal, symlink
  escape, non-regular file all rejected.
- `buildArgs`: **argv-exact** assertions per field, including the new parity
  fields ([CLI_PARITY.md](CLI_PARITY.md) §2). E.g. `authorized:false` → error;
  target+modules+ports produce `-t … -m … -p …` in the expected order;
  `-timeout` emitted as `Ns`.
- Output-name allow-list: valid names accepted; `..` and bad charset rejected;
  auto-name format when empty.

### 2.2 `main.go` — httptest handler tests
- `originGuard`: non-loopback `Host` → `421`; foreign `Origin` → `403`;
  `Sec-Fetch-Site: cross-site` → `403`; legit loopback GET → `200`.
- Security headers on `GET /`: `Content-Security-Policy`, `X-Content-Type-Options`,
  `X-Frame-Options`, `Referrer-Policy` present; SSE route omits CSP.
- `requireToken`: with `W1R3HOUND_UI_TOKEN` set, mutating endpoints return `401`
  without/with-wrong token and `200/201` with correct token (constant-time).
- `handleStartScan`: invalid JSON → `400`; unknown field → `400`
  (`DisallowUnknownFields`); body > 64 KB → error; `authorized:false` → `400`;
  valid → `201` with `{id,status}`.
- `confinedResultFile`: `id` with `/`, `..`, `%2f`, absolute → `400/404`; valid
  id serves the file; nothing outside `results/` is served.
- `handleEvents` (SSE): buffered replay then a `status` event on a finished job;
  correct `Content-Type: text/event-stream`; heartbeat on idle.
- `handleListScans`/`handleGetScan`: in-memory + disk-recovered merge; sort
  order; not-found → `404`.
- `handleReport`: `.json`/`.md` `200` with `Content-Disposition`; missing →`404`.

### 2.3 `jobs.go` — lifecycle & concurrency (use `TestHelperProcess`)
- `Submit`: duplicate base name → error; queue full (`queueCapacity`) → error;
  creates the `.log` file `0600`.
- `run`: stub emits stdout+stderr lines → `logBuf` captured, ANSI stripped,
  `finish(StatusDone)`; non-zero exit → `StatusFailed`; exit 130 → `StatusCancelled`.
- `Cancel`: queued (pre-start) vs running vs already-finished states.
- `subscribe`/`unsubscribe`: replay snapshot correctness; slow subscriber
  dropped without blocking; channels closed on `finish`.
- Run the whole suite under `-race`.

## 3. Frontend QA

The frontend is dependency-free vanilla JS; keep automated coverage light and
lean on a manual matrix plus API-level assertions.

### 3.1 Automated (low-cost)
- CSP-hygiene check (can be a shell/Go test): assert `webui/static/` contains no
  inline `on*=` handlers and no external `src`/`href` (keeps the strict CSP
  satisfiable). This guards against regressions in the reskin.
- API-contract checks with `curl`/Go against a running server (already proven in
  the reskin smoke test): `/api/modules` count, `/api/scans` shape, a loopback
  scan producing a report whose finding keys match `js/api.js` expectations
  (`module`, `wstg_id`, `title`, `description`, `severity`, `data`).
- Optional (dev-only, not shipped): a headless-browser smoke (Playwright) that
  loads the page, launches a loopback scan, and asserts the terminal streams and
  the Findings table renders — kept out of the zero-dep build.

### 3.2 Manual QA matrix (per page)
- Overview: stat cards, severity breakdown, donut, recent scans populate from
  `/api/scans`; date renders; "View all" navigates to Scans.
- Scans: list + status badges; filters (status, search) and sort toggle; row →
  Console; "view findings" for reports; cancel for running.
- Findings: scan selector defaults to newest completed; severity/triage/search
  filters; detail panel shows module/WSTG/description/data; triage select
  persists to `localStorage` (`w1r3hound_triage`) and survives reload; CSV export.
- Console: New Scan modal (all options incl. the parity additions), authorized
  gate blocks submit; live SSE terminal with severity coloring; progress state;
  cancel; scan tabs; clear log; download log/json/md links.
- Settings: token save to `localStorage` and used on scan/cancel; clear-local
  triage; authorized-use banner.
- Cross-cutting: Escape closes modal/panel; empty states; server-unreachable LED;
  no console CSP violations; responsive down to a narrow window.

## 4. End-to-end scenarios (contained)

1. Loopback portscan (`127.0.0.1`, `-m portscan`) — fast, purely local; used as
   the CI smoke.
2. OWASP Juice Shop on `127.0.0.1:3000`, full pipeline
   (`-m metadata,crawler,deepdive,apiscan,headers,webserver`) — reproduces the
   audit's Phase C (expects e.g. `/ftp` directory listing High, stack-trace
   Medium, `/api-docs`). Validates the report → GUI Findings pipeline on real
   content.
3. Cancel mid-scan: start a longer scan, cancel from Scans/Console, assert
   `cancelled` status and partial report/log.
4. Token mode: start server with `W1R3HOUND_UI_TOKEN=…`; unauthenticated
   scan/cancel `401`; token entered in Settings works.
5. Disk-recovered scan: restart the server; a prior report still lists and its
   log loads via the static `/log` path (non-live branch in `app.js`).

## 5. Continuous integration (suggested)

Add a `Makefile`/CI workflow (no runtime deps introduced) running on push:

- `go vet ./...`
- `gofmt -l .` (must be empty)
- `go test -race ./...`
- `govulncheck ./...` (tracks `C-11`/`F-13` toolchain vulns)
- `gosec ./...` (informational; triage against the audit's accepted G-items)
- Frontend CSP-hygiene check (§3.1)
- Optional job: build both binaries + loopback portscan smoke.

## 6. Exit criteria

- webui backend packages have meaningful coverage (validation, transport guard,
  file confinement, job lifecycle) and pass under `-race`.
- Every CLI flag has a functional test and a matching GUI control test.
- The manual QA matrix passes on a fresh build with no CSP violations.
- The two primary e2e scenarios (loopback portscan, Juice Shop) pass and match
  the equivalent CLI output.
