# Security Assessment & Open-Items Tracker

This condenses the prior full audit (`AUDIT.md`, Parts I-III, which lives in the
original `~/Projects/w1r3houndGUI-alpha/` copy) into the canonical project and
reconciles it against the **current** code in `~/Desktop/w1r3hound/`. It is the
living security tracker for the next phase. No fixes are applied here.

## 1. Security model (as built)

- **Trust boundary:** browser → loopback Go server → validated `[]string` argv →
  CLI subprocess → network target. The browser never reaches the target; the CLI
  is the only network egress point.
- **No shell anywhere.** The webui uses `exec.CommandContext(ctx, binPath, argv...)`
  ([webui/jobs.go](../webui/jobs.go) ~325) — no `sh -c`, no string parsing.
- **Transport guard (verified present):** `originGuard` wraps the whole mux
  ([webui/main.go](../webui/main.go):76) — rejects non-loopback `Host` (`421`),
  foreign `Origin` (`403`), and `Sec-Fetch-Site: cross-site` (`403`).
- **Input allow-lists:** target (host/IP/CIDR/URL), module catalog, numeric
  bounds, ports set, UA CRLF/length, `DisallowUnknownFields` + 64 KB body cap.
- **File confinement:** `resolveWordlist` and `confinedResultFile`
  (EvalSymlinks + prefix + `Base(id)==id` + `..` reject).
- **SSRF confinement (verified present):** `isSameDomainURL` gates
  target-derived URL fetches in `metafiles.go`, `api.go`, `content.go`,
  `jsanalysis.go` (the `C-1` fix).
- **Opt-in egress guard (verified present):** `Config.BlockPrivateEgress` +
  dialer control (the `C-2` fix), flag `-block-private-egress`.
- **Output hygiene:** `0600` report/log files; `esc()`/`textContent` in the UI;
  `mdInline` markdown escaping; `json.Marshal`-framed SSE.
- **Authentication (optional login panel):** account-based auth
  ([webui/auth.go](../webui/auth.go), [webui/password.go](../webui/password.go)).
  Passwords are PBKDF2-HMAC-SHA256 (600k iters, 128-bit salt, `0600`
  `users.json` in a `0700` dir); sessions are 256-bit CSPRNG tokens stored only
  as their SHA-256, delivered in an `HttpOnly`/`SameSite=Strict` cookie with
  idle+absolute timeouts. Login is constant-time (dummy-hash on unknown users)
  with per-account lockout; mutations carry a per-session `X-CSRF-Token`; roles
  are admin/user. When enabled the `authGate` requires a session on **every**
  `/api` route (read and write), closing `F-3b`.

## 2. Fixed & verified (context — do not re-litigate)

| ID | Item | Status in this tree |
|----|------|---------------------|
| F-1 | CSRF via cross-origin POST | Fixed — `originGuard` (`webui/main.go:76`) + per-session `X-CSRF-Token` |
| F-2 | DNS rebinding vs loopback | Fixed — `Host` allow-list in `originGuard` |
| F-3 | Cross-origin read endpoints | Fixed — guard wraps the whole mux |
| F-3b | Read endpoints unauthenticated when token set | Fixed (when login panel enabled) — `authGate` gates all `/api` routes (`webui/auth.go`) |
| C-1 | SSRF via target-controlled URLs | Fixed — `isSameDomainURL` gates fetches |
| C-2 | Dial-time egress to internal IPs | Fixed (opt-in) — `-block-private-egress` |
| F-16 | Per-user scan/report isolation (BOLA) | Fixed (2026-08-27) — `Job.Owner` + `<base>.meta.json` sidecar + `canAccessScan`; every scan route (list/get/log/report/events/cancel) is owner-scoped; admin sees all; legacy sidecar-less reports are admin-only (`webui/jobs.go`, `webui/main.go`) |

## 3. Open items (reconciled tracker)

Severity uses the audit's ratings. "Location" is current code.

| ID | Sev | Item | Location | Recommended fix |
|----|-----|------|----------|-----------------|
| F-4 | Fixed | No `http.Server` timeouts (slowloris/resource) | `webui/main.go` (`newHTTPServer`) | **Fixed (2026-08-27):** `newHTTPServer` sets `ReadHeaderTimeout`/`ReadTimeout`/`IdleTimeout`; `WriteTimeout` left unset so the SSE stream survives |
| C-3 | Fixed | TLS verification off by default incl. OSINT APIs | `internal/core/core.go` HTTP clients | **Fixed (2026-08-27):** `NewVerifiedHTTPClient` (verify on + `MinVersion` TLS1.2) now serves the fixed-host intel calls (`passive.go`, `asn.go`, Wayback in `discovery.go`); target traffic still honours `-skip-tls-verify` |
| F-3b | Medium | Read endpoints unauthenticated even when token set | `webui/main.go` (`requireToken` only on mutating) | **Addressed by the login panel:** with accounts enabled, `authGate` (`webui/auth.go`) requires a session on every `/api` route. Open (no-account) mode is unchanged — the legacy token still only gates mutations. |
| C-4 | Fixed | Terminal/log injection via `[]string` field logged with `%v` | `internal/core/core.go` (`scrubArgs`) | **Fixed + tested (2026-08-27):** `scrubArgs` now scrubs `[]string` element-wise into a fresh slice (never mutating the caller); pinned by `internal/core/scrub_test.go` (`TestScrubArgsSlices`, `TestStripControl`) |
| C-5 | Low | AXFR name-walker `extractDNSNames` O(n^2) | `internal/modules/dnsextra.go` | Structural single-pass parse (see [OPTIMIZATIONS.md](OPTIMIZATIONS.md)) |
| C-6 | Low | Unbounded host set from hostile OSINT/CT volume | passive/dns modules | Cap discovered-host set + active-probe fan-out |
| C-7/C-8 | Low | Hostile banners / bidi/line-sep controls stored un-scrubbed in `Finding.Data` | modules writing `Data` | Scrub control + Unicode bidi at store time |
| C-9 | Low | Unbounded external-link/crawler accumulation | `internal/modules/crawler.go`, `content.go` | Cap collected links/JS per host |
| F-6 | Fixed | Info disclosure: absolute paths in errors + report enumeration | `webui/main.go` handlers, `webui/validate.go` | **Fixed (2026-08-27):** generic 500 on scan submit (real error logged server-side); wordlist error no longer echoes the absolute base path; report enumeration closed by per-user isolation (F-16) |
| F-7 | Fixed | Cancel/run race can drop a cancellation | `webui/jobs.go` `run` | **Fixed:** the cancel-func install and `StatusRunning` flip now happen under the same lock |
| F-8 | Fixed | `results/`/`wordlists/` created `0755` | `webui/jobs.go` `NewManager` | **Fixed (2026-08-27):** created `0700` + `Chmod 0700` on pre-existing dirs |
| F-9 | Low | Unbounded in-memory job map (log lines already ring-capped) | `webui/jobs.go` | Evict old finished jobs; cap `.log` size |
| F-10 | Low | File I/O performed while holding a lock | `webui/jobs.go` `appendLog` | Do disk writes outside the mutex |
| F-11 | Partially fixed | CSP allows `style-src 'unsafe-inline'`; no `base-uri`/`object-src` | `webui/main.go` `securityHeaders` | **Fixed (2026-08-27):** added `base-uri 'none'; object-src 'none'; form-action 'self'; frame-ancestors 'none'`; COOP/CORP/COEP + `Permissions-Policy` added (§9). Residual: dropping `style-src 'unsafe-inline'` still needs the inline-style refactor (§4) |
| F-12 | Low | UI token stored in `localStorage` | `webui/static/js/api.js` | Only the legacy open-mode token uses `localStorage`. The login panel's session token is an `HttpOnly` cookie (never exposed to JS) and its CSRF token is in-memory only. |
| C-10 | Info | Missing internal passive-mode guards in some active modules (latent) | several modules | Add early passive returns defensively |
| C-11/F-13 | Info | Toolchain currency (built `go1.26.5`) | build | Rebuild with the latest patch (`go1.26.6+`); track via `govulncheck` |
| F-14 | Info | Binaries in working tree | (n/a in this tree) | Already excluded from the canonical copy; keep it that way |
| C-12 | Info | ASN module trusts 3rd-party BGP CIDRs (report-only) | `internal/modules/asn.go` | Treat as untrusted; already report-only |
| C-13 | Info | `endpointprobe` naive `target+path` concat | `internal/modules/endpointprobe.go` | Use proper URL join |

## 4. New considerations from the reskin + parity work

- **Reskin vs `F-11`.** The new SPA is CSP-safe for scripts (self-hosted, no
  inline `<script>`/`on*=`), but it **uses inline `style="..."` attributes** in
  `index.html`/`app.js`, so it currently *depends on* `style-src 'unsafe-inline'`.
  Tightening the CSP to drop inline styles now requires moving those inline
  styles into `css/styles.css` (utility classes) first. Track as part of `F-11`.
- **Parity `-header/-H` (header injection).** Exposing custom headers in the GUI
  is a header-injection sink: enforce the CRLF/charset/count rules in
  [CLI_PARITY.md](CLI_PARITY.md) §2.3 before emitting `-H`. Also note headers
  land in the subprocess argv (visible in host process listings) — surface this
  in the UI hint; don't persist secrets.
- **Parity path inputs (`-dir-wordlist`, `-resolvers`).** Must reuse the same
  EvalSymlinks + prefix confinement as `resolveWordlist`; never accept arbitrary
  absolute paths.
- **Parity security wins.** Exposing `-skip-tls-verify` lets the GUI *re-enable*
  verification (helps `C-3`/`F-15`); exposing `-block-private-egress` surfaces
  the `C-2` guard to GUI users.

## 4a. Login panel — accepted trade-offs & residual items

- **KDF choice.** PBKDF2-HMAC-SHA256 (not Argon2id/scrypt) is used because the
  project is stdlib-only and pins `go 1.22`, which rules out
  `golang.org/x/crypto` and the `crypto/pbkdf2` stdlib package (go1.24+). The
  construction is verified against RFC test vectors (`password_test.go`). If the
  go floor rises to 1.24, switch to `crypto/pbkdf2`; if a dependency is ever
  accepted, prefer Argon2id.
- **Sessions are in-memory.** A server restart invalidates all sessions (users
  re-login). This is intentional (no session secret at rest) and acceptable for
  a loopback tool. Eviction is lazy (on lookup) bounded by the absolute timeout;
  a periodic sweeper is a possible future nicety.
- **`Secure` cookie flag** is set only under TLS. The GUI is loopback HTTP, so
  the flag is off there; `HttpOnly` + `SameSite=Strict` + the origin guard still
  apply. Front it with TLS to get `Secure`.
- **Rate limiting.** Per-account lockout + PBKDF2 cost bound online brute force.
  A process-wide pre-auth throttle (concurrency semaphore + token bucket) now
  also caps the CPU an unauthenticated caller can spend on `login`/`setup`
  hashing — see **F-18 / §9** (closed the pre-auth CPU-DoS this note previously
  deferred).
- **Enumeration.** Login timing is flattened with a dummy-hash verification on
  unknown usernames; lockout messages are generic on the login path.

## 5. Re-verification checklist (later phase, contained)

The audit's Part III proved several items with live PoCs on loopback. Re-run and
extend after fixes land:

- Transport guard battery: `Host` spoof → `421`; foreign `Host`/`Origin` →
  `421/403`; cross-origin/`text/plain` POST → `403`; legit same-origin `200`.
- SSRF: loopback mock `robots.txt`/`swagger` pointing off-host → confirm the
  off-host canary is **not** hit (C-1 holds); with `-block-private-egress` on,
  private-IP dials refused (C-2).
- Injection: hostile `<input name>` with raw ANSI → confirm scrubbed in logs
  after the `C-4` fix; XSS payload stays inert (JSON `nosniff` + `esc()`).
- DNS parsers: re-run fuzzing (`readDNSName`, `extractDNSNames`, `parseAnswer`),
  target 0 panics; watch the slow-input windows that corroborate `C-5`.
- Concurrency: `go test -race ./...` clean, including the new `webui/jobs_test.go`.
- Toolchain: `govulncheck ./...` clean after the `go` bump.

## 6. Notes

- This file is the canonical tracker going forward. The exhaustive original
  narrative (evidence, PoC transcripts) remains in the `Projects` copy's
  `AUDIT.md` if deeper detail is needed.
- Sections 1-6 were originally a static reconciliation. Section 7 records the
  first pass in which fixes were actually applied to the tree (statuses above
  updated accordingly).

## 7. Hardening pass — 2026-08-27

Applied (statuses updated in the tables above):

- **F-4** — server timeouts via `newHTTPServer` (`ReadHeaderTimeout` 10s,
  `ReadTimeout` 15s, `IdleTimeout` 120s; no `WriteTimeout`, so the SSE stream is
  not severed mid-scan).
- **C-3** — `core.NewVerifiedHTTPClient` (TLS verification on + `MinVersion`
  TLS1.2) now serves the trusted fixed-host intel calls in `passive.go`,
  `asn.go` and the Wayback fetcher in `discovery.go`; traffic to the scan target
  still honours `-skip-tls-verify`. Trade-off: OSINT behind a MITM proxy fails.
- **F-16** — per-user scan/report isolation: `Job.Owner`, a `<base>.meta.json`
  ownership sidecar (so ownership survives a server restart) and `canAccessScan`
  applied to list/get/log/report/events/cancel. Admin sees all; a report without
  a sidecar is admin-only; open (no-account) mode remains a shared console.
- **F-8** — `results/` and `wordlists/` created `0700` (+`Chmod`).
- **F-11 (partial)** — CSP gained `base-uri 'none'; object-src 'none';
  form-action 'self'; frame-ancestors 'none'`.
- **F-6** — generic `500` on scan-submit failures (the real error is logged
  server-side); the wordlist error no longer leaks the absolute base path;
  report enumeration is closed by F-16.

Tests added: `internal/core/client_test.go`
(`TestNewVerifiedHTTPClientAlwaysVerifies` — verified client rejects an
untrusted cert even with `SkipSSLCheck=true`); `webui/server_test.go`
(`TestNewHTTPServerTimeouts` + extended CSP assertions);
`webui/isolation_test.go` (`TestPerUserScanIsolation`).

Consciously deferred / accepted (loopback threat model, single trusted operator):

- **C-2** — the private/link-local/metadata egress guard stays opt-in
  (`-block-private-egress`) so intended internal/CTF targets keep working. Enable
  it on cloud VMs (blocks the IMDS `169.254.169.254` SSRF path).
- **Subprocess argv exposure** — target / user-agent / wordlist path are passed
  as argv to the CLI subprocess and are visible to other local users via `ps`.
  Acceptable on a single-operator loopback host; do **not** add secret-bearing
  flags (e.g. `-H Authorization: …`) to the GUI without redesigning this.
- **F-9 / F-10 / C-4** — unbounded in-memory job map, `appendLog` disk I/O under
  the job mutex, and un-scrubbed slice-typed log args. Low impact on loopback;
  revisit if the GUI is ever fronted beyond `127.0.0.1`.
- **Info** — `W1R3HOUND_ADMIN_PASS` via env (process-env exposure; convenience
  for headless bootstrap), lazy session eviction (bounded by the absolute
  timeout), and toolchain currency (track via `govulncheck`).

## 8. QA rounds 13–18 — 2026-08-27

Verification + parity work (no new open items; audit tooling clean):

- **Audit sweep.** `govulncheck ./...` → **no vulnerabilities**; `gosec ./...`
  → 49 findings, all **G104** (unhandled `resp.Body.Close()` / `SetDeadline`) —
  the previously-accepted low-severity G-items, unchanged.
- **Parity `-header/-H` injection sink — closed with the parity work (§4).**
  `validateHeaders` (`webui/validate.go`) enforces the RFC-token name (<=128),
  no CR/LF/NUL, value <=1024, and <=32 headers; the HTTP handler returns `400`
  on a CRLF payload. Pinned by `webui/parity_test.go` +
  `TestHandleStartScan/CRLF header injection -> 400`.
- **Parity path inputs.** `-dir-wordlist` and `-resolvers` reuse
  `resolveWordlist` (EvalSymlinks + prefix + regular-file), so they cannot
  escape `webui/wordlists/`; `-resolver` is IP/`ip:port` only (no hostname
  lookup). Traversal/symlink/absolute cases are pinned in `parity_test.go`.
- **Parity security levers surfaced.** The GUI can now re-enable TLS
  verification (`skip_tls_verify:false` → `-skip-tls-verify=false`, helps
  `C-3`/`F-15`) and enable the egress guard (`-block-private-egress`, `C-2`).
- **Authz battery extended** (`webui/authz_battery_test.go`): session **idle**
  timeout eviction (complements the absolute-timeout test), `W1R3HOUND_AUTH=required`
  gating the API before first admin (hard `F-3b`), and immediate session
  revocation when an account is deleted.
- **E2E hygiene.** Removed a real external-target scan artifact (`loot.{json,md}`
  for `kolbi.cr`) from `webui/e2e/`; the smoke now runs a **hermetic open-mode**
  server (`serve-hermetic.sh`) so it never touches the real `webui/auth` and
  never targets anything off loopback.

- **C-4 was already fixed in code but untested** (`scrubArgs` scrubs
  slice-typed log args); this round adds the regression test
  (`internal/core/scrub_test.go`) and corrects the tracker row above.

Still consciously deferred / accepted (unchanged; loopback threat model):
`C-7`/`C-8` (Unicode-bidi/control scrub in `Finding.Data` at store time — the
report *output* is already neutralised by `mdInline`/`esc()`), `C-13`
(`endpointprobe` naive `target+path` join; report-only, self-limiting since a
malformed absolute path yields an unreachable host), `F-9`/`F-10`.

## 9. Dynamic red-team hardening — 2026-08-27

A live red-team pass against a running instance (nyxstrike: whatweb / wafw00f /
nuclei / nikto / ffuf; Burp: raw HTTP request crafting) plus a re-review. The
scanners surfaced **no exploitable issues** — nuclei (3,525 templates, 7,447
requests) and nikto reported only *info*-level "missing security header" items,
and the transport guard, auth gate, CSRF, RBAC, per-user isolation and lockout
all held under active probing (Host spoof / absolute-URI Host confusion → `421`,
cross-origin → `403`). The pass did close two logic gaps that scanners cannot
find, plus the residual header flags.

Applied:

- **F-17 — forced password change enforced server-side.** `authGate`
  ([webui/auth.go](../webui/auth.go)) now confines an account whose session
  carries `MustChange` to `/api/auth/me`, `/api/auth/change-password` and
  `/api/auth/logout`; every other `/api` route returns `403` until the
  admin-provisioned initial password is rotated. Previously the "change on first
  sign-in" rule was enforced only by the SPA and was bypassable by calling the
  API directly (a provisioned user could scan/list without ever rotating).
  `Session.MustChange` is snapshotted in `createSession`. Tested by
  `TestMustChangeEnforcedServerSide` ([webui/hardening_test.go](../webui/hardening_test.go)).
- **F-18 — pre-auth PBKDF2 CPU-DoS guard.** `/api/auth/login` and
  `/api/auth/setup` run a full 600k-iteration hash on every attempt — even for
  unknown users, to keep login constant-time — so an unauthenticated loopback
  flood could pin every core (measured ~200x amplification; 40 concurrent
  requests saturated 4 cores, ~5 s CPU). A process-wide `loginLimiter`
  ([webui/auth.go](../webui/auth.go)) now bounds that work: a concurrency
  semaphore (2) plus a token bucket (burst 12, refill 6/s); over-rate requests
  are shed with `429` before any hashing. Measured after the fix: 40 concurrent
  attempts → 12 processed + 28 `429`, server CPU ≈ 0. This implements the global
  limiter previously deferred in §4a. Tested by `TestLoginRateLimited` +
  `TestLoginLimiterMechanics`.
- **F-11 (headers) — residual scanner flags closed.** `securityHeaders`
  ([webui/main.go](../webui/main.go)) now also sets
  `Cross-Origin-Opener-Policy: same-origin`, `Cross-Origin-Resource-Policy:
  same-origin`, `Cross-Origin-Embedder-Policy: require-corp` and a restrictive
  `Permissions-Policy`. Safe because the console is single-origin with no
  cross-origin subresources (CSP `default-src 'self'`, no CDNs/fonts); verified
  live that all static assets still load with `CORP` under `COEP`.

Verification (all green): `go vet`, `gofmt`, `staticcheck` (0 — also removed a
dead test helper, `U1000`), `govulncheck` (0), `gosec` (49 — unchanged accepted
G-items), `go test -race ./...` (pass, incl. the three new tests).

Still deferred / accepted (loopback threat model): the `Secure` cookie flag
(loopback HTTP), `W1R3HOUND_ADMIN_PASS` env bootstrap, the first-run
`/api/auth/setup` race on multi-user hosts (mitigate with
`W1R3HOUND_AUTH=required` + env bootstrap at deploy), and the private-egress
SSRF guard staying opt-in (`-block-private-egress`; enable on cloud VMs).
