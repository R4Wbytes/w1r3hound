# CLI ↔ Web GUI Capability Parity

Goal: **the web GUI must offer the same capabilities as the CLI, not fewer.**

> **Status: IMPLEMENTED (QA Round 14, 2026-08-27).** All 10 previously-missing
> options are now exposed in the New-scan modal's **Advanced options** section
> and validated in `buildArgs` (`webui/validate.go`). The parity contract is
> pinned by `webui/parity_test.go` (argv-exact table, header-injection
> rejection, path confinement, resolver IP-only, numeric bounds, TLS-pointer
> semantics) and by the Playwright smoke (`webui/e2e/tests/smoke.spec.ts`).
> The sections below are retained as the design record.

Source of truth:
- CLI flags: [main.go](../main.go) lines 206-235.
- Engine config: `core.Config` in [internal/core/core.go](../internal/core/core.go) lines 27-64.
- GUI request + arg builder: `ScanRequest` and `buildArgs` in
  [webui/validate.go](../webui/validate.go) lines 67-80 and 249-327.
- GUI form: the New Scan modal in [webui/static/js/app.js](../webui/static/js/app.js)
  (`openScanModal`) and the request body assembled in `launchScan`.

## 1. Flag matrix

| CLI flag | Config field | In GUI today? | Notes |
|----------|--------------|---------------|-------|
| `-t/-target` | `Target` | Yes | validated allow-list (host/IP/CIDR/URL) |
| `-m/-protocols` | `Modules` | Yes | module catalog, all/none/passive presets |
| `-c/-concurrency` | `Concurrency` | Yes | 1-500 |
| `-p/-ports` | `Ports` | Yes | top100 / 1-1024 / full |
| `-w/-wordlist` | `Wordlist` | Yes | confined to `webui/wordlists/` |
| `-passive` | `Passive` | Yes | GUI defaults ON (safety) |
| `-rate` | `RateLimit` | Yes | 0-10000 |
| `-timeout` | `Timeout` | Yes | sent as `Ns`, 1-300 |
| `-ua` | `UserAgent` | Yes | CRLF/length checked |
| `-o/-output` | `OutputFile` | Yes | name allow-list, `..` rejected |
| `-v/-verbose` | `Verbose` | Yes | |
| (authorized gate) | — | Yes | required `authorized:true` |
| **`-dir-wordlist`** | `DirWordlist` | **Yes (R14)** | directory brute-force list (confined to `webui/wordlists/`) |
| **`-dir-ext`** | `DirExtensions` | **Yes (R14)** | appended extensions csv (charset-restricted) |
| **`-header/-H`** | `RequestHeaders` | **Yes (R14)** | repeatable custom headers (CRLF/charset/count-checked) |
| **`-skip-tls-verify`** | `SkipSSLCheck` | **Yes (R14)** | `*bool`; GUI can now re-enable verify (`=false`) |
| **`-block-private-egress`** | `BlockPrivateEgress` | **Yes (R14)** | opt-in SSRF egress guard |
| **`-resolver`** | `Resolver` | **Yes (R14)** | single custom DNS resolver (IP/ip:port only) |
| **`-resolvers`** | `Resolvers` | **Yes (R14)** | resolver-pool file (confined to `webui/wordlists/`) |
| **`-wayback-limit`** | `WaybackLimit` | **Yes (R14)** | wayback CDX cap (0..100000) |
| **`-crawl-pages`** | `CrawlMaxPages` | **Yes (R14)** | crawler page cap (0..5000) |
| **`-js-files`** | `MaxJSFiles` | **Yes (R14)** | JS analysis cap (0..2000) |

**All 10 options are now exposed** (Round 14; the "No" rows above were the gap
before it landed — see the status banner). Two of them (`-skip-tls-verify`,
`-block-private-egress`) are also security levers the audit flagged as
unavailable from the GUI, so exposing them is both a parity fix and a security
improvement. Implementation notes vs. the original design: `-resolvers` is
confined to the existing `webui/wordlists/` dir (reusing `resolveWordlist`)
rather than a new `webui/resolvers/` dir.

## 2. Per-option design (how to expose each safely)

For each: the `ScanRequest` JSON field to add, the `buildArgs` emission, the
validation rule, and the modal control. Recall the decoder uses
`DisallowUnknownFields` ([webui/main.go](../webui/main.go) ~189), so the struct
must be extended before the frontend can send these.

### 2.1 `-dir-wordlist` (path)
- Field: `dir_wordlist string`.
- Validation: reuse `resolveWordlist(wordlistsDir, raw)` — confine to
  `webui/wordlists/` (EvalSymlinks + prefix + regular-file check).
- Emit: `-dir-wordlist <resolved>` when non-empty.
- UI: text input in an "Advanced" section; hint "must live in webui/wordlists/".

### 2.2 `-dir-ext` (csv)
- Field: `dir_ext string`.
- Validation: allow only a short token set, e.g. matches
  `^(\.[A-Za-z0-9~]{1,10})(,\.[A-Za-z0-9~]{1,10})*$` or a conservative charset
  `[A-Za-z0-9.,~_-]`, reject CR/LF/space/control, cap length (e.g. 256).
- Emit: `-dir-ext <value>` when non-empty.
- UI: text input, placeholder `.bak,.php,.zip,~`.

### 2.3 `-header/-H` (repeatable)
- Field: `headers []string` (each `"Name: value"`).
- Validation (critical — this is a header-injection sink): each entry must
  match `^[A-Za-z0-9-]+:[ ]?.+$`, contain no CR/LF/NUL, name length <=128,
  value length <=1024, and cap the list (e.g. <=32). Reject anything else.
- Emit: one `-H <entry>` per validated header.
- UI: a small repeater (add/remove rows) or a textarea (one header per line);
  parse lines, trim, drop empties.

### 2.4 `-skip-tls-verify` (bool, default true)
- Field: `skip_tls_verify *bool` (pointer to distinguish "unset" from false),
  default true to match the CLI.
- Emit: because the CLI default is true, emit `-skip-tls-verify=false` when the
  user opts into verification; omit otherwise (or always emit explicit value).
- UI: toggle labelled "Verify TLS certificate" (checked = verification on =
  `skip_tls_verify:false`). Default unchecked to mirror CLI behavior.
- Benefit: closes audit `F-15`/`C-3` (GUI could not previously re-enable TLS
  verification, e.g. for OSINT endpoints).

### 2.5 `-block-private-egress` (bool, default false)
- Field: `block_private_egress bool`.
- Emit: `-block-private-egress` when true.
- UI: toggle "Block private/internal egress (SSRF guard)"; default off to keep
  internal/CTF scans working (mirrors CLI). Add a short note that enabling it
  refuses dials to loopback/private/link-local IPs.
- Benefit: surfaces the audit `C-2` remediation in the GUI.

### 2.6 `-resolver` (single ip[:port])
- Field: `resolver string`.
- Validation: must be a bare IP or `ip:port` (reject hostnames to avoid a DNS
  lookup for the resolver itself); reuse/adapt `validHostPort` restricted to
  `net.ParseIP`.
- Emit: `-resolver <value>` when non-empty.
- UI: text input, placeholder `1.1.1.1` or `8.8.8.8:53`.

### 2.7 `-resolvers` (path to list)
- Field: `resolvers string` (path).
- Validation: confine to a dedicated dir (e.g. `webui/wordlists/` or a new
  `webui/resolvers/`) with the same EvalSymlinks + prefix + regular-file check
  as `resolveWordlist`. Never accept an arbitrary absolute path.
- Emit: `-resolvers <resolved>` when non-empty.
- UI: text input with the confinement hint.

### 2.8 Tuning ints: `-wayback-limit`, `-crawl-pages`, `-js-files`
- Fields: `wayback_limit int`, `crawl_pages int`, `js_files int`.
- Validation: numeric bounds, e.g. `wayback_limit 0..100000`,
  `crawl_pages 1..5000`, `js_files 1..2000`; `0`/empty means "omit, use engine
  default".
- Emit: `-wayback-limit N` / `-crawl-pages N` / `-js-files N` when > 0.
- UI: number inputs under "Advanced", pre-filled with the engine defaults shown
  as placeholders.

## 3. Files to change (implementation checklist, later phase)

1. [webui/validate.go](../webui/validate.go)
   - Extend `ScanRequest` (lines 67-80) with the 10 fields above.
   - Add validators: `resolveWordlist`-style confinement for `dir_wordlist` and
     `resolvers`; header allow-list; `dir_ext` charset; resolver IP check;
     numeric bounds. Add a helper `resolveResolvers` if using a separate dir.
   - Extend `buildArgs` (lines 249-327) to emit the new flags in a stable order.
2. [webui/main.go](../webui/main.go)
   - No route changes; `DisallowUnknownFields` now accepts the new fields once
     the struct is extended. Ensure the request `io.LimitReader` (64 KB) still
     comfortably fits headers lists.
   - If a `webui/resolvers/` dir is introduced, create it in `NewManager`
     alongside `results/` and `wordlists/`.
3. [webui/static/js/app.js](../webui/static/js/app.js)
   - Add an "Advanced options" collapsible to `openScanModal` with the new
     controls; include them in the `launchScan` request body.
   - Mirror CLI defaults in the control initial state.
4. [webui/static/css/styles.css](../webui/static/css/styles.css)
   - Minor styles for the header repeater / advanced section (reuse existing
     `.form-*` classes where possible).

## 4. Acceptance criteria (parity "done")

- Every CLI flag in the matrix has a GUI control (or an intentional, documented
  exception — none currently planned).
- For each new field, a `buildArgs` table test asserts the exact argv produced
  and that invalid input is rejected with `400` (see [TEST_PLAN.md](TEST_PLAN.md)).
- Path fields (`dir_wordlist`, `resolvers`) cannot escape their confinement dir
  (traversal + symlink tests).
- Header entries with CR/LF are rejected (injection test).
- A manual end-to-end run confirms a GUI scan using the new options produces the
  same report as the equivalent CLI invocation.

## 5. Non-goals / intentional divergences

- The GUI keeps `-passive` **on by default** for safety even though the CLI
  default is off; the capability (toggle) is present, so this is a default
  choice, not a capability gap.
- `-header` secrets (e.g. `Authorization`) are entered per-scan and not
  persisted; they are passed to the subprocess argv only. (Note: argv is
  visible in process listings on the host — call this out in the UI hint.)
