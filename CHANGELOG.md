# CHANGELOG

All notable changes to **w1r3hound** are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/), and this
project adheres to [Semantic Versioning](https://semver.org/) where
applicable.

## [2.0.0] — 2026-08-30

Major release: localhost-only Web GUI dashboard.

### Added
- Web GUI: dark card-based SPA at `127.0.0.1:8737` with sidebar navigation
- Login panel with PBKDF2-HMAC-SHA256 (600k iterations), session management, RBAC, account lockout
- Scan queue with 2-worker pool and Server-Sent Events live output streaming
- Full CLI-GUI parity: all CLI flags exposed through the web interface
- Six dashboard pages: Overview, Scans, Findings, Console, Account, Settings
- Severity donut chart, findings table with CSV export, real-time console terminal
- Playwright end-to-end smoke tests for the web console
- GitHub Actions CI pipeline (vet, gofmt, test-race, CSP, golden, fuzz, smoke)
- Makefile with 16 targets (build, test, lint, security, CI)
- Build-time version injection via `-ldflags`
- CONTRIBUTING.md, SECURITY.md, and GUI screenshots in README

### Security
- Origin/Referer guard on all mutating endpoints (DNS rebinding defense)
- Strict Content Security Policy with nonce enforcement
- CSRF token validation on state-changing requests
- COOP/CORP/COEP headers
- Module catalog validation for GUI scan requests

## [1.0.6] — 2026-08-11

Eight false-positive fixes validated against three Anthropic HackerOne
bug bounty targets (`docs.anthropic.com`, `console.anthropic.com`, and
`claude.ai`), comparing W1r3Hound output against manual Kali Linux tool
verification.

### False-Positive Fixes

- **Stripe publishable keys / Google OAuth IDs flagged as HIGH secrets**
  (`content.go`): `pk_live_*` Stripe publishable keys and Google OAuth
  Client IDs are designed for client-side use and are NOT secrets. They
  are now separated from real secrets into an INFO-level "Public
  client-side credentials" finding. The HIGH-severity "Potential
  secrets/API keys found" finding now only fires for actual secret
  material (sk_live, AWS keys, private keys, etc.).

- **Cloud bucket generic name detection incomplete** (`discovery.go`,
  `looksGenericBucketName`): when the base name (e.g. `docs`, `console`)
  is in the generic set, all its permutations (`docs-dev`,
  `console-prod`, etc.) are now also marked generic. Previously only
  exact matches were checked, so `docs-api`, `docs-images`,
  `console-dev`, `console-prod` etc. — all belonging to unrelated third
  parties — were counted as HIGH-severity public buckets.

- **`console` added to generic bucket names** (`discovery.go`): the name
  `console` is as generic as `app`, `api`, `docs` — verified that
  `console-dev` GCS contains Google AdMob/DSP data, not target data.

- **SaaS module uses subdomain instead of organisation name**
  (`saas.go`): `orgName` was derived from `strings.Split(cfg.Domain,
  ".")[0]`, giving `docs` for `docs.anthropic.com`. Now uses
  `extractApexDomain` to get the apex, then takes the first label
  (`anthropic`). This eliminated 8 false positives (e.g.
  `docs.zoom.us`) and found 9 correct matches (e.g.
  `anthropic.zendesk.com`, `anthropic.okta.com`).

- **Internal IP detection flags documentation example IPs**
  (`content.go`): common RFC 1918 addresses used in documentation
  (192.168.1.0, 192.168.1.1, 10.0.0.1, etc.) are now filtered via
  `isDocumentationIP`. On `docs.anthropic.com`, this eliminated a false
  `192.168.1.0` "leak" that was actually documentation content.

- **API docs false positive on cross-domain redirects** (`api.go`):
  `/docs` on `console.anthropic.com` redirects to
  `platform.claude.com/docs` (the public product docs). The apiscan
  module now tracks the final URL after redirects and skips findings
  where the response came from a different domain (using apex-aware
  comparison). Additionally, the `api-docs` type validation was
  tightened: it no longer matches on `"api documentation"` alone (which
  matched any docs site), now requiring OpenAPI/Swagger spec markers.

- **Sensitive path detection on SPA/catch-all sites** (`metafiles.go`,
  `helpers.go`): PingFederate, WordPress, Azure App Service paths were
  flagged as accessible (MEDIUM/LOW) on `claude.ai` even though the
  server returns its SPA shell for every path. The metadata module now
  runs catch-all calibration before probing sensitive paths — if the
  server serves a catch-all response, probes that match its signature
  are skipped. Additionally, a new `isCloudflareChallenge()` helper
  detects Cloudflare JS challenge pages and prevents them from being
  misinterpreted as real content. Response body markers per endpoint type
  (e.g. "XML-RPC" for xmlrpc.php) add a third layer of validation.
  Eliminated 8 false positives on `claude.ai`.

- **Public cloud bucket ownership validation** (`discovery.go`): when a
  public (listable) bucket is found and its name is not in the generic
  set, the module now inspects the first 20 object keys in the XML
  listing. If none reference the target domain or organisation, the
  bucket is marked as unrelated (demoted from HIGH). On `claude.ai`,
  this correctly identified the GCS `claude` bucket (Gandhi PDFs from
  2016) and the S3 `claude-test` bucket (baisonNavCoreData from 2018)
  as belonging to unrelated parties sharing the common first name.

### Compatibility

- All 4 packages pass `go test -race -count=1`; `gofmt -l .` and
  `go vet ./...` clean.
- No CLI flag changes; no API breakage; no report-schema changes.
- Live-verified against three Anthropic HackerOne authorized targets.

### Validation

| Target | HIGH before | HIGH after | MEDIUM before | MEDIUM after | Total before | Total after |
|---|---|---|---|---|---|---|
| docs.anthropic.com | 2 | 0 | 0 | 0 | 26 | 24 |
| console.anthropic.com | 1 | 0 | 1 | 1 | 27 | 25 |
| claude.ai | 1 | 0 | 5 | 1 | 32 | 22 |

## [1.0.5] — 2026-08-11

Four rounds of fixes driven by two external audits
(`AUDIT_w1r3hound_DNS.md` — DNS resolver/AXFR/wildcard/takeover focus, and
`AUDIT_w1r3hound.md` — full-framework review against the
subfinder/httpx/dnsx/naabu/nuclei/massdns/reconftw baseline), triaged and
verified against the code before implementing.

### DNS Resolver Correctness & Security (from the DNS audit)

- **IPv6 custom resolver broken** (`internal/core/core.go`, `NewResolver`):
  `-resolver 2001:4860:4860::8888` silently failed every lookup — the
  "does it contain `:`" heuristic used to decide whether a port was already
  present misfired on bare IPv6 literals. Now uses `net.SplitHostPort`,
  which also brackets IPv6 correctly.
- **`-timeout`/SIGINT not respected by DNS lookups**: NS/MX/TXT/DMARC/SRV/
  CNAME/wildcard/brute lookups across `dns.go`, `dnsextra.go`, `takeover.go`,
  `asn.go`, `portscan.go`, and `saas.go` used `context.Background()`, so
  `-timeout` had no effect and Ctrl+C couldn't interrupt an in-flight
  lookup. All 13 call sites now derive from `cfg.Context(cfg.Timeout)`.
- **IP targets treated as broken domains** (`dns.go`, `RunDNS`): `-t
  10.10.10.10` was normalised to the nonsense apex `"10.10"` and every NS/
  MX/TXT/brute query ran against it. Now skipped with an explanatory log
  when the target is a bare IP.
- **Fixed DNS transaction ID** (`dnsextra.go`, `buildDNSQuery`): the AXFR
  query used a hardcoded `0x1337` ID. Now `crypto/rand`-generated —
  closes a spoofing/cache-poisoning weakness ahead of the raw-UDP engine
  below, which reuses this query builder.
- **Wildcard detection: single, hardcoded probe** (`dns.go`): despite the
  variable name, the "random" wildcard-probe label was a fixed string, and
  only one probe was fired — a round-robin wildcard pool could evade
  detection, and a target could special-case the fixed label. Replaced
  `detectWildcard`/`getWildcardIPs` with `wildcardSet`: 4 real
  `crypto/rand` probes, IPs unioned. Also removed a redundant double-probe
  in `RunPermute`.

### Directory Bruteforce & Apex Normalisation (quick wins)

- **`-dir-wordlist` / `-dir-ext`** (`discovery.go`, `main.go`): directory
  bruteforce previously ignored `-w` entirely and always used the embedded
  162-path list. Now accepts its own wordlist and extension-fuzzing list
  (`.bak,.php,.zip,~`-style, ffuf/feroxbuster-style), reusing the same
  wordlist loader as subdomain brute-force.
- **Real Mozilla Public Suffix List** (`internal/modules/psl.go`,
  `internal/modules/data/public_suffix_list.dat`, embedded via `go:embed`):
  replaces a ~50-entry curated `compoundTLDs` map. Fixes apex normalisation
  for any compound TLD not in that curated set (`.edu.co`, `.gov.br`,
  `.ac.nz`, `.gov.cn`, …), which previously mis-split the apex and threw off
  DNS infrastructure queries and DMARC/SPF inheritance for those targets.
- **HTTP/2** (`core.go`, `NewHTTPClient`): the hand-built `http.Transport`
  never negotiated h2 (`ForceAttemptHTTP2` unset). Now enabled.

### Portscan, Wildcard Amplification & Passive Coverage

- **Portscan: single IP, passive-only banner grab, no retry**
  (`portscan.go`): now scans up to 3 resolved IPs (deduped, IPv4
  preferred) instead of only `ips[0]`; sends an active `HEAD` probe on
  classified web ports and a generic `\r\n` on others when the passive read
  comes back empty (HTTP/TLS ports never speak first); retries once on a
  connection *timeout* (not on a definitive "connection refused").
- **Certspotter** added as a 6th passive subdomain source (`passive.go`),
  same keyless/coverage-tracked pattern as the existing 5.

### Raw-UDP DNS Brute-Force Engine (opt-in)

- **`-resolvers <file>`** (`main.go`, new `internal/modules/dnsengine.go`):
  subdomain brute-force and permutation can now resolve through a
  rotating pool of resolvers over raw UDP instead of the stdlib
  `net.Resolver`, with retry-on-a-different-resolver and the shared
  `RateLimiter` finally governing DNS query rate (`-rate` previously only
  applied to HTTP). Ships with a from-scratch, bounds-checked DNS message
  parser (A/AAAA/CNAME) that validates the response's transaction ID and
  echoed question name before accepting it. **Opt-in only** — without
  `-resolvers`, behaviour is byte-for-byte the same as before (system/
  `-resolver` resolver, unchanged code path).

### Compatibility

- All packages pass `go test -race -count=1`; `gofmt -l .` and
  `go vet ./...` clean.
- No behaviour change for any existing flag; every fix above is either a
  correctness fix on the existing default path or gated behind a new,
  opt-in flag (`-dir-wordlist`, `-dir-ext`, `-resolvers`).
- Live-verified against real, authorized targets (not just unit tests):
  `scanme.nmap.org` (portscan multi-IP + active banner probing) and
  `hackerone.com` (passive sources incl. certspotter; DNS brute-force
  producing identical subdomain/IP results with and without `-resolvers`).

## [1.0.4] — 2026-08-11

### False-Negative Fixes (validated against an authorized
### CDN-fronted Drupal + Pantheon target)

- **Subdomain target apex normalisation** (`internal/modules/dns.go`,
  `extractApexDomain`; `internal/modules/passive.go`): when the operator runs
  `-t www.<apex>` (a very common pattern when copy-pasting the URL from a
  browser address bar), the DNS module now normalises the target to its apex
  (eTLD+1) before issuing NS, MX, TXT, and subdomain brute-force queries.
  Previously every DNS infrastructure query was issued against the subdomain
  itself, which has no NS/MX records and either returns no SPF or returns a
  misleading hard-fail SPF (e.g. `v=spf1 -all` on `www`) that hides the
  apex's real policy with `include:` statements. The passive source filter
  (`add` in passive.go) was affected because it filtered results against the
  subdomain (`endsWith(".www.<apex>")` discards real subdomains of the apex),
  producing "1 unique subdomain" when the apex had 10+. Verified against the
  CDN-fronted target: passive subdomains 1 → 21; NS 0 → 2; MX 0 → 5; SPF
  changed from a misleading `v=spf1 -all` to the apex's real policy with
  6 `include:` statements. The operator-facing log emits
  `▸ Target "www.<apex>" is a subdomain — normalising DNS queries to apex "<apex>"`
  so the auto-normalisation is never silent.

### Compatibility

- All 4 packages pass `go test -race -count=1`.
- `gofmt -l .` and `go vet ./...` clean.
- No CLI flag changes; no API breakage; no report-schema changes
- `extractApexDomain` is an internal helper — not exported, so it does not
  affect downstream consumers.

## [1.0.3] — 2026-08-11

### False-Positive Fixes (validated against 3 authorized targets spanning
### two tech stacks: a Wix-hosted SPA and 2 Apache/PHP sites)

- **Cloud bucket false ownership** (`internal/modules/discovery.go`,
  `RunCloudStorage`): buckets responding HTTP 200 with generic names
  like `www`, `www-staging`, `www-cdn`, `www-test`, `www-images`, etc.
  are now flagged as `Generic=true` and excluded from the HIGH-severity
  "Public cloud storage buckets found" finding. Previously any 200
  response from `storage.googleapis.com/<name>`,
  `<name>.digitaloceanspaces.com`, or `<name>.s3.amazonaws.com` was
  treated as a target-owned public bucket — producing 9 false positives
  per target on shared-name buckets that belong to other parties
  (verified: `storage.googleapis.com/www-staging` is owned by Google
  project 868530998679, not the scan target).

- **Source map detection without HTTP verification** (`internal/modules/content.go`,
  `RunContent` section 5): inline `//# sourceMappingURL=` references in JS
  files are now fetched and validated (`status == 200` + `looksLikeSourceMap`)
  before being added to the findings. Previously the URL was added on
  reference alone, producing MEDIUM false positives when CMS themes
  ship the comment but not the `.map` file. Verified: 3 false positives
  in the Apache/PHP targets (all return 404), 1 in the Wix-hosted target.

### False-Negative Fixes

- **Wayback Machine zero results for CDN-hosted targets**
  (`internal/modules/discovery.go`, `RunWayback`): if the initial
  wildcard-subdomain CDX query
  (`url=*.{domain}/*`) returns zero rows, the tool now falls back to
  a domain-scope query (`matchType=domain`) before giving up.
  Previously CDN-hosted targets (Wix, Cloudflare, Azure) reported
  "Wayback Machine: 0 URLs" even when the CDX API had thousands of
  historical snapshots of the apex domain. Verified: the Wix-hosted
  target went from 0 → 10,782 URLs; the largest Apache/PHP target
  from 5,000 → 100,001 URLs.

- **DNS module silent failures** (`internal/modules/dns.go`, `RunDNS`):
  the resolver errors from `LookupNS`, `LookupMX`, and `LookupTXT`
  are now captured and logged via `log.Warn`. Previously the errors
  were discarded with `nss, _ := cfg.Resolver.LookupNS(...)`, making
  it impossible to distinguish "no records exist" from "the resolver
  is unreachable". The "DNS Enumeration: 0 NS, 0 MX" INFO finding
  itself is unchanged — but the operator can now see the root cause
  in the log (e.g. `⚠ NS lookup failed: lookup ... on 10.0.2.3:53: no such host`).

### Compatibility

- All 4 packages pass `go test -race -count=1`.
- `gofmt -l .` and `go vet ./...` clean.
- No CLI flag changes; no API breakage; no report-schema changes
  (new `Generic` field on `CloudBucket` is `omitempty`).

### Validation

Regression-tested against three authorized targets covering two tech
stacks (Wix-hosted SPA + Apache/PHP):

| Target type | HIGH before | HIGH after | Total findings |
|---|---|---|---|
| Apache/PHP (largest) | 1 | 0 | 24 → 21 |
| Wix-hosted SPA     | 1 | 0 | 24 → 23 |

## [1.0.2] — 2026-08-10

### Security / False Negative Fixes

- **CSP content analysis** (`headers.go`): the security headers check now
  parses CSP directives and flags `'unsafe-inline'`, `'unsafe-eval'`,
  wildcard `*` in script-src/default-src, missing `default-src`, and
  `data:` in script-src. Previously only checked for CSP presence.
- **SameSite=None without Secure** (`headers.go`): new finding for cookies
  with `SameSite=None` but no `Secure` flag (rejected by modern browsers).
- **HSTS max-age minimum** (`headers.go`): flags HSTS with `max-age` below
  31536000 (1 year), the HSTS preload requirement.
- **OIDC/OAuth dangerous grants** (`metafiles.go`): when `openid-configuration`
  or `oauth-authorization-server` is found, parses the JSON and flags
  `password` and `implicit` grant types as dangerous.
- **Fingerprint-aware path probing** (`metafiles.go`): probes for PingFederate
  (`/pf/heartbeat.ping`, `/pf-ws/rest/sessionMgmt/`), WordPress
  (`/wp-json/`, `/wp-signup.php`, `/wp-admin/maint/repair.php`), and Azure
  (`/.auth/me`, `/.auth/login/aad`) endpoints.

### Bug Fixes

- **DMARC apex lookup for compound TLDs** (`dns.go`): `lookupApexDMARC` now
  iterates progressively shorter domain suffixes to handle compound TLDs
  like `.co.uk` and `.com.br`. Previously only stripped one label.
- **Crawler parallelised** (`crawler.go`): the sequential BFS crawler is now
  a concurrent worker pool with semaphore, reducing worst-case time from
  ~17 minutes to ~2 minutes for 100 pages.
- **DNS compression pointer advancement** (`dnsextra.go`): `readName` now
  correctly tracks the position after the first compression pointer,
  preventing re-parsing and duplicate name extraction.
- **Zone transfer size limit** (`dnsextra.go`): AXFR read loop now caps
  total data at 10 MB to prevent memory exhaustion from malicious NS.
- **DNS label length validation** (`dnsextra.go`): labels exceeding 63
  bytes are truncated in `buildDNSQuery` instead of silently wrapping.

### False Positive Reduction

- **Twilio regex** (`content.go`): now requires assignment context
  (`twilio|account_sid|api_key` prefix) instead of matching bare `SK[hex]{32}`.
- **Mailgun regex** (`content.go`): now requires `mailgun|mg_api` context.
- **Bearer token regex** (`content.go`): now requires `authorization|auth|token`
  context and minimum 20-char token length.
- **Basic Auth regex** (`content.go`): now requires `authorization|auth` context.

### New Features

- **Wayback CDX pagination** (`discovery.go`): uses `resumeKey` to fetch
  up to 20 pages instead of truncating at the `limit` parameter. For large
  domains this increases coverage from ~5,000 to hundreds of thousands of URLs.
- **10 new takeover fingerprints** (`takeover.go`, `dns.go`): AWS Elastic
  Beanstalk, Azure CDN, Azure Front Door, Desk.com, Campaign Monitor,
  Intercom, Fly.io, SmartJobBoard, Strikingly, HatenaBlog. Total: 37 services.
- **Email extraction from JS** (`content.go`): emails are now extracted from
  JS file bodies in addition to the main page.
- **Envoy/Kubernetes header detection** (`headers.go`): detects
  `X-Envoy-Upstream-Service-Time`, `X-Envoy-Decorator-Operation`,
  and `X-Kubernetes-Pf-Flowschema-Uid`.
- **RDAP JSON parsing** (`crawler.go`): `RunWhois` now extracts registrar,
  registration/expiration dates, and nameservers from RDAP JSON responses
  instead of leaving the struct fields empty.
- **Markdown report includes Data** (`report.go`): findings with `[]string`
  or `map[string]string` data now render in the Markdown report (capped at
  20 items) instead of being JSON-only.

### Performance

- **Wildcard detection deduplication** (`dns.go`): `RunDNS` now calls
  `getWildcardIPs` once instead of calling `detectWildcard` and then
  `getWildcardIPs` separately (two identical DNS queries → one).
- **Persistent dedup maps** (`core.go`): `AddSharedSubdomains`,
  `AddSharedURLs`, and `AddSharedParams` now maintain persistent `seen`
  maps instead of rebuilding them on every call (O(1) vs O(n) per insert).
- **inspectTLS context-aware** (`webserver.go`): uses `cfg.Context()`
  instead of `context.Background()` so Ctrl+C interrupts TLS handshakes.

### Changed

- **Naming standardised**: all user-facing references now use lowercase
  `w1r3hound` consistently (CLI usage, output filenames, report headers,
  README, CHANGELOG). Internal probe path strings unchanged.

## [1.0.1] — 2026-08-07

### Security

- **TLS verification bypass fixed** (`internal/modules/webserver.go`):
  the `webserver` module hardcoded `InsecureSkipVerify: true` in two
  places, silently overriding the `-skip-tls-verify=false` flag. Users
  who explicitly opted into strict TLS verification got no enforcement.
  Now both `tls.Dial` calls (the malformed-request fingerprint path and
  the `inspectTLS` cert inspection path) honour `cfg.SkipSSLCheck`.
  The signature of `inspectTLS(hostAddr, timeout, log)` is now
  `inspectTLS(hostAddr, timeout, skipVerify, log)`; the caller passes
  `cfg.SkipSSLCheck` through.

### Performance

- **Context-aware dials** (`internal/core/core.go`,
  `internal/modules/portscan.go`, `internal/modules/dnsextra.go`,
  `internal/modules/webserver.go`): `net.DialTimeout` /
  `tls.DialWithDialer` calls outside the shared HTTP client have been
  migrated to `DialContext` so SIGINT tears down in-flight dials
  immediately instead of blocking for the full OS-level timeout.
  A new `Config.Context(timeout)` helper returns a child context
  derived from a root cancel context initialised in `DefaultConfig`;
  the SIGINT signal handler in `main` now calls `cfg.Cancel()` so all
  in-flight goroutines using the helper abort at once.

### Changed

- **Banner art** (`main.go`): the figlet wordmark has been replaced
  with a new skull-and-worm ASCII art piece. The subtitle line
  (`[ wiretap-grade offensive recon ] · w1r3hound v1.0 · OWASP WSTG · BBP · CTF`)
  is preserved verbatim below the art for brand continuity.

### Compatibility

- Public API: `internal/modules.realZoneTransfer` now takes an extra
  `*core.Config` argument. This is an internal helper, not part of
  the CLI surface. Call sites in `internal/modules/dns.go` updated.
- All 4 packages still pass `go test -race -count=1`. `go vet ./...`
  and `gofmt -l .` remain clean.

## [1.0] — 2026-08-07

### Initial release

**w1r3hound v1.0** is a single-binary offensive reconnaissance
framework for bug bounty hunting, penetration testing, and CTF
competitions. The name combines *wire* (wiretap, digital listening
post) + *hound* (tracker with predator instinct). It implements the
full OWASP WSTG v4.2 Information Gathering phase and extends it with
coverage gaps that most scanners miss.

### Fixed (pre-release audit)

- **Deadlock / crash on `-c 0` or negative `-c`.** Every concurrent
  module built its worker semaphore as `make(chan struct{}, cfg.Concurrency)`
  and did `sem <- struct{}{}` *before* spawning the releasing goroutine.
  With `-c 0` that channel is unbuffered, so the first send blocked forever
  (hang); with a negative `-c`, `make()` itself panicked. `-c` is now
  clamped to a sane range in `main.go` before any module runs.
- **Aggressive soft-404 path stripping.** `stripPathHash` and the baseline
  / `isSoft404` comparisons called `strings.ReplaceAll(body, path[1:], "")`
  (path without its leading `/`), which deleted *every* occurrence of a
  generic word (e.g. `api` for `/api`) across the whole body — silently
  filtering unrelated real pages as soft-404s (false negatives). Only the
  full requested path is stripped now.
- **Passive-source coverage lie.** When crt.sh / AlienVault / Anubis
  returned an HTTP 200 that failed to JSON-parse, the source was silently
  counted as *successful* in `sources_successful`, defeating the coverage
  reporting feature. Those parse failures now call `recordFailure` and are
  surfaced as a warning.
- **HTTP-method probing inflated by 3xx.** A 3xx redirect (issued for any
  method) was counted as the method being "accepted", inflating the allowed
  method list. Methods are now accepted only on 2xx.
- **`maskSecret` split multi-byte characters.** Prevention/suffix masking
  sliced the string by bytes, which could split a UTF-8 rune and emit
  invalid text into the JSON report. It now slices on runes.
- **`.gitignore` missed the lowercase binary.** `go build .` on Linux emits
  `w1r3hound` (lowercase); only the capitalised spellings were ignored, so
  the compiled binary would be committed. `/w1r3hound` added.
- **Consolidated v1.0 naming.** The `-protocols` help string, the usage
  example, and the console module headers retained pre-rebrand names
  (`profile,syscheck,deepscope`, NETSCANNER, TIMEWARP, SYSCHECK, …). They
  now use the canonical v1.0 names (fingerprinter, sentry, deepdive,
  probescan, archaeology, etc.). Legacy aliases still work.

### 19 modules across 5 categories

- **Passive OSINT** (3): `recon` (whois), `traceroute` (asnmap),
  `passivewatch` (passivesrc — 6 sources including crt.sh, CertSpotter,
  HackerTarget, AlienVault OTX, RapidDNS, Anubis).
- **DNS & Subdomains** (3): `fingerprinter` (dns enum, real AXFR, SRV,
  SPF/DMARC, takeover), `archaeology` (wayback URL harvesting),
  `diversify` (subfinder-style permutation with wildcard filtering).
- **Live Detection & Fingerprinting** (5): `heartbeat` (httprobe +
  favicon hash for Shodan pivoting), `probescan` (server fingerprint,
  TLS cert, HTTP methods), `metadata` (robots.txt, sitemap, security.txt,
  .well-known), `sentry` (security headers + tech fingerprinting),
  `deepdive` (HTML/JS analysis, secrets, source maps).
- **Attack Surface** (7): `portscan`, `corstrace` (CORS misconfig),
  `cloudsniff` (S3/Azure/GCS/Firebase/DO buckets), `bruteforce`
  (dir/file discovery with soft-404 filter), `apiscan` (GraphQL/Swagger/
  OpenAPI/REST/WS), `saasenum` (30+ third-party platforms),
  `crawler` (forms, params, entry points).
- **Deep Analysis** (2): `jsdeep` (LinkFinder-style endpoint
  extraction), `takeover` (HTTP-signature subdomain takeover across
  28 services).

### Highlights

- **Apex-aware findings** — subdomains inherit DMARC/SPF from the
  apex (RFC 7489 §6.3); no more "No DMARC" false positives on every
  subdomain of a domain with a strict apex policy.
- **Source coverage reporting** — every passive scan reports
  `sources_attempted` / `sources_failed` / `sources_successful` so
  coverage gaps are visible (no more silent failures hidden behind
  `log.Debug`).
- **i18n-aware secret scanner** — the `Hardcoded Password` regex no
  longer matches translation keys in minified JavaScript
  (`FORGOT_PASSWORD`, `INVALID_EMAIL_OR_PASS***ord`).
- **Cookie dedup + framework whitelist** — `wordpress_*`, `wp-*`,
  `__Secure-*`, `__Host-*`, etc. are deduplicated and not reported
  as "missing Secure" false positives.
- **Type-safe subdomain projection** — `DNSResult.SubdomainNames`
  exposes a flat `[]string` for consumers that don't want to dig
  into the `[]struct{Name,IPs,CNAMEs}` of `Subdomains`.
- **CDN/WAF awareness** — portscans correctly warn when the target
  resolves to a CDN edge (Fastly, Akamai, Cloudflare) and recommend
  resolving the origin IP first.
- **No external dependencies** — single binary, cross-platform,
  zero install beyond `go build`.

### Quick start

```bash
git clone https://github.com/w1r3hound/w1r3hound.git
cd w1r3hound
go build -o w1r3hound .
./w1r3hound -t example.com
```

### Origin

w1r3hound v1.0 is the consolidation of an internal offensive-recon
tool that was previously distributed under a different name. The
v1.0 release is a clean rebrand with no historical artifacts in
the version history.
