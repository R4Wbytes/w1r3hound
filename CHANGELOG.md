# CHANGELOG

All notable changes to **w1r3hound** are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/), and this
project adheres to [Semantic Versioning](https://semver.org/) where
applicable.

## [1.0.4] — 2026-08-11

### False-Negative Fixes (validated against hackerone.com)

- **Subdomain target apex normalisation** (`internal/modules/dns.go`,
  `extractApexDomain`; `internal/modules/passive.go`): when the operator runs
  `-t www.<apex>` (a very common pattern when copy-pasting the URL from a
  browser address bar), the DNS module now normalises the target to its apex
  (eTLD+1) before issuing NS, MX, TXT, and subdomain brute-force queries.
  Previously every DNS infrastructure query was issued against the subdomain
  itself, which has no NS/MX records and either returns no SPF or returns a
  misleading hard-fail SPF (e.g. `v=spf1 -all` on `www.hackerone.com`) that
  hides the apex's real policy with `include:` statements. The passive source
  filter (`add` in passive.go) was affected because it filtered results against
  the subdomain (`endsWith(".www.hackerone.com")` discards
  `api.hackerone.com`), producing "1 unique subdomain" when the apex had 10+.
  Verified against hackerone.com: passive subdomains 1 → 21
  (hackertarget 10, rapiddns 11); NS 0 → 2; MX 0 → 5; SPF
  `v=spf1 -all` → `v=spf1 include:_spf.google.com include:amazonses.com
  include:mail.zendesk.com include:spf.mail.intercom.io include:mktomail.com
  include:registrarmail.net -all`. The operator-facing log emits
  `▸ Target "www.hackerone.com" is a subdomain — normalising DNS queries to
  apex "hackerone.com"` so the auto-normalisation is never silent.

### Compatibility

- All 4 packages pass `go test -race -count=1`.
- `gofmt -l .` and `go vet ./...` clean.
- No CLI flag changes; no API breakage; no report-schema changes
- `extractApexDomain` is an internal helper — not exported, so it does not
  affect downstream consumers.

## [1.0.3] — 2026-08-11

### False-Positive Fixes (validated against nuevageneracion.ed.cr,
### lasalle.ed.cr, keralauniversity.ac.in)

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
  in keralauniversity.ac.in (all return 404), 1 in lasalle.ed.cr.

### False-Negative Fixes

- **Wayback Machine zero results for CDN-hosted targets**
  (`internal/modules/discovery.go`, `RunWayback`): if the initial
  wildcard-subdomain CDX query
  (`url=*.{domain}/*`) returns zero rows, the tool now falls back to
  a domain-scope query (`matchType=domain`) before giving up.
  Previously CDN-hosted targets (Wix, Cloudflare, Azure) reported
  "Wayback Machine: 0 URLs" even when the CDX API had thousands of
  historical snapshots of the apex domain. Verified: lasalle.ed.cr
  went from 0 → 10782 URLs; keralauniversity.ac.in from 5000 → 100001 URLs.

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

| Target | HIGH before | HIGH after | Total findings |
|---|---|---|---|
| keralauniversity.ac.in | 1 | 0 | 24 → 21 |
| lasalle.ed.cr | 1 | 0 | 24 → 23 |

Full analysis at `/home/kali/recon/<target>/13_analisis/COMPARATIVO_PRE_vs_POST_FIX.md`.

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
