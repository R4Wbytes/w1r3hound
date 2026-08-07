# CHANGELOG

All notable changes to **W1r3hound** are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/), and this
project adheres to [Semantic Versioning](https://semver.org/) where
applicable.

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
  (`[ wiretap-grade offensive recon ] · W1r3hound v1.0 · OWASP WSTG · BBP · CTF`)
  is preserved verbatim below the art for brand continuity.

### Compatibility

- Public API: `internal/modules.realZoneTransfer` now takes an extra
  `*core.Config` argument. This is an internal helper, not part of
  the CLI surface. Call sites in `internal/modules/dns.go` updated.
- All 4 packages still pass `go test -race -count=1`. `go vet ./...`
  and `gofmt -l .` remain clean.

## [1.0] — 2026-08-07

### Initial release

**W1r3hound v1.0** is a single-binary offensive reconnaissance
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
go build -o W1r3hound .
./W1r3hound -t example.com
```

### Origin

W1r3hound v1.0 is the consolidation of an internal offensive-recon
tool that was previously distributed under a different name. The
v1.0 release is a clean rebrand with no historical artifacts in
the version history.
