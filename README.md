# w1r3hound — wiretap-grade offensive recon

```
██╗    ██╗ ██╗██████╗ ███████╗██╗  ██╗ ██████╗ ██╗   ██╗███╗   ██╗██████╗
██║    ██║███║██╔══██╗██╔════╝██║  ██║██╔═══██╗██║   ██║████╗  ██║██╔══██╗
██║ █╗ ██║╚██║██████╔╝█████╗  ███████║██║   ██║██║   ██║██╔██╗ ██║██║  ██║
██║███╗██║ ██║██╔══██╗██╔══╝  ██╔══██║██║   ██║██║   ██║██║╚██╗██║██║  ██║
╚███╔███╔╝ ██║██║  ██║███████╗██║  ██║╚██████╔╝╚██████╔╝██║ ╚████║██████╔╝
 ╚══╝╚══╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝╚═════╝

   [ wiretap-grade offensive recon ]
   ─────────────────────────────────────
   w1r3hound v1.0.3 · OWASP WSTG · BBP · CTF
```

> *"Privacy is a lie. Security is an illusion. The only thing that's real is the data.
— Dusan Nemec"*

**w1r3hound** is a single-binary offensive reconnaissance framework for
bug bounty hunting, penetration testing, and CTF competitions. The name
is a play on *wire* (a wiretap, a digital listening post) + *hound* (a
tracker with predator instinct): a surveillance system that picks up a
scent and doesn't let go. It implements the full OWASP WSTG v4.2
Information Gathering phase and extends it with coverage gaps that
most scanners miss: ASN-to-CIDR expansion, subfinder-style
permutations, JS endpoint extraction, cloud-bucket probing, SaaS
enumeration, and HTTP-signature subdomain takeover fingerprinting.

Zero dependencies. Single binary. Cross-platform. One scan to profile
everything.

## What's new in v1.0.3

v1.0.3 is a stability release that closes four bug-hunt findings from
the v1.0.2 audit against three authorized targets (Wix-hosted + Apache/PHP):

- **Cloud bucket false ownership eliminated** — 9 false-positive HIGH
  findings per target are now suppressed when the bucket name is a known
  generic (`www`, `www-staging`, `www-cdn`, etc.) because those names
  resolve to buckets owned by other parties (Google project 868530998679,
  DO owner 359009, etc.). The buckets are still listed in the INFO
  finding for awareness.
- **Source map detection now verifies HTTP 200** — inline
  `//# sourceMappingURL=` references that point to non-existent `.map`
  files (a common pattern in CMS themes) no longer raise MEDIUM findings.
- **Wayback Machine fallback to `matchType=domain`** — targets behind
  CDNs (Wix, Cloudflare) now report historical snapshots instead of
  "0 URLs" (Lasalle: 0 → 10782 URLs; Kerala: 5000 → 100001 URLs).
- **DNS module logs resolver errors** — `LookupNS`/`MX`/`TXT` failures
  are no longer silently swallowed; the operator sees the underlying
  error in the log.

Full details in [CHANGELOG.md](CHANGELOG.md).

## Installation

```bash
git clone https://github.com/w1r3hound/w1r3hound.git
cd w1r3hound
go build -o w1r3hound .
```

### Cross-compile

```bash
GOOS=linux   GOARCH=amd64 go build -o w1r3hound-linux .
GOOS=darwin  GOARCH=arm64 go build -o w1r3hound-mac .
GOOS=windows GOARCH=amd64 go build -o w1r3hound.exe .
```

## Usage

```bash
# Profile everything
w1r3hound -t example.com

# Save the breach report
w1r3hound -t example.com -o breach_report

# Passive signals only — no active probing
w1r3hound -t example.com -passive

# Select specific protocols
w1r3hound -t example.com -m fingerprinter,sentry,deepdive

# Aggressive CTF scan
w1r3hound -t 10.10.10.100 -p full -c 100 -v

# Bug bounty with custom subdomain list
w1r3hound -t target.com -w /path/to/subdomains.txt -o bb_report
```

### Options

```
  -t, -target        Target to profile (required)
  -o, -output        Output file base (generates .json + .md)
  -m, -protocols     Comma-separated protocols (default: all)
  -c, -concurrency   Parallel connections per protocol (default: 20)
  -p, -ports         Port range: top100, 1-1024, full (default: top100)
  -w, -wordlist      Path to subdomain wordlist file
  -v, -verbose       Debug output
  -passive           Passive mode (no traffic to target)
  -rate              Max requests/sec (0 = unlimited)
  -timeout           Per-request timeout (default: 10s)
  -ua                Custom User-Agent
```

## Scan Protocols

The framework ships with **19 modules** grouped in 5 categories.
The themed aliases use a wiretap/surveillance vocabulary — both
themed names and the plain internal names are accepted on the
command line.

### Passive OSINT (safe — no traffic to target)

| Alias | Internal | What it does | WSTG |
|-------|----------|-------------|------|
| `recon` | whois | WHOIS/RDAP domain intelligence | INFO-01 |
| `traceroute` | asnmap | ASN → CIDR range discovery via BGP | INFO-04 |
| `passivewatch` | passivesrc | Passive subdomains (CT logs, 6 sources) | INFO-01 |

### DNS & Subdomains

| Alias | Internal | What it does | WSTG |
|-------|----------|-------------|------|
| `fingerprinter` | dns | DNS enum, real AXFR, SRV, SPF/DMARC, takeover | INFO-04, CONF-10 |
| `archaeology` | wayback | Wayback Machine URL & parameter harvesting | INFO-01 |
| `diversify` | permute | Subdomain permutation & resolution | INFO-04 |

### Live Detection & Fingerprinting

| Alias | Internal | What it does | WSTG |
|-------|----------|-------------|------|
| `heartbeat` | httprobe | HTTP probe + favicon hash (Shodan pivoting) | INFO-04 |
| `probescan` | webserver | Server fingerprint, TLS cert, HTTP methods | INFO-02, CONF-06 |
| `metadata` | metafiles | robots.txt, sitemap, security.txt, .well-known | INFO-03, CONF-08 |
| `sentry` | headers | Security headers audit, tech fingerprinting | INFO-08, CONF-07 |
| `deepdive` | content | HTML comments, JS secrets, source maps, leaks | INFO-05 |

### Attack Surface

| Alias | Internal | What it does | WSTG |
|-------|----------|-------------|------|
| `portscan` | portscan | TCP port scan with service ID & banner grab | INFO-04, CONF-01 |
| `corstrace` | cors | CORS misconfiguration testing | CLNT-07 |
| `cloudsniff` | cloud | S3/Azure/GCS/Firebase/DigitalOcean buckets | CONF-11 |
| `bruteforce` | dirbrute | Hidden paths, admin panels, backups, configs | CONF-03/04/05 |
| `apiscan` | apiscan | GraphQL introspection, Swagger/OpenAPI, REST, WS | INFO-06 |
| `saasenum` | saasenum | SaaS enum (Zendesk/JIRA/Okta/Salesforce +30) | INFO-10 |
| `crawler` | crawler | Web crawl for forms, params, entry points | INFO-06/07 |

### Deep Analysis

| Alias | Internal | What it does | WSTG |
|-------|----------|-------------|------|
| `jsdeep` | jsdeep | JS endpoint extraction (LinkFinder style) | INFO-05 |
| `takeover` | takeover | Subdomain takeover via HTTP fingerprints (37 services) | CONF-10 |

### Beyond WSTG

- **Certificate Transparency** — subdomain discovery from crt.sh + 5 more passive sources
- **ASN/CIDR mapping** — finds IP space DNS enumeration never reaches (BGPView)
- **Favicon hashing** — MurmurHash3 (Shodan-compatible) for `http.favicon.hash:` pivoting
- **Real AXFR** — raw TCP/53 zone transfer, no external dependencies
- **SRV enumeration** — 30+ service prefixes (SIP, LDAP, Kerberos, XMPP)
- **GraphQL introspection** — detects exposed schemas
- **API doc discovery** — Swagger/OpenAPI/Postman across 20+ paths
- **SaaS enumeration** — 30 third-party platforms outside the security review cycle
- **JS endpoint extraction** — LinkFinder-style with cloud URL & secret detection
- **HTTP-signature takeover** — 37 service fingerprints (beyond NXDOMAIN-only)
- **Subdomain permutation** — dev/staging/prod variations with wildcard filtering
- **Data feedback pipeline** — modules feed subdomains/JS/endpoints to each other
- **30+ secret patterns** — AWS keys, Stripe, GitHub tokens, JWT, DB strings
- **CORS exploitation testing** — origin reflection, null origin, wildcard + credentials
- **Smart soft-404 detection** — 4-strategy filter + cluster analysis
- **CDN/WAF awareness** — detects Cloudflare and flags CDN ports
- **Apex-aware findings** — subdomains inherit DMARC/SPF from apex (RFC 7489 §6.3)
- **Source coverage reporting** — `sources_attempted` / `_failed` / `_successful` per scan

## Output

**JSON** (`w1r3hound_target_timestamp.json`) — machine-readable, pipeline-friendly, every finding with raw data.

**Markdown** (`w1r3hound_target_timestamp.md`) — human-readable breach report grouped by severity with WSTG IDs.

### Severity Scale

| Level | Meaning |
|-------|---------|
| CRITICAL | Exposed configs (.env, .git), public cloud buckets |
| HIGH | Subdomain takeover, CORS with credentials, dangerous services |
| MEDIUM | Missing security headers, TRACE method, source maps |
| LOW | Version leak, internal IPs, informational exposure |
| INFO | Scan data, tech stack, crawl results |

## Quick Playbook

### Bug Bounty

```bash
w1r3hound -t target.com -w subdomains-top1million.txt -o loot
w1r3hound -t target.com -m fingerprinter,archaeology,recon -passive   # passive first
w1r3hound -t target.com -m deepdive,sentry,bruteforce                   # then active
```

### Pentest

```bash
w1r3hound -t client.com -p full -c 50 -v -o pentest_recon
w1r3hound -t 192.168.1.0/24 -m portscan,probescan -p 1-65535
```

### CTF

```bash
w1r3hound -t 10.10.10.100 -p full -c 100 -v
w1r3hound -t http://challenge.ctf:31337 -m probescan,deepdive,bruteforce,crawler
```

## Architecture

```
w1r3hound/
├── main.go                          # CLI, protocol router, banner
├── go.mod                           # module github.com/w1r3hound/w1r3hound
├── internal/
│   ├── core/
│   │   └── core.go                  # Config, HTTP client, rate limiter, logger
│   ├── modules/
│   │   ├── dns.go                   # FINGERPRINTER — subdomain enum, zone transfer
│   │   ├── webserver.go             # PROBESCAN — server fingerprint, TLS
│   │   ├── metafiles.go             # METADATA — robots.txt, sitemap, security.txt
│   │   ├── headers.go               # SENTRY — security headers, tech detection
│   │   ├── content.go               # DEEPDIVE — HTML/JS analysis, secret scan
│   │   ├── portscan.go              # PORTSCAN — TCP scanner
│   │   ├── discovery.go             # ARCHAEOLOGY, CORSTRACE, CLOUDSNIFF, BRUTEFORCE
│   │   ├── crawler.go               # CRAWLER, RECON
│   │   └── helpers.go               # Shared utils
│   └── report/
│       └── report.go                # JSON + Markdown report gen
├── CHANGELOG.md
├── LICENSE
└── README.md
```

## Known Limitations

- No public-suffix (eTLD+1) scoping — pointing it at a subdomain scopes
  passive sources to that subdomain only, missing the apex and siblings.
- crt.sh/Wayback responses are capped at 10 MB, so very large CT logs get
  truncated.
- Only the root target is actively fingerprinted/secret-scanned; discovered
  subdomains are probed for liveness but not deep-scanned.
- The crawler doesn't preserve query parameters from `<a href>` links.
- No deduplication across multiple `w1r3hound` runs against the same target
  (each run produces its own `w1r3hound_target_timestamp.{json,md}` pair).

## Legal

This tool is for authorized security testing, bug bounty programs, CTF
competitions, and educational purposes only. Always have explicit
permission before profiling any target. Unauthorized access may violate
laws in your jurisdiction.

## License

MIT License
