// w1r3hound — wiretap-grade offensive reconnaissance
//
// Bug bounty / pentest / CTF recon framework implementing the full
// OWASP WSTG v4.2 Information Gathering phase, plus ASN mapping, CT
// log harvesting, subfinder-style permutations, JS endpoint extraction,
// cloud-bucket discovery, SaaS enumeration, and HTTP-signature
// subdomain takeover fingerprinting.
//
// "Give me six hours to hack a system and I will spend the first
//  four scanning the infrastructure." — Every pentester, probably.

package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/w1r3hound/w1r3hound/internal/core"
	"github.com/w1r3hound/w1r3hound/internal/modules"
	"github.com/w1r3hound/w1r3hound/internal/report"
)

// knownModules is the set of internal module names mapProtocol can resolve
// to (i.e. every RunXxx registered in main), plus "all". mapProtocol passes
// unrecognised input straight through, so without this check a typo'd -m
// value (e.g. "profil") silently matched nothing in shouldRun and produced
// an empty report with exit code 0.
var knownModules = map[string]bool{
	"all":        true,
	"whois":      true,
	"asnmap":     true,
	"passivesrc": true,
	"dns":        true,
	"wayback":    true,
	"permute":    true,
	"httprobe":   true,
	"webserver":  true,
	"metafiles":  true,
	"headers":    true,
	"content":    true,
	"portscan":   true,
	"cors":       true,
	"cloud":      true,
	"dirbrute":   true,
	"apiscan":    true,
	"saasenum":   true,
	"crawler":    true,
	"jsdeep":     true,
	"takeover":   true,
}

// safeRun executes a module and contains any panic to that module. Modules
// process hostile third-party input across many goroutines; without this a
// single panic in one module would crash the whole process and lose every
// finding the other (already-run) modules had already contributed.
func safeRun(log *core.Logger, name string, fn func()) {
	defer func() {
		if r := recover(); r != nil {
			log.Error("Module %q panicked and was skipped: %v", name, r)
		}
	}()
	fn()
}

const banner = `
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⡟⣷⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣶⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⡿⠀⢻⡆⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⠟⠉⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣴⣿⠜⠀⠈⣷⠀⠀⠀⠀⠀⠀⢀⣴⠟⠁⠀⠀⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⠾⠛⠁⠀⠀⠀⣿⠀⠀⠀⠀⣠⡶⢟⠁⠀⠀⠀⠀⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣴⠟⠁⠀⠀⠀⠀⠀⠀⣿⠀⣀⣴⠞⠋⡰⠋⠀⠀⠀⠀⣠⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⠞⠋⠀⠀⠀⠀⠀⠀⠀⢀⣴⣷⠾⠋⠁⢀⡞⠁⠀⠀⠀⠀⢠⢿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⠞⠋⠁⠀⠀⠀⠀⠀⠀⣠⣴⡶⠛⠉⠀⠀⠀⠀⣼⠁⠀⠀⠀⠀⠀⢸⢸⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣤⡤⠴⠖⠒⠚⠛⠉⠉⠙⠛⠒⠲⢤⣄⣤⡶⠛⠉⠀⠀⠀⠀⠀⠀⠀⢰⡇⠀⠀⠀⠀⠀⠀⢸⢸⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⣴⠤⠶⠶⠶⠦⠤⣤⣄⣀⣀⣀⣀⣾⠉⣡⠴⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⠃⠀⠀⠀⠀⠀⠀⡎⣸⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⣿⠀⠀⠀⠀⠀⠀⠀⠀⠈⢉⣡⡤⠟⠛⠳⢤⡀⠀⠀⠀⠀⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠠⣄⠀⠀⠀⠀⠀⠀⣰⠇⣠⡴⠀⠀⠀⠀⡸⠃⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣠⣿⣄⣠⣖⣲⣦⡤⠇⠀⠀⠀⠀⠀⠀⢀⣤⠤⠭⣵⣒⢶⣺⣷⢊⣟⣦⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠛⠶⠶⠶⠾⠛⠻⠿⣮⣁⠀⠀⠰⢁⣼⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⢻⣤⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⠤⠤⠤⠀⠀⠈⠉⠉⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡴⣢⣾⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⢠⣿⡙⢶⣄⡀⠀⠀⠀⠀⠀⠀⠈⠉⠁⠀⠀⠀⠈⠓⠢⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⡴⣶⣵⠾⠋⢳⣶⣄⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⡞⢿⡉⢿⣾⠟⢯⣙⣲⣶⢤⣀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠈⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣶⣾⣿⠾⣟⡉⠀⠀⠀⠀⠈⠿⢿⣶⠄⠀⠀⠀⠀⠀⠀⠀⠀⠀
⡇⡞⠉⢻⣿⢀⠞⣇⢿⣩⣟⢻⡛⣿⢿⢿⣿⣷⣦⣄⠀⠀⠀⠀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣦⡀⠙⢦⠀⠀⠀⠀⠀⠈⠻⣿⣆⠀⠀⠀⠀⣴⡗⠀⠀
⢻⡇⠀⠀⢿⣸⠀⠈⠀⠁⠈⠛⠿⠻⣏⢦⠶⢧⣙⢙⣧⡀⢀⠀⢿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢳⣜⣿⣆⠀⠀⣸⠀⠀⠀⠀⠀⠀⠀⠙⢿⣦⣤⣠⠞⣽⢀⣰⠀
⠀⠁⠀⠀⠘⢿⠀⠀⠀⠀⠀⠀⠀⠀⠘⢷⡀⠀⢉⣿⠾⡇⠈⢦⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠀⠀⠀⠀⠀⡀⠀⠹⡍⠁⠀⣠⠏⠀⠀⠀⠀⠀⠀⠀⠀⣰⡟⠈⢻⣦⡷⠋⡟⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣧⡾⠋⢀⣠⡇⠀⠈⢳⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⡇⠀⠀⢀⣀⣙⣷⡦⡷⠀⡞⠁⠀⠀⠀⠀⠀⠀⠀⢀⣴⠟⠀⢀⡾⠋⠀⣾⠁⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⡟⠁⢀⣰⣟⡾⠁⠀⣠⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⣰⠇⣠⡤⠶⠾⠟⠉⠀⠀⠀⣇⠀⠀⠀⠀⠀⠀⠀⣰⡿⠋⠀⠀⣻⡄⠀⣼⣧⡀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⠟⠀⣤⣼⣹⠟⠀⣀⠼⠃⠀⠀⠀⠀⠀⠀⠀⠀⣠⡾⠋⣰⠋⠀⠀⠀⠀⠀⠀⠀⢸⠏⠀⠀⠀⠀⠀⣠⡾⠏⠀⢀⡤⠛⢹⠋⠋⢁⣿⠋⠉
⠀⠀⠀⢀⣄⠀⠀⠀⠀⠀⠀⢀⡾⠋⠀⣤⣯⡽⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⠴⠚⠁⣠⡜⠁⠀⠀⠀⠀⠀⠀⠀⢠⡏⠀⠀⠀⠀⣠⡾⠋⠁⠀⠐⣏⠀⢠⡏⠀⢀⡾⠋⠀⠀
⠀⠀⠀⠀⣿⡇⢸⣆⠀⠀⣰⣿⣄⢸⢦⡷⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡄⠀⠀⣠⠟⠁⠀⠀⠀⠀⠀⠀⠀⢠⠏⠀⠀⢀⣠⡾⠋⠀⠀⢰⠋⠉⣿⠛⠋⢀⣴⢟⣁⢤⡤⠀
⠀⠀⠀⠀⢹⣽⣾⡜⢶⣾⠳⣿⣨⠿⠋⠀⠀⢀⣀⡤⠤⢶⣄⠀⠀⠀⠀⠀⠀⣸⠀⣰⠃⠀⠀⠀⠀⠀⠀⠀⢀⡴⠃⠀⣀⡴⣟⠿⠀⠀⠀⠀⠸⠦⠼⠁⢀⣴⠟⠻⠽⠾⠭⠤⠤
⠀⠀⠀⠀⠀⢿⡿⣧⣈⠽⠞⠋⠀⠀⢀⣠⠶⠛⠁⠀⠀⠀⠈⢹⡟⠛⠻⠆⣴⠃⠀⠀⠀⠀⠀⠀⠀⠀⣀⠀⣸⣥⣴⠟⠫⠛⠁⢠⠴⠲⡄⠀⠀⠀⣠⣴⠟⠁⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠘⠷⣄⣀⣀⣀⣠⡴⠟⠉⠀⠀⠀⠀⠀⠀⠀⠀⠹⣧⣀⠀⠸⡇⠀⠀⠀⠀⠀⠀⠀⢠⣾⣯⠾⠛⠉⠀⣀⣀⠀⠀⢺⣀⣀⡏⢀⣤⡾⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⢿⣦⣄⣻⣄⠀⠀⠀⢀⣠⠾⢿⣿⣶⣦⣀⠀⡞⠉⢹⠃⠀⠀⢈⣡⡶⠟⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⡉⠉⠉⠉⠛⠛⠋⢁⣀⣀⠀⠉⠻⢻⡄⠻⠤⠏⣀⣤⡶⠛⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠴⢾⡿⣟⣆⠀⢰⢦⠀⠀⠈⠧⣸⠆⠀⢀⣼⣁⣠⣴⠿⠛⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡴⠋⣀⣽⣿⡀⠈⠛⠀⠀⠀⠀⣀⣤⣾⡿⣿⡿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⢴⠿⠒⠋⠉⠀⠘⡻⢦⡤⠴⠶⠶⡛⡛⢉⣡⣞⡵⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀

   [ wiretap-grade offensive recon ]   w1r3hound v1.0.6 · OWASP WSTG · BBP · CTF
`

const helpFooter = `
  ┌─────────────────────────────────────────────────────────┐
  │  SCAN PROTOCOLS                                         │
  │─────────────────────────────────────────────────────────│
  │  PASSIVE OSINT (safe, no traffic to target):            │
  │  recon        WHOIS/RDAP domain intelligence            │
  │  traceroute   ASN/CIDR range discovery (BGP)            │
  │  passivewatch CT logs & passive DNS aggregation         │
  │                                                         │
  │  DNS & SUBDOMAINS:                                      │
  │  fingerprinter DNS enum, AXFR, SRV, SPF/DMARC, takeover│
  │  archaeology  Wayback Machine URL harvesting            │
  │  diversify    Subdomain permutation & resolution        │
  │                                                         │
  │  LIVE DETECTION:                                        │
  │  heartbeat    HTTP probe + favicon hash (Shodan pivot)  │
  │                                                         │
  │  FINGERPRINTING:                                        │
  │  probescan    Server fingerprint, TLS cert, HTTP methods│
  │  metadata     robots.txt, sitemap, security.txt,        │
  │               .well-known endpoints                     │
  │  sentry       Security headers audit, tech detection    │
  │  deepdive     HTML comments, JS secrets, source maps    │
  │                                                         │
  │  ATTACK SURFACE:                                        │
  │  portscan     TCP port scanner with service ID          │
  │  corstrace    CORS misconfiguration testing             │
  │  cloudsniff   S3/Azure/GCS/Firebase/DigitalOcean buckets│
  │  bruteforce   Directory/file/backup discovery           │
  │  apiscan      GraphQL/Swagger/OpenAPI/REST/WS detection │
  │  saasenum     SaaS enum (Zendesk/JIRA/Okta/Salesforce)  │
  │  crawler      Web crawl for forms, params, entry points │
  │                                                         │
  │  DEEP ANALYSIS:                                         │
  │  jsdeep       JS endpoint extraction (LinkFinder style) │
  │  takeover     HTTP-signature subdomain takeover (37 svcs)│
  │                                                         │
  │  "Listen long enough on the wire, and the target       │
  │   tells you everything it never meant to."            │
  └─────────────────────────────────────────────────────────┘
`

func main() {
	cfg := core.DefaultConfig()

	// ── CLI Flags ──
	flag.StringVar(&cfg.Target, "target", "", "Target to profile (URL or domain)")
	flag.StringVar(&cfg.Target, "t", "", "Target (shorthand)")
	flag.IntVar(&cfg.Concurrency, "concurrency", 20, "Parallel connections per protocol")
	flag.IntVar(&cfg.Concurrency, "c", 20, "Concurrency (shorthand)")
	flag.DurationVar(&cfg.Timeout, "timeout", 10*time.Second, "Per-request timeout")
	flag.StringVar(&cfg.OutputFile, "output", "", "Output file base name (without extension)")
	flag.StringVar(&cfg.OutputFile, "o", "", "Output file (shorthand)")
	flag.BoolVar(&cfg.Verbose, "verbose", false, "Enable debug/verbose output")
	flag.BoolVar(&cfg.Verbose, "v", false, "Verbose (shorthand)")
	flag.StringVar(&cfg.Wordlist, "wordlist", "", "Path to subdomain wordlist")
	flag.StringVar(&cfg.Wordlist, "w", "", "Wordlist (shorthand)")
	flag.StringVar(&cfg.DirWordlist, "dir-wordlist", "", "Path to a directory/file bruteforce wordlist (default: embedded list)")
	flag.StringVar(&cfg.DirExtensions, "dir-ext", "", "Comma-separated extensions appended to each dirbrute word, e.g. .bak,.php,.zip,~")
	flag.StringVar(&cfg.Ports, "ports", "top100", "Port range: top100, 1-1024, full")
	flag.StringVar(&cfg.Ports, "p", "top100", "Ports (shorthand)")
	flag.IntVar(&cfg.RateLimit, "rate", 0, "Max requests/sec (0 = unlimited)")
	flag.BoolVar(&cfg.Passive, "passive", false, "Passive mode: no active probing")
	flag.StringVar(&cfg.UserAgent, "ua", cfg.UserAgent, "Custom User-Agent")
	flag.BoolVar(&cfg.SkipSSLCheck, "skip-tls-verify", true, "Skip TLS certificate verification (recon often targets broken/self-signed TLS)")
	resolverAddr := flag.String("resolver", "", "Custom DNS resolver, e.g. 1.1.1.1 or 8.8.8.8:53 (default: system)")
	resolversFile := flag.String("resolvers", "", "Path to a resolver list (one ip[:port] per line) — opts subdomain brute-force/permutation into the raw-UDP engine, rotating across the list instead of the single system/-resolver resolver; -rate then governs DNS too")
	flag.IntVar(&cfg.WaybackLimit, "wayback-limit", cfg.WaybackLimit, "Max URLs to pull from the Wayback CDX API")
	flag.IntVar(&cfg.CrawlMaxPages, "crawl-pages", cfg.CrawlMaxPages, "Max pages for the crawler")
	flag.IntVar(&cfg.MaxJSFiles, "js-files", cfg.MaxJSFiles, "Max JavaScript files to analyse")

	moduleList := flag.String("protocols", "all", "Comma-separated protocols: recon,traceroute,passivewatch,fingerprinter,archaeology,diversify,heartbeat,probescan,metadata,sentry,deepdive,portscan,corstrace,cloudsniff,bruteforce,apiscan,saasenum,crawler,jsdeep,takeover")
	flag.StringVar(moduleList, "m", "all", "Protocols (shorthand)")

	flag.Usage = func() {
		fmt.Fprint(os.Stderr, banner)
		fmt.Fprintf(os.Stderr, "\nUsage: w1r3hound -t <target> [options]\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  w1r3hound -t example.com                       Full system profile\n")
		fmt.Fprintf(os.Stderr, "  w1r3hound -t example.com -o report              Save scan to report.json/.md\n")
		fmt.Fprintf(os.Stderr, "  w1r3hound -t example.com -m fingerprinter,sentry,deepdive    Run only specific protocols\n")
		fmt.Fprintf(os.Stderr, "  w1r3hound -t example.com -passive               Passive recon only\n")
		fmt.Fprintf(os.Stderr, "  w1r3hound -t example.com -p full -c 50          Full port scan, 50 threads\n")
		fmt.Fprintf(os.Stderr, "  w1r3hound -t example.com -w subs.txt            Custom subdomain wordlist\n")
		fmt.Fprintf(os.Stderr, "  w1r3hound -t https://10.10.10.1:8080 -m all     CTF box full scan\n")
		fmt.Fprint(os.Stderr, helpFooter)
	}

	flag.Parse()

	// Positional argument support: w1r3hound example.com
	if cfg.Target == "" && flag.NArg() > 0 {
		cfg.Target = flag.Arg(0)
	}

	if cfg.Target == "" {
		flag.Usage()
		os.Exit(1)
	}

	// Clamp concurrency before any module runs. Every module builds a
	// semaphore as make(chan struct{}, cfg.Concurrency) and does
	// `sem <- struct{}{}` BEFORE spawning the worker that releases it. With
	// -c 0 that channel is unbuffered and the very first send blocks forever
	// (deadlock, since the receiver goroutine hasn't been launched yet); with
	// -c negative make() itself panics. Nudge bad values to a sane range so
	// a bad flag can't hang or crash the whole scan.
	if cfg.Concurrency < 1 {
		fmt.Fprintf(os.Stderr, "\033[33m  ⚠ Concurrency %d is invalid, using 1\033[0m\n", cfg.Concurrency)
		cfg.Concurrency = 1
	}
	if cfg.Concurrency > 100000 {
		fmt.Fprintf(os.Stderr, "\033[33m  ⚠ Concurrency %d is very high, clamping to 100000\033[0m\n", cfg.Concurrency)
		cfg.Concurrency = 100000
	}

	// Parse protocols — map themed names to internal module names
	rawModules := strings.Split(*moduleList, ",")
	cfg.Modules = []string{}
	for _, m := range rawModules {
		trimmed := strings.TrimSpace(strings.ToLower(m))
		mapped := mapProtocol(trimmed)
		if !knownModules[mapped] {
			fmt.Fprintf(os.Stderr, "\nUnknown protocol: %q\n", strings.TrimSpace(m))
			fmt.Fprintf(os.Stderr, "Run 'w1r3hound -help' to see the full list of valid -m/-protocols values.\n")
			os.Exit(1)
		}
		cfg.Modules = append(cfg.Modules, mapped)
	}

	cfg.Domain = extractDomain(cfg.Target)
	// Fix #3 (2026-08-07): seed RootDomains with the extracted
	// apex so isSubdomain() helpers can identify subdomains of the target.
	cfg.RootDomains = []string{cfg.Domain}

	if cfg.OutputFile == "" {
		// UTC to match core.NewReport/Finalize, which both timestamp in UTC —
		// otherwise the filename and the report's own started_at/ended_at
		// fields can disagree by the local UTC offset.
		cfg.OutputFile = fmt.Sprintf("w1r3hound_%s_%s", sanitize(cfg.Domain), time.Now().UTC().Format("20060102_150405"))
	}

	// ── Initialize ──
	log := core.NewLogger(cfg.Verbose)
	fmt.Fprint(os.Stderr, banner)
	log.Info("Target:      %s", cfg.Target)
	log.Info("Domain:      %s", cfg.Domain)
	log.Info("Protocols:   %s", strings.Join(cfg.Modules, ", "))
	log.Info("Threads:     %d", cfg.Concurrency)
	log.Info("Mode:        %s", modeLabel(cfg.Passive))
	if cfg.SkipSSLCheck {
		log.Warn("TLS verification disabled — recon traffic is not authenticated (pass -skip-tls-verify=false to enforce)")
	}
	fmt.Fprintf(os.Stderr, "\033[90m  Initializing w1r3hound...\033[0m\n")

	r := core.NewReport(cfg.Target)

	rl := core.NewRateLimiter(cfg.RateLimit)
	cfg.RL = rl
	cfg.Resolver = core.NewResolver(*resolverAddr, cfg.Timeout)
	if *resolversFile != "" {
		resolvers := core.ReadLines(*resolversFile)
		if len(resolvers) == 0 {
			log.Warn("-resolvers %q is missing or empty — falling back to the stdlib resolver", *resolversFile)
		} else {
			cfg.Resolvers = resolvers
			log.Info("Raw-UDP DNS engine enabled: %d resolver(s) from %s", len(resolvers), *resolversFile)
		}
	}
	defer func() {
		if rl != nil {
			rl.Stop()
		}
	}()

	// Ctrl+C / SIGTERM: without this, an interrupt mid-scan lost the report
	// entirely, since it was only ever written at the very end (after every
	// module ran). Write whatever findings have accumulated so far instead of
	// discarding a long scan's work. Also cancel cfg.Cancel() so any
	// in-flight net.Dial/tls.Dial using the shared context tears down
	// immediately instead of waiting for the OS-level dial timeout.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Fprintf(os.Stderr, "\n")
		log.Warn("Interrupted — writing partial report before exit...")
		if cfg.Cancel != nil {
			cfg.Cancel()
		}
		report.GenerateReport(r, cfg.OutputFile, log)
		os.Exit(130)
	}()

	// ── Protocol Execution ──
	// Active modules are skipped in -passive mode. Note that passivesrc and
	// asnmap are OSINT-only (they query third-party APIs, not the target), so
	// they are NOT gated and run even in passive mode.
	activeModules := map[string]bool{
		"webserver": true, "metafiles": true, "headers": true, "content": true,
		"portscan": true, "cors": true, "cloud": true, "dirbrute": true, "crawler": true,
		"httprobe": true, "apiscan": true, "saasenum": true, "jsdeep": true,
		"takeover": true, "permute": true,
	}

	shouldRun := func(name string) bool {
		if cfg.Passive && activeModules[name] {
			return false
		}
		for _, m := range cfg.Modules {
			if m == "all" || m == name {
				return true
			}
		}
		return false
	}

	// ── Phase 0: Passive OSINT (no traffic to target) ──
	if shouldRun("whois") {
		safeRun(log, "whois", func() { modules.RunWhois(cfg, r, log) })
	}
	if shouldRun("asnmap") {
		safeRun(log, "asnmap", func() { modules.RunASN(cfg, r, log) })
	}
	if shouldRun("passivesrc") {
		safeRun(log, "passivesrc", func() { modules.RunPassive(cfg, r, log) })
	}

	// ── Phase 1: DNS & Subdomain Enumeration ──
	if shouldRun("dns") {
		safeRun(log, "dns", func() { modules.RunDNS(cfg, r, log) })
	}
	if shouldRun("wayback") {
		safeRun(log, "wayback", func() { modules.RunWayback(cfg, r, log) })
	}
	// Permutation runs after passive+dns gathered a base list
	if shouldRun("permute") {
		safeRun(log, "permute", func() { modules.RunPermute(cfg, r, log) })
	}

	// ── Phase 2: Live Host Detection (after subdomains gathered) ──
	if shouldRun("httprobe") {
		safeRun(log, "httprobe", func() { modules.RunHTTProbe(cfg, r, log) })
	}

	// ── Phase 3: Active Fingerprinting ──
	if shouldRun("webserver") {
		safeRun(log, "webserver", func() { modules.RunWebServer(cfg, r, log) })
	}
	if shouldRun("metafiles") {
		safeRun(log, "metafiles", func() { modules.RunMetafiles(cfg, r, log) })
	}
	if shouldRun("headers") {
		safeRun(log, "headers", func() { modules.RunHeaders(cfg, r, log) })
	}
	if shouldRun("content") {
		safeRun(log, "content", func() { modules.RunContent(cfg, r, log) })
	}

	// ── Phase 4: Attack Surface Discovery ──
	if shouldRun("portscan") {
		safeRun(log, "portscan", func() { modules.RunPortScan(cfg, r, log) })
	}
	if shouldRun("cors") {
		safeRun(log, "cors", func() { modules.RunCORS(cfg, r, log) })
	}
	if shouldRun("cloud") {
		safeRun(log, "cloud", func() { modules.RunCloudStorage(cfg, r, log) })
	}
	if shouldRun("dirbrute") {
		safeRun(log, "dirbrute", func() { modules.RunDirBrute(cfg, r, log) })
	}
	if shouldRun("apiscan") {
		safeRun(log, "apiscan", func() { modules.RunAPI(cfg, r, log) })
	}
	if shouldRun("saasenum") {
		safeRun(log, "saasenum", func() { modules.RunSaaS(cfg, r, log) })
	}
	if shouldRun("crawler") {
		safeRun(log, "crawler", func() { modules.RunCrawler(cfg, r, log) })
	}

	// ── Phase 5: JS analysis & takeover (after content+subdomains) ──
	if shouldRun("jsdeep") {
		safeRun(log, "jsdeep", func() { modules.RunJSAnalysis(cfg, r, log) })
	}
	if shouldRun("takeover") {
		safeRun(log, "takeover", func() { modules.RunTakeover(cfg, r, log) })
	}

	// ── Phase 6: Aggregated attack-surface summary ──
	// Consumes the shared context (params/endpoints/URLs/IP ranges) that the
	// modules above populate, so the "data feedback" data is actually reported.
	safeRun(log, "surface", func() { modules.RunSurfaceSummary(cfg, r, log) })

	// ── Report ──
	report.GenerateReport(r, cfg.OutputFile, log)
	log.Info("Connection closed.")
}

// mapProtocol translates w1r3hound-themed names → internal module names.
// Also accepts the internal name directly for backward compat.
//
// The themed aliases (recon, fingerprinter, deepdive, cloudsniff, etc.)
// are the canonical command-line names. Internal module names
// (`whois`, `dns`, `headers`, etc.) are accepted as-is for users
// who prefer to think in implementation terms. A small set of
// legacy themed aliases is also accepted for backward compat with
// older scripts — see the "legacy aliases" section below.
func mapProtocol(name string) string {
	switch name {
	// ── w1r3hound-themed aliases ──
	case "recon":
		return "whois"
	case "traceroute":
		return "asnmap"
	case "passivewatch":
		return "passivesrc"
	case "fingerprinter":
		return "dns"
	case "archaeology":
		return "wayback"
	case "diversify":
		return "permute"
	case "heartbeat":
		return "httprobe"
	case "probescan":
		return "webserver"
	case "metadata":
		return "metafiles"
	case "sentry":
		return "headers"
	case "deepdive":
		return "content"
	case "corstrace":
		return "cors"
	case "cloudsniff":
		return "cloud"
	case "bruteforce":
		return "dirbrute"
	case "crawler":
		return "crawler"
	case "jsdeep":
		return "jsdeep"
	case "takeover":
		return "takeover"
	case "saasenum":
		return "saasenum"
	// ── legacy themed aliases (still accepted) ──
	case "osint":
		return "whois"
	case "backtrace":
		return "asnmap"
	case "ghosts":
		return "passivesrc"
	case "profile":
		return "dns"
	case "timewarp":
		return "wayback"
	case "blume":
		return "permute"
	case "pulse":
		return "httprobe"
	case "netscanner":
		return "webserver"
	case "datafiles":
		return "metafiles"
	case "syscheck":
		return "headers"
	case "deepscope":
		return "content"
	case "corscheck":
		return "cors"
	case "cloudpull":
		return "cloud"
	case "intrusion":
		return "dirbrute"
	case "spider":
		return "crawler"
	case "breach":
		return "apiscan"
	case "cloudnet":
		return "saasenum"
	case "decrypt":
		return "jsdeep"
	case "hijack":
		return "takeover"
	default:
		return name // pass through internal names too
	}
}

func extractDomain(target string) string {
	t := strings.TrimPrefix(target, "https://")
	t = strings.TrimPrefix(t, "http://")
	t = strings.Split(t, "/")[0]
	// IPv6 literal in brackets: "[::1]:8080" or "[::1]".
	if strings.HasPrefix(t, "[") {
		if i := strings.Index(t, "]"); i != -1 {
			return t[1:i]
		}
		return t
	}
	// "host:port" → drop the port. Only strip when there is a single colon, so a
	// bare IPv6 literal without brackets ("::1") is left intact rather than
	// truncated to "[" or "".
	if i := strings.LastIndex(t, ":"); i != -1 && !strings.Contains(t[:i], ":") {
		t = t[:i]
	}
	return t
}

func sanitize(s string) string {
	s = strings.ReplaceAll(s, ".", "_")
	s = strings.ReplaceAll(s, "/", "_")
	s = strings.ReplaceAll(s, ":", "_")
	return s
}

func modeLabel(passive bool) string {
	if passive {
		return "PASSIVE // Signals only"
	}
	return "ACTIVE // Full system breach"
}
