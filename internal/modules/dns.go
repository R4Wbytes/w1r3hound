package modules

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"sync"

	"github.com/w1r3hound/w1r3hound/internal/core"
)

// ──────────────────────────────────────────────
//  WSTG-INFO-04 — DNS Enumeration
//  Subdomain brute-force, zone transfer, reverse
//  lookups, CNAME detection (subdomain takeover)
// ──────────────────────────────────────────────

type DNSResult struct {
	Subdomains []SubdomainEntry `json:"subdomains"`
	// Fix #4 (bbp-abercrombie-2026-08-07): SubdomainNames provides a flat
	// []string projection of the names in Subdomains. The two field types
	// (struct vs string) used to be conflated by downstream consumers (e.g.
	// `jq '.subdomains[]?'` returned keys/values from the struct, polluting
	// the output with raw IPs, "]", "{", etc.). With this field, a consumer
	// can pick the right projection without having to know the module.
	SubdomainNames []string `json:"subdomain_names"`
	Nameservers    []string `json:"nameservers"`
	MXRecords      []string `json:"mx_records"`
	TXTRecords     []string `json:"txt_records"`
	SRVRecords     []string `json:"srv_records,omitempty"`
	ZoneTransfer   []string `json:"zone_transfer,omitempty"`
	TakeoverRisks  []string `json:"takeover_risks,omitempty"`
	WildcardDetect bool     `json:"wildcard_detected"`
	SPFRecord      string   `json:"spf_record,omitempty"`
	DMARCPolicy    string   `json:"dmarc_policy,omitempty"`
}

type SubdomainEntry struct {
	Name   string   `json:"name"`
	IPs    []string `json:"ips,omitempty"`
	CNAMEs []string `json:"cnames,omitempty"`
}

// Common subdomains for brute force — embedded minimal list.
var defaultSubdomains = []string{
	"www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
	"dns", "dns1", "dns2", "mx", "mx1", "mx2", "admin", "api", "dev", "staging",
	"stage", "test", "testing", "beta", "demo", "app", "apps", "portal", "vpn",
	"remote", "gateway", "gw", "proxy", "cdn", "static", "assets", "img", "images",
	"media", "docs", "doc", "help", "support", "status", "monitor", "monitoring",
	"blog", "forum", "shop", "store", "payment", "pay", "billing", "git", "gitlab",
	"github", "bitbucket", "jenkins", "ci", "cd", "build", "deploy", "docker",
	"k8s", "kubernetes", "registry", "npm", "pypi", "repo", "sso", "auth",
	"login", "signin", "signup", "register", "oauth", "id", "identity",
	"accounts", "account", "dashboard", "panel", "console", "cms", "wp",
	"wordpress", "jira", "confluence", "slack", "teams", "chat", "irc",
	"internal", "intranet", "extranet", "uat", "qa", "sandbox", "lab",
	"old", "new", "legacy", "archive", "backup", "bak", "temp", "tmp",
	"db", "database", "mysql", "postgres", "redis", "mongo", "elastic",
	"elasticsearch", "kibana", "grafana", "prometheus", "nagios", "zabbix",
	"splunk", "log", "logs", "syslog", "waf", "firewall", "security",
	"secure", "ssl", "tls", "cert", "certs", "pki", "ca", "ldap", "ad",
	"exchange", "owa", "autodiscover", "cpanel", "whm", "plesk",
	"webmin", "phpmyadmin", "adminer", "pgadmin", "s3", "cloud", "aws",
	"azure", "gcp", "storage", "bucket", "files", "upload", "download",
	"share", "drive", "calendar", "wiki", "kb", "knowledge", "crm",
	"erp", "hr", "finance", "corp", "corporate", "www2", "www3",
	"m", "mobile", "wap", "rest", "graphql", "grpc", "ws", "websocket",
	"socket", "v1", "v2", "v3", "api2", "api3", "public", "private",
	"data", "analytics", "track", "tracking", "click", "ad", "ads",
	"marketing", "campaign", "email", "newsletter", "notify", "notification",
	"push", "webhook", "hook", "callback", "relay", "ns3", "ns4",
	"origin", "origin-www", "direct", "host", "node1", "node2",
	"worker", "job", "queue", "cache", "memcache", "memcached",
	"varnish", "haproxy", "lb", "loadbalancer", "edge", "pop",
}

// Fingerprints for CNAME-based subdomain takeover candidates.
var takeoverFingerprints = map[string]string{
	"amazonaws.com":         "AWS S3 / CloudFront",
	"azurewebsites.net":     "Azure App Service",
	"cloudapp.net":          "Azure Cloud App",
	"trafficmanager.net":    "Azure Traffic Manager",
	"blob.core.windows.net": "Azure Blob",
	"github.io":             "GitHub Pages",
	"herokuapp.com":         "Heroku",
	"herokudns.com":         "Heroku DNS",
	"pantheonsite.io":       "Pantheon",
	"domains.tumblr.com":    "Tumblr",
	"shopify.com":           "Shopify",
	"myshopify.com":         "Shopify",
	"wordpress.com":         "WordPress.com",
	"wpengine.com":          "WP Engine",
	"ghost.io":              "Ghost",
	"surge.sh":              "Surge.sh",
	"bitbucket.io":          "Bitbucket",
	"fastly.net":            "Fastly",
	"helpjuice.com":         "Helpjuice",
	"helpscoutdocs.com":     "HelpScout",
	"zendesk.com":           "Zendesk",
	"teamwork.com":          "Teamwork",
	"unbounce.com":          "Unbounce",
	"feedpress.me":          "FeedPress",
	"freshdesk.com":         "Freshdesk",
	"uservoice.com":         "UserVoice",
	"statuspage.io":         "Statuspage",
	"squarespace.com":       "Squarespace",
	"fly.dev":               "Fly.io",
	"netlify.app":           "Netlify",
	"vercel.app":            "Vercel",
	"render.com":            "Render",
	"firebaseapp.com":       "Firebase",
	"web.app":               "Firebase Hosting",
	"appspot.com":           "Google App Engine",
	"run.app":               "Google Cloud Run",
	"cloudfunctions.net":    "Google Cloud Functions",
	"ngrok.io":              "Ngrok",
	"cargocollective.com":   "Cargo Collective",
	"readme.io":             "ReadMe",
	"gitbook.io":            "GitBook",
	"elasticbeanstalk.com":  "AWS Elastic Beanstalk",
	"azureedge.net":         "Azure CDN",
	"azurefd.net":           "Azure Front Door",
	"desk.com":              "Desk.com",
	"createsend.com":        "Campaign Monitor",
	"intercom.help":         "Intercom",
	"strikinglydns.com":     "Strikingly",
	"hatenablog.com":        "HatenaBlog",
	"smartjobboard.com":     "SmartJobBoard",
}

func RunDNS(cfg *core.Config, report *core.ReconReport, log *core.Logger) {
	log.Module("FINGERPRINTER // Network Mapping & Subdomain Recon")

	domain := cfg.Domain
	result := DNSResult{}

	// 1. Nameservers (FIX #3: log the resolver error instead of silently
	// dropping it. Previously an empty Nameservers slice was indistinguishable
	// from a lookup failure, producing false negatives like "DNS Enumeration:
	// 0 NS, 0 MX" when the resolver was actually unreachable.)
	nss, nsErr := cfg.Resolver.LookupNS(context.Background(), domain)
	if nsErr != nil {
		log.Warn("NS lookup failed: %v", nsErr)
	}
	for _, ns := range nss {
		host := strings.TrimSuffix(ns.Host, ".")
		result.Nameservers = append(result.Nameservers, host)
		log.Info("NS: %s", host)
	}

	// 2. MX records (FIX #3: log error)
	mxs, mxErr := cfg.Resolver.LookupMX(context.Background(), domain)
	if mxErr != nil {
		log.Warn("MX lookup failed: %v", mxErr)
	}
	for _, mx := range mxs {
		host := strings.TrimSuffix(mx.Host, ".")
		result.MXRecords = append(result.MXRecords, fmt.Sprintf("%s (prio %d)", host, mx.Pref))
		log.Info("MX: %s (priority %d)", host, mx.Pref)
	}

	// 3. TXT records — SPF, DMARC, DKIM, verification tokens (FIX #3: log error)
	txts, txtErr := cfg.Resolver.LookupTXT(context.Background(), domain)
	if txtErr != nil {
		log.Warn("TXT lookup failed: %v", txtErr)
	}
	result.TXTRecords = txts
	for _, t := range txts {
		log.Info("TXT: %s", truncate(t, 120))
		if strings.HasPrefix(strings.ToLower(t), "v=spf1") {
			result.SPFRecord = t
		}
	}
	// DMARC
	// Fix #1 (bbp-abercrombie-2026-08-07): DMARC record lives at _dmarc.<domain>,
	// not at the apex. Appending it to TXTRecords with a "DMARC: " prefix polluted
	// the TXT record set, causing downstream consumers (jq parsers, human readers)
	// to miscount TXT records and treat DMARC as an apex TXT entry. Now DMARC is
	// stored ONLY in DMARCPolicy.
	dmarcTxts, _ := cfg.Resolver.LookupTXT(context.Background(), "_dmarc."+domain)
	for _, t := range dmarcTxts {
		result.DMARCPolicy = t
		log.Info("DMARC: %s", truncate(t, 120))
	}
	// Flag missing DMARC (email spoofing risk)
	// Fix #3 (bbp-abercrombie-2026-08-07): Subdomains inherit DMARC policy from
	// the apex per RFC 7489 §6.3. Reporting "No DMARC" on every subdomain
	// produces massive false positives (e.g. corporate.abercrombie.com was
	// flagged LOW despite abercrombie.com having p=reject). When the target is a
	// subdomain, fall back to the apex's DMARC before flagging.
	if result.DMARCPolicy == "" {
		apexDMARC := lookupApexDMARC(domain, cfg, log)
		if apexDMARC != "" {
			log.Debug("DMARC inherited from apex (skipping subdomain finding): %s", truncate(apexDMARC, 120))
			result.DMARCPolicy = "(inherited from apex) " + apexDMARC
		} else if isSubdomain(domain, cfg.RootDomains) {
			log.Debug("No DMARC and target is a subdomain with no apex DMARC — skipping (subdomain inherits NXDOMAIN behaviour from apex)")
		} else {
			log.Warn("No DMARC record — domain may be spoofable")
			report.Add(core.Finding{
				Module:      "dns",
				WSTG:        "WSTG-INFO-04",
				Title:       "No DMARC record configured",
				Severity:    core.SevLow,
				Description: "Absence of DMARC policy makes email spoofing easier.",
			})
		}
	} else if strings.Contains(result.DMARCPolicy, "p=none") {
		log.Warn("DMARC policy is p=none (monitoring only, no enforcement)")
	}

	// 4. Zone transfer attempt (real AXFR)
	for _, ns := range result.Nameservers {
		log.Debug("Attempting AXFR zone transfer from %s", ns)
		records := realZoneTransfer(domain, ns, cfg.Timeout, cfg)
		if len(records) > 0 {
			result.ZoneTransfer = records
			log.Warn("Zone transfer SUCCESSFUL from %s — %d records", ns, len(records))
			report.Add(core.Finding{
				Module:      "dns",
				WSTG:        "WSTG-INFO-04",
				Title:       fmt.Sprintf("DNS Zone Transfer (AXFR) possible from %s", ns),
				Severity:    core.SevHigh,
				Description: "Full zone transfer succeeded, exposing all DNS records.",
				Data:        records,
			})
			// Feed discovered names into shared context
			cfg.AddSharedSubdomains(records)
			break
		}
	}

	// 4b. SRV record enumeration
	result.SRVRecords = EnumerateSRV(cfg, log)
	if len(result.SRVRecords) > 0 {
		log.Info("Found %d SRV records exposing internal services", len(result.SRVRecords))
	}

	// 5. Wildcard detection (single DNS query for both detection and IP collection)
	wildcardIPs := getWildcardIPs(cfg.Resolver, domain)
	result.WildcardDetect = len(wildcardIPs) > 0
	if result.WildcardDetect {
		log.Warn("Wildcard DNS detected — subdomain brute results may contain false positives")
		log.Info("Wildcard IPs: %v (will filter matches)", mapKeys(wildcardIPs))
	}

	// 6. Subdomain brute-force
	wordlist := loadSubdomainWordlist(cfg.Wordlist)
	if len(wordlist) == 0 {
		wordlist = defaultSubdomains
	}
	log.Info("Brute-forcing %d subdomain candidates...", len(wordlist))

	var (
		mu    sync.Mutex
		wg    sync.WaitGroup
		sem   = make(chan struct{}, cfg.Concurrency)
		found = make(map[string]SubdomainEntry)
	)

	// Use system resolver by default (works in internal/CTF networks)
	resolver := cfg.Resolver

	for _, sub := range wordlist {
		fqdn := sub + "." + domain
		wg.Add(1)
		sem <- struct{}{}
		go func(fqdn, sub string) {
			defer core.RecoverWorker(log, "dns")
			defer wg.Done()
			defer func() { <-sem }()

			ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
			defer cancel()

			ips, err := resolver.LookupHost(ctx, fqdn)
			if err != nil || len(ips) == 0 {
				return
			}

			// Skip if ALL IPs match the wildcard set
			if result.WildcardDetect && allIPsMatch(ips, wildcardIPs) {
				return
			}

			entry := SubdomainEntry{Name: fqdn, IPs: ips}

			// Check CNAME for takeover
			cname, err := resolver.LookupCNAME(ctx, fqdn)
			if err == nil && cname != "" && cname != fqdn+"." {
				cname = strings.TrimSuffix(cname, ".")
				entry.CNAMEs = []string{cname}
				for fp, svc := range takeoverFingerprints {
					if strings.HasSuffix(cname, fp) {
						// Verify: does the CNAME target actually resolve?
						// If it resolves → service is active → NOT a takeover.
						// If NXDOMAIN → unclaimed → potential takeover.
						cnameIPs, cnameErr := resolver.LookupHost(ctx, cname)
						status := "active"
						if cnameErr != nil || len(cnameIPs) == 0 {
							status = "dangling"
						}

						mu.Lock()
						if status == "dangling" {
							result.TakeoverRisks = append(result.TakeoverRisks,
								fmt.Sprintf("%s → %s (%s) [DANGLING — likely vulnerable]", fqdn, cname, svc))
							log.Warn("TAKEOVER: %s → %s (%s) — CNAME target does not resolve!", fqdn, cname, svc)
						} else {
							log.Info("CNAME match (active, not vulnerable): %s → %s (%s)", fqdn, cname, svc)
						}
						mu.Unlock()
						break
					}
				}
			}

			mu.Lock()
			found[fqdn] = entry
			mu.Unlock()
			log.Info("Found: %-40s %s", fqdn, strings.Join(ips, ", "))
		}(fqdn, sub)
	}
	wg.Wait()

	// Collect and sort
	for _, e := range found {
		result.Subdomains = append(result.Subdomains, e)
	}
	sort.Slice(result.Subdomains, func(i, j int) bool {
		return result.Subdomains[i].Name < result.Subdomains[j].Name
	})

	// Fix #4 (bbp-abercrombie-2026-08-07): populate SubdomainNames with the
	// flat []string projection so downstream jq/grep consumers get clean FQDNs
	// without having to dig into the struct.
	for _, s := range result.Subdomains {
		result.SubdomainNames = append(result.SubdomainNames, s.Name)
	}

	log.Info("Total subdomains found: %d", len(result.Subdomains))

	// Feed brute-forced subdomains into shared context (data feedback) so
	// downstream modules (httprobe, takeover, permute) can consume them even
	// when the passive source module isn't run.
	var dnsSubs []string
	for _, s := range result.Subdomains {
		dnsSubs = append(dnsSubs, s.Name)
	}
	cfg.AddSharedSubdomains(dnsSubs)

	// Report
	report.Add(core.Finding{
		Module:   "dns",
		WSTG:     "WSTG-INFO-04",
		Title:    fmt.Sprintf("DNS Enumeration: %d subdomains, %d NS, %d MX", len(result.Subdomains), len(result.Nameservers), len(result.MXRecords)),
		Severity: core.SevInfo,
		Data:     result,
	})

	if len(result.TakeoverRisks) > 0 {
		report.Add(core.Finding{
			Module:      "dns",
			WSTG:        "WSTG-CONF-10",
			Title:       fmt.Sprintf("Potential subdomain takeover: %d candidates", len(result.TakeoverRisks)),
			Severity:    core.SevHigh,
			Description: "Subdomains with CNAMEs pointing to unclaimed third-party services (detected via CNAME/DNS resolution; may overlap with the HTTP-fingerprint takeover module).",
			Data:        result.TakeoverRisks,
		})
	}
}

// ── helpers ──

func detectWildcard(resolver *net.Resolver, domain string) bool {
	randomSub := "W1r3hound-wildcard-probe-xq7k9m." + domain
	ips, err := resolver.LookupHost(context.Background(), randomSub)
	return err == nil && len(ips) > 0
}

func getWildcardIPs(resolver *net.Resolver, domain string) map[string]bool {
	randomSub := "W1r3hound-wildcard-probe-xq7k9m." + domain
	ips, err := resolver.LookupHost(context.Background(), randomSub)
	if err != nil {
		return nil
	}
	m := make(map[string]bool)
	for _, ip := range ips {
		m[ip] = true
	}
	return m
}

func allIPsMatch(ips []string, wildcardIPs map[string]bool) bool {
	if len(wildcardIPs) == 0 {
		return false
	}
	for _, ip := range ips {
		if !wildcardIPs[ip] {
			return false
		}
	}
	return true
}

func mapKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func loadSubdomainWordlist(path string) []string {
	if path == "" {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var subs []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			subs = append(subs, line)
		}
	}
	return subs
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// isSubdomain returns true if `target` is a subdomain of any of the root
// domains configured for the scan. Used to suppress subdomain findings that
// would otherwise be duplicated/inherited from the apex (e.g. DMARC, SPF).
// Fix #3 (bbp-abercrombie-2026-08-07).
func isSubdomain(target string, roots []string) bool {
	if len(roots) == 0 {
		// No roots configured — treat anything with a dot as a subdomain.
		// Best-effort heuristic: if it has 2+ labels and no root list, assume
		// it's a subdomain unless we can prove it's the apex.
		return strings.Count(target, ".") >= 2
	}
	t := strings.ToLower(strings.TrimSpace(target))
	for _, r := range roots {
		r = strings.ToLower(strings.TrimSpace(r))
		if t == r {
			return false
		}
		if strings.HasSuffix(t, "."+r) {
			return true
		}
	}
	// Not under any known root — assume subdomain (conservative).
	return strings.Count(t, ".") >= 2
}

// lookupApexDMARC looks up the DMARC policy at the apex domain. The apex is
// derived by stripping the leftmost label from the target. If the target is
// already the apex, it returns "" so the caller knows not to recurse.
// Fix #3 (bbp-abercrombie-2026-08-07).
func lookupApexDMARC(target string, cfg *core.Config, log *core.Logger) string {
	parts := strings.Split(target, ".")
	if len(parts) < 3 {
		return ""
	}
	// Try progressively shorter suffixes to handle compound TLDs
	// (e.g. sub.example.co.uk → try example.co.uk, then co.uk)
	for i := 1; i < len(parts)-1; i++ {
		candidate := strings.Join(parts[i:], ".")
		recs, err := cfg.Resolver.LookupTXT(context.Background(), "_dmarc."+candidate)
		if err != nil || len(recs) == 0 {
			continue
		}
		return recs[0]
	}
	return ""
}
