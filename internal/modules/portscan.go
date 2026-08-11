package modules

import (
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/w1r3hound/w1r3hound/internal/core"
)

// ──────────────────────────────────────────────
//  WSTG-INFO-04 / WSTG-CONF-01 — Port Scanning
//  TCP connect scan with service fingerprinting.
// ──────────────────────────────────────────────

type PortScanResult struct {
	Host      string     `json:"host"`
	OpenPorts []PortInfo `json:"open_ports"`
}

type PortInfo struct {
	Port    int    `json:"port"`
	State   string `json:"state"`
	Service string `json:"service"`
	Banner  string `json:"banner,omitempty"`
}

// Curated list of the most common web/infra ports for fast scanning. The "-p
// top100" label is kept for CLI backward-compatibility; the list currently holds
// ~106 ports.
var top100Ports = []int{
	21, 22, 23, 25, 53, 80, 81, 110, 111, 119, 135, 139, 143, 161,
	389, 443, 445, 465, 514, 515, 587, 636, 993, 995,
	1080, 1099, 1433, 1434, 1521, 1723, 2049, 2082, 2083, 2086,
	2087, 2095, 2096, 3000, 3128, 3306, 3389, 4443, 4567, 4848,
	5000, 5432, 5555, 5601, 5672, 5900, 5984, 5985, 5986,
	6000, 6379, 6443, 6666, 7001, 7002, 7070, 7080, 7443,
	8000, 8001, 8008, 8010, 8042, 8060, 8069, 8080, 8081,
	8083, 8088, 8090, 8091, 8161, 8443, 8444, 8500, 8800,
	8880, 8888, 8983, 9000, 9001, 9042, 9043, 9060, 9080,
	9090, 9091, 9200, 9300, 9443, 9999, 10000, 10250, 10443,
	11211, 15672, 27017, 28017, 50000, 50030, 50070,
}

// Common service names
var serviceNames = map[int]string{
	21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
	80: "http", 81: "http-alt", 110: "pop3", 111: "rpcbind",
	119: "nntp", 135: "msrpc", 139: "netbios", 143: "imap",
	161: "snmp", 389: "ldap", 443: "https", 445: "smb",
	465: "smtps", 514: "syslog", 515: "printer", 587: "submission",
	636: "ldaps", 993: "imaps", 995: "pop3s", 1080: "socks",
	1099: "java-rmi", 1433: "mssql", 1434: "mssql-m",
	1521: "oracle", 1723: "pptp", 2049: "nfs",
	2082: "cpanel", 2083: "cpanel-ssl", 2086: "whm", 2087: "whm-ssl",
	2095: "webmail", 2096: "webmail-ssl",
	3000: "dev-http/grafana", 3128: "squid-proxy", 3306: "mysql",
	3389: "rdp", 4443: "https-alt", 4848: "glassfish",
	5000: "dev-http/docker", 5432: "postgresql",
	5555: "adb", 5601: "kibana", 5672: "amqp", 5900: "vnc",
	5984: "couchdb", 5985: "winrm", 5986: "winrm-ssl",
	6000: "x11", 6379: "redis", 6443: "k8s-api",
	7001: "weblogic", 7002: "weblogic-ssl", 7070: "http-alt",
	7080: "http-alt", 7443: "https-alt",
	8000: "http-alt", 8001: "http-alt", 8008: "http-alt",
	8042: "yarn-nm", 8060: "http-alt", 8069: "odoo",
	8080: "http-proxy", 8081: "http-alt", 8083: "http-alt",
	8088: "http-alt", 8090: "http-alt", 8091: "http-alt",
	8161: "activemq", 8443: "https-alt", 8444: "https-alt",
	8500: "consul", 8800: "http-alt", 8880: "http-alt",
	8888: "http-alt", 8983: "solr",
	9000: "php-fpm/sonar", 9001: "http-alt",
	9042: "cassandra", 9043: "websphere-admin",
	9060: "websphere-admin", 9080: "http-alt",
	9090: "prometheus/cockpit", 9091: "http-alt",
	9200: "elasticsearch", 9300: "elasticsearch-transport",
	9443: "https-alt", 9999: "http-alt",
	10000: "webmin", 10250: "kubelet", 10443: "https-alt",
	11211: "memcached", 15672: "rabbitmq-mgmt",
	27017: "mongodb", 28017: "mongodb-http",
	50000: "sap/jenkins", 50030: "hadoop-jobtracker",
	50070: "hadoop-namenode",
}

// maxPortScanIPs caps how many of a target's resolved addresses get a full
// port sweep. Scanning every A/AAAA record unconditionally would multiply
// scan time without bound for targets with many records (round-robin LBs,
// large anycast setups); capping keeps the module's cost predictable while
// still covering more than the previous single-IP behaviour.
const maxPortScanIPs = 3

// cdnPorts are cPanel/WHM and common alt-HTTP(S) ports that tend to cluster
// on CDN/reverse-proxy edges rather than origin servers.
var cdnPorts = []int{2082, 2083, 2086, 2087, 2095, 2096, 8080, 8443, 8880}

// dangerousServices are services whose exposure is independently notable
// regardless of what else is open.
var dangerousServices = map[string]bool{
	"telnet": true, "ftp": true, "rdp": true, "vnc": true, "redis": true,
	"mongodb": true, "memcached": true, "elasticsearch": true, "couchdb": true,
	"adb": true, "mysql": true, "postgresql": true, "mssql": true, "oracle": true,
}

func RunPortScan(cfg *core.Config, report *core.ReconReport, log *core.Logger) {
	log.Module("PORTSCAN // Network Service Discovery")

	if cfg.Passive {
		log.Info("Skipping port scan in passive mode")
		return
	}

	host := extractHost(cfg.Target)
	resolveCtx, resolveCancel := cfg.Context(cfg.Timeout)
	ips, err := cfg.Resolver.LookupHost(resolveCtx, host)
	resolveCancel()
	if err != nil || len(ips) == 0 {
		log.Error("Could not resolve host: %v", err)
		return
	}

	targets, skipped := selectScanIPs(ips, maxPortScanIPs)
	if len(skipped) > 0 {
		log.Warn("%s resolves to %d IPs — scanning the first %d (%s); use -t <ip> to target another directly",
			host, len(ips), len(targets), strings.Join(targets, ", "))
	}

	ports := selectPorts(cfg.Ports)
	log.Info("Scanning %d ports across %d IP(s)...", len(ports), len(targets))

	// Respect -timeout for the connect, but keep the banner-read window short so
	// open web ports (which send no unsolicited banner) don't stall the scan.
	dialTimeout := cfg.Timeout
	if dialTimeout <= 0 {
		dialTimeout = 3 * time.Second
	}
	bannerWindow := 2 * time.Second
	if bannerWindow > dialTimeout {
		bannerWindow = dialTimeout
	}

	for _, ip := range targets {
		// Warn if the target resolves to a CDN — scanning the CDN edge is
		// pointless (you'd be scanning Cloudflare, not the origin). The real
		// value is finding the origin IP (via CT logs, SPF records, or
		// historical DNS).
		if cdn := detectCDNByIP(ip); cdn != "" {
			log.Warn("%s (%s) resolves to %s CDN — port scan hits the CDN edge, not the origin", host, ip, cdn)
			log.Warn("To scan the real server, find the origin IP (CT logs, SPF, DNS history) first")
		}
		log.Info("Scanning %s (%s)...", host, ip)

		result := scanOneIP(cfg, log, host, ip, ports, dialTimeout, bannerWindow)
		reportPortScanResult(report, log, result)
	}
}

// scanOneIP sweeps ports concurrently against a single IP and returns the
// findings. Split out of RunPortScan so the P4 multi-IP loop can call it once
// per resolved address.
func scanOneIP(cfg *core.Config, log *core.Logger, host, ip string, ports []int, dialTimeout, bannerWindow time.Duration) PortScanResult {
	result := PortScanResult{Host: ip}
	var (
		mu sync.Mutex
		wg sync.WaitGroup
		// Respect the exact -concurrency value (previously doubled, which could
		// exhaust file descriptors on constrained hosts and was inconsistent with
		// the other modules).
		sem = make(chan struct{}, cfg.Concurrency)
	)

	for _, port := range ports {
		wg.Add(1)
		sem <- struct{}{}
		go func(p int) {
			defer core.RecoverWorker(log, "portscan")
			defer wg.Done()
			defer func() { <-sem }()

			// net.JoinHostPort (not Sprintf) so an IPv6 target is bracketed
			// correctly — "%s:%d" on a bare IPv6 literal produces an address
			// net.Dial can't parse (go vet flags this).
			addr := net.JoinHostPort(ip, strconv.Itoa(p))
			conn, err := dialWithRetry(cfg, addr, dialTimeout)
			if err != nil {
				return
			}

			pi := PortInfo{
				Port:    p,
				State:   "open",
				Service: serviceNames[p],
			}
			pi.Banner = probeBanner(conn, pi.Service, host, bannerWindow)
			conn.Close()

			mu.Lock()
			result.OpenPorts = append(result.OpenPorts, pi)
			mu.Unlock()

			log.Info("  %-5d/tcp  open  %-25s %s", p, pi.Service, truncate(pi.Banner, 60))
		}(port)
	}
	wg.Wait()

	sort.Slice(result.OpenPorts, func(i, j int) bool {
		return result.OpenPorts[i].Port < result.OpenPorts[j].Port
	})
	log.Info("Total open ports on %s: %d", ip, len(result.OpenPorts))
	return result
}

// dialWithRetry connects once and, only on a *timeout* (not a definitive
// "connection refused"), retries exactly once. A dropped SYN under a short
// -timeout otherwise reads as "closed" when the port may well be open —
// retrying on refusal would just add noise since that's a firm answer.
func dialWithRetry(cfg *core.Config, addr string, dialTimeout time.Duration) (net.Conn, error) {
	dial := func() (net.Conn, error) {
		ctx, cancel := cfg.Context(dialTimeout)
		defer cancel()
		return (&net.Dialer{Timeout: dialTimeout}).DialContext(ctx, "tcp", addr)
	}
	conn, err := dial()
	if err == nil {
		return conn, nil
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return dial()
	}
	return nil, err
}

// probeBanner reads whatever the service offers on connect and, if that's
// nothing, tries to elicit a response: a minimal HEAD request for ports
// already classified as web (they never speak first), or a bare CRLF for
// everything else (some services wait for input before responding). Passive
// services (SSH, FTP, SMTP, …) that already greet on connect are unaffected —
// the active probe only fires when the passive read came up empty.
func probeBanner(conn net.Conn, service, hostHeader string, bannerWindow time.Duration) string {
	buf := make([]byte, 1024)

	conn.SetReadDeadline(time.Now().Add(bannerWindow))
	n, _ := conn.Read(buf)

	if n == 0 {
		if strings.Contains(service, "http") {
			conn.SetWriteDeadline(time.Now().Add(bannerWindow))
			fmt.Fprintf(conn, "HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n", hostHeader)
		} else {
			conn.SetWriteDeadline(time.Now().Add(bannerWindow))
			conn.Write([]byte("\r\n"))
		}
		conn.SetReadDeadline(time.Now().Add(bannerWindow))
		n, _ = conn.Read(buf)
	}
	if n == 0 {
		return ""
	}
	return truncate(strings.TrimSpace(string(buf[:n])), 200)
}

// selectScanIPs dedupes the resolved addresses, prefers IPv4 first (matching
// the previous single-IP behaviour's preference), and caps the result at max.
// Returns the IPs to scan and the ones dropped by the cap.
func selectScanIPs(ips []string, max int) (targets, skipped []string) {
	seen := make(map[string]bool, len(ips))
	var v4, v6 []string
	for _, ip := range ips {
		if seen[ip] {
			continue
		}
		seen[ip] = true
		if net.ParseIP(ip).To4() != nil {
			v4 = append(v4, ip)
		} else {
			v6 = append(v6, ip)
		}
	}
	ordered := append(v4, v6...)
	if len(ordered) <= max {
		return ordered, nil
	}
	return ordered[:max], ordered[max:]
}

// reportPortScanResult applies the CDN/dangerous-service analysis (previously
// inline in RunPortScan) to a single IP's scan result and adds findings.
func reportPortScanResult(report *core.ReconReport, log *core.Logger, result PortScanResult) {
	ip := result.Host

	cdnPortCount := 0
	for _, p := range result.OpenPorts {
		for _, cp := range cdnPorts {
			if p.Port == cp {
				cdnPortCount++
				break
			}
		}
	}
	isBehindCDN := cdnPortCount >= 4
	if isBehindCDN {
		log.Warn("%s appears to be behind a CDN/reverse proxy (Cloudflare, etc.)", ip)
		log.Warn("  %d ports may belong to the CDN infrastructure, not the origin server", cdnPortCount)
		report.Add(core.Finding{
			Module:      "portscan",
			WSTG:        "WSTG-INFO-10",
			Title:       fmt.Sprintf("Target behind CDN/WAF (%s) — port results may reflect CDN infrastructure", ip),
			Severity:    core.SevInfo,
			Description: fmt.Sprintf("%d of %d open ports are typical CDN ports (2082-2096, 8080, 8443, 8880). Results may not represent the origin server.", cdnPortCount, len(result.OpenPorts)),
		})
	}

	// Flag dangerous services (but only if not behind CDN, or if they're non-CDN ports)
	dangerous := []string{}
	for _, p := range result.OpenPorts {
		isCDNPort := false
		for _, cp := range cdnPorts {
			if p.Port == cp {
				isCDNPort = true
				break
			}
		}
		if isBehindCDN && isCDNPort {
			continue
		}
		if dangerousServices[p.Service] {
			dangerous = append(dangerous, fmt.Sprintf("%d/%s", p.Port, p.Service))
		}
	}
	if len(dangerous) > 0 {
		log.Warn("Potentially dangerous exposed services on %s: %v", ip, dangerous)
		report.Add(core.Finding{
			Module:      "portscan",
			WSTG:        "WSTG-CONF-01",
			Title:       fmt.Sprintf("Dangerous services exposed on %s: %d", ip, len(dangerous)),
			Severity:    core.SevHigh,
			Description: strings.Join(dangerous, ", "),
		})
	}

	report.Add(core.Finding{
		Module:   "portscan",
		WSTG:     "WSTG-INFO-04",
		Title:    fmt.Sprintf("Port scan: %d open ports on %s", len(result.OpenPorts), ip),
		Severity: core.SevInfo,
		Data:     result,
	})
}

func selectPorts(spec string) []int {
	switch strings.ToLower(spec) {
	case "full":
		ports := make([]int, 0, 65535)
		for i := 1; i <= 65535; i++ {
			ports = append(ports, i)
		}
		return ports
	case "top100":
		return top100Ports
	default:
		// Try to parse "start-end"
		var start, end int
		if _, err := fmt.Sscanf(spec, "%d-%d", &start, &end); err == nil {
			// Clamp to the valid TCP port range and reject inverted ranges so a
			// spec like "1000-10" (negative capacity → make panic) or
			// "1-70000000000" (huge allocation → OOM) can't crash the scanner.
			if start < 1 {
				start = 1
			}
			if end > 65535 {
				end = 65535
			}
			if end < start {
				return top100Ports
			}
			ports := make([]int, 0, end-start+1)
			for i := start; i <= end; i++ {
				ports = append(ports, i)
			}
			return ports
		}
		return top100Ports
	}
}

func extractHost(target string) string {
	target = strings.TrimPrefix(target, "https://")
	target = strings.TrimPrefix(target, "http://")
	host := strings.SplitN(target, "/", 2)[0]
	// IPv6 literal in brackets: "[::1]:8080" → "::1".
	if strings.HasPrefix(host, "[") {
		if i := strings.Index(host, "]"); i != -1 {
			return host[1:i]
		}
		return host
	}
	if i := strings.LastIndex(host, ":"); i != -1 && !strings.Contains(host[:i], ":") {
		host = host[:i]
	}
	return host
}
