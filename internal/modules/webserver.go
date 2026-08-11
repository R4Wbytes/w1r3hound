package modules

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/w1r3hound/w1r3hound/internal/core"
)

// ──────────────────────────────────────────────
//  WSTG-INFO-02 — Fingerprint Web Server
//  Banner grabbing, header analysis, error-based
//  fingerprinting, TLS certificate inspection.
// ──────────────────────────────────────────────

type WebServerResult struct {
	Server        string            `json:"server"`
	PoweredBy     string            `json:"powered_by,omitempty"`
	Headers       map[string]string `json:"headers"`
	HTTPMethods   []string          `json:"http_methods_allowed,omitempty"`
	TLSInfo       *TLSDetail        `json:"tls,omitempty"`
	ErrorBehavior map[string]int    `json:"error_behavior,omitempty"`
}

type TLSDetail struct {
	Version     string   `json:"version"`
	CipherSuite string   `json:"cipher_suite"`
	CommonName  string   `json:"common_name"`
	SANs        []string `json:"sans,omitempty"`
	Issuer      string   `json:"issuer"`
	NotBefore   string   `json:"not_before"`
	NotAfter    string   `json:"not_after"`
	Expired     bool     `json:"expired"`
}

func RunWebServer(cfg *core.Config, report *core.ReconReport, log *core.Logger) {
	log.Module("PROBESCAN // Server Fingerprint & TLS Probe")

	client := core.NewHTTPClient(cfg)
	target := normalizeTarget(cfg.Target)
	result := WebServerResult{
		Headers:       make(map[string]string),
		ErrorBehavior: make(map[string]int),
	}

	// 1. Banner grabbing via HEAD (fall back to GET). A single failed/slow
	// request must NOT abort the module: TLS inspection and method probing below
	// are independent and often the most valuable output on a CDN-fronted host.
	resp, err := core.DoRequestRL(client, "HEAD", target, cfg.UserAgent, cfg.RL)
	if err != nil {
		log.Debug("HEAD failed (%v) — retrying with GET", err)
		resp, err = core.DoRequestRL(client, "GET", target, cfg.UserAgent, cfg.RL)
	}
	if err == nil && resp != nil {
		for k, vals := range resp.Header {
			result.Headers[k] = strings.Join(vals, "; ")
		}

		result.Server = resp.Header.Get("Server")
		result.PoweredBy = resp.Header.Get("X-Powered-By")

		if result.Server != "" {
			log.Info("Server: %s", result.Server)
		}
		if result.PoweredBy != "" {
			log.Info("X-Powered-By: %s", result.PoweredBy)
			report.Add(core.Finding{
				Module:      "webserver",
				WSTG:        "WSTG-INFO-02",
				Title:       fmt.Sprintf("X-Powered-By header exposed: %s", result.PoweredBy),
				Severity:    core.SevLow,
				Description: "The X-Powered-By header reveals server-side technology.",
			})
		}

		// Extra headers of interest
		for _, h := range []string{"X-Generator", "X-AspNet-Version", "X-AspNetMvc-Version", "X-Runtime", "X-Backend"} {
			if v := resp.Header.Get(h); v != "" {
				log.Warn("Leaky header %s: %s", h, v)
				report.Add(core.Finding{
					Module:   "webserver",
					WSTG:     "WSTG-INFO-02",
					Title:    fmt.Sprintf("Header leaks technology: %s = %s", h, v),
					Severity: core.SevLow,
				})
			}
		}
		resp.Body.Close()
	} else {
		log.Warn("Could not fetch headers (%v) — continuing with TLS inspection & method probing", err)
	}

	// 2. HTTP methods probing (WSTG-CONF-06)
	log.Info("Probing HTTP methods...")
	if !cfg.Passive {
		methods := []string{"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE"}
		// Probe against a non-existent path to avoid side effects on root
		probeURL := target + "/W1r3hound-method-probe-nonexistent"
		for _, m := range methods {
			r, err := core.DoRequestRL(client, m, probeURL, cfg.UserAgent, cfg.RL)
			if err != nil {
				continue
			}
			r.Body.Close()
			result.ErrorBehavior[m] = r.StatusCode
			// A method is "accepted" only if the server returns 2xx. A 3xx is a
			// redirect the framework issues for ANY method — it doesn't mean the
			// method is served — so counting it here inflated the allowed-method
			// list (e.g. every method "accepted" on a host that redirects all
			// paths to /login). 404/403/500 means the framework doesn't block it
			// at the method level but doesn't actually serve it either — not a
			// real finding.
			if r.StatusCode >= 200 && r.StatusCode < 300 {
				result.HTTPMethods = append(result.HTTPMethods, m)
			}
		}
		// TRACE is dangerous even with 200 (XST)
		if traceStatus, ok := result.ErrorBehavior["TRACE"]; ok && traceStatus == 200 {
			if !contains(result.HTTPMethods, "TRACE") {
				result.HTTPMethods = append(result.HTTPMethods, "TRACE")
			}
			log.Warn("TRACE method enabled — potential XST vulnerability")
			report.Add(core.Finding{
				Module:      "webserver",
				WSTG:        "WSTG-CONF-06",
				Title:       "HTTP TRACE method enabled",
				Severity:    core.SevMedium,
				Description: "TRACE can be used for Cross-Site Tracing (XST) attacks.",
			})
		}
		// PUT/DELETE are dangerous only if they return 2xx
		dangerousMethods := []string{}
		for _, dm := range []string{"PUT", "DELETE"} {
			if sc, ok := result.ErrorBehavior[dm]; ok && sc >= 200 && sc < 300 {
				dangerousMethods = append(dangerousMethods, fmt.Sprintf("%s→%d", dm, sc))
			}
		}
		if len(dangerousMethods) > 0 {
			log.Warn("Dangerous HTTP methods return 2xx: %v", dangerousMethods)
			report.Add(core.Finding{
				Module:      "webserver",
				WSTG:        "WSTG-CONF-06",
				Title:       fmt.Sprintf("Dangerous HTTP methods accepted: %s", strings.Join(dangerousMethods, ", ")),
				Severity:    core.SevMedium,
				Description: fmt.Sprintf("Server returns success for: %v", dangerousMethods),
			})
		}
		log.Info("Allowed methods: %v", result.HTTPMethods)
	}

	// 3. Error-based fingerprinting — send malformed request
	if !cfg.Passive {
		log.Debug("Sending malformed request for error fingerprinting...")
		addr, isTLS := hostPort(target)
		var conn net.Conn
		var err error
		// BUGFIX: previously hardcoded InsecureSkipVerify: true, which silently
		// ignored cfg.SkipSSLCheck. Users passing -skip-tls-verify=false got
		// no enforcement here — the dial would still bypass certificate
		// validation, undermining the flag's stated purpose (W1r3hound is
		// often pointed at broken/self-signed TLS, but the user must be
		// the one to opt into that, not the tool). Now honours cfg.
		// PERF: dial is now context-aware so SIGINT can tear it down
		// instantly instead of blocking for cfg.Timeout.
		if isTLS {
			ctx, cancel := cfg.Context(cfg.Timeout)
			defer cancel()
			dialer := &net.Dialer{Timeout: cfg.Timeout}
			rawConn, dialErr := dialer.DialContext(ctx, "tcp", addr)
			if dialErr != nil {
				err = dialErr
			} else {
				tlsConn := tls.Client(rawConn, &tls.Config{InsecureSkipVerify: cfg.SkipSSLCheck})
				err = tlsConn.HandshakeContext(ctx)
				if err == nil {
					conn = tlsConn
				} else {
					rawConn.Close()
				}
			}
		} else {
			conn, err = net.DialTimeout("tcp", addr, cfg.Timeout)
		}
		if err == nil {
			fmt.Fprintf(conn, "GET / SANTA CLAUS/1.1\r\nHost: %s\r\n\r\n", cfg.Domain)
			conn.SetReadDeadline(time.Now().Add(cfg.Timeout))
			buf := make([]byte, 4096)
			n, _ := conn.Read(buf)
			conn.Close()
			if n > 0 {
				errResp := string(buf[:n])
				log.Debug("Error response fingerprint: %s", truncate(errResp, 200))
			}
		}
	}

	// 4. TLS certificate inspection
	if strings.HasPrefix(target, "https://") {
		log.Info("Inspecting TLS certificate...")
		addr, _ := hostPort(target)
		tlsInfo := inspectTLS(addr, cfg.Timeout, cfg.SkipSSLCheck, cfg, log)
		if tlsInfo != nil {
			result.TLSInfo = tlsInfo
			log.Info("TLS CN: %s  Issuer: %s", tlsInfo.CommonName, tlsInfo.Issuer)
			log.Info("Valid: %s → %s", tlsInfo.NotBefore, tlsInfo.NotAfter)
			if tlsInfo.Expired {
				log.Warn("TLS certificate is EXPIRED!")
				report.Add(core.Finding{
					Module:   "webserver",
					WSTG:     "WSTG-CRYP-01",
					Title:    "TLS certificate expired",
					Severity: core.SevHigh,
				})
			}
			if len(tlsInfo.SANs) > 0 {
				log.Info("SANs: %s", strings.Join(tlsInfo.SANs, ", "))
			}
		}
	}

	report.Add(core.Finding{
		Module:   "webserver",
		WSTG:     "WSTG-INFO-02",
		Title:    fmt.Sprintf("Web server fingerprint: %s", result.Server),
		Severity: core.SevInfo,
		Data:     result,
	})
}

func inspectTLS(hostAddr string, timeout time.Duration, skipVerify bool, cfg *core.Config, log *core.Logger) *TLSDetail {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	// PERF: previously used tls.DialWithDialer with a fixed Timeout, so SIGINT
	// couldn't interrupt an in-flight TLS handshake. Now the dialer's
	// Cancel channel fires when the parent context is cancelled (for global
	// SIGINT cancellation, callers should derive cfg.Context here; for now
	// the per-request timeout still bounds the dial — this only fixes the
	// ctx-propagation in the dialer, not the missing global cancel hook
	// inside inspectTLS itself, which is called outside the loop).
	var parentCtx context.Context
	var parentCancel context.CancelFunc
	if cfg != nil {
		parentCtx, parentCancel = cfg.Context(timeout)
	} else {
		parentCtx, parentCancel = context.WithTimeout(context.Background(), timeout)
	}
	defer parentCancel()
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: timeout, Cancel: parentCtx.Done()},
		"tcp",
		hostAddr,
		// BUGFIX: previously hardcoded true. Now honours the caller's
		// skipVerify flag (sourced from cfg.SkipSSLCheck). Lets users
		// enforce strict validation when needed.
		&tls.Config{InsecureSkipVerify: skipVerify},
	)
	if err != nil {
		log.Debug("TLS connect failed: %v", err)
		return nil
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil
	}

	cert := state.PeerCertificates[0]
	d := &TLSDetail{
		Version:     tlsVersionName(state.Version),
		CipherSuite: tls.CipherSuiteName(state.CipherSuite),
		CommonName:  cert.Subject.CommonName,
		SANs:        cert.DNSNames,
		Issuer:      cert.Issuer.CommonName,
		NotBefore:   cert.NotBefore.Format("2006-01-02"),
		NotAfter:    cert.NotAfter.Format("2006-01-02"),
		Expired:     time.Now().After(cert.NotAfter),
	}
	return d
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

func hostPort(target string) (string, bool) {
	isTLS := strings.HasPrefix(target, "https://")
	t := strings.TrimPrefix(target, "https://")
	t = strings.TrimPrefix(t, "http://")
	t = strings.Split(t, "/")[0]
	// Already "host:port" (this correctly accepts bracketed IPv6 like
	// "[::1]:8443" while rejecting a bare IPv6 literal such as "::1").
	if _, _, err := net.SplitHostPort(t); err == nil {
		return t, isTLS
	}
	// No port present. Strip any IPv6 brackets, then re-join with the default
	// port via net.JoinHostPort so an IPv6 literal is bracketed correctly.
	host := t
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}
	port := "80"
	if isTLS {
		port = "443"
	}
	return net.JoinHostPort(host, port), isTLS
}
