package modules

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
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

		// Detect custom non-standard X- headers that may leak internal
		// information (hiring pages, debug flags, internal routing, build
		// metadata).  Standard headers and well-known security headers are
		// already covered above; this catches the long tail of app-specific
		// headers that frameworks like Express allow developers to set.
		for _, hh := range nonStandardInfoHeaders(resp.Header) {
			log.Info("Non-standard header: %s = %s", hh[0], hh[1])
			report.Add(core.Finding{
				Module:      "webserver",
				WSTG:        "WSTG-INFO-02",
				Title:       fmt.Sprintf("Non-standard header leaks info: %s = %s", hh[0], hh[1]),
				Severity:    core.SevInfo,
				Description: fmt.Sprintf("Custom response header %s may reveal internal information.", hh[0]),
			})
		}
		resp.Body.Close()
	} else {
		log.Warn("Could not fetch headers (%v) — continuing with TLS inspection & method probing", err)
	}

	// 2. HTTP methods probing (WSTG-CONF-06)
	log.Info("Probing HTTP methods...")
	if !cfg.Passive {
		methods := []string{"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE"}
		probeURL := target + "/W1r3hound-method-probe-nonexistent"

		// Establish a baseline GET response body hash. SPA frameworks
		// (Express, Next.js, Nuxt, Angular Universal, …) serve the same
		// index.html catch-all for any method/path combination, so every
		// method returns 200 with an identical body. Comparing each
		// method's body against the GET baseline detects this and
		// suppresses the resulting false positives.
		var baselineHash [sha256.Size]byte
		var baselineLen int64
		if baseResp, baseErr := core.DoRequestRL(client, "GET", probeURL, cfg.UserAgent, cfg.RL); baseErr == nil {
			baseBody, _ := io.ReadAll(io.LimitReader(baseResp.Body, 256*1024))
			baseResp.Body.Close()
			baselineHash = sha256.Sum256(baseBody)
			baselineLen = int64(len(baseBody))
		}

		// Per-method body hashes + TRACE body for echo detection.
		methodBodyHash := make(map[string][sha256.Size]byte)
		var traceBody string
		var traceCT string

		for _, m := range methods {
			r, err := core.DoRequestRL(client, m, probeURL, cfg.UserAgent, cfg.RL)
			if err != nil {
				continue
			}
			body, _ := io.ReadAll(io.LimitReader(r.Body, 256*1024))
			r.Body.Close()
			result.ErrorBehavior[m] = r.StatusCode
			h := sha256.Sum256(body)
			methodBodyHash[m] = h

			if m == "TRACE" {
				traceBody = string(body)
				traceCT = r.Header.Get("Content-Type")
			}

			if r.StatusCode >= 200 && r.StatusCode < 300 {
				// Suppress SPA catch-all: if the body is identical to the
				// baseline GET and the response is HTML, this method is
				// not actually handled — the SPA fallback served it.
				if baselineLen > 0 && h == baselineHash && isHTMLContentType(r.Header.Get("Content-Type")) {
					log.Debug("Method %s returned SPA catch-all (body matches GET baseline) — suppressed", m)
					continue
				}
				result.HTTPMethods = append(result.HTTPMethods, m)
			}
		}

		// TRACE is a real XST vector only when the server echoes the
		// request back per RFC 7231 §4.3.8: Content-Type message/http, or
		// the body literally starts with the request line. A SPA catch-all
		// that returns text/html with the same index.html for any method
		// is not a TRACE implementation.
		traceIsReal := false
		if traceStatus, ok := result.ErrorBehavior["TRACE"]; ok && traceStatus == 200 {
			if strings.HasPrefix(traceCT, "message/http") {
				traceIsReal = true
			} else if strings.HasPrefix(strings.TrimSpace(traceBody), "TRACE ") {
				traceIsReal = true
			}
		}
		if traceIsReal {
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
		} else if _, ok := result.ErrorBehavior["TRACE"]; ok && result.ErrorBehavior["TRACE"] == 200 {
			log.Debug("TRACE returns 200 but does not echo request (SPA catch-all) — not a real XST")
		}

		// When the SPA catch-all suppressed every probed method, the
		// list contains only OPTIONS (its response body differs).
		// Direct body comparison is unreliable on catch-all servers,
		// so fall back to the Allow or Access-Control-Allow-Methods
		// header from the OPTIONS response to populate the list.
		if len(result.HTTPMethods) <= 1 {
			if optResp, optErr := core.DoRequestRL(client, "OPTIONS", target, cfg.UserAgent, cfg.RL); optErr == nil {
				allowHdr := optResp.Header.Get("Allow")
				if allowHdr == "" {
					allowHdr = optResp.Header.Get("Access-Control-Allow-Methods")
				}
				optResp.Body.Close()
				if allowHdr != "" {
					declared := parseMethodList(allowHdr)
					if len(declared) > len(result.HTTPMethods) {
						result.HTTPMethods = declared
						log.Debug("SPA catch-all detected — methods populated from server-declared header: %v", declared)
					}
				}
			}
		}

		// PUT/DELETE are dangerous only if they return 2xx AND the
		// response differs from the baseline GET (ruling out SPA
		// catch-alls that serve index.html for every method).
		dangerousMethods := []string{}
		for _, dm := range []string{"PUT", "DELETE"} {
			sc, ok := result.ErrorBehavior[dm]
			if !ok || sc < 200 || sc >= 300 {
				continue
			}
			if h, hOK := methodBodyHash[dm]; hOK && baselineLen > 0 && h == baselineHash {
				log.Debug("%s returns 200 but body matches GET baseline (SPA catch-all) — suppressed", dm)
				continue
			}
			dangerousMethods = append(dangerousMethods, fmt.Sprintf("%s→%d", dm, sc))
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

	// Title fallback: an empty Server header (Express/Node default, CDN-stripped)
	// previously rendered as "Web server fingerprint: " — a useless report line.
	fpTitle := result.Server
	if fpTitle == "" {
		if result.PoweredBy != "" {
			fpTitle = "(no Server header) X-Powered-By: " + result.PoweredBy
		} else {
			fpTitle = "(no Server header — server suppresses banner)"
		}
	}
	report.Add(core.Finding{
		Module:   "webserver",
		WSTG:     "WSTG-INFO-02",
		Title:    fmt.Sprintf("Web server fingerprint: %s", fpTitle),
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

func isHTMLContentType(ct string) bool {
	ct = strings.ToLower(ct)
	return strings.HasPrefix(ct, "text/html") || strings.Contains(ct, "xhtml")
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

// parseMethodList splits a comma-separated HTTP method list (from Allow or
// Access-Control-Allow-Methods headers) into deduplicated uppercase tokens.
func parseMethodList(hdr string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, part := range strings.Split(hdr, ",") {
		m := strings.TrimSpace(strings.ToUpper(part))
		if m != "" && !seen[m] {
			seen[m] = true
			out = append(out, m)
		}
	}
	return out
}

// standardHeaders is the set of well-known HTTP headers that every web server
// uses.  Any header NOT in this set AND starting with "X-" is potentially a
// custom application header that reveals internal information.
var standardHeaders = map[string]bool{
	"Accept-Ranges":                  true,
	"Access-Control-Allow-Credentials": true,
	"Access-Control-Allow-Headers":  true,
	"Access-Control-Allow-Methods":  true,
	"Access-Control-Allow-Origin":   true,
	"Access-Control-Expose-Headers": true,
	"Access-Control-Max-Age":        true,
	"Age":                           true,
	"Allow":                         true,
	"Cache-Control":                 true,
	"Connection":                    true,
	"Content-Disposition":           true,
	"Content-Encoding":              true,
	"Content-Language":              true,
	"Content-Length":                 true,
	"Content-Range":                 true,
	"Content-Security-Policy":       true,
	"Content-Security-Policy-Report-Only": true,
	"Content-Type":                  true,
	"Cross-Origin-Embedder-Policy":  true,
	"Cross-Origin-Opener-Policy":    true,
	"Cross-Origin-Resource-Policy":  true,
	"Date":                          true,
	"Etag":                          true,
	"Expires":                       true,
	"Feature-Policy":                true,
	"Keep-Alive":                    true,
	"Last-Modified":                 true,
	"Link":                          true,
	"Location":                      true,
	"Nel":                           true,
	"P3p":                           true,
	"Permissions-Policy":            true,
	"Pragma":                        true,
	"Referrer-Policy":               true,
	"Report-To":                     true,
	"Retry-After":                   true,
	"Server":                        true,
	"Set-Cookie":                    true,
	"Strict-Transport-Security":     true,
	"Timing-Allow-Origin":           true,
	"Tk":                            true,
	"Trailer":                       true,
	"Transfer-Encoding":             true,
	"Vary":                          true,
	"Via":                           true,
	"Www-Authenticate":              true,
	"X-Content-Type-Options":        true,
	"X-Download-Options":            true,
	"X-Frame-Options":               true,
	"X-Permitted-Cross-Domain-Policies": true,
	"X-Xss-Protection":              true,
	// Well-known infrastructure headers already covered above
	"X-Powered-By":                  true,
	"X-Generator":                   true,
	"X-Aspnet-Version":              true,
	"X-Aspnetmvc-Version":           true,
	"X-Runtime":                     true,
	"X-Backend":                     true,
	// CDN / proxy / cache headers (infra, not app-specific)
	"X-Cache":                       true,
	"X-Cache-Status":                true,
	"X-Cache-Hits":                  true,
	"X-Served-By":                   true,
	"X-Backend-Server":              true,
	"X-Cdn":                         true,
	"X-Request-Id":                  true,
	"X-Correlation-Id":              true,
	"X-Amzn-Requestid":              true,
	"X-Amzn-Trace-Id":               true,
	"X-Azure-Ref":                   true,
	"X-Envoy-Upstream-Service-Time": true,
	"X-Varnish":                     true,
	"X-Pingback":                    true,
	"X-Litespeed-Cache":             true,
	"X-Turbo-Charged-By":            true,
	"X-Mod-Pagespeed":               true,
	"X-Page-Speed":                  true,
	"X-Drupal-Cache":                true,
	"X-Drupal-Dynamic-Cache":        true,
	"X-Envoy-Decorator-Operation":   true,
	"X-Kubernetes-Pf-Flowschema-Uid": true,
}

// nonStandardInfoHeaders returns custom response headers that are not in the
// standard/well-known set and start with "X-".  These often leak internal
// application details (hiring pages, debug flags, build metadata).
func nonStandardInfoHeaders(h http.Header) [][2]string {
	var found [][2]string
	for name, vals := range h {
		canonical := http.CanonicalHeaderKey(name)
		if !strings.HasPrefix(canonical, "X-") {
			continue
		}
		if standardHeaders[canonical] {
			continue
		}
		found = append(found, [2]string{canonical, strings.Join(vals, "; ")})
	}
	return found
}
