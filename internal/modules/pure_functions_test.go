package modules

import (
	"crypto/tls"
	"net/http"
	"strings"
	"testing"
)

func TestIsBoringComment(t *testing.T) {
	boring := []string{
		"[if IE]",
		"Google Analytics",
		"facebook sdk",
		"schema.org markup",
		strings.Repeat("x", 501), // too long
	}
	for _, c := range boring {
		if !isBoringComment(c) {
			t.Errorf("expected %q to be boring", truncate(c, 30))
		}
	}
	interesting := []string{
		"TODO: remove hardcoded password",
		"DEBUG: admin bypass enabled",
		"API key: sk-1234",
	}
	for _, c := range interesting {
		if isBoringComment(c) {
			t.Errorf("expected %q to NOT be boring", c)
		}
	}
}

func TestIsDocumentationIP(t *testing.T) {
	docs := []string{
		"10.0.0.0", "10.0.0.1", "192.168.0.1", "192.168.1.1", "172.16.0.0",
	}
	for _, ip := range docs {
		if !isDocumentationIP(ip) {
			t.Errorf("expected %q to be a documentation IP", ip)
		}
	}
	real := []string{
		"10.0.0.5", "192.168.1.100", "172.16.5.10", "8.8.8.8", "1.1.1.1",
	}
	for _, ip := range real {
		if isDocumentationIP(ip) {
			t.Errorf("expected %q to NOT be a documentation IP", ip)
		}
	}
}

func TestIsSensitiveEndpoint(t *testing.T) {
	sensitive := []string{
		"/admin/users", "/api/config", "/internal/status",
		"/debug/pprof", "/actuator/health", "/management/info",
	}
	for _, ep := range sensitive {
		if !isSensitiveEndpoint(ep) {
			t.Errorf("expected %q to be sensitive", ep)
		}
	}
	safe := []string{
		"/api/products", "/users/login", "/public/assets",
	}
	for _, ep := range safe {
		if isSensitiveEndpoint(ep) {
			t.Errorf("expected %q to NOT be sensitive", ep)
		}
	}
}

func TestStripQuery(t *testing.T) {
	cases := map[string]string{
		"/path?foo=bar": "/path",
		"/path":         "/path",
		"/a?b=c&d=e":    "/a",
		"?onlyquery":    "",
		"/path?":        "/path",
	}
	for in, want := range cases {
		if got := stripQuery(in); got != want {
			t.Errorf("stripQuery(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSameSiteName(t *testing.T) {
	cases := map[http.SameSite]string{
		http.SameSiteDefaultMode: "Default",
		http.SameSiteLaxMode:     "Lax",
		http.SameSiteStrictMode:  "Strict",
		http.SameSiteNoneMode:    "None",
		http.SameSite(99):        "Unknown",
	}
	for mode, want := range cases {
		if got := sameSiteName(mode); got != want {
			t.Errorf("sameSiteName(%d) = %q, want %q", mode, got, want)
		}
	}
}

func TestContainsVersion(t *testing.T) {
	yes := []string{"nginx/1.21", "Apache/2.4.51", "Express 4.18"}
	for _, s := range yes {
		if !containsVersion(s) {
			t.Errorf("expected %q to contain a version", s)
		}
	}
	no := []string{"nginx", "Apache", "Express", ""}
	for _, s := range no {
		if containsVersion(s) {
			t.Errorf("expected %q to NOT contain a version", s)
		}
	}
}

func TestIsSessionCookie(t *testing.T) {
	session := []string{
		"PHPSESSID", "JSESSIONID", "connect.sid", "session",
		"auth_token", "access_token", "my_session_cookie",
	}
	for _, name := range session {
		if !isSessionCookie(name) {
			t.Errorf("expected %q to be a session cookie", name)
		}
	}
	notSession := []string{
		"csrf_token", "XSRF-TOKEN", "authenticity_token",
		"_ga", "theme", "language", "consent",
	}
	for _, name := range notSession {
		if isSessionCookie(name) {
			t.Errorf("expected %q to NOT be a session cookie", name)
		}
	}
}

func TestTlsVersionName(t *testing.T) {
	cases := map[uint16]string{
		tls.VersionTLS10: "TLS 1.0",
		tls.VersionTLS11: "TLS 1.1",
		tls.VersionTLS12: "TLS 1.2",
		tls.VersionTLS13: "TLS 1.3",
		0x0200:           "0x0200",
	}
	for v, want := range cases {
		if got := tlsVersionName(v); got != want {
			t.Errorf("tlsVersionName(0x%04x) = %q, want %q", v, got, want)
		}
	}
}

func TestParseMethodList(t *testing.T) {
	cases := []struct {
		input string
		want  []string
	}{
		{"GET, POST, PUT", []string{"GET", "POST", "PUT"}},
		{"get, GET, Get", []string{"GET"}}, // deduplication
		{"", nil},
		{"OPTIONS, , TRACE", []string{"OPTIONS", "TRACE"}},
	}
	for _, tc := range cases {
		got := parseMethodList(tc.input)
		if len(got) != len(tc.want) {
			t.Errorf("parseMethodList(%q) = %v, want %v", tc.input, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("parseMethodList(%q)[%d] = %q, want %q", tc.input, i, got[i], tc.want[i])
			}
		}
	}
}

func TestIsGenericTitle(t *testing.T) {
	generic := []string{
		"404 Not Found", "Error", "Page Not Found", "Welcome",
		"Home", "Index", "Loading...", "ab", // <=3 chars
	}
	for _, title := range generic {
		if !isGenericTitle(title) {
			t.Errorf("expected %q to be generic", title)
		}
	}
	specific := []string{
		"User Dashboard", "Product Catalog", "ACME Corp Admin Panel",
	}
	for _, title := range specific {
		if isGenericTitle(title) {
			t.Errorf("expected %q to NOT be generic", title)
		}
	}
}

func TestIsSoft404_TitleMatch(t *testing.T) {
	baseline := soft404Baseline{
		status:   200,
		bodyLen:  500,
		titleTag: "Not Found",
		bodyHash: 0,
	}
	body := `<html><head><title>Not Found</title></head><body>Sorry</body></html>`
	if !isSoft404(baseline, len(body), body, "/test") {
		t.Error("expected soft-404 when title matches baseline")
	}
}

func TestIsSoft404_RawFileNotSoft404(t *testing.T) {
	baseline := soft404Baseline{
		status:  200,
		bodyLen: 50,
	}
	body := "DB_PASSWORD=secret123\nAPI_KEY=abcdef"
	if isSoft404(baseline, len(body), body, "/.env") {
		t.Error("raw file without HTML should never be a soft-404")
	}
}

func TestIsSoft404_NotFoundKeywordInTitle(t *testing.T) {
	baseline := soft404Baseline{
		status:   200,
		bodyLen:  10000, // very different size
		titleTag: "My App",
	}
	body := `<html><head><title>page not found</title></head><body>The page was not found.</body></html>`
	if !isSoft404(baseline, len(body), body, "/missing") {
		t.Error("expected soft-404 for 'not found' keyword in title")
	}
}
