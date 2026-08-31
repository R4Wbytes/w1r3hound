package modules

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/R4Wbytes/w1r3hound/internal/core"
)

// TestScanForSecrets_DropsPlaceholderAPIKeys covers the FP fix: placeholder /
// example API keys that fill config templates and docs must not be reported as
// real secrets, while a genuine high-entropy key still is.
func TestScanForSecrets_DropsPlaceholderAPIKeys(t *testing.T) {
	log := core.NewLogger(false)

	placeholders := []string{
		`api_key = "your-api-key-here-replace"`,
		`API_KEY = "CHANGEME_CHANGEME_CHANGEME"`,
		`apikey: "REPLACE_ME_WITH_REAL_KEY"`,
		`api_secret = "xxxxxxxxxxxxxxxxxxxx"`,
		`api-key="put_your_key_here_now"`,
	}
	for _, src := range placeholders {
		var res ContentResult
		scanForSecrets(&res, src, "test.js", log)
		for _, s := range res.SecretsFound {
			if s.Type == "Generic API Key" {
				t.Errorf("placeholder flagged as a real Generic API Key: %q → %+v", src, s)
			}
		}
	}
}

func TestScanForSecrets_KeepsRealAPIKey(t *testing.T) {
	log := core.NewLogger(false)
	// A high-entropy value with no dictionary/placeholder token.
	src := `const apiKey = "a8F3kQ92zLmX7bV1pR4t";`

	var res ContentResult
	scanForSecrets(&res, src, "app.js", log)

	found := false
	for _, s := range res.SecretsFound {
		if s.Type == "Generic API Key" {
			found = true
		}
	}
	if !found {
		t.Errorf("genuine API key was suppressed; secrets=%+v", res.SecretsFound)
	}
}

func TestIsLikelyPlaceholderSecret(t *testing.T) {
	drop := []string{
		"your-api-key-here", "EXAMPLE_KEY_VALUE", "changeme12345678",
		"REPLACE_ME_PLEASE", "xxxxxxxxxxxxxxxx", "0000000000000000",
	}
	for _, v := range drop {
		if !isLikelyPlaceholderSecret(v) {
			t.Errorf("expected %q to be treated as a placeholder", v)
		}
	}
	keep := []string{
		"a8F3kQ92zLmX7bV1pR4t", "sk9dJ2mNp4Qr7Tv0Wx3Yz", "Zm9vYmFyYmF6cXV4MTIz",
	}
	for _, v := range keep {
		if isLikelyPlaceholderSecret(v) {
			t.Errorf("expected %q to be treated as a real value", v)
		}
	}
	// Guard against a placeholder token colliding with a plausible real key body.
	if strings.Contains("a8F3kQ92zLmX7bV1pR4t", "your") {
		t.Fatal("test fixture unexpectedly contains a placeholder token")
	}
}

// TestRunContent_ScansSourceMapForSecrets covers the FN-5.3 fix: a secret that
// exists only in a source map's embedded original source (sourcesContent) — and
// was stripped from the served/minified bundle — must still be detected, because
// content now scans validated source-map bodies with the secret patterns.
func TestRunContent_ScansSourceMapForSecrets(t *testing.T) {
	const secret = "Xy9KqZ2mNp4Rt7Vw0Bc3Df" // high-entropy, not a placeholder
	sourceMap := `{"version":3,"file":"app.min.js","sources":["app.js"],` +
		`"names":[],"mappings":"AAAA",` +
		`"sourcesContent":["const apiKey = '` + secret + `';\n"]}`

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<!DOCTYPE html><html><body><script src="/app.min.js"></script></body></html>`))
	})
	mux.HandleFunc("/app.min.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		// The served bundle carries NO secret — only the sourceMappingURL comment.
		_, _ = w.Write([]byte("var a=1;\n//# sourceMappingURL=/app.min.js.map\n"))
	})
	mux.HandleFunc("/app.min.js.map", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(sourceMap))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cfg := core.DefaultConfig()
	cfg.Target = srv.URL
	cfg.Domain = "127.0.0.1" // httptest host; issameDomain gates JS/map fetches
	report := core.NewReport(srv.URL)

	RunContent(cfg, report, core.NewLogger(false))

	found := false
	for _, f := range report.Snapshot().Findings {
		var secrets []SecretMatch
		switch d := f.Data.(type) {
		case []SecretMatch:
			secrets = d
		case ContentResult:
			secrets = d.SecretsFound
		}
		for _, s := range secrets {
			if strings.Contains(s.Source, ".map") {
				found = true
			}
		}
	}
	if !found {
		t.Error("secret embedded only in the source map was not detected")
	}
}
