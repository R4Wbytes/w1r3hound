package main

import (
	"io/fs"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// These guard the strict Content-Security-Policy served by securityHeaders
// ("default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:").
// The reskinned SPA must stay self-hosted with no inline scripts or event
// handlers, so any regression that would need a looser CSP fails the build.
var (
	// An HTML tag carrying an inline event handler, e.g. onclick=, onload=.
	inlineHandlerRe = regexp.MustCompile(`(?i)<[a-zA-Z][^>]*\son[a-z]+\s*=`)
	// A src=/href= whose value is absolute-external or protocol-relative.
	externalRefRe = regexp.MustCompile(`(?i)(?:src|href)\s*=\s*["'](?:https?:)?//`)
	// A <script ...> ... </script> block (attributes, then body).
	scriptBlockRe = regexp.MustCompile(`(?is)<script\b([^>]*)>(.*?)</script>`)
	// A CSS url() pointing at an absolute-external or protocol-relative URL.
	cssExternalURLRe = regexp.MustCompile(`(?i)url\(\s*['"]?(?:https?:)?//`)
)

func TestStaticAssetsAreCSPClean(t *testing.T) {
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		t.Fatalf("fs.Sub: %v", err)
	}

	var violations []string
	var htmlSeen, jsSeen, cssSeen int

	walkErr := fs.WalkDir(sub, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		data, err := fs.ReadFile(sub, path)
		if err != nil {
			return err
		}
		content := string(data)

		switch strings.ToLower(filepath.Ext(path)) {
		case ".html":
			htmlSeen++
			if loc := inlineHandlerRe.FindString(content); loc != "" {
				violations = append(violations, path+": inline event handler: "+strings.TrimSpace(loc))
			}
			if loc := externalRefRe.FindString(content); loc != "" {
				violations = append(violations, path+": external src/href: "+loc)
			}
			for _, m := range scriptBlockRe.FindAllStringSubmatch(content, -1) {
				attrs, body := m[1], strings.TrimSpace(m[2])
				if !strings.Contains(strings.ToLower(attrs), "src=") {
					violations = append(violations, path+": <script> without src (inline script)")
				}
				if body != "" {
					violations = append(violations, path+": inline <script> body")
				}
			}
		case ".js":
			jsSeen++
			// Catches on*= handlers or external src/href injected via innerHTML.
			if loc := inlineHandlerRe.FindString(content); loc != "" {
				violations = append(violations, path+": inline event handler in JS string: "+strings.TrimSpace(loc))
			}
			if loc := externalRefRe.FindString(content); loc != "" {
				violations = append(violations, path+": external src/href in JS string: "+loc)
			}
		case ".css":
			cssSeen++
			if loc := cssExternalURLRe.FindString(content); loc != "" {
				violations = append(violations, path+": external CSS url(): "+loc)
			}
		}
		return nil
	})
	if walkErr != nil {
		t.Fatalf("walk static: %v", walkErr)
	}

	// Guard against a vacuously-passing test if the embed ever breaks.
	if htmlSeen == 0 || jsSeen == 0 || cssSeen == 0 {
		t.Fatalf("expected html+js+css assets, saw html=%d js=%d css=%d", htmlSeen, jsSeen, cssSeen)
	}
	if len(violations) != 0 {
		t.Fatalf("CSP hygiene violations:\n  %s", strings.Join(violations, "\n  "))
	}
}
