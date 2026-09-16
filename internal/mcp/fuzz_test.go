package mcp

import "testing"

func FuzzNormalizeTarget(f *testing.F) {
	f.Add("example.com")
	f.Add("https://example.com/path")
	f.Add("http://example.com")
	f.Add("[::1]:8080")
	f.Add("")
	f.Add("https://")
	f.Add("///")
	f.Fuzz(func(t *testing.T, target string) {
		_ = normalizeTarget(target)
	})
}

func FuzzExtractDomain(f *testing.F) {
	f.Add("https://example.com:8080/path")
	f.Add("[::1]:8080")
	f.Add("[::1")
	f.Add("::1")
	f.Add("")
	f.Add("http://user:pass@host:80/")
	f.Fuzz(func(t *testing.T, target string) {
		_ = extractDomain(target)
	})
}

func FuzzValidateTarget(f *testing.F) {
	f.Add("example.com")
	f.Add("10.0.0.1")
	f.Add("192.168.0.0/24")
	f.Add("https://example.com")
	f.Add("ftp://evil")
	f.Add("")
	f.Add("has spaces")
	f.Add("a]b[c")
	f.Fuzz(func(t *testing.T, target string) {
		_ = validateTarget(target)
	})
}
