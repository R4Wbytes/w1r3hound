package modules

import (
	"strings"
	"testing"
)

func TestPublicSuffixLabelCount(t *testing.T) {
	tests := []struct {
		domain string
		want   int
	}{
		{"example.com", 1},
		{"example.co.uk", 2},
		{"sub.example.co.uk", 2},
		{"example.org", 1},
		{"test.github.io", 2},
		{"deep.sub.example.com", 1},
		{"example.edu.au", 2},
	}
	for _, tt := range tests {
		labels := strings.Split(tt.domain, ".")
		got := publicSuffixLabelCount(labels)
		if got != tt.want {
			t.Errorf("publicSuffixLabelCount(%q) = %d, want %d", tt.domain, got, tt.want)
		}
	}
}

func TestExtractApexDomainPSL(t *testing.T) {
	tests := []struct {
		domain string
		want   string
	}{
		{"example.com", "example.com"},
		{"www.example.com", "example.com"},
		{"sub.deep.example.co.uk", "example.co.uk"},
		{"api.github.io", "api.github.io"},
	}
	for _, tt := range tests {
		got := extractApexDomain(tt.domain)
		if got != tt.want {
			t.Errorf("extractApexDomain(%q) = %q, want %q", tt.domain, got, tt.want)
		}
	}
}
