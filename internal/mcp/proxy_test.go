package mcp

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestExecuteScanRejectsBadProxy ensures an unsupported proxy scheme is rejected
// during argument validation, before any network activity.
func TestExecuteScanRejectsBadProxy(t *testing.T) {
	args, _ := json.Marshal(map[string]any{"target": "example.com", "proxy": "ftp://nope"})
	tr := executeScan(json.RawMessage(args), &toolCall{})
	if !tr.IsError {
		t.Fatalf("expected an error result for an unsupported proxy scheme, got: %s", tr.Text)
	}
	if !strings.Contains(strings.ToLower(tr.Text), "proxy") {
		t.Errorf("expected the error to mention the proxy, got: %s", tr.Text)
	}
}

// TestScanToolAdvertisesProxy confirms the scan tool's input schema exposes the
// proxy parameters so agents can discover them.
func TestScanToolAdvertisesProxy(t *testing.T) {
	data, err := json.Marshal(toolDefinitions())
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	for _, want := range []string{`"proxy"`, `"proxy_cacert"`} {
		if !strings.Contains(s, want) {
			t.Errorf("tool definitions do not advertise %s", want)
		}
	}
}
