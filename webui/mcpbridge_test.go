package main

import (
	"context"
	"strings"
	"testing"
	"time"
)

func newTestBridge(t *testing.T) *MCPBridge {
	t.Helper()
	b, err := NewMCPBridge("test")
	if err != nil {
		t.Fatalf("NewMCPBridge: %v", err)
	}
	t.Cleanup(b.Close)
	return b
}

func TestNewMCPBridge(t *testing.T) {
	b := newTestBridge(t)
	if b == nil {
		t.Fatal("bridge is nil")
	}
}

func TestMCPBridgeCallTool(t *testing.T) {
	b := newTestBridge(t)
	text, err := b.CallTool("list_modules", nil)
	if err != nil {
		t.Fatalf("CallTool list_modules: %v", err)
	}
	if text == "" {
		t.Fatal("list_modules returned empty text")
	}
	for _, name := range []string{"recon", "portscan", "crawler"} {
		if !strings.Contains(text, name) {
			t.Errorf("list_modules output missing %q", name)
		}
	}
}

func TestMCPBridgePrompts(t *testing.T) {
	b := newTestBridge(t)
	raw, err := b.Prompts()
	if err != nil {
		t.Fatalf("Prompts: %v", err)
	}
	s := string(raw)
	for _, name := range []string{"passive_recon", "bug_bounty_recon", "exhaustive_recon", "full_recon", "web_assessment", "subdomain_takeover_check"} {
		if !strings.Contains(s, name) {
			t.Errorf("prompts missing %q", name)
		}
	}
}

func TestMCPBridgeGetPrompt(t *testing.T) {
	b := newTestBridge(t)
	msgs, err := b.GetPrompt("passive_recon", map[string]string{"target": "example.com"})
	if err != nil {
		t.Fatalf("GetPrompt: %v", err)
	}
	if len(msgs) == 0 {
		t.Fatal("GetPrompt returned empty messages")
	}
	if !strings.Contains(string(msgs), "example.com") {
		t.Error("prompt messages do not reference the target")
	}
}

func TestMCPBridgeScanInvalidTarget(t *testing.T) {
	b := newTestBridge(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := b.Scan(ctx, MCPScanParams{Target: ""}, nil)
	if err == nil {
		t.Fatal("expected error for empty target, got nil")
	}
	if !strings.Contains(err.Error(), "target") {
		t.Errorf("error should mention target, got: %v", err)
	}
}

func TestMCPBridgeClose(t *testing.T) {
	b, err := NewMCPBridge("test")
	if err != nil {
		t.Fatalf("NewMCPBridge: %v", err)
	}
	b.Close()
	// After close, writing to the pipe should fail.
	_, err = b.CallTool("server_info", nil)
	if err == nil {
		t.Fatal("expected error after Close, got nil")
	}
}
