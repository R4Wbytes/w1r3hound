package main

import (
	"bufio"
	"context"
	"io"
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

// HC-1: readLoop exit must unblock pending callers instead of leaking goroutines.
func TestMCPBridgeReadLoopDrainsPending(t *testing.T) {
	b, err := NewMCPBridge("test")
	if err != nil {
		t.Fatalf("NewMCPBridge: %v", err)
	}

	// Close the bridge to trigger readLoop exit (MCP server sees EOF, closes
	// its stdout, readLoop's Scan returns false).
	b.Close()

	// Wait for done channel to close (readLoop exited).
	select {
	case <-b.done:
	case <-time.After(5 * time.Second):
		t.Fatal("readLoop did not exit within 5s after Close")
	}

	// Any subsequent CallTool must return an error, not block.
	done := make(chan error, 1)
	go func() {
		_, err := b.CallTool("server_info", nil)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected error after readLoop exit, got nil")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("CallTool blocked after readLoop exit — goroutine leak (HC-1)")
	}
}

// HC-2: send() must not block forever if the bridge connection is lost.
func TestMCPBridgeSendUnblocksOnConnectionLoss(t *testing.T) {
	b, err := NewMCPBridge("test")
	if err != nil {
		t.Fatalf("NewMCPBridge: %v", err)
	}

	// Start a CallTool in the background, then kill the bridge.
	result := make(chan error, 1)
	go func() {
		// server_info is fast, but we close the bridge immediately after
		// to test the done-channel path for any pending call.
		b.Close()
		_, err := b.CallTool("list_modules", nil)
		result <- err
	}()

	select {
	case err := <-result:
		if err == nil {
			t.Fatal("expected error from send() after bridge closed")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("send() blocked forever after bridge closed (HC-2)")
	}
}

// HA-6: Verify the bridge correctly routes responses through the
// error-checked readLoop path using raw pipes (no MCP server).
func TestMCPBridgeRawPipeResponseRouting(t *testing.T) {
	fromServerR, fromServerW := io.Pipe()
	toServerR, toServerW := io.Pipe()

	b := &MCPBridge{
		toMCP:       toServerW,
		fromMCP:     bufio.NewScanner(fromServerR),
		fromMCPPipe: fromServerR,
		done:        make(chan struct{}),
		pending:     make(map[string]chan mcpResponse),
		notifyFns:   make(map[string]func(mcpNotification)),
	}
	b.fromMCP.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	go b.readLoop()
	defer b.Close()
	go io.Copy(io.Discard, toServerR)

	ch := make(chan mcpResponse, 1)
	b.pendMu.Lock()
	b.pending[`1`] = ch
	b.pendMu.Unlock()

	_, _ = fromServerW.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"text":"ok"}]}}` + "\n"))

	select {
	case resp := <-ch:
		if resp.Error != nil {
			t.Fatalf("expected success, got error: %s", resp.Error.Message)
		}
		if len(resp.Result) == 0 {
			t.Fatal("expected non-empty result")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for response")
	}
}

// HC-3: Scan cancellation must not block forever waiting for the MCP response.
func TestMCPBridgeScanCancelDoesNotHang(t *testing.T) {
	b, err := NewMCPBridge("test")
	if err != nil {
		t.Fatalf("NewMCPBridge: %v", err)
	}
	defer b.Close()

	// Use an already-cancelled context so the cancel path fires immediately.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	done := make(chan error, 1)
	go func() {
		_, err := b.Scan(ctx, MCPScanParams{Target: "example.com"}, nil)
		done <- err
	}()

	select {
	case err := <-done:
		if err != context.Canceled {
			t.Fatalf("expected context.Canceled, got: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Scan cancel path blocked for >10s (HC-3)")
	}
}
