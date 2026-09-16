package mcp

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// helper: send one JSON-RPC message and return the raw response line.
func roundTrip(t *testing.T, msg string) string {
	t.Helper()
	var out bytes.Buffer
	ServeIO("test-version", strings.NewReader(msg+"\n"), &out)
	return strings.TrimSpace(out.String())
}

// helper: send multiple newline-separated messages, return all response lines.
func roundTripMulti(t *testing.T, msgs string) []string {
	t.Helper()
	var out bytes.Buffer
	ServeIO("test-version", strings.NewReader(msgs), &out)
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	var result []string
	for _, l := range lines {
		if l = strings.TrimSpace(l); l != "" {
			result = append(result, l)
		}
	}
	return result
}

func unmarshalResponse(t *testing.T, raw string) response {
	t.Helper()
	var resp response
	if err := json.Unmarshal([]byte(raw), &resp); err != nil {
		t.Fatalf("failed to unmarshal response %q: %v", raw, err)
	}
	return resp
}

func TestInitialize(t *testing.T) {
	raw := roundTrip(t, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}`)
	resp := unmarshalResponse(t, raw)
	if resp.Error != nil {
		t.Fatalf("initialize returned error: %v", resp.Error)
	}
	result, ok := resp.Result.(map[string]any)
	if !ok {
		t.Fatalf("result is not a map")
	}
	if result["protocolVersion"] != "2025-06-18" {
		t.Errorf("protocolVersion = %v, want 2025-06-18", result["protocolVersion"])
	}
	serverInfo, _ := result["serverInfo"].(map[string]any)
	if serverInfo["name"] != "w1r3hound" {
		t.Errorf("serverInfo.name = %v, want w1r3hound", serverInfo["name"])
	}
	if serverInfo["version"] != "test-version" {
		t.Errorf("serverInfo.version = %v, want test-version", serverInfo["version"])
	}
	caps, _ := result["capabilities"].(map[string]any)
	if _, ok := caps["tools"]; !ok {
		t.Error("capabilities.tools missing")
	}
}

func TestInitializeStringID(t *testing.T) {
	raw := roundTrip(t, `{"jsonrpc":"2.0","id":"abc-123","method":"initialize","params":{}}`)
	resp := unmarshalResponse(t, raw)
	if string(resp.ID) != `"abc-123"` {
		t.Errorf("id = %s, want \"abc-123\"", string(resp.ID))
	}
}

func TestPing(t *testing.T) {
	raw := roundTrip(t, `{"jsonrpc":"2.0","id":42,"method":"ping"}`)
	resp := unmarshalResponse(t, raw)
	if resp.Error != nil {
		t.Fatalf("ping returned error: %v", resp.Error)
	}
}

func TestNotificationNoResponse(t *testing.T) {
	lines := roundTripMulti(t, `{"jsonrpc":"2.0","method":"notifications/initialized"}`+"\n")
	if len(lines) != 0 {
		t.Errorf("notifications/initialized should produce no response, got %d lines", len(lines))
	}
}

func TestUnknownMethodError(t *testing.T) {
	raw := roundTrip(t, `{"jsonrpc":"2.0","id":1,"method":"bogus/method"}`)
	resp := unmarshalResponse(t, raw)
	if resp.Error == nil {
		t.Fatal("expected an error for unknown method")
	}
	if resp.Error.Code != -32601 {
		t.Errorf("error code = %d, want -32601", resp.Error.Code)
	}
}

func TestUnknownNotificationSilent(t *testing.T) {
	lines := roundTripMulti(t, `{"jsonrpc":"2.0","method":"notifications/bogus"}`+"\n")
	if len(lines) != 0 {
		t.Errorf("unknown notification should produce no response, got %d", len(lines))
	}
}

func TestParseError(t *testing.T) {
	raw := roundTrip(t, `this is not json`)
	resp := unmarshalResponse(t, raw)
	if resp.Error == nil || resp.Error.Code != -32700 {
		t.Errorf("expected parse error -32700, got %+v", resp.Error)
	}
}

func TestToolsList(t *testing.T) {
	raw := roundTrip(t, `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`)
	resp := unmarshalResponse(t, raw)
	if resp.Error != nil {
		t.Fatalf("tools/list returned error: %v", resp.Error)
	}
	result, _ := resp.Result.(map[string]any)
	tools, _ := result["tools"].([]any)
	if len(tools) != 2 {
		t.Fatalf("expected 2 tools, got %d", len(tools))
	}

	names := make(map[string]bool)
	for _, t := range tools {
		tool, _ := t.(map[string]any)
		names[tool["name"].(string)] = true
	}
	if !names["list_modules"] {
		t.Error("missing list_modules tool")
	}
	if !names["scan"] {
		t.Error("missing scan tool")
	}
}

func TestToolsCallListModules(t *testing.T) {
	raw := roundTrip(t, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_modules","arguments":{}}}`)
	resp := unmarshalResponse(t, raw)
	if resp.Error != nil {
		t.Fatalf("tools/call list_modules returned error: %v", resp.Error)
	}
	result, _ := resp.Result.(map[string]any)
	isErr, _ := result["isError"].(bool)
	if isErr {
		t.Error("list_modules returned isError=true")
	}
	content, _ := result["content"].([]any)
	if len(content) == 0 {
		t.Fatal("list_modules returned empty content")
	}
	first, _ := content[0].(map[string]any)
	text, _ := first["text"].(string)
	if !strings.Contains(text, "whois") || !strings.Contains(text, "portscan") {
		t.Error("list_modules output missing expected module names")
	}
}

func TestToolsCallUnknownTool(t *testing.T) {
	raw := roundTrip(t, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"nonexistent","arguments":{}}}`)
	resp := unmarshalResponse(t, raw)
	result, _ := resp.Result.(map[string]any)
	isErr, _ := result["isError"].(bool)
	if !isErr {
		t.Error("expected isError=true for unknown tool")
	}
}

func TestScanMissingTarget(t *testing.T) {
	raw := roundTrip(t, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"scan","arguments":{}}}`)
	resp := unmarshalResponse(t, raw)
	result, _ := resp.Result.(map[string]any)
	isErr, _ := result["isError"].(bool)
	if !isErr {
		t.Error("expected isError=true for missing target")
	}
}

func TestScanUnknownModule(t *testing.T) {
	raw := roundTrip(t, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"scan","arguments":{"target":"example.com","modules":["fake"]}}}`)
	resp := unmarshalResponse(t, raw)
	result, _ := resp.Result.(map[string]any)
	isErr, _ := result["isError"].(bool)
	if !isErr {
		t.Error("expected isError=true for unknown module")
	}
	content, _ := result["content"].([]any)
	first, _ := content[0].(map[string]any)
	text, _ := first["text"].(string)
	if !strings.Contains(text, "fake") {
		t.Errorf("error should mention the bad module name, got: %s", text)
	}
}

func TestScanInvalidTarget(t *testing.T) {
	raw := roundTrip(t, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"scan","arguments":{"target":"not valid target!"}}}`)
	resp := unmarshalResponse(t, raw)
	result, _ := resp.Result.(map[string]any)
	isErr, _ := result["isError"].(bool)
	if !isErr {
		t.Error("expected isError=true for invalid target")
	}
}

func TestFullLifecycle(t *testing.T) {
	msgs := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"ping"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/list","params":{}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"list_modules","arguments":{}}}`,
	}, "\n") + "\n"

	lines := roundTripMulti(t, msgs)
	// Should get 4 responses (notification produces none).
	if len(lines) != 4 {
		t.Fatalf("expected 4 responses, got %d:\n%s", len(lines), strings.Join(lines, "\n"))
	}

	// Verify IDs match in order.
	for i, wantID := range []string{"1", "2", "3", "4"} {
		var resp response
		if err := json.Unmarshal([]byte(lines[i]), &resp); err != nil {
			t.Fatalf("response %d: %v", i, err)
		}
		if string(resp.ID) != wantID {
			t.Errorf("response %d: id = %s, want %s", i, string(resp.ID), wantID)
		}
	}
}

func TestModuleRegistryMatchesCatalog(t *testing.T) {
	registryNames := make(map[string]bool, len(moduleRegistry))
	for _, e := range moduleRegistry {
		registryNames[e.Name] = true
	}
	for _, c := range moduleCatalog {
		if !registryNames[c.Name] {
			t.Errorf("catalog entry %q has no matching registry entry", c.Name)
		}
	}
	catalogNames := make(map[string]bool, len(moduleCatalog))
	for _, c := range moduleCatalog {
		catalogNames[c.Name] = true
	}
	for _, e := range moduleRegistry {
		if !catalogNames[e.Name] {
			t.Errorf("registry entry %q has no matching catalog entry", e.Name)
		}
	}
}

func TestToolsCallNilParams(t *testing.T) {
	raw := roundTrip(t, `{"jsonrpc":"2.0","id":1,"method":"tools/call"}`)
	resp := unmarshalResponse(t, raw)
	if resp.Error == nil {
		t.Fatal("expected error for tools/call with no params")
	}
	if resp.Error.Code != -32602 {
		t.Errorf("error code = %d, want -32602", resp.Error.Code)
	}
}

func TestToolsCallNullParams(t *testing.T) {
	raw := roundTrip(t, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":null}`)
	resp := unmarshalResponse(t, raw)
	// null params unmarshals to zero-value struct → name="" → unknown tool
	// returned as a tool-level error (isError=true), not a JSON-RPC error.
	if resp.Error != nil {
		return // also acceptable: -32602
	}
	result, _ := resp.Result.(map[string]any)
	isErr, _ := result["isError"].(bool)
	if !isErr {
		t.Error("expected isError=true for null params (empty tool name)")
	}
}

func TestEmptyLinesIgnored(t *testing.T) {
	msgs := "\n\n" + `{"jsonrpc":"2.0","id":1,"method":"ping"}` + "\n\n"
	lines := roundTripMulti(t, msgs)
	if len(lines) != 1 {
		t.Fatalf("expected 1 response, got %d", len(lines))
	}
	resp := unmarshalResponse(t, lines[0])
	if resp.Error != nil {
		t.Errorf("ping returned error: %v", resp.Error)
	}
}

func TestBatchRequestRejected(t *testing.T) {
	raw := roundTrip(t, `[{"jsonrpc":"2.0","id":1,"method":"ping"}]`)
	resp := unmarshalResponse(t, raw)
	if resp.Error == nil || resp.Error.Code != -32600 {
		t.Errorf("batch request should return -32600, got %+v", resp.Error)
	}
}

func TestMissingJsonrpcField(t *testing.T) {
	raw := roundTrip(t, `{"id":1,"method":"ping"}`)
	resp := unmarshalResponse(t, raw)
	if resp.Error == nil || resp.Error.Code != -32600 {
		t.Errorf("missing jsonrpc field should return -32600, got %+v", resp.Error)
	}
}

func TestWrongJsonrpcVersion(t *testing.T) {
	raw := roundTrip(t, `{"jsonrpc":"1.0","id":1,"method":"ping"}`)
	resp := unmarshalResponse(t, raw)
	if resp.Error == nil || resp.Error.Code != -32600 {
		t.Errorf("wrong jsonrpc version should return -32600, got %+v", resp.Error)
	}
}

func TestNotificationWithoutJsonrpcSilent(t *testing.T) {
	lines := roundTripMulti(t, `{"method":"notifications/initialized"}`+"\n")
	if len(lines) != 0 {
		t.Errorf("notification without jsonrpc should be silently ignored, got %d lines", len(lines))
	}
}

func TestToolsListContainsNewParams(t *testing.T) {
	raw := roundTrip(t, `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`)
	resp := unmarshalResponse(t, raw)
	result, _ := resp.Result.(map[string]any)
	tools, _ := result["tools"].([]any)
	for _, tool := range tools {
		tm, _ := tool.(map[string]any)
		if tm["name"] == "scan" {
			schema, _ := tm["inputSchema"].(map[string]any)
			props, _ := schema["properties"].(map[string]any)
			if _, ok := props["max_duration_seconds"]; !ok {
				t.Error("scan tool schema missing max_duration_seconds")
			}
			if _, ok := props["allow_private"]; !ok {
				t.Error("scan tool schema missing allow_private")
			}
			return
		}
	}
	t.Error("scan tool not found")
}
