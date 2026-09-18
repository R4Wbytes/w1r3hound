package mcp

import (
	"bytes"
	"encoding/json"
	"fmt"
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
	if serverInfo["title"] == nil || serverInfo["title"] == "" {
		t.Error("serverInfo.title missing")
	}
	caps, _ := result["capabilities"].(map[string]any)
	if _, ok := caps["tools"]; !ok {
		t.Error("capabilities.tools missing")
	}
	if _, ok := caps["logging"]; !ok {
		t.Error("capabilities.logging missing")
	}
	if result["instructions"] == nil || result["instructions"] == "" {
		t.Error("instructions field missing")
	}
}

// ── Spec compliance: server/discover (2026-07-28) ──

func TestServerDiscover(t *testing.T) {
	raw := roundTrip(t, `{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`)
	resp := unmarshalResponse(t, raw)
	if resp.Error != nil {
		t.Fatalf("server/discover returned error: %v", resp.Error)
	}
	result, ok := resp.Result.(map[string]any)
	if !ok {
		t.Fatalf("result is not a map")
	}
	if result["resultType"] != "complete" {
		t.Errorf("resultType = %v, want complete", result["resultType"])
	}
	versions, ok := result["supportedVersions"].([]any)
	if !ok || len(versions) < 2 {
		t.Fatalf("supportedVersions missing or too short: %v", result["supportedVersions"])
	}
	caps, ok := result["capabilities"].(map[string]any)
	if !ok {
		t.Fatal("capabilities missing")
	}
	if _, ok := caps["tools"]; !ok {
		t.Error("capabilities.tools missing")
	}
	if _, ok := caps["logging"]; !ok {
		t.Error("capabilities.logging missing")
	}
	meta, ok := result["_meta"].(map[string]any)
	if !ok {
		t.Fatal("_meta missing in discover result")
	}
	srvInfo, ok := meta["io.modelcontextprotocol/serverInfo"].(map[string]any)
	if !ok {
		t.Fatal("_meta.io.modelcontextprotocol/serverInfo missing")
	}
	if srvInfo["name"] != "w1r3hound" {
		t.Errorf("serverInfo.name = %v, want w1r3hound", srvInfo["name"])
	}
	if result["ttlMs"] == nil {
		t.Error("ttlMs missing")
	}
	if result["cacheScope"] != "public" {
		t.Errorf("cacheScope = %v, want public", result["cacheScope"])
	}
	if result["instructions"] == nil || result["instructions"] == "" {
		t.Error("instructions missing")
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
	if len(tools) != 4 {
		t.Fatalf("expected 4 tools, got %d", len(tools))
	}

	names := make(map[string]bool)
	for _, t := range tools {
		tool, _ := t.(map[string]any)
		names[tool["name"].(string)] = true
	}
	for _, want := range []string{"list_modules", "suggest_modules", "server_info", "scan"} {
		if !names[want] {
			t.Errorf("missing %s tool", want)
		}
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

// ── Spec compliance: resultType and caching ──

func TestToolsListResultType(t *testing.T) {
	raw := roundTrip(t, `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`)
	resp := unmarshalResponse(t, raw)
	result, _ := resp.Result.(map[string]any)
	if result["resultType"] != "complete" {
		t.Errorf("resultType = %v, want complete", result["resultType"])
	}
	if result["ttlMs"] == nil {
		t.Error("ttlMs missing from tools/list response")
	}
	if result["cacheScope"] != "public" {
		t.Errorf("cacheScope = %v, want public", result["cacheScope"])
	}
}

func TestToolCallResultType(t *testing.T) {
	raw := roundTrip(t, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_modules","arguments":{}}}`)
	resp := unmarshalResponse(t, raw)
	result, _ := resp.Result.(map[string]any)
	if result["resultType"] != "complete" {
		t.Errorf("resultType = %v, want complete", result["resultType"])
	}
}

func TestToolCallContentAnnotations(t *testing.T) {
	raw := roundTrip(t, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"server_info","arguments":{}}}`)
	resp := unmarshalResponse(t, raw)
	result, _ := resp.Result.(map[string]any)
	content, _ := result["content"].([]any)
	if len(content) == 0 {
		t.Fatal("content empty")
	}
	first, _ := content[0].(map[string]any)
	ann, ok := first["annotations"].(map[string]any)
	if !ok {
		t.Fatal("annotations missing from content block")
	}
	audience, ok := ann["audience"].([]any)
	if !ok || len(audience) == 0 {
		t.Error("annotations.audience missing or empty")
	}
	if ann["priority"] == nil {
		t.Error("annotations.priority missing")
	}
}

func TestPingResultType(t *testing.T) {
	raw := roundTrip(t, `{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	resp := unmarshalResponse(t, raw)
	result, _ := resp.Result.(map[string]any)
	if result["resultType"] != "complete" {
		t.Errorf("resultType = %v, want complete", result["resultType"])
	}
}

func TestToolsListContainsAllParams(t *testing.T) {
	raw := roundTrip(t, `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`)
	resp := unmarshalResponse(t, raw)
	result, _ := resp.Result.(map[string]any)
	tools, _ := result["tools"].([]any)
	for _, tool := range tools {
		tm, _ := tool.(map[string]any)
		if tm["name"] == "scan" {
			schema, _ := tm["inputSchema"].(map[string]any)
			props, _ := schema["properties"].(map[string]any)
			required := []string{
				"max_duration_seconds", "allow_private",
				"user_agent", "headers", "wordlist", "dir_wordlist",
				"dir_extensions", "skip_tls_verify", "resolver", "resolvers",
				"wayback_limit", "crawl_pages", "js_files", "min_severity",
			}
			for _, p := range required {
				if _, ok := props[p]; !ok {
					t.Errorf("scan tool schema missing %s", p)
				}
			}
			return
		}
	}
	t.Error("scan tool not found")
}

func TestSuggestModulesViaRPC(t *testing.T) {
	raw := roundTrip(t, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"suggest_modules","arguments":{"objective":"find subdomains"}}}`)
	resp := unmarshalResponse(t, raw)
	if resp.Error != nil {
		t.Fatalf("suggest_modules error: %v", resp.Error)
	}
	result, _ := resp.Result.(map[string]any)
	isErr, _ := result["isError"].(bool)
	if isErr {
		t.Error("suggest_modules returned isError=true")
	}
	content, _ := result["content"].([]any)
	first, _ := content[0].(map[string]any)
	text, _ := first["text"].(string)
	if !strings.Contains(text, "recommended_modules") {
		t.Error("suggest_modules response missing recommended_modules")
	}
}

func TestServerInfoViaRPC(t *testing.T) {
	raw := roundTrip(t, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"server_info","arguments":{}}}`)
	resp := unmarshalResponse(t, raw)
	if resp.Error != nil {
		t.Fatalf("server_info error: %v", resp.Error)
	}
	result, _ := resp.Result.(map[string]any)
	isErr, _ := result["isError"].(bool)
	if isErr {
		t.Error("server_info returned isError=true")
	}
	content, _ := result["content"].([]any)
	first, _ := content[0].(map[string]any)
	text, _ := first["text"].(string)
	if !strings.Contains(text, "w1r3hound") {
		t.Error("server_info response missing w1r3hound name")
	}
	if !strings.Contains(text, "suggest_modules") {
		t.Error("server_info response missing suggest_modules in tools list")
	}
}

// ── Spec compliance: null ID rejection ──

func TestNullIDRejected(t *testing.T) {
	raw := roundTrip(t, `{"jsonrpc":"2.0","id":null,"method":"ping"}`)
	resp := unmarshalResponse(t, raw)
	if resp.Error == nil || resp.Error.Code != -32600 {
		t.Errorf("null id should return -32600, got %+v", resp.Error)
	}
}

// ── Spec compliance: logging/setLevel ──

func TestSetLogLevel(t *testing.T) {
	raw := roundTrip(t, `{"jsonrpc":"2.0","id":1,"method":"logging/setLevel","params":{"level":"warning"}}`)
	resp := unmarshalResponse(t, raw)
	if resp.Error != nil {
		t.Fatalf("logging/setLevel returned error: %v", resp.Error)
	}
}

func TestSetLogLevelInvalid(t *testing.T) {
	raw := roundTrip(t, `{"jsonrpc":"2.0","id":1,"method":"logging/setLevel","params":{"level":"bogus"}}`)
	resp := unmarshalResponse(t, raw)
	if resp.Error == nil {
		t.Fatal("expected error for invalid log level")
	}
	if resp.Error.Code != -32602 {
		t.Errorf("error code = %d, want -32602", resp.Error.Code)
	}
}

// ── Spec compliance: tool annotations ──

func TestToolAnnotations(t *testing.T) {
	raw := roundTrip(t, `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`)
	resp := unmarshalResponse(t, raw)
	result, _ := resp.Result.(map[string]any)
	tools, _ := result["tools"].([]any)
	for _, tool := range tools {
		tm, _ := tool.(map[string]any)
		name := tm["name"].(string)
		ann, ok := tm["annotations"].(map[string]any)
		if !ok {
			t.Errorf("tool %q missing annotations", name)
			continue
		}
		if ann["readOnlyHint"] != true {
			t.Errorf("tool %q: readOnlyHint should be true", name)
		}
		if name == "scan" {
			if ann["openWorldHint"] != true {
				t.Errorf("scan tool: openWorldHint should be true")
			}
		} else {
			if ann["openWorldHint"] != false {
				t.Errorf("tool %q: openWorldHint should be false", name)
			}
		}
		if tm["title"] == nil || tm["title"] == "" {
			t.Errorf("tool %q missing title", name)
		}
	}
}

// ── Spec compliance: progressToken ──

func TestProgressOnlyWithToken(t *testing.T) {
	// Scan WITHOUT progressToken should produce NO progress notifications.
	var out bytes.Buffer
	msgs := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}
{"jsonrpc":"2.0","method":"notifications/initialized"}
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"scan","arguments":{"target":"127.0.0.1","modules":["headers"],"allow_private":true,"max_duration_seconds":10}}}
`
	ServeIO("test-version", strings.NewReader(msgs), &out)
	if strings.Contains(out.String(), "notifications/progress") {
		t.Error("progress notifications should NOT be sent without a progressToken")
	}
}

func TestProgressWithToken(t *testing.T) {
	// Scan WITH progressToken should produce progress notifications containing the token.
	var out bytes.Buffer
	msgs := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}
{"jsonrpc":"2.0","method":"notifications/initialized"}
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"scan","arguments":{"target":"127.0.0.1","modules":["headers"],"allow_private":true,"max_duration_seconds":10},"_meta":{"progressToken":"tok-42"}}}
`
	ServeIO("test-version", strings.NewReader(msgs), &out)
	output := out.String()
	if !strings.Contains(output, "notifications/progress") {
		t.Error("expected progress notifications with progressToken")
	}
	if !strings.Contains(output, "tok-42") {
		t.Error("expected progressToken value in notifications")
	}
}

// ── Spec compliance: cancellation ──

func TestCancellationStopsScan(t *testing.T) {
	// Send a scan, then immediately cancel it. The server should process
	// the cancellation after the scan starts (async).
	var out bytes.Buffer
	msgs := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}
{"jsonrpc":"2.0","method":"notifications/initialized"}
{"jsonrpc":"2.0","id":99,"method":"tools/call","params":{"name":"scan","arguments":{"target":"192.0.2.1","modules":["portscan"],"allow_private":true,"max_duration_seconds":60}}}
{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":99,"reason":"user requested"}}
`
	ServeIO("test-version", strings.NewReader(msgs), &out)
	// Just verify it completes without hanging — the cancellation shortens the scan.
	// The scan should still return a response (possibly partial).
	if !strings.Contains(out.String(), `"id":99`) {
		t.Error("expected response for cancelled scan request")
	}
}

// ── Prompts ──

func TestPromptsList(t *testing.T) {
	raw := roundTrip(t, `{"jsonrpc":"2.0","id":1,"method":"prompts/list","params":{}}`)
	resp := unmarshalResponse(t, raw)
	if resp.Error != nil {
		t.Fatalf("prompts/list error: %v", resp.Error)
	}
	result, _ := resp.Result.(map[string]any)
	if result["resultType"] != "complete" {
		t.Errorf("resultType = %v, want complete", result["resultType"])
	}
	prompts, ok := result["prompts"].([]any)
	if !ok || len(prompts) < 3 {
		t.Fatalf("expected at least 3 prompts, got %v", result["prompts"])
	}
	names := map[string]bool{}
	for _, p := range prompts {
		pm, _ := p.(map[string]any)
		names[pm["name"].(string)] = true
		if pm["description"] == nil || pm["description"] == "" {
			t.Errorf("prompt %q missing description", pm["name"])
		}
		args, ok := pm["arguments"].([]any)
		if !ok || len(args) == 0 {
			t.Errorf("prompt %q missing arguments", pm["name"])
		}
	}
	for _, want := range []string{"bug_bounty_recon", "passive_recon", "subdomain_takeover_check"} {
		if !names[want] {
			t.Errorf("missing prompt %q", want)
		}
	}
}

func TestPromptsGet(t *testing.T) {
	raw := roundTrip(t, `{"jsonrpc":"2.0","id":1,"method":"prompts/get","params":{"name":"bug_bounty_recon","arguments":{"target":"example.com"}}}`)
	resp := unmarshalResponse(t, raw)
	if resp.Error != nil {
		t.Fatalf("prompts/get error: %v", resp.Error)
	}
	result, _ := resp.Result.(map[string]any)
	messages, ok := result["messages"].([]any)
	if !ok || len(messages) == 0 {
		t.Fatal("prompts/get returned no messages")
	}
	msg, _ := messages[0].(map[string]any)
	if msg["role"] != "user" {
		t.Errorf("message role = %v, want user", msg["role"])
	}
	content, _ := msg["content"].(map[string]any)
	text, _ := content["text"].(string)
	if !strings.Contains(text, "example.com") {
		t.Error("prompt message should contain the target")
	}
	if !strings.Contains(text, "scan") {
		t.Error("prompt message should reference the scan tool")
	}
}

func TestPromptsGetUnknown(t *testing.T) {
	raw := roundTrip(t, `{"jsonrpc":"2.0","id":1,"method":"prompts/get","params":{"name":"nonexistent"}}`)
	resp := unmarshalResponse(t, raw)
	if resp.Error == nil {
		t.Fatal("expected error for unknown prompt")
	}
	if resp.Error.Code != -32602 {
		t.Errorf("error code = %d, want -32602", resp.Error.Code)
	}
}

func TestPromptsGetExhaustive(t *testing.T) {
	raw := roundTrip(t, `{"jsonrpc":"2.0","id":1,"method":"prompts/get","params":{"name":"exhaustive_recon","arguments":{"target":"example.com"}}}`)
	resp := unmarshalResponse(t, raw)
	if resp.Error != nil {
		t.Fatalf("prompts/get error: %v", resp.Error)
	}
	result, _ := resp.Result.(map[string]any)
	messages, ok := result["messages"].([]any)
	if !ok || len(messages) == 0 {
		t.Fatal("expected messages in response")
	}
	msg, _ := messages[0].(map[string]any)
	content, _ := msg["content"].(map[string]any)
	text, _ := content["text"].(string)
	if !strings.Contains(text, `"ports": "full"`) {
		t.Error("exhaustive_recon prompt should include full port scan")
	}
	if !strings.Contains(text, `"rate_limit": 3`) {
		t.Error("exhaustive_recon prompt should include rate limiting")
	}
}

// ── Completions ──

func TestCompletionModules(t *testing.T) {
	raw := roundTrip(t, `{"jsonrpc":"2.0","id":1,"method":"completion/complete","params":{"ref":{"type":"ref/tool","name":"scan"},"argument":{"name":"modules","value":"port"}}}`)
	resp := unmarshalResponse(t, raw)
	if resp.Error != nil {
		t.Fatalf("completion/complete error: %v", resp.Error)
	}
	result, _ := resp.Result.(map[string]any)
	completion, _ := result["completion"].(map[string]any)
	values, ok := completion["values"].([]any)
	if !ok || len(values) == 0 {
		t.Fatal("expected completion values for 'port'")
	}
	found := false
	for _, v := range values {
		if v == "portscan" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'portscan' in completions, got %v", values)
	}
}

func TestCompletionSeverity(t *testing.T) {
	raw := roundTrip(t, `{"jsonrpc":"2.0","id":1,"method":"completion/complete","params":{"ref":{"type":"ref/tool","name":"scan"},"argument":{"name":"min_severity","value":"H"}}}`)
	resp := unmarshalResponse(t, raw)
	if resp.Error != nil {
		t.Fatalf("completion/complete error: %v", resp.Error)
	}
	result, _ := resp.Result.(map[string]any)
	completion, _ := result["completion"].(map[string]any)
	values, ok := completion["values"].([]any)
	if !ok || len(values) == 0 {
		t.Fatal("expected completion values for severity 'H'")
	}
	found := false
	for _, v := range values {
		if v == "HIGH" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'HIGH' in completions, got %v", values)
	}
}

func TestCompletionEmpty(t *testing.T) {
	raw := roundTrip(t, `{"jsonrpc":"2.0","id":1,"method":"completion/complete","params":{"ref":{"type":"ref/tool","name":"scan"},"argument":{"name":"target","value":"exam"}}}`)
	resp := unmarshalResponse(t, raw)
	if resp.Error != nil {
		t.Fatalf("completion/complete error: %v", resp.Error)
	}
	result, _ := resp.Result.(map[string]any)
	completion, _ := result["completion"].(map[string]any)
	values, _ := completion["values"].([]any)
	if len(values) != 0 {
		t.Errorf("expected empty completions for target, got %v", values)
	}
}

// ── Capabilities advertised ──

func TestCapabilitiesIncludePromptsAndCompletions(t *testing.T) {
	raw := roundTrip(t, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}`)
	resp := unmarshalResponse(t, raw)
	result, _ := resp.Result.(map[string]any)
	caps, _ := result["capabilities"].(map[string]any)
	if _, ok := caps["prompts"]; !ok {
		t.Error("capabilities.prompts missing")
	}
	if _, ok := caps["completions"]; !ok {
		t.Error("capabilities.completions missing")
	}
}

// ── Regression: prompts/get without arguments must not panic ──

func TestPromptsGetNoArguments(t *testing.T) {
	raw := roundTrip(t, `{"jsonrpc":"2.0","id":1,"method":"prompts/get","params":{"name":"bug_bounty_recon"}}`)
	resp := unmarshalResponse(t, raw)
	if resp.Error != nil {
		t.Fatalf("prompts/get without arguments should not error: %v", resp.Error)
	}
	result, _ := resp.Result.(map[string]any)
	messages, ok := result["messages"].([]any)
	if !ok || len(messages) == 0 {
		t.Fatal("expected messages even without explicit arguments")
	}
}

func TestPromptsGetNullArguments(t *testing.T) {
	raw := roundTrip(t, `{"jsonrpc":"2.0","id":1,"method":"prompts/get","params":{"name":"passive_recon","arguments":null}}`)
	resp := unmarshalResponse(t, raw)
	if resp.Error != nil {
		t.Fatalf("prompts/get with null arguments should not error: %v", resp.Error)
	}
}

// ── Regression: completion/complete without params ──

func TestCompletionNoParams(t *testing.T) {
	raw := roundTrip(t, `{"jsonrpc":"2.0","id":1,"method":"completion/complete"}`)
	resp := unmarshalResponse(t, raw)
	if resp.Error != nil {
		// Acceptable: -32602 for missing params
		return
	}
	result, _ := resp.Result.(map[string]any)
	completion, _ := result["completion"].(map[string]any)
	values, _ := completion["values"].([]any)
	if len(values) != 0 {
		t.Errorf("expected empty completions for no params, got %v", values)
	}
}

// HC-4: When the output writer breaks (pipe closed), the server must detect it
// and stop processing instead of silently dropping all subsequent responses.
func TestServeIOBrokenWriter(t *testing.T) {
	// brokenWriter fails on every Write after the first successful one.
	w := &brokenAfterN{max: 1}
	input := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/list"}`,
		"",
	}, "\n")

	ServeIO("test-version", strings.NewReader(input), w)

	// The server should have stopped after the first encode error instead of
	// silently processing all remaining requests. We can't assert the exact
	// count because the first write may succeed, but subsequent ones must fail
	// and trigger the encodeErr break in the run loop.
	if w.writes > 3 {
		t.Fatalf("server wrote %d times to a broken writer — expected it to stop early", w.writes)
	}
}

type brokenAfterN struct {
	max    int
	writes int
}

func (b *brokenAfterN) Write(p []byte) (int, error) {
	b.writes++
	if b.writes > b.max {
		return 0, fmt.Errorf("broken pipe")
	}
	return len(p), nil
}
