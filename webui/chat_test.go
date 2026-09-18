package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestChatManagerCreateAndLoad(t *testing.T) {
	dir := t.TempDir()
	cm, err := NewChatManager(dir, nil)
	if err != nil {
		t.Fatalf("NewChatManager: %v", err)
	}
	convo, err := cm.CreateConversation("alice", "Test convo")
	if err != nil {
		t.Fatalf("CreateConversation: %v", err)
	}
	if convo.Title != "Test convo" {
		t.Fatalf("title = %q, want %q", convo.Title, "Test convo")
	}
	if convo.Owner != "alice" {
		t.Fatalf("owner = %q, want %q", convo.Owner, "alice")
	}

	loaded, err := cm.loadConversation(convo.ID)
	if err != nil {
		t.Fatalf("loadConversation: %v", err)
	}
	if loaded.Title != "Test convo" {
		t.Fatalf("loaded title = %q, want %q", loaded.Title, "Test convo")
	}
}

func TestChatManagerListConversations(t *testing.T) {
	dir := t.TempDir()
	cm, err := NewChatManager(dir, nil)
	if err != nil {
		t.Fatalf("NewChatManager: %v", err)
	}
	_, _ = cm.CreateConversation("alice", "Alice 1")
	_, _ = cm.CreateConversation("bob", "Bob 1")

	aliceList := cm.ListConversations("alice", false)
	if len(aliceList) != 1 {
		t.Fatalf("alice sees %d conversations, want 1", len(aliceList))
	}
	if aliceList[0].Title != "Alice 1" {
		t.Fatalf("alice convo title = %q, want %q", aliceList[0].Title, "Alice 1")
	}

	adminList := cm.ListConversations("alice", true)
	if len(adminList) != 2 {
		t.Fatalf("admin sees %d conversations, want 2", len(adminList))
	}
}

func TestChatManagerDeleteConversation(t *testing.T) {
	dir := t.TempDir()
	cm, err := NewChatManager(dir, nil)
	if err != nil {
		t.Fatalf("NewChatManager: %v", err)
	}
	convo, _ := cm.CreateConversation("alice", "To delete")
	if err := cm.DeleteConversation(convo.ID); err != nil {
		t.Fatalf("DeleteConversation: %v", err)
	}
	if _, err := cm.loadConversation(convo.ID); err == nil {
		t.Fatal("expected error loading deleted conversation")
	}
}

func TestChatManagerConfig(t *testing.T) {
	dir := t.TempDir()
	cm, err := NewChatManager(dir, nil)
	if err != nil {
		t.Fatalf("NewChatManager: %v", err)
	}
	if cm.Configured() {
		t.Fatal("should not be configured without API key")
	}

	if err := cm.SetConfig("sk-test-key", "claude-opus-5", 8192); err != nil {
		t.Fatalf("SetConfig: %v", err)
	}
	if !cm.Configured() {
		t.Fatal("should be configured after SetConfig")
	}
	status := cm.ConfigStatus()
	if status["model"] != "claude-opus-5" {
		t.Fatalf("model = %v, want claude-opus-5", status["model"])
	}
	if status["max_tokens"] != 8192 {
		t.Fatalf("max_tokens = %v, want 8192", status["max_tokens"])
	}

	// Config persisted
	cfgPath := filepath.Join(dir, "config.json")
	if _, err := os.Stat(cfgPath); err != nil {
		t.Fatalf("config file not written: %v", err)
	}

	cm2, err := NewChatManager(dir, nil)
	if err != nil {
		t.Fatalf("NewChatManager reload: %v", err)
	}
	if !cm2.Configured() {
		t.Fatal("should be configured after reload")
	}
}

func TestChatDeleteHTTPHandler(t *testing.T) {
	s := newTestServer(t, "")
	convo, err := s.chat.CreateConversation("default", "To delete via HTTP")
	if err != nil {
		t.Fatalf("CreateConversation: %v", err)
	}

	// Verify it exists.
	req := loopbackReq("GET", "/api/chat/conversations/"+convo.ID, nil)
	rec := serve(t, s, req)
	if rec.Code != 200 {
		t.Fatalf("GET before delete: %d, want 200", rec.Code)
	}

	// Delete it.
	req = loopbackReq("DELETE", "/api/chat/conversations/"+convo.ID, nil)
	rec = serve(t, s, req)
	if rec.Code != 200 {
		t.Fatalf("DELETE: %d, body: %s", rec.Code, rec.Body.String())
	}

	// Verify it's gone.
	req = loopbackReq("GET", "/api/chat/conversations/"+convo.ID, nil)
	rec = serve(t, s, req)
	if rec.Code != 404 {
		t.Fatalf("GET after delete: %d, want 404", rec.Code)
	}
}

func TestValidConvoID(t *testing.T) {
	tests := []struct {
		id   string
		want bool
	}{
		{"conv_20260916_120000_abcd1234", true},
		{"", false},
		{"../etc/passwd", false},
		{"conv_test", true},
		{"/absolute/path", false},
	}
	for _, tt := range tests {
		if got := validConvoID(tt.id); got != tt.want {
			t.Errorf("validConvoID(%q) = %v, want %v", tt.id, got, tt.want)
		}
	}
}

// HC-5: Malformed tool_use input must be dropped, not invoked with nil.
func TestCallLLMMalformedToolInput(t *testing.T) {
	// Mock SSE stream: a tool_use block whose input_json_delta is invalid JSON.
	ssePayload := strings.Join([]string{
		"event: message_start",
		`data: {"type":"message_start","message":{"id":"msg_test","type":"message","role":"assistant","model":"test","stop_reason":null}}`,
		"",
		"event: content_block_start",
		`data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_01","name":"scan"}}`,
		"",
		"event: content_block_delta",
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"target\": \"ex"}}`,
		"",
		// No closing brace — truncated JSON.
		"event: content_block_stop",
		`data: {"type":"content_block_stop","index":0}`,
		"",
		"event: content_block_start",
		`data: {"type":"content_block_start","index":1,"content_block":{"type":"text","text":""}}`,
		"",
		"event: content_block_delta",
		`data: {"type":"content_block_delta","index":1,"delta":{"type":"text_delta","text":"Done"}}`,
		"",
		"event: content_block_stop",
		`data: {"type":"content_block_stop","index":1}`,
		"",
		"event: message_stop",
		`data: {"type":"message_stop"}`,
		"",
	}, "\n")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		fmt.Fprint(w, ssePayload)
	}))
	defer srv.Close()

	dir := t.TempDir()
	cm, err := NewChatManager(dir, nil)
	if err != nil {
		t.Fatalf("NewChatManager: %v", err)
	}

	msgs := []map[string]any{
		{"role": "user", "content": "test"},
	}
	resp, err := cm.callLLM(context.Background(), "test-key", srv.URL, "test-model", "system", msgs, nil, 1024, func(chatEvent) {})
	if err != nil {
		t.Fatalf("callLLM: %v", err)
	}

	// The malformed tool_use block should be dropped; only the text block remains.
	for _, block := range resp.Content {
		if block.Type == "tool_use" {
			t.Fatalf("malformed tool_use block was NOT dropped — got block with name %q, input=%v", block.Name, block.Input)
		}
	}
	if len(resp.Content) != 1 || resp.Content[0].Type != "text" {
		t.Fatalf("expected 1 text block, got %d blocks: %+v", len(resp.Content), resp.Content)
	}
}

// HC-6: LLM API errors must not leak the raw error body to callers.
func TestCallLLMErrorSanitized(t *testing.T) {
	sensitiveBody := `{"error":{"type":"authentication_error","message":"Invalid API key sk-ant-REDACTED for account acct_01XXXX"}}`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(401)
		fmt.Fprint(w, sensitiveBody)
	}))
	defer srv.Close()

	dir := t.TempDir()
	cm, err := NewChatManager(dir, nil)
	if err != nil {
		t.Fatalf("NewChatManager: %v", err)
	}

	msgs := []map[string]any{
		{"role": "user", "content": "test"},
	}
	_, err = cm.callLLM(context.Background(), "test-key", srv.URL, "test-model", "system", msgs, nil, 1024, func(chatEvent) {})
	if err == nil {
		t.Fatal("expected error for 401, got nil")
	}

	errMsg := err.Error()
	if strings.Contains(errMsg, "sk-ant") || strings.Contains(errMsg, "acct_01") || strings.Contains(errMsg, "REDACTED") {
		t.Fatalf("error leaks sensitive data to caller: %s", errMsg)
	}
	if !strings.Contains(errMsg, "401") {
		t.Fatalf("error should mention status code 401, got: %s", errMsg)
	}
}

// HA-2: When the tool-use loop hits its 10-iteration cap, a warning event
// must be emitted before "done" so the user knows the response was truncated.
func TestChatSendMaxIterationsWarning(t *testing.T) {
	// Mock LLM that always returns a tool_use block, never a plain text stop.
	sseAlwaysToolUse := strings.Join([]string{
		"event: message_start",
		`data: {"type":"message_start","message":{"id":"msg_loop","type":"message","role":"assistant","model":"test","stop_reason":null}}`,
		"",
		"event: content_block_start",
		`data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_loop","name":"server_info"}}`,
		"",
		"event: content_block_delta",
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{}"}}`,
		"",
		"event: content_block_stop",
		`data: {"type":"content_block_stop","index":0}`,
		"",
		"event: message_stop",
		`data: {"type":"message_stop"}`,
		"",
	}, "\n")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		fmt.Fprint(w, sseAlwaysToolUse)
	}))
	defer srv.Close()

	dir := t.TempDir()
	cm, err := NewChatManager(dir, nil)
	if err != nil {
		t.Fatalf("NewChatManager: %v", err)
	}
	cm.config.APIKey = "test-key"
	cm.config.Endpoint = srv.URL
	cm.config.Model = "test-model"
	cm.config.MaxTokens = 1024

	convo, err := cm.CreateConversation("test", "Loop test")
	if err != nil {
		t.Fatalf("CreateConversation: %v", err)
	}

	var events []chatEvent
	err = cm.Send(context.Background(), convo.ID, "trigger loop", func(e chatEvent) {
		events = append(events, e)
	})
	if err != nil {
		t.Fatalf("Send: %v", err)
	}

	// Find the warning event.
	var gotWarning, gotDone bool
	var warningIdx, doneIdx int
	for i, e := range events {
		if e.Type == "warning" && strings.Contains(e.Data, "iterations") {
			gotWarning = true
			warningIdx = i
		}
		if e.Type == "done" {
			gotDone = true
			doneIdx = i
		}
	}
	if !gotWarning {
		t.Fatal("no warning event emitted when tool-use loop hit max iterations")
	}
	if !gotDone {
		t.Fatal("no done event emitted")
	}
	if warningIdx >= doneIdx {
		t.Fatalf("warning event (idx %d) must come before done event (idx %d)", warningIdx, doneIdx)
	}
}

// HB-2: handleChatCreate must return 400 for malformed JSON body.
func TestHandleChatCreateMalformedBody(t *testing.T) {
	s := newTestServer(t, "")
	req := loopbackReq("POST", "/api/chat/conversations", strings.NewReader("{bad json"))
	rec := serve(t, s, req)
	if rec.Code != 400 {
		t.Fatalf("expected 400 for malformed JSON, got %d; body=%s", rec.Code, rec.Body.String())
	}
}

// HA-4: handleChatCreate returns 201 with valid JSON.
func TestHandleChatCreateValid(t *testing.T) {
	s := newTestServer(t, "")
	req := loopbackReq("POST", "/api/chat/conversations", strings.NewReader(`{"title":"Test Chat"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := serve(t, s, req)
	if rec.Code != 201 {
		t.Fatalf("expected 201, got %d; body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Test Chat") {
		t.Fatalf("response should contain title, got: %s", body)
	}
	if !strings.Contains(body, `"id"`) {
		t.Fatalf("response should contain conversation id, got: %s", body)
	}
}

// HA-4: handleSetChatConfig requires admin when auth is enabled.
func TestSetChatConfigRequiresAdmin(t *testing.T) {
	s, adminCookie, adminCSRF := newAuthTestServer(t, "cfgadmin", "cfgadmin-long-password")

	configBody := `{"api_key":"sk-test","model":"claude-sonnet-5","max_tokens":4096}`

	// Non-admin user POST -> 403.
	if _, err := s.auth.createUser("viewer", "viewer-long-password", RoleUser, false); err != nil {
		t.Fatalf("createUser: %v", err)
	}
	rawUser, sessUser, err := s.auth.createSession("viewer", RoleUser)
	if err != nil {
		t.Fatalf("createSession user: %v", err)
	}
	userCookie := &http.Cookie{Name: sessionCookieName, Value: rawUser}
	userCSRF := sessUser.CSRFToken

	req := authReq("POST", "/api/chat/config", configBody, userCookie, userCSRF)
	if rec := serve(t, s, req); rec.Code != http.StatusForbidden {
		t.Fatalf("non-admin set config = %d, want 403; body=%s", rec.Code, rec.Body.String())
	}

	// Admin POST -> 200.
	req = authReq("POST", "/api/chat/config", configBody, adminCookie, adminCSRF)
	if rec := serve(t, s, req); rec.Code != http.StatusOK {
		t.Fatalf("admin set config = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
}

func TestHandleChatConfigGET(t *testing.T) {
	s := newTestServer(t, "")
	req := loopbackReq("GET", "/api/chat/config", nil)
	rec := serve(t, s, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/chat/config = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"configured"`) || !strings.Contains(body, `"model"`) {
		t.Fatalf("response missing expected fields: %s", body)
	}
}

func TestHandleChatConfigGET_NoChatManager(t *testing.T) {
	s := newTestServer(t, "")
	s.chat = nil
	req := loopbackReq("GET", "/api/chat/config", nil)
	rec := serve(t, s, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("GET /api/chat/config with nil chat = %d, want 503", rec.Code)
	}
}

func TestHandleChatConversations_ListsOwned(t *testing.T) {
	s := newTestServer(t, "")
	_, _ = s.chat.CreateConversation("default", "My Chat")
	req := loopbackReq("GET", "/api/chat/conversations", nil)
	rec := serve(t, s, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "My Chat") {
		t.Fatalf("expected conversation in list, got: %s", body)
	}
}

func TestHandleChatConversations_NilChat(t *testing.T) {
	s := newTestServer(t, "")
	s.chat = nil
	req := loopbackReq("GET", "/api/chat/conversations", nil)
	rec := serve(t, s, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("code = %d, want 503", rec.Code)
	}
}

func TestHandleChatConversations_OwnerIsolation(t *testing.T) {
	s, adminCookie, _ := newAuthTestServer(t, "chatadmin", "chatadmin-long-password")
	_, _ = s.chat.CreateConversation("chatadmin", "Admin Chat")
	_, _ = s.chat.CreateConversation("otheruser", "Other Chat")

	req := authReq("GET", "/api/chat/conversations", "", adminCookie, "")
	rec := serve(t, s, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	// Admin sees all conversations
	if !strings.Contains(body, "Admin Chat") || !strings.Contains(body, "Other Chat") {
		t.Fatalf("admin should see all convos, got: %s", body)
	}

	// Non-admin only sees their own
	if _, err := s.auth.createUser("viewer2", "viewer2-long-password", RoleUser, false); err != nil {
		t.Fatalf("createUser: %v", err)
	}
	raw, _, err := s.auth.createSession("viewer2", RoleUser)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}
	userCookie := &http.Cookie{Name: sessionCookieName, Value: raw}
	req = authReq("GET", "/api/chat/conversations", "", userCookie, "")
	rec = serve(t, s, req)
	body = rec.Body.String()
	if strings.Contains(body, "Admin Chat") || strings.Contains(body, "Other Chat") {
		t.Fatalf("non-admin should not see other convos, got: %s", body)
	}
}

func TestHandleChatGet_OwnershipEnforced(t *testing.T) {
	s, _, _ := newAuthTestServer(t, "getadmin", "getadmin-long-password")
	convo, _ := s.chat.CreateConversation("getadmin", "Private")

	// Non-admin trying to read admin's convo -> 404
	if _, err := s.auth.createUser("intruder", "intruder-long-password", RoleUser, false); err != nil {
		t.Fatalf("createUser: %v", err)
	}
	raw, _, _ := s.auth.createSession("intruder", RoleUser)
	cookie := &http.Cookie{Name: sessionCookieName, Value: raw}
	req := authReq("GET", "/api/chat/conversations/"+convo.ID, "", cookie, "")
	rec := serve(t, s, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("non-owner GET = %d, want 404", rec.Code)
	}
}

func TestHandleChatDelete_OwnershipEnforced(t *testing.T) {
	s, adminCookie, adminCSRF := newAuthTestServer(t, "deladmin", "deladmin-long-password")
	convo, _ := s.chat.CreateConversation("deladmin", "To Delete")

	// Non-admin trying to delete admin's convo -> 404
	if _, err := s.auth.createUser("intruder2", "intruder2-long-password", RoleUser, false); err != nil {
		t.Fatalf("createUser: %v", err)
	}
	raw, sess, _ := s.auth.createSession("intruder2", RoleUser)
	cookie := &http.Cookie{Name: sessionCookieName, Value: raw}
	req := authReq("DELETE", "/api/chat/conversations/"+convo.ID, "", cookie, sess.CSRFToken)
	rec := serve(t, s, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("non-owner DELETE = %d, want 404", rec.Code)
	}

	// Owner can delete
	req = authReq("DELETE", "/api/chat/conversations/"+convo.ID, "", adminCookie, adminCSRF)
	rec = serve(t, s, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("owner DELETE = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
}

func TestHandleChatMessage_GuardClauses(t *testing.T) {
	s := newTestServer(t, "")

	// nil chat -> 503
	s.chat = nil
	req := loopbackReq("POST", "/api/chat/conversations/fake/message", strings.NewReader(`{"message":"hi"}`))
	rec := serve(t, s, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("nil chat = %d, want 503", rec.Code)
	}

	// Restore chat but no API key -> 412
	dir := t.TempDir()
	chat, _ := NewChatManager(dir, nil)
	s.chat = chat
	req = loopbackReq("POST", "/api/chat/conversations/fake/message", strings.NewReader(`{"message":"hi"}`))
	rec = serve(t, s, req)
	if rec.Code != http.StatusPreconditionFailed {
		t.Fatalf("no API key = %d, want 412", rec.Code)
	}

	// With API key but bad convo ID -> 404
	_ = chat.SetConfig("sk-test", "claude-sonnet-5", 4096)
	req = loopbackReq("POST", "/api/chat/conversations/nonexistent/message", strings.NewReader(`{"message":"hi"}`))
	rec = serve(t, s, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("bad convo = %d, want 404", rec.Code)
	}

	// Empty message -> 400
	convo, _ := chat.CreateConversation("default", "Test")
	req = loopbackReq("POST", "/api/chat/conversations/"+convo.ID+"/message", strings.NewReader(`{"message":""}`))
	rec = serve(t, s, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("empty message = %d, want 400", rec.Code)
	}

	// Malformed JSON -> 400
	req = loopbackReq("POST", "/api/chat/conversations/"+convo.ID+"/message", strings.NewReader(`{bad`))
	rec = serve(t, s, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad JSON = %d, want 400", rec.Code)
	}
}

func TestHandleChatMessage_OwnershipEnforced(t *testing.T) {
	s, _, _ := newAuthTestServer(t, "msgadmin", "msgadmin-long-password")
	_ = s.chat.SetConfig("sk-test", "claude-sonnet-5", 4096)
	convo, _ := s.chat.CreateConversation("msgadmin", "Admin Only")

	if _, err := s.auth.createUser("outsider", "outsider-long-password", RoleUser, false); err != nil {
		t.Fatalf("createUser: %v", err)
	}
	raw, sess, _ := s.auth.createSession("outsider", RoleUser)
	cookie := &http.Cookie{Name: sessionCookieName, Value: raw}
	req := authReq("POST", "/api/chat/conversations/"+convo.ID+"/message", `{"message":"hi"}`, cookie, sess.CSRFToken)
	rec := serve(t, s, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("non-owner message = %d, want 404", rec.Code)
	}
}
