package main

import (
	"os"
	"path/filepath"
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
