package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// toolCaller is satisfied by *MCPBridge (from mcpbridge.go).
type toolCaller interface {
	CallTool(name string, args any) (string, error)
}

type ChatConfig struct {
	APIKey    string `json:"api_key,omitempty"`
	Model     string `json:"model"`
	Endpoint  string `json:"endpoint"`
	MaxTokens int    `json:"max_tokens"`
}

type ChatMessage struct {
	Role      string         `json:"role"`
	Content   string         `json:"content"`
	ToolUseID string         `json:"tool_use_id,omitempty"`
	ToolName  string         `json:"tool_name,omitempty"`
	ToolInput map[string]any `json:"tool_input,omitempty"`
	Timestamp string         `json:"timestamp"`
}

type Conversation struct {
	ID        string        `json:"id"`
	Title     string        `json:"title"`
	Owner     string        `json:"owner"`
	CreatedAt string        `json:"created_at"`
	UpdatedAt string        `json:"updated_at"`
	Messages  []ChatMessage `json:"messages"`
}

type ConvoSummary struct {
	ID        string `json:"id"`
	Title     string `json:"title"`
	Owner     string `json:"owner"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
	MsgCount  int    `json:"message_count"`
}

type ChatManager struct {
	mu       sync.Mutex
	config   ChatConfig
	bridge   toolCaller
	chatsDir string
}

func NewChatManager(chatsDir string, bridge toolCaller) (*ChatManager, error) {
	if err := os.MkdirAll(chatsDir, 0o700); err != nil {
		return nil, err
	}
	cm := &ChatManager{
		config: ChatConfig{
			Model:     "claude-sonnet-4-20250514",
			Endpoint:  "https://api.anthropic.com/v1/messages",
			MaxTokens: 4096,
		},
		bridge:   bridge,
		chatsDir: chatsDir,
	}
	cfgPath := filepath.Join(chatsDir, "config.json")
	if data, err := os.ReadFile(cfgPath); err == nil { // #nosec G304 — path is under server-controlled chatsDir
		var saved ChatConfig
		if json.Unmarshal(data, &saved) == nil {
			if saved.APIKey != "" {
				cm.config.APIKey = saved.APIKey
			}
			if saved.Model != "" {
				cm.config.Model = saved.Model
			}
			if saved.MaxTokens > 0 {
				cm.config.MaxTokens = saved.MaxTokens
			}
		}
	}
	return cm, nil
}

func (cm *ChatManager) Configured() bool {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	return cm.config.APIKey != ""
}

func (cm *ChatManager) ConfigStatus() map[string]any {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	return map[string]any{
		"configured": cm.config.APIKey != "",
		"model":      cm.config.Model,
		"max_tokens": cm.config.MaxTokens,
	}
}

func (cm *ChatManager) SetConfig(apiKey, model string, maxTokens int) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	if apiKey != "" {
		cm.config.APIKey = apiKey
	}
	if model != "" {
		cm.config.Model = model
	}
	if maxTokens > 0 {
		cm.config.MaxTokens = maxTokens
	}
	data, _ := json.MarshalIndent(cm.config, "", "  ") // #nosec G117 — APIKey is intentionally persisted to the server-side config file (0600); it is never sent to the browser
	return os.WriteFile(filepath.Join(cm.chatsDir, "config.json"), data, 0o600)
}

func (cm *ChatManager) CreateConversation(owner, title string) (*Conversation, error) {
	id := generateConvoID()
	now := time.Now().UTC().Format(time.RFC3339)
	if title == "" {
		title = "New conversation"
	}
	convo := &Conversation{
		ID: id, Title: title, Owner: owner,
		CreatedAt: now, UpdatedAt: now,
		Messages: []ChatMessage{},
	}
	if err := cm.saveConversation(convo); err != nil {
		return nil, err
	}
	return convo, nil
}

func generateConvoID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return fmt.Sprintf("conv_%s_%s", time.Now().UTC().Format("20060102_150405"), hex.EncodeToString(b))
}

func (cm *ChatManager) convoPath(id string) string {
	return filepath.Join(cm.chatsDir, id+".json")
}

func (cm *ChatManager) loadConversation(id string) (*Conversation, error) {
	if !validConvoID(id) {
		return nil, fmt.Errorf("invalid conversation id")
	}
	data, err := os.ReadFile(cm.convoPath(id)) // #nosec G304 — id is validated by validConvoID (single path component, no "..")
	if err != nil {
		return nil, err
	}
	var c Conversation
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

func (cm *ChatManager) saveConversation(c *Conversation) error {
	c.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp := cm.convoPath(c.ID) + ".tmp"
	// #nosec G703 — c.ID is validated by validConvoID (single path component, no ".."); convoPath joins it under chatsDir
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, cm.convoPath(c.ID))
}

func (cm *ChatManager) DeleteConversation(id string) error {
	if !validConvoID(id) {
		return fmt.Errorf("invalid conversation id")
	}
	return os.Remove(cm.convoPath(id))
}

func (cm *ChatManager) ListConversations(owner string, isAdmin bool) []ConvoSummary {
	entries, _ := os.ReadDir(cm.chatsDir)
	var out []ConvoSummary
	for _, e := range entries {
		if e.IsDir() || !strings.HasPrefix(e.Name(), "conv_") || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		id := strings.TrimSuffix(e.Name(), ".json")
		c, err := cm.loadConversation(id)
		if err != nil {
			continue
		}
		if !isAdmin && c.Owner != owner {
			continue
		}
		out = append(out, ConvoSummary{
			ID: c.ID, Title: c.Title, Owner: c.Owner,
			CreatedAt: c.CreatedAt, UpdatedAt: c.UpdatedAt,
			MsgCount: len(c.Messages),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UpdatedAt > out[j].UpdatedAt })
	return out
}

func validConvoID(id string) bool {
	if id == "" || len(id) > 64 {
		return false
	}
	return filepath.Base(id) == id && !strings.Contains(id, "..")
}

func (cm *ChatManager) toolDefinitions() []map[string]any {
	return []map[string]any{
		{
			"name":        "scan",
			"description": "Run a w1r3hound reconnaissance scan against a target. Always confirm authorization before scanning.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"target":          map[string]any{"type": "string", "description": "Target hostname, IP, CIDR, or URL"},
					"modules":         map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "Modules to run (empty = all)"},
					"passive":         map[string]any{"type": "boolean", "description": "Passive-only mode"},
					"ports":           map[string]any{"type": "string", "enum": []string{"top100", "1-1024", "full"}},
					"concurrency":     map[string]any{"type": "integer", "description": "Concurrent workers"},
					"timeout_seconds": map[string]any{"type": "integer", "description": "Per-request timeout"},
				},
				"required": []string{"target"},
			},
		},
		{
			"name":         "list_modules",
			"description":  "List available w1r3hound reconnaissance modules",
			"input_schema": map[string]any{"type": "object", "properties": map[string]any{}},
		},
		{
			"name":        "suggest_modules",
			"description": "Suggest which modules to run based on the target and objective",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"target":    map[string]any{"type": "string"},
					"objective": map[string]any{"type": "string"},
				},
				"required": []string{"target"},
			},
		},
		{
			"name":         "server_info",
			"description":  "Get w1r3hound server status and capabilities",
			"input_schema": map[string]any{"type": "object", "properties": map[string]any{}},
		},
	}
}

type chatEvent struct {
	Type string `json:"type"`
	Data string `json:"data,omitempty"`
	Tool string `json:"tool,omitempty"`
	ID   string `json:"id,omitempty"`
}

func (cm *ChatManager) Send(ctx context.Context, convoID, userMsg string, onEvent func(chatEvent)) error {
	cm.mu.Lock()
	apiKey := cm.config.APIKey
	model := cm.config.Model
	endpoint := cm.config.Endpoint
	maxTokens := cm.config.MaxTokens
	cm.mu.Unlock()

	if apiKey == "" {
		return fmt.Errorf("API key not configured")
	}

	convo, err := cm.loadConversation(convoID)
	if err != nil {
		return fmt.Errorf("conversation not found")
	}

	convo.Messages = append(convo.Messages, ChatMessage{
		Role: "user", Content: userMsg,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	})

	apiMessages := cm.buildAPIMessages(convo.Messages)
	tools := cm.toolDefinitions()

	systemPrompt := "You are w1r3hound, an offensive reconnaissance assistant. You have access to " +
		"scan, list_modules, suggest_modules, and server_info tools. Always confirm authorization " +
		"before scanning. Summarize findings by severity. Never fabricate findings."

	for i := 0; i < 10; i++ {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		response, err := cm.callLLM(ctx, apiKey, endpoint, model, systemPrompt, apiMessages, tools, maxTokens, onEvent)
		if err != nil {
			onEvent(chatEvent{Type: "error", Data: err.Error()})
			return err
		}

		hasToolUse := false
		var assistantText string
		type toolUseEntry struct {
			ID    string
			Name  string
			Input map[string]any
		}
		var toolUses []toolUseEntry

		for _, block := range response.Content {
			if block.Type == "text" {
				assistantText += block.Text
			} else if block.Type == "tool_use" {
				hasToolUse = true
				toolUses = append(toolUses, toolUseEntry{ID: block.ID, Name: block.Name, Input: block.Input})
			}
		}

		if assistantText != "" {
			convo.Messages = append(convo.Messages, ChatMessage{
				Role: "assistant", Content: assistantText,
				Timestamp: time.Now().UTC().Format(time.RFC3339),
			})
		}

		if !hasToolUse {
			break
		}

		for _, tu := range toolUses {
			convo.Messages = append(convo.Messages, ChatMessage{
				Role: "assistant_tool_use", ToolUseID: tu.ID,
				ToolName: tu.Name, ToolInput: tu.Input,
				Timestamp: time.Now().UTC().Format(time.RFC3339),
			})
		}

		apiMessages = append(apiMessages, response.toAPIMessage())

		var toolResults []map[string]any
		for _, tu := range toolUses {
			onEvent(chatEvent{Type: "tool_start", Tool: tu.Name, ID: tu.ID})

			result := ""
			if cm.bridge != nil {
				var toolErr error
				result, toolErr = cm.bridge.CallTool(tu.Name, tu.Input)
				if toolErr != nil {
					result = "Error: " + toolErr.Error()
				}
			} else {
				result = "Error: MCP bridge not available"
			}

			onEvent(chatEvent{Type: "tool_result", Tool: tu.Name, ID: tu.ID, Data: truncateToolResult(result, 4000)})

			convo.Messages = append(convo.Messages, ChatMessage{
				Role: "tool_result", Content: result,
				ToolUseID: tu.ID, ToolName: tu.Name,
				Timestamp: time.Now().UTC().Format(time.RFC3339),
			})

			toolResults = append(toolResults, map[string]any{
				"type":        "tool_result",
				"tool_use_id": tu.ID,
				"content":     result,
			})
		}

		apiMessages = append(apiMessages, map[string]any{
			"role":    "user",
			"content": toolResults,
		})
	}

	if convo.Title == "New conversation" && userMsg != "" {
		t := userMsg
		if len(t) > 60 {
			t = t[:60] + "..."
		}
		convo.Title = t
	}

	onEvent(chatEvent{Type: "done"})
	return cm.saveConversation(convo)
}

func truncateToolResult(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "\n... (truncated)"
}

type llmResponse struct {
	Content    []llmContentBlock `json:"content"`
	StopReason string            `json:"stop_reason"`
}

type llmContentBlock struct {
	Type  string         `json:"type"`
	Text  string         `json:"text,omitempty"`
	ID    string         `json:"id,omitempty"`
	Name  string         `json:"name,omitempty"`
	Input map[string]any `json:"input,omitempty"`
}

func (r *llmResponse) toAPIMessage() map[string]any {
	content := make([]map[string]any, 0, len(r.Content))
	for _, b := range r.Content {
		block := map[string]any{"type": b.Type}
		switch b.Type {
		case "text":
			block["text"] = b.Text
		case "tool_use":
			block["id"] = b.ID
			block["name"] = b.Name
			block["input"] = b.Input
		}
		content = append(content, block)
	}
	return map[string]any{"role": "assistant", "content": content}
}

func (cm *ChatManager) buildAPIMessages(msgs []ChatMessage) []map[string]any {
	var out []map[string]any
	for i := 0; i < len(msgs); i++ {
		m := msgs[i]
		switch m.Role {
		case "user":
			out = append(out, map[string]any{"role": "user", "content": m.Content})
		case "assistant":
			content := []map[string]any{{"type": "text", "text": m.Content}}
			for i+1 < len(msgs) && msgs[i+1].Role == "assistant_tool_use" {
				i++
				tu := msgs[i]
				content = append(content, map[string]any{
					"type": "tool_use", "id": tu.ToolUseID,
					"name": tu.ToolName, "input": tu.ToolInput,
				})
			}
			out = append(out, map[string]any{"role": "assistant", "content": content})
		case "assistant_tool_use":
			// Orphaned tool_use without preceding assistant text — wrap it.
			content := []map[string]any{{
				"type": "tool_use", "id": m.ToolUseID,
				"name": m.ToolName, "input": m.ToolInput,
			}}
			for i+1 < len(msgs) && msgs[i+1].Role == "assistant_tool_use" {
				i++
				tu := msgs[i]
				content = append(content, map[string]any{
					"type": "tool_use", "id": tu.ToolUseID,
					"name": tu.ToolName, "input": tu.ToolInput,
				})
			}
			out = append(out, map[string]any{"role": "assistant", "content": content})
		case "tool_result":
			results := []map[string]any{{
				"type": "tool_result", "tool_use_id": m.ToolUseID, "content": m.Content,
			}}
			for i+1 < len(msgs) && msgs[i+1].Role == "tool_result" {
				i++
				tr := msgs[i]
				results = append(results, map[string]any{
					"type": "tool_result", "tool_use_id": tr.ToolUseID, "content": tr.Content,
				})
			}
			out = append(out, map[string]any{"role": "user", "content": results})
		}
	}
	return out
}

func (cm *ChatManager) callLLM(ctx context.Context, apiKey, endpoint, model, system string, messages []map[string]any, tools []map[string]any, maxTokens int, onEvent func(chatEvent)) (*llmResponse, error) {
	body := map[string]any{
		"model":      model,
		"max_tokens": maxTokens,
		"system":     system,
		"messages":   messages,
		"stream":     true,
	}
	if len(tools) > 0 {
		body["tools"] = tools
	}

	data, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, strings.NewReader(string(data)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("LLM request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 200 {
		errBody, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return nil, fmt.Errorf("LLM API error %d: %s", resp.StatusCode, string(errBody))
	}

	result := &llmResponse{}
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var currentBlock *llmContentBlock
	var inputJSON strings.Builder

	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		payload := line[6:]
		if payload == "[DONE]" {
			break
		}

		var event struct {
			Type         string `json:"type"`
			ContentBlock struct {
				Type string `json:"type"`
				ID   string `json:"id,omitempty"`
				Name string `json:"name,omitempty"`
				Text string `json:"text,omitempty"`
			} `json:"content_block,omitempty"`
			Delta struct {
				Type        string `json:"type"`
				Text        string `json:"text,omitempty"`
				PartialJSON string `json:"partial_json,omitempty"`
			} `json:"delta,omitempty"`
		}
		if err := json.Unmarshal([]byte(payload), &event); err != nil {
			continue
		}

		switch event.Type {
		case "content_block_start":
			block := llmContentBlock{
				Type: event.ContentBlock.Type,
				ID:   event.ContentBlock.ID,
				Name: event.ContentBlock.Name,
				Text: event.ContentBlock.Text,
			}
			currentBlock = &block
			inputJSON.Reset()

		case "content_block_delta":
			if currentBlock == nil {
				continue
			}
			if event.Delta.Type == "text_delta" {
				currentBlock.Text += event.Delta.Text
				onEvent(chatEvent{Type: "text", Data: event.Delta.Text})
			} else if event.Delta.Type == "input_json_delta" {
				inputJSON.WriteString(event.Delta.PartialJSON)
			}

		case "content_block_stop":
			if currentBlock == nil {
				continue
			}
			if currentBlock.Type == "tool_use" {
				var input map[string]any
				if inputJSON.Len() > 0 {
					_ = json.Unmarshal([]byte(inputJSON.String()), &input)
				}
				currentBlock.Input = input
			}
			result.Content = append(result.Content, *currentBlock)
			currentBlock = nil

		case "message_stop":
			// end of message
		}
	}

	return result, nil
}
