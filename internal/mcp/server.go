// Package mcp implements a Model Context Protocol (JSON-RPC 2.0 over stdio)
// server that exposes w1r3hound's recon modules as tools for AI agents.
package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"sync"
	"sync/atomic"
)

// JSON-RPC 2.0 types. id is kept as json.RawMessage so string, number and
// null values round-trip without interpretation.

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (r *request) isNotification() bool { return len(r.ID) == 0 }

var logLevelOrder = map[string]int{
	"debug": 0, "info": 1, "notice": 2, "warning": 3,
	"error": 4, "critical": 5, "alert": 6, "emergency": 7,
}

// Server is the MCP stdio server.
type Server struct {
	version    string
	enc        *json.Encoder
	mu         sync.Mutex     // serializes writes to stdout
	activeReqs sync.Map       // string(requestID) → context.CancelFunc
	wg         sync.WaitGroup // tracks in-flight async tool calls
	logLevel   atomic.Int32   // minimum syslog level for notifications/message
}

// notify sends a JSON-RPC notification (no id, no response expected).
func (s *Server) notify(method string, params any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = s.enc.Encode(map[string]any{
		"jsonrpc": "2.0",
		"method":  method,
		"params":  params,
	})
}

// notifyProgress sends a progress notification only if the client provided a
// progressToken in _meta. The token is echoed back as-is (string or integer).
func (s *Server) notifyProgress(token json.RawMessage, progress, total int, message string) {
	if len(token) == 0 {
		return
	}
	s.notify("notifications/progress", map[string]any{
		"progressToken": token,
		"progress":      progress,
		"total":         total,
		"message":       message,
	})
}

// notifyLog sends a notifications/message if the level meets the threshold.
func (s *Server) notifyLog(level, logger, data string) {
	if logLevelOrder[level] < int(s.logLevel.Load()) {
		return
	}
	s.notify("notifications/message", map[string]any{
		"level":  level,
		"logger": logger,
		"data":   data,
	})
}

// Serve is the public entry point called from main when --mcp is set.
// It blocks until stdin is closed (EOF).
func Serve(version string) {
	log.SetOutput(os.Stderr)

	s := &Server{
		version: version,
		enc:     json.NewEncoder(os.Stdout),
	}
	s.run(os.Stdin)
}

// ServeIO is like Serve but accepts explicit reader/writer for testing.
func ServeIO(version string, r io.Reader, w io.Writer) {
	s := &Server{
		version: version,
		enc:     json.NewEncoder(w),
	}
	s.run(r)
}

func (s *Server) run(r io.Reader) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 1024*1024), 10*1024*1024)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		// Detect batch requests (JSON arrays) before unmarshal.
		if trimmed := bytes.TrimLeft(line, " \t"); len(trimmed) > 0 && trimmed[0] == '[' {
			s.sendError(nil, -32600, "batch requests are not supported")
			continue
		}
		var req request
		if err := json.Unmarshal(line, &req); err != nil {
			s.sendError(nil, -32700, "parse error")
			continue
		}
		if req.JSONRPC != "2.0" && !req.isNotification() {
			s.sendError(req.ID, -32600, `invalid request: jsonrpc field must be "2.0"`)
			continue
		}
		// Spec: request id MUST NOT be null.
		if !req.isNotification() && string(req.ID) == "null" {
			s.sendError(nil, -32600, "invalid request: id must not be null")
			continue
		}
		s.dispatch(&req)
	}
	s.wg.Wait()
}

func (s *Server) dispatch(req *request) {
	switch req.Method {
	case "initialize":
		s.handleInitialize(req)
	case "server/discover":
		s.handleDiscover(req)
	case "notifications/initialized":
		// no response
	case "notifications/cancelled":
		s.handleCancelled(req)
	case "ping":
		s.send(req.ID, map[string]any{"resultType": "complete"})
	case "logging/setLevel":
		s.handleSetLogLevel(req)
	case "prompts/list":
		s.handlePromptsList(req)
	case "prompts/get":
		s.handlePromptsGet(req)
	case "completion/complete":
		s.handleComplete(req)
	case "tools/list":
		s.handleToolsList(req)
	case "tools/call":
		s.handleToolsCall(req)
	default:
		if !req.isNotification() {
			s.sendError(req.ID, -32601, fmt.Sprintf("method not found: %s", req.Method))
		}
	}
}

var serverInstructions = "w1r3hound is an offensive reconnaissance toolkit with 21 modules. " +
	"Use list_modules to discover modules, suggest_modules for recommendations based on your objective, " +
	"server_info to check status, and scan to execute recon. " +
	"SSRF guard is ON by default (set allow_private=true for internal targets). " +
	"Progress notifications require a progressToken in _meta. " +
	"Send logging/setLevel to control log verbosity during scans."

func (s *Server) serverCapabilities() map[string]any {
	return map[string]any{
		"tools":       map[string]any{"listChanged": false},
		"prompts":     map[string]any{"listChanged": false},
		"completions": map[string]any{},
		"logging":     map[string]any{},
	}
}

func (s *Server) serverInfoMap() map[string]any {
	return map[string]any{
		"name":    "w1r3hound",
		"title":   "w1r3hound Recon Toolkit",
		"version": s.version,
	}
}

func (s *Server) handleInitialize(req *request) {
	s.send(req.ID, map[string]any{
		"protocolVersion": "2025-06-18",
		"capabilities":    s.serverCapabilities(),
		"serverInfo":      s.serverInfoMap(),
		"instructions":    serverInstructions,
	})
}

func (s *Server) handleDiscover(req *request) {
	s.send(req.ID, map[string]any{
		"resultType":        "complete",
		"supportedVersions": []string{"2025-06-18", "2026-07-28"},
		"capabilities":      s.serverCapabilities(),
		"instructions":      serverInstructions,
		"ttlMs":             3600000,
		"cacheScope":        "public",
		"_meta": map[string]any{
			"io.modelcontextprotocol/serverInfo": s.serverInfoMap(),
		},
	})
}

func (s *Server) handleCancelled(req *request) {
	var params struct {
		RequestID json.RawMessage `json:"requestId"`
	}
	if len(req.Params) > 0 {
		_ = json.Unmarshal(req.Params, &params)
	}
	if cancel, ok := s.activeReqs.LoadAndDelete(string(params.RequestID)); ok {
		cancel.(context.CancelFunc)()
	}
}

func (s *Server) handleSetLogLevel(req *request) {
	var params struct {
		Level string `json:"level"`
	}
	if len(req.Params) > 0 {
		_ = json.Unmarshal(req.Params, &params)
	}
	level, ok := logLevelOrder[params.Level]
	if !ok {
		s.sendError(req.ID, -32602, fmt.Sprintf("unknown log level: %q — valid: debug, info, notice, warning, error, critical, alert, emergency", params.Level))
		return
	}
	s.logLevel.Store(int32(level))
	s.send(req.ID, map[string]any{"resultType": "complete"})
}

func (s *Server) handlePromptsList(req *request) {
	s.send(req.ID, map[string]any{
		"resultType": "complete",
		"prompts":    promptDefinitions(),
	})
}

func (s *Server) handlePromptsGet(req *request) {
	var params struct {
		Name      string            `json:"name"`
		Arguments map[string]string `json:"arguments"`
	}
	if len(req.Params) > 0 {
		if err := json.Unmarshal(req.Params, &params); err != nil {
			s.sendError(req.ID, -32602, "invalid params: "+err.Error())
			return
		}
	}
	messages, ok := buildPrompt(params.Name, params.Arguments)
	if !ok {
		s.sendError(req.ID, -32602, fmt.Sprintf("unknown prompt: %q", params.Name))
		return
	}
	s.send(req.ID, map[string]any{
		"resultType": "complete",
		"messages":   messages,
	})
}

func (s *Server) handleComplete(req *request) {
	var params struct {
		Ref struct {
			Type string `json:"type"`
			Name string `json:"name"`
		} `json:"ref"`
		Argument struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		} `json:"argument"`
	}
	if len(req.Params) > 0 {
		if err := json.Unmarshal(req.Params, &params); err != nil {
			s.sendError(req.ID, -32602, "invalid params: "+err.Error())
			return
		}
	}
	values := completeArgument(params.Ref.Type, params.Ref.Name, params.Argument.Name, params.Argument.Value)
	s.send(req.ID, map[string]any{
		"completion": map[string]any{
			"values":  values,
			"hasMore": false,
			"total":   len(values),
		},
	})
}

func (s *Server) handleToolsList(req *request) {
	s.send(req.ID, map[string]any{
		"resultType": "complete",
		"tools":      toolDefinitions(),
		"ttlMs":      3600000,
		"cacheScope": "public",
	})
}

func (s *Server) handleToolsCall(req *request) {
	var params struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
		Meta      *struct {
			ProgressToken json.RawMessage `json:"progressToken"`
		} `json:"_meta"`
	}
	if err := json.Unmarshal(req.Params, &params); err != nil {
		s.sendError(req.ID, -32602, "invalid params: "+err.Error())
		return
	}

	var progressToken json.RawMessage
	if params.Meta != nil {
		progressToken = params.Meta.ProgressToken
	}

	tc := &toolCall{
		srv:           s,
		progressToken: progressToken,
	}

	// Scan runs async to support cancellation via notifications/cancelled.
	if params.Name == "scan" {
		ctx, cancel := context.WithCancel(context.Background())
		reqKey := string(req.ID)
		s.activeReqs.Store(reqKey, cancel)
		s.wg.Add(1)

		go func() {
			defer s.wg.Done()
			defer cancel()
			defer s.activeReqs.Delete(reqKey)
			defer func() {
				if r := recover(); r != nil {
					s.sendToolResult(req.ID, toolResult{
						Text:    fmt.Sprintf("internal error: %v", r),
						IsError: true,
					})
				}
			}()
			tc.ctx = ctx
			tr := executeTool(params.Name, params.Arguments, tc)
			s.sendToolResult(req.ID, tr)
		}()
		return
	}

	tc.ctx = context.Background()
	tr := executeTool(params.Name, params.Arguments, tc)
	s.sendToolResult(req.ID, tr)
}

func (s *Server) sendToolResult(id json.RawMessage, tr toolResult) {
	result := map[string]any{
		"resultType": "complete",
		"content": []map[string]any{
			{
				"type": "text",
				"text": tr.Text,
				"annotations": map[string]any{
					"audience": []string{"user", "assistant"},
					"priority": 1.0,
				},
			},
		},
		"isError": tr.IsError,
	}
	if tr.StructuredContent != nil {
		result["structuredContent"] = tr.StructuredContent
	}
	s.send(id, result)
}

func (s *Server) send(id json.RawMessage, result any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = s.enc.Encode(response{
		JSONRPC: "2.0",
		ID:      id,
		Result:  result,
	})
}

func (s *Server) sendError(id json.RawMessage, code int, msg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = s.enc.Encode(response{
		JSONRPC: "2.0",
		ID:      id,
		Error:   &rpcError{Code: code, Message: msg},
	})
}
