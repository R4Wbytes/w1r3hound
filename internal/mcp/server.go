// Package mcp implements a Model Context Protocol (JSON-RPC 2.0 over stdio)
// server that exposes w1r3hound's recon modules as tools for AI agents.
package mcp

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"sync"
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

// Server is the MCP stdio server.
type Server struct {
	version string
	enc     *json.Encoder
	mu      sync.Mutex // serializes writes to stdout
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
		s.dispatch(&req)
	}
}

func (s *Server) dispatch(req *request) {
	switch req.Method {
	case "initialize":
		s.handleInitialize(req)
	case "notifications/initialized":
		// no response
	case "notifications/cancelled":
		// v1: no-op (single-threaded, scan blocks the loop)
	case "ping":
		s.send(req.ID, map[string]any{})
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

func (s *Server) handleInitialize(req *request) {
	s.send(req.ID, map[string]any{
		"protocolVersion": "2025-06-18",
		"capabilities": map[string]any{
			"tools": map[string]any{},
		},
		"serverInfo": map[string]any{
			"name":    "w1r3hound",
			"version": s.version,
		},
	})
}

func (s *Server) handleToolsList(req *request) {
	s.send(req.ID, map[string]any{
		"tools": toolDefinitions(),
	})
}

func (s *Server) handleToolsCall(req *request) {
	var params struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(req.Params, &params); err != nil {
		s.sendError(req.ID, -32602, "invalid params: "+err.Error())
		return
	}

	text, isErr := executeTool(params.Name, params.Arguments)
	s.send(req.ID, map[string]any{
		"content": []map[string]string{
			{"type": "text", "text": text},
		},
		"isError": isErr,
	})
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
