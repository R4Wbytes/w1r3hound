package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/R4Wbytes/w1r3hound/internal/core"
	"github.com/R4Wbytes/w1r3hound/internal/mcp"
)

var errBridgeLost = fmt.Errorf("MCP bridge connection lost")

type mcpResponse struct {
	ID     json.RawMessage `json:"id"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

type mcpNotification struct {
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
}

type MCPScanResult struct {
	Report  core.ReportData
	Log     string
	Summary map[string]any
}

type MCPScanParams struct {
	Target             string            `json:"target"`
	Modules            []string          `json:"modules,omitempty"`
	Passive            bool              `json:"passive,omitempty"`
	Concurrency        int               `json:"concurrency,omitempty"`
	TimeoutSeconds     int               `json:"timeout_seconds,omitempty"`
	Ports              string            `json:"ports,omitempty"`
	RateLimit          int               `json:"rate_limit,omitempty"`
	MaxDurationSeconds int               `json:"max_duration_seconds,omitempty"`
	AllowPrivate       bool              `json:"allow_private,omitempty"`
	Verbose            bool              `json:"verbose,omitempty"`
	UserAgent          string            `json:"user_agent,omitempty"`
	Headers            map[string]string `json:"headers,omitempty"`
	Wordlist           string            `json:"wordlist,omitempty"`
	DirWordlist        string            `json:"dir_wordlist,omitempty"`
	DirExtensions      string            `json:"dir_extensions,omitempty"`
	SkipTLSVerify      *bool             `json:"skip_tls_verify,omitempty"`
	Resolver           string            `json:"resolver,omitempty"`
	Resolvers          []string          `json:"resolvers,omitempty"`
	WaybackLimit       int               `json:"wayback_limit,omitempty"`
	CrawlPages         int               `json:"crawl_pages,omitempty"`
	JSFiles            int               `json:"js_files,omitempty"`
	MinSeverity        string            `json:"min_severity,omitempty"`
}

// MCPBridge holds a persistent in-process connection to the MCP server via
// io.Pipe. One bridge per webui process; it multiplexes requests by ID.
type MCPBridge struct {
	toMCP      io.WriteCloser
	fromMCP    *bufio.Scanner
	fromMCPPipe io.Closer // read end of the response pipe

	reqID atomic.Int64
	done  chan struct{} // closed when readLoop exits

	pendMu  sync.Mutex
	pending map[string]chan mcpResponse

	notifyMu  sync.Mutex
	notifyFns map[string]func(mcpNotification) // keyed by progressToken
}

func NewMCPBridge(version string) (*MCPBridge, error) {
	pr, pw := io.Pipe()
	rr, rw := io.Pipe()

	b := &MCPBridge{
		toMCP:      pw,
		fromMCP:    bufio.NewScanner(rr),
		fromMCPPipe: rr,
		done:       make(chan struct{}),
		pending:    make(map[string]chan mcpResponse),
		notifyFns:  make(map[string]func(mcpNotification)),
	}
	b.fromMCP.Buffer(make([]byte, 0, 1024*1024), 10*1024*1024)

	go mcp.ServeIO(version, pr, rw)
	go b.readLoop()

	if err := b.init(); err != nil {
		_ = pw.Close()
		return nil, fmt.Errorf("MCP bridge init: %w", err)
	}
	return b, nil
}

func (b *MCPBridge) readLoop() {
	defer b.drainPending()
	defer close(b.done)
	for b.fromMCP.Scan() {
		line := b.fromMCP.Bytes()
		if len(line) == 0 {
			continue
		}
		var envelope struct {
			ID     json.RawMessage `json:"id,omitempty"`
			Method string          `json:"method,omitempty"`
		}
		if err := json.Unmarshal(line, &envelope); err != nil {
			continue
		}

		if len(envelope.ID) > 0 && envelope.ID[0] != 'n' {
			var resp mcpResponse
			_ = json.Unmarshal(line, &resp)
			key := string(resp.ID)

			b.pendMu.Lock()
			ch, ok := b.pending[key]
			if ok {
				delete(b.pending, key)
			}
			b.pendMu.Unlock()

			if ok {
				ch <- resp
			}
			continue
		}

		if envelope.Method != "" {
			var notif mcpNotification
			_ = json.Unmarshal(line, &notif)
			// Route by progressToken so concurrent scans get their own callbacks.
			var token string
			var params struct {
				ProgressToken string `json:"progressToken"`
			}
			if json.Unmarshal(notif.Params, &params) == nil && params.ProgressToken != "" {
				token = params.ProgressToken
			}
			b.notifyMu.Lock()
			fn := b.notifyFns[token]
			if fn == nil {
				fn = b.notifyFns[""]
			}
			b.notifyMu.Unlock()
			if fn != nil {
				fn(notif)
			}
		}
	}
}

// drainPending sends a synthetic error to every caller still waiting for a
// response, preventing goroutine leaks when the read loop exits.
func (b *MCPBridge) drainPending() {
	b.pendMu.Lock()
	defer b.pendMu.Unlock()
	for id, ch := range b.pending {
		ch <- mcpResponse{
			Error: &struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
			}{Code: -32000, Message: "MCP bridge connection lost"},
		}
		delete(b.pending, id)
	}
}

func (b *MCPBridge) send(id string, method string, params any) (mcpResponse, error) {
	ch := make(chan mcpResponse, 1)

	b.pendMu.Lock()
	b.pending[id] = ch
	b.pendMu.Unlock()

	msg := map[string]any{
		"jsonrpc": "2.0",
		"id":      json.RawMessage(id),
		"method":  method,
	}
	if params != nil {
		msg["params"] = params
	}
	data, err := json.Marshal(msg)
	if err != nil {
		b.pendMu.Lock()
		delete(b.pending, id)
		b.pendMu.Unlock()
		return mcpResponse{}, err
	}
	data = append(data, '\n')

	if _, err := b.toMCP.Write(data); err != nil {
		b.pendMu.Lock()
		delete(b.pending, id)
		b.pendMu.Unlock()
		return mcpResponse{}, err
	}

	select {
	case resp := <-ch:
		return resp, nil
	case <-b.done:
		select {
		case resp := <-ch:
			return resp, nil
		default:
		}
		return mcpResponse{}, errBridgeLost
	}
}

func (b *MCPBridge) nextID() string {
	return strconv.FormatInt(b.reqID.Add(1), 10)
}

func (b *MCPBridge) init() error {
	resp, err := b.send(b.nextID(), "initialize", map[string]any{
		"protocolVersion": "2025-06-18",
		"capabilities":    map[string]any{},
		"clientInfo": map[string]any{
			"name":    "w1r3hound-webui",
			"version": "1.0.0",
		},
	})
	if err != nil {
		return err
	}
	if resp.Error != nil {
		return fmt.Errorf("initialize error: %s", resp.Error.Message)
	}

	// Send initialized notification (no response expected).
	notif := map[string]any{
		"jsonrpc": "2.0",
		"method":  "notifications/initialized",
	}
	data, _ := json.Marshal(notif)
	data = append(data, '\n')
	_, _ = b.toMCP.Write(data)

	return nil
}

// Scan sends a tools/call for "scan" and blocks until the result arrives.
// Progress and log notifications are routed to onNotify while the scan runs.
// Each concurrent scan gets its own callback keyed by progressToken.
func (b *MCPBridge) Scan(ctx context.Context, params MCPScanParams, onNotify func(mcpNotification)) (*MCPScanResult, error) {
	id := b.nextID()
	token := "webui-" + id

	b.notifyMu.Lock()
	if onNotify != nil {
		b.notifyFns[token] = onNotify
	}
	b.notifyMu.Unlock()
	defer func() {
		b.notifyMu.Lock()
		delete(b.notifyFns, token)
		b.notifyMu.Unlock()
	}()
	argsData, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}

	ch := make(chan mcpResponse, 1)
	b.pendMu.Lock()
	b.pending[id] = ch
	b.pendMu.Unlock()

	msg := map[string]any{
		"jsonrpc": "2.0",
		"id":      json.RawMessage(id),
		"method":  "tools/call",
		"params": map[string]any{
			"name":      "scan",
			"arguments": json.RawMessage(argsData),
			"_meta": map[string]any{
				"progressToken": "webui-" + id,
			},
		},
	}
	data, _ := json.Marshal(msg)
	data = append(data, '\n')

	if _, err := b.toMCP.Write(data); err != nil {
		b.pendMu.Lock()
		delete(b.pending, id)
		b.pendMu.Unlock()
		return nil, err
	}

	select {
	case <-ctx.Done():
		// Send cancellation to MCP.
		cancel := map[string]any{
			"jsonrpc": "2.0",
			"method":  "notifications/cancelled",
			"params": map[string]any{
				"requestId": json.RawMessage(id),
			},
		}
		cdata, _ := json.Marshal(cancel)
		cdata = append(cdata, '\n')
		_, _ = b.toMCP.Write(cdata)

		// Wait for the response with a bounded timeout so we don't hang
		// if the MCP server crashed before acknowledging the cancellation.
		select {
		case <-ch:
		case <-time.After(5 * time.Second):
			b.pendMu.Lock()
			delete(b.pending, id)
			b.pendMu.Unlock()
		case <-b.done:
		}
		return nil, ctx.Err()

	case resp := <-ch:
		if resp.Error != nil {
			return nil, fmt.Errorf("MCP scan error [%d]: %s", resp.Error.Code, resp.Error.Message)
		}
		return parseScanResult(resp.Result)
	}
}

func parseScanResult(raw json.RawMessage) (*MCPScanResult, error) {
	var result struct {
		StructuredContent struct {
			Report  core.ReportData `json:"report"`
			Log     string          `json:"log"`
			Summary map[string]any  `json:"summary"`
		} `json:"structuredContent"`
		IsError bool `json:"isError"`
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, fmt.Errorf("parse scan result: %w", err)
	}
	if result.IsError {
		text := ""
		if len(result.Content) > 0 {
			text = result.Content[0].Text
		}
		return nil, fmt.Errorf("scan failed: %s", text)
	}
	return &MCPScanResult{
		Report:  result.StructuredContent.Report,
		Log:     result.StructuredContent.Log,
		Summary: result.StructuredContent.Summary,
	}, nil
}

// CallTool sends a generic tools/call and returns the raw text result.
func (b *MCPBridge) CallTool(name string, args any) (string, error) {
	argsData, err := json.Marshal(args)
	if err != nil {
		return "", err
	}
	resp, err := b.send(b.nextID(), "tools/call", map[string]any{
		"name":      name,
		"arguments": json.RawMessage(argsData),
	})
	if err != nil {
		return "", err
	}
	if resp.Error != nil {
		return "", fmt.Errorf("tool %s error: %s", name, resp.Error.Message)
	}
	var result struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		return "", err
	}
	if len(result.Content) > 0 {
		return result.Content[0].Text, nil
	}
	return "", nil
}

// Prompts calls prompts/list and returns the raw definitions.
func (b *MCPBridge) Prompts() (json.RawMessage, error) {
	resp, err := b.send(b.nextID(), "prompts/list", nil)
	if err != nil {
		return nil, err
	}
	if resp.Error != nil {
		return nil, fmt.Errorf("prompts/list error: %s", resp.Error.Message)
	}
	var result struct {
		Prompts json.RawMessage `json:"prompts"`
	}
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		return nil, err
	}
	return result.Prompts, nil
}

// GetPrompt calls prompts/get and returns the messages.
func (b *MCPBridge) GetPrompt(name string, args map[string]string) (json.RawMessage, error) {
	resp, err := b.send(b.nextID(), "prompts/get", map[string]any{
		"name":      name,
		"arguments": args,
	})
	if err != nil {
		return nil, err
	}
	if resp.Error != nil {
		return nil, fmt.Errorf("prompts/get error: %s", resp.Error.Message)
	}
	var result struct {
		Messages json.RawMessage `json:"messages"`
	}
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		return nil, err
	}
	return result.Messages, nil
}

// Close shuts down the bridge by closing both pipes. The write close causes
// the MCP server's run() loop to exit on EOF; the read close unblocks
// readLoop if the server hasn't closed its writer yet.
func (b *MCPBridge) Close() {
	_ = b.toMCP.Close()
	_ = b.fromMCPPipe.Close()
}

// version is the webui build version, injected at build time or read from env.
func mcpVersion() string {
	if v := os.Getenv("W1R3HOUND_VERSION"); v != "" {
		return v
	}
	return "dev"
}
