package core

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadLines(t *testing.T) {
	t.Run("empty path", func(t *testing.T) {
		if got := ReadLines(""); got != nil {
			t.Fatalf("expected nil for empty path, got %v", got)
		}
	})

	t.Run("nonexistent file", func(t *testing.T) {
		if got := ReadLines("/nonexistent/path/file.txt"); got != nil {
			t.Fatalf("expected nil for missing file, got %v", got)
		}
	})

	t.Run("reads and trims lines", func(t *testing.T) {
		dir := t.TempDir()
		p := filepath.Join(dir, "words.txt")
		content := "alpha\n  beta  \n# comment\n\ngamma\n"
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		got := ReadLines(p)
		want := []string{"alpha", "beta", "gamma"}
		if len(got) != len(want) {
			t.Fatalf("got %v, want %v", got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("line %d: got %q, want %q", i, got[i], want[i])
			}
		}
	})
}

func TestDoRequestRL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	client := srv.Client()

	t.Run("nil rate limiter", func(t *testing.T) {
		resp, err := DoRequestRL(client, "GET", srv.URL, "test-ua", nil)
		if err != nil {
			t.Fatalf("DoRequestRL: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
	})

	t.Run("with rate limiter", func(t *testing.T) {
		rl := NewRateLimiter(1000)
		defer rl.Stop()
		resp, err := DoRequestRL(client, "GET", srv.URL, "test-ua", rl)
		if err != nil {
			t.Fatalf("DoRequestRL: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
	})
}

func TestFetchBodyRL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("hello world"))
	}))
	defer srv.Close()

	body, code, err := FetchBodyRL(srv.Client(), srv.URL, "test-ua", nil)
	if err != nil {
		t.Fatalf("FetchBodyRL: %v", err)
	}
	if code != 200 {
		t.Fatalf("code = %d, want 200", code)
	}
	if body != "hello world" {
		t.Fatalf("body = %q, want %q", body, "hello world")
	}
}

func TestFetchBodyCT(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	body, code, ct, err := FetchBodyCT(srv.Client(), srv.URL, "test-ua")
	if err != nil {
		t.Fatalf("FetchBodyCT: %v", err)
	}
	if code != 200 {
		t.Fatalf("code = %d", code)
	}
	if !strings.Contains(ct, "application/json") {
		t.Fatalf("content-type = %q, want application/json", ct)
	}
	if body != `{"ok":true}` {
		t.Fatalf("body = %q", body)
	}
}

func TestFetchBodyCTRL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("rate-limited"))
	}))
	defer srv.Close()

	rl := NewRateLimiter(1000)
	defer rl.Stop()

	body, code, ct, err := FetchBodyCTRL(srv.Client(), srv.URL, "test-ua", rl)
	if err != nil {
		t.Fatalf("FetchBodyCTRL: %v", err)
	}
	if code != 200 || !strings.Contains(ct, "text/plain") || body != "rate-limited" {
		t.Fatalf("got (%d, %q, %q)", code, ct, body)
	}
}

func TestNewPostRequest(t *testing.T) {
	req, err := NewPostRequest("http://example.com/api", "application/json", `{"key":"val"}`, "my-ua")
	if err != nil {
		t.Fatalf("NewPostRequest: %v", err)
	}
	if req.Method != "POST" {
		t.Fatalf("method = %q", req.Method)
	}
	if req.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("content-type = %q", req.Header.Get("Content-Type"))
	}
	if req.Header.Get("User-Agent") != "my-ua" {
		t.Fatalf("user-agent = %q", req.Header.Get("User-Agent"))
	}
}

func TestReadBodyLimit(t *testing.T) {
	t.Run("within limit", func(t *testing.T) {
		resp := &http.Response{Body: http.NoBody}
		resp.Body = newStringBody("short")
		got := ReadBodyLimit(resp, 1024)
		if got != "short" {
			t.Fatalf("got %q, want %q", got, "short")
		}
	})

	t.Run("truncated at limit", func(t *testing.T) {
		resp := &http.Response{Body: newStringBody("abcdefghij")}
		got := ReadBodyLimit(resp, 5)
		if got != "abcde" {
			t.Fatalf("got %q, want %q", got, "abcde")
		}
	})
}

func TestNewLoggerWriter(t *testing.T) {
	var buf bytes.Buffer
	log := NewLoggerWriter(true, true, &buf)
	log.Info("test message %s", "hello")
	if !strings.Contains(buf.String(), "test message hello") {
		t.Fatalf("log output = %q, want 'test message hello'", buf.String())
	}

	buf.Reset()
	log.Debug("debug %d", 42)
	if !strings.Contains(buf.String(), "debug 42") {
		t.Fatalf("verbose logger should emit debug, got %q", buf.String())
	}

	var buf2 bytes.Buffer
	quiet := NewLoggerWriter(false, true, &buf2)
	quiet.Debug("should not appear")
	if buf2.Len() > 0 {
		t.Fatalf("non-verbose logger should suppress debug, got %q", buf2.String())
	}
}

func TestNewLoggerWriterNilFallback(t *testing.T) {
	log := NewLoggerWriter(false, true, nil)
	log.Info("should not panic")
}

func TestRecoverWorker(t *testing.T) {
	var buf bytes.Buffer
	log := NewLoggerWriter(true, true, &buf)

	done := make(chan bool, 1)
	go func() {
		defer func() { done <- true }()
		defer RecoverWorker(log, "test-module")
		panic("intentional test panic")
	}()
	<-done

	if !strings.Contains(buf.String(), "worker panic recovered") {
		t.Fatalf("panic not logged: %q", buf.String())
	}
	if !strings.Contains(buf.String(), "test-module") {
		t.Fatalf("module name not in log: %q", buf.String())
	}
}

type stringReadCloser struct {
	*strings.Reader
}

func (s stringReadCloser) Close() error { return nil }

func newStringBody(s string) stringReadCloser {
	return stringReadCloser{strings.NewReader(s)}
}
