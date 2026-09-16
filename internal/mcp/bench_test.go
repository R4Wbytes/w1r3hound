package mcp

import (
	"bytes"
	"strings"
	"testing"
)

func BenchmarkRoundTrip_Ping(b *testing.B) {
	msg := `{"jsonrpc":"2.0","id":1,"method":"ping"}` + "\n"
	for i := 0; i < b.N; i++ {
		var out bytes.Buffer
		ServeIO("bench", strings.NewReader(msg), &out)
	}
}

func BenchmarkRoundTrip_ListModules(b *testing.B) {
	msg := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_modules","arguments":{}}}` + "\n"
	for i := 0; i < b.N; i++ {
		var out bytes.Buffer
		ServeIO("bench", strings.NewReader(msg), &out)
	}
}
