package modules

import (
	"fmt"
	"strings"
	"testing"
)

func benchEncodeName(name string) []byte {
	var b []byte
	for _, label := range strings.Split(name, ".") {
		b = append(b, byte(len(label)))
		b = append(b, label...)
	}
	return append(b, 0x00)
}

// benchZoneMsg builds a 12-byte DNS header followed by n sequential subdomain
// names of example.com, mimicking the answer section of a zone transfer.
func benchZoneMsg(n int) []byte {
	msg := make([]byte, 12)
	for i := 0; i < n; i++ {
		msg = append(msg, benchEncodeName(fmt.Sprintf("host%d.example.com", i))...)
	}
	return msg
}

// BenchmarkExtractDNSNames measures the AXFR name-walker across input sizes
// (OPTIMIZATIONS.md §1.1 / C-5). Compare ns/op across n to watch the walk's
// scaling — the baseline to beat if the O(n^2) walker is ever restructured.
func BenchmarkExtractDNSNames(b *testing.B) {
	for _, n := range []int{50, 500, 5000} {
		msg := benchZoneMsg(n)
		b.Run(fmt.Sprintf("n=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(msg)))
			for i := 0; i < b.N; i++ {
				_ = extractDNSNames(msg, "example.com")
			}
		})
	}
}
