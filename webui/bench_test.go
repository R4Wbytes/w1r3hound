package main

import "testing"

// BenchmarkBuildArgs measures the full validate+assemble path for a scan
// request with the complete CLI-parity option set (OPTIMIZATIONS.md §7; also
// guards the parity path). Path fields are left empty so the benchmark is pure
// CPU (no per-iteration filesystem I/O).
func BenchmarkBuildArgs(b *testing.B) {
	dir := b.TempDir()
	req := &ScanRequest{
		Target:             "https://target.example.com:8443/app",
		Modules:            []string{"headers", "content", "portscan", "crawler", "apiscan"},
		Concurrency:        50,
		Ports:              "full",
		Rate:               200,
		TimeoutSec:         15,
		UserAgent:          "w1r3hound/1.0 bench",
		Output:             "bench_out",
		Verbose:            true,
		Authorized:         true,
		DirExt:             ".bak,.php,.zip,~",
		Headers:            []string{"X-Api-Key: abc123", "Authorization: Bearer z"},
		SkipTLSVerify:      boolPtr(false),
		BlockPrivateEgress: true,
		Resolver:           "8.8.8.8:53",
		WaybackLimit:       5000,
		CrawlPages:         100,
		JSFiles:            50,
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, _, err := buildArgs(req, dir, dir); err != nil {
			b.Fatal(err)
		}
	}
}
