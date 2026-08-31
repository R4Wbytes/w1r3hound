package modules

import (
	"testing"
	"time"
)

// TestExtractDNSNames_PointerBombBounded is the regression guard for the C-5
// fix: a malicious AXFR message crafted so that every offset is a compression
// pointer into a long label run used to make extractDNSNames' every-offset scan
// O(n²) (a CPU DoS on the scanner). With the shared work budget it must stay
// linear and finish near-instantly. The message is built at the 64 KB TCP-DNS
// ceiling to maximise the pre-fix blow-up.
func TestExtractDNSNames_PointerBombBounded(t *testing.T) {
	const n = 65000
	msg := make([]byte, n)
	// A long run of 63-byte labels starting at offset 12, terminated by a root
	// byte at the halfway mark. Reading it from any pointer costs ~n/2 bytes.
	half := n / 2
	i := 12
	for i+64 < half {
		msg[i] = 63 // label length
		// label bytes left as 0x00 payload; content is irrelevant to the cost
		i += 64
	}
	msg[half] = 0x00 // root terminator ends the label run
	// Fill the rest with compression pointers (0xC0 0x0C) → offset 12.
	for j := half + 1; j+1 < n; j += 2 {
		msg[j] = 0xC0
		msg[j+1] = 0x0C
	}

	// realZoneTransfer calls extractDNSNames once per AXFR message, up to ~160
	// messages (10 MB / 64 KB). Loop to mirror that aggregate: the fix keeps each
	// call ~linear (whole loop well under a second), while the pre-fix quadratic
	// (~0.6s per 64 KB message) makes the aggregate blow past the deadline.
	const messages = 40
	done := make(chan struct{})
	go func() {
		for k := 0; k < messages; k++ {
			_ = extractDNSNames(msg, "example.com")
		}
		close(done)
	}()
	select {
	case <-done:
		// completed — the budget kept it linear
	case <-time.After(3 * time.Second):
		t.Fatal("extractDNSNames did not complete within 3s on pointer-bomb messages — quadratic blow-up reintroduced?")
	}
}

// TestExtractDNSNames_BenignStillWorks confirms the budget does not break normal
// extraction: a plain uncompressed name in the message body is still returned.
func TestExtractDNSNames_BenignStillWorks(t *testing.T) {
	// 12-byte header, then "host.example.com" as length-prefixed labels + root.
	msg := make([]byte, 12)
	for _, label := range []string{"host", "example", "com"} {
		msg = append(msg, byte(len(label)))
		msg = append(msg, []byte(label)...)
	}
	msg = append(msg, 0x00)

	names := extractDNSNames(msg, "example.com")
	found := false
	for _, nm := range names {
		if nm == "host.example.com" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected host.example.com to be extracted, got %v", names)
	}
}
