package modules

import "testing"

// Fuzz targets for the raw DNS wire parsers (SECURITY_ASSESSMENT §5). These
// parse hostile, attacker-controlled bytes (AXFR/UDP responses), so the
// invariant is simple: never panic. Run the seed corpus with `make fuzz`
// (go test -run=Fuzz) or an actual campaign with:
//
//	go test ./internal/modules/ -run=xxx -fuzz=FuzzReadDNSName -fuzztime=30s

func FuzzReadDNSName(f *testing.F) {
	f.Add([]byte{0x03, 'w', 'w', 'w', 0x03, 'c', 'o', 'm', 0x00}, 0)
	f.Add([]byte{0xc0, 0x00}, 0) // compression pointer loop (guarded by jump cap)
	f.Add([]byte{0x01, 'a'}, 0)  // truncated: length byte without the label
	f.Add([]byte{0x00}, 0)       // root
	f.Fuzz(func(t *testing.T, msg []byte, start int) {
		_, _ = readDNSName(msg, start) // must not panic
	})
}

func FuzzExtractDNSNames(f *testing.F) {
	header := []byte{0x00, 0x01, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00}
	f.Add(append(append([]byte{}, header...), 0x03, 'w', 'w', 'w', 0x00), "example.com")
	f.Add(header, "example.com")
	f.Add([]byte{}, "")
	f.Fuzz(func(t *testing.T, msg []byte, domain string) {
		_ = extractDNSNames(msg, domain) // must not panic
	})
}

func FuzzParseAnswer(f *testing.F) {
	// Minimal DNS response header: id=1, QR set, 1 question, 1 answer.
	resp := []byte{
		0x00, 0x01, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
		0x03, 'w', 'w', 'w', 0x03, 'c', 'o', 'm', 0x00, 0x00, 0x01, 0x00, 0x01,
	}
	f.Add(resp, uint16(1), "www.com")
	f.Add([]byte{0x00, 0x01}, uint16(1), "x") // too short for the header
	f.Fuzz(func(t *testing.T, msg []byte, wantID uint16, wantQName string) {
		_, _, _, _ = parseAnswer(msg, wantID, wantQName) // must not panic
	})
}
