package modules

import (
	"encoding/binary"
	"reflect"
	"strings"
	"testing"
)

// ── wire-format test helpers ──

func encodeTestName(name string) []byte {
	if name == "" {
		return []byte{0x00}
	}
	var buf []byte
	for _, label := range strings.Split(name, ".") {
		buf = append(buf, byte(len(label)))
		buf = append(buf, []byte(label)...)
	}
	return append(buf, 0x00)
}

func buildTestHeader(id, flags, qd, an, ns, ar uint16) []byte {
	buf := make([]byte, 12)
	binary.BigEndian.PutUint16(buf[0:2], id)
	binary.BigEndian.PutUint16(buf[2:4], flags)
	binary.BigEndian.PutUint16(buf[4:6], qd)
	binary.BigEndian.PutUint16(buf[6:8], an)
	binary.BigEndian.PutUint16(buf[8:10], ns)
	binary.BigEndian.PutUint16(buf[10:12], ar)
	return buf
}

// ── parseAnswer ──

func TestParseAnswer_ValidA(t *testing.T) {
	id := uint16(0x1234)
	qname := "sub.example.com"

	msg := buildTestHeader(id, 0x8000, 1, 1, 0, 0) // QR=1, RCODE=0
	msg = append(msg, encodeTestName(qname)...)
	msg = append(msg, 0x00, 0x01, 0x00, 0x01) // QTYPE=A, QCLASS=IN
	msg = append(msg, 0xC0, 0x0C)             // NAME: pointer back to question
	msg = append(msg, 0x00, 0x01, 0x00, 0x01) // TYPE=A, CLASS=IN
	msg = append(msg, 0x00, 0x00, 0x00, 0x3c) // TTL=60
	msg = append(msg, 0x00, 0x04)             // RDLENGTH=4
	msg = append(msg, 93, 184, 216, 34)       // RDATA

	ips, cname, rcode, err := parseAnswer(msg, id, qname)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rcode != 0 {
		t.Errorf("rcode = %d, want 0", rcode)
	}
	if !reflect.DeepEqual(ips, []string{"93.184.216.34"}) {
		t.Errorf("ips = %v, want [93.184.216.34]", ips)
	}
	if cname != "" {
		t.Errorf("cname = %q, want empty", cname)
	}
}

func TestParseAnswer_ValidCNAME(t *testing.T) {
	id := uint16(0xABCD)
	qname := "www.example.com"
	target := "example.com"

	msg := buildTestHeader(id, 0x8000, 1, 1, 0, 0)
	msg = append(msg, encodeTestName(qname)...)
	msg = append(msg, 0x00, 0x05, 0x00, 0x01) // QTYPE=CNAME
	msg = append(msg, 0xC0, 0x0C)
	msg = append(msg, 0x00, 0x05, 0x00, 0x01) // TYPE=CNAME, CLASS=IN
	msg = append(msg, 0x00, 0x00, 0x00, 0x3c)
	rdata := encodeTestName(target)
	msg = append(msg, byte(len(rdata)>>8), byte(len(rdata)))
	msg = append(msg, rdata...)

	ips, cname, rcode, err := parseAnswer(msg, id, qname)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rcode != 0 {
		t.Errorf("rcode = %d, want 0", rcode)
	}
	if len(ips) != 0 {
		t.Errorf("ips = %v, want none", ips)
	}
	if want := target + "."; cname != want {
		t.Errorf("cname = %q, want %q", cname, want)
	}
}

func TestParseAnswer_NXDOMAIN(t *testing.T) {
	id := uint16(0x2222)
	qname := "nope.example.com"

	msg := buildTestHeader(id, 0x8003, 1, 0, 0, 0) // RCODE=3 (NXDOMAIN)
	msg = append(msg, encodeTestName(qname)...)
	msg = append(msg, 0x00, 0x01, 0x00, 0x01)

	ips, cname, rcode, err := parseAnswer(msg, id, qname)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rcode != 3 {
		t.Errorf("rcode = %d, want 3", rcode)
	}
	if len(ips) != 0 || cname != "" {
		t.Errorf("expected no data on NXDOMAIN, got ips=%v cname=%q", ips, cname)
	}
}

func TestParseAnswer_SERVFAIL(t *testing.T) {
	id := uint16(0x3333)
	qname := "slow.example.com"

	msg := buildTestHeader(id, 0x8002, 1, 0, 0, 0) // RCODE=2 (SERVFAIL)
	msg = append(msg, encodeTestName(qname)...)
	msg = append(msg, 0x00, 0x01, 0x00, 0x01)

	_, _, rcode, err := parseAnswer(msg, id, qname)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rcode != 2 {
		t.Errorf("rcode = %d, want 2", rcode)
	}
}

func TestParseAnswer_IDMismatch(t *testing.T) {
	msg := buildTestHeader(0x0001, 0x8000, 1, 0, 0, 0)
	msg = append(msg, encodeTestName("x.example.com")...)
	msg = append(msg, 0x00, 0x01, 0x00, 0x01)

	if _, _, _, err := parseAnswer(msg, 0x0002, "x.example.com"); err == nil {
		t.Fatal("expected an error for transaction ID mismatch, got nil")
	}
}

func TestParseAnswer_QNameMismatch(t *testing.T) {
	id := uint16(0x0003)
	msg := buildTestHeader(id, 0x8000, 1, 0, 0, 0)
	msg = append(msg, encodeTestName("x.example.com")...)
	msg = append(msg, 0x00, 0x01, 0x00, 0x01)

	if _, _, _, err := parseAnswer(msg, id, "y.example.com"); err == nil {
		t.Fatal("expected an error for question name mismatch, got nil")
	}
}

// TestParseAnswer_Malformed feeds parseAnswer hostile/truncated input and
// requires an error, never a panic — this parses untrusted wire data from
// whatever's listening on the configured resolver addresses.
func TestParseAnswer_Malformed(t *testing.T) {
	cases := [][]byte{
		nil,
		{},
		{0x00, 0x01, 0x02},                     // shorter than a 12-byte header
		buildTestHeader(1, 0x8000, 1, 0, 0, 0), // QDCOUNT=1 but no question follows
		buildTestHeader(1, 0x8000, 0, 1, 0, 0), // ANCOUNT=1 but no answer follows
		append(buildTestHeader(1, 0x0000, 1, 0, 0, 0), encodeTestName("x")...), // QR bit not set
	}
	for i, msg := range cases {
		if _, _, _, err := parseAnswer(msg, 1, "x"); err == nil {
			t.Errorf("case %d: expected an error for malformed input, got nil", i)
		}
	}
}

// ── buildDNSQuery recursion flag ──

func TestBuildDNSQuery_RecursionFlag(t *testing.T) {
	nonRecursive := buildDNSQuery("example.com", 252, false)
	if nonRecursive[2]&0x01 != 0 {
		t.Errorf("RD bit set on a non-recursive (AXFR) query")
	}
	recursive := buildDNSQuery("example.com", 1, true)
	if recursive[2]&0x01 != 0x01 {
		t.Errorf("RD bit not set on a recursive query")
	}
}

// ── udpResolverPool round-robin ──

func TestUDPResolverPool_RoundRobin(t *testing.T) {
	p := newUDPResolverPool([]string{"1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:53"}, nil)
	var got []string
	for i := 0; i < 7; i++ {
		got = append(got, p.pick())
	}
	want := []string{
		"1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:53",
		"1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:53",
		"1.1.1.1:53",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("pick sequence = %v, want %v", got, want)
	}
}

func TestNormalizeResolverAddr(t *testing.T) {
	cases := []struct{ in, want string }{
		{"1.1.1.1", "1.1.1.1:53"},
		{"8.8.8.8:53", "8.8.8.8:53"},
		{"2001:4860:4860::8888", "[2001:4860:4860::8888]:53"},
	}
	for _, c := range cases {
		got, err := normalizeResolverAddr(c.in)
		if err != nil {
			t.Fatalf("normalizeResolverAddr(%q): unexpected error: %v", c.in, err)
		}
		if got != c.want {
			t.Errorf("normalizeResolverAddr(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	if _, err := normalizeResolverAddr(""); err == nil {
		t.Error("normalizeResolverAddr(\"\"): expected an error, got nil")
	}
}
