package modules

import (
	"context"
	"encoding/binary"
	"net"
	"reflect"
	"testing"
)

// startFakeDNSServer binds a UDP listener on loopback and answers every
// incoming query with whatever `answer` returns (nil = drop it, simulating a
// resolver that never replies). No real network involved — deterministic and
// fast. Reuses buildTestHeader/encodeTestName from dnsengine_test.go (same
// package).
func startFakeDNSServer(t *testing.T, answer func(query []byte) []byte) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	go func() {
		buf := make([]byte, 512)
		for {
			n, addr, err := conn.ReadFromUDP(buf)
			if err != nil {
				return // listener closed — test cleanup
			}
			if resp := answer(append([]byte(nil), buf[:n]...)); resp != nil {
				_, _ = conn.WriteToUDP(resp, addr)
			}
		}
	}()
	t.Cleanup(func() { conn.Close() })
	return conn
}

// goodAnswerFor builds an answer function that echoes the query's ID and
// QNAME back with a single A record for A queries — a well-behaved recursive
// resolver. LookupHost queries both A and AAAA, so a query for anything else
// (AAAA in practice) gets a clean empty NOERROR rather than an A answer,
// otherwise the test would see the same IP twice.
func goodAnswerFor(ip string) func([]byte) []byte {
	return func(query []byte) []byte {
		if len(query) < 12 {
			return nil
		}
		id := binary.BigEndian.Uint16(query[0:2])
		qname, next := readDNSName(query, 12)
		if next+4 > len(query) {
			return nil
		}
		qtype := binary.BigEndian.Uint16(query[next : next+2])

		if qtype != 1 { // A
			resp := buildTestHeader(id, 0x8000, 1, 0, 0, 0)
			resp = append(resp, encodeTestName(qname)...)
			resp = append(resp, query[next:next+4]...) // echo QTYPE+QCLASS
			return resp
		}

		resp := buildTestHeader(id, 0x8000, 1, 1, 0, 0)
		resp = append(resp, encodeTestName(qname)...)
		resp = append(resp, 0x00, 0x01, 0x00, 0x01) // QTYPE=A, QCLASS=IN
		resp = append(resp, 0xC0, 0x0C)
		resp = append(resp, 0x00, 0x01, 0x00, 0x01)
		resp = append(resp, 0x00, 0x00, 0x00, 0x3c)
		resp = append(resp, 0x00, 0x04)
		resp = append(resp, net.ParseIP(ip).To4()...)
		return resp
	}
}

func TestUDPResolverPool_LiveLoopback_Success(t *testing.T) {
	conn := startFakeDNSServer(t, goodAnswerFor("203.0.113.9"))
	pool := newUDPResolverPool([]string{conn.LocalAddr().String()}, nil)

	ips, err := pool.LookupHost(context.Background(), "test.example.com")
	if err != nil {
		t.Fatalf("LookupHost: unexpected error: %v", err)
	}
	if !reflect.DeepEqual(ips, []string{"203.0.113.9"}) {
		t.Errorf("ips = %v, want [203.0.113.9]", ips)
	}
}

// TestUDPResolverPool_RetriesAcrossResolvers exercises the "one bad resolver
// in the pool" case P1 was built for: a dead entry shouldn't sink the whole
// lookup once the pool rotates to a resolver that actually answers.
func TestUDPResolverPool_RetriesAcrossResolvers(t *testing.T) {
	// Bind then immediately close: nothing's listening on this address
	// afterwards, so a UDP write there surfaces as a fast "connection
	// refused" on loopback (ICMP port-unreachable) rather than a multi-second
	// read timeout — keeps the test quick and deterministic.
	deadConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	deadAddr := deadConn.LocalAddr().String()
	deadConn.Close()

	goodConn := startFakeDNSServer(t, goodAnswerFor("198.51.100.7"))

	pool := newUDPResolverPool([]string{deadAddr, goodConn.LocalAddr().String()}, nil)
	ips, err := pool.LookupHost(context.Background(), "retry.example.com")
	if err != nil {
		t.Fatalf("LookupHost: unexpected error: %v", err)
	}
	if !reflect.DeepEqual(ips, []string{"198.51.100.7"}) {
		t.Errorf("ips = %v, want [198.51.100.7]", ips)
	}
}

// TestUDPResolverPool_BadIDExhaustsRetries confirms a resolver that answers
// with a mismatched transaction ID on every attempt (spoofing / cross-talk
// simulation) never gets treated as a valid answer, even after exhausting
// every retry.
func TestUDPResolverPool_BadIDExhaustsRetries(t *testing.T) {
	conn := startFakeDNSServer(t, func(query []byte) []byte {
		return buildTestHeader(0xFFFF, 0x8000, 0, 0, 0, 0)
	})
	pool := newUDPResolverPool([]string{conn.LocalAddr().String()}, nil)

	if _, err := pool.LookupHost(context.Background(), "bad.example.com"); err == nil {
		t.Fatal("expected an error after exhausting retries against a resolver returning mismatched IDs, got nil")
	}
}
