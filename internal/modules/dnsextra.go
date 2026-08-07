package modules

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/w1r3hound/w1r3hound/internal/core"
)

// ══════════════════════════════════════════════
//  DNS ZONE TRANSFER (AXFR) — real implementation
//  over raw TCP/53, no external deps. Replaces the
//  previous stub.
//  (Checklist Fase 1.1: zone transfer AXFR)
// ══════════════════════════════════════════════

// realZoneTransfer attempts an AXFR against a nameserver and returns
// any hostnames extracted from the response. Best-effort DNS wire parsing.
func realZoneTransfer(domain, ns string, timeout time.Duration) []string {
	ns = strings.TrimSuffix(ns, ".")
	addr := net.JoinHostPort(ns, "53")

	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout * 3))

	// Build an AXFR query (type 252)
	query := buildDNSQuery(domain, 252)

	// TCP DNS: 2-byte length prefix
	lenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, uint16(len(query)))
	if _, err := conn.Write(append(lenBuf, query...)); err != nil {
		return nil
	}

	var hostnames []string
	seen := make(map[string]bool)

	// Read responses (AXFR can be multiple messages)
	for {
		// Read 2-byte length
		lb := make([]byte, 2)
		if _, err := io.ReadFull(conn, lb); err != nil {
			break
		}
		msgLen := binary.BigEndian.Uint16(lb)
		if msgLen == 0 {
			break
		}
		msg := make([]byte, msgLen)
		if _, err := io.ReadFull(conn, msg); err != nil {
			break
		}

		// Extract domain names from the message body
		for _, name := range extractDNSNames(msg, domain) {
			if !seen[name] {
				seen[name] = true
				hostnames = append(hostnames, name)
			}
		}

		// Stop if we've read a lot (avoid infinite loops on weird servers)
		if len(hostnames) > 10000 {
			break
		}
	}

	return hostnames
}

// buildDNSQuery constructs a minimal DNS query packet.
func buildDNSQuery(domain string, qtype uint16) []byte {
	var buf []byte
	// Header: ID=0x1337, flags=0x0000 (standard query), QDCOUNT=1
	buf = append(buf, 0x13, 0x37) // ID
	buf = append(buf, 0x00, 0x00) // flags
	buf = append(buf, 0x00, 0x01) // QDCOUNT
	buf = append(buf, 0x00, 0x00) // ANCOUNT
	buf = append(buf, 0x00, 0x00) // NSCOUNT
	buf = append(buf, 0x00, 0x00) // ARCOUNT

	// Question: QNAME
	for _, label := range strings.Split(domain, ".") {
		buf = append(buf, byte(len(label)))
		buf = append(buf, []byte(label)...)
	}
	buf = append(buf, 0x00) // root

	// QTYPE + QCLASS(IN=1)
	qt := make([]byte, 2)
	binary.BigEndian.PutUint16(qt, qtype)
	buf = append(buf, qt...)
	buf = append(buf, 0x00, 0x01)

	return buf
}

// extractDNSNames pulls printable domain-name-like strings out of a DNS message.
// This is a heuristic parser that walks the label sequences.
func extractDNSNames(msg []byte, domain string) []string {
	var names []string
	i := 12 // skip header

	readName := func(start int) (string, int) {
		var labels []string
		pos := start
		jumps := 0
		for pos < len(msg) {
			l := int(msg[pos])
			if l == 0 {
				pos++
				break
			}
			if l&0xc0 == 0xc0 {
				// compression pointer — follow once for name, stop advancing
				if pos+1 >= len(msg) {
					break
				}
				ptr := int(binary.BigEndian.Uint16(msg[pos:pos+2]) & 0x3fff)
				if jumps > 10 || ptr >= len(msg) {
					break
				}
				jumps++
				pos = ptr
				continue
			}
			if pos+1+l > len(msg) {
				break
			}
			labels = append(labels, string(msg[pos+1:pos+1+l]))
			pos += 1 + l
		}
		return strings.Join(labels, "."), pos
	}

	// Walk through the message extracting names
	for i < len(msg)-1 {
		name, next := readName(i)
		// Require a real label boundary: "x.example.com" or exactly "example.com",
		// never "notexample.com" which merely shares the suffix. A malicious AXFR
		// response could otherwise inject sibling-domain names into the shared
		// subdomain set and get them scanned.
		if (name == domain || strings.HasSuffix(name, "."+domain)) && len(name) > len(domain) {
			if isPrintableDNS(name) {
				names = append(names, strings.ToLower(name))
			}
		}
		if next <= i {
			i++
		} else {
			i = next
		}
	}
	return names
}

func isPrintableDNS(s string) bool {
	for _, c := range s {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// ══════════════════════════════════════════════
//  SRV RECORD ENUMERATION
//  Reveals internal services (SIP, XMPP, LDAP,
//  Kerberos, etc.) often exposed inadvertently.
//  (Checklist Fase 1.1: análisis de registros SRV)
// ══════════════════════════════════════════════

var srvServices = []string{
	"_sip._tcp", "_sip._udp", "_sips._tcp",
	"_xmpp-server._tcp", "_xmpp-client._tcp", "_jabber._tcp",
	"_ldap._tcp", "_ldaps._tcp",
	"_kerberos._tcp", "_kerberos._udp", "_kpasswd._tcp",
	"_gc._tcp", "_kerberos-master._tcp",
	"_autodiscover._tcp", "_caldav._tcp", "_carddav._tcp",
	"_imap._tcp", "_imaps._tcp", "_pop3._tcp", "_pop3s._tcp",
	"_submission._tcp", "_smtp._tcp",
	"_h323cs._tcp", "_sipfederationtls._tcp",
	"_vlmcs._tcp", "_minecraft._tcp", "_teamspeak._udp",
	"_ts3._udp", "_mongodb._tcp", "_stun._udp", "_turn._udp",
}

// EnumerateSRV runs SRV lookups for common service prefixes.
func EnumerateSRV(cfg *core.Config, log *core.Logger) []string {
	domain := cfg.Domain
	var found []string
	for _, svc := range srvServices {
		_, addrs, err := cfg.Resolver.LookupSRV(context.Background(), "", "", svc+"."+domain)
		if err != nil || len(addrs) == 0 {
			continue
		}
		for _, a := range addrs {
			target := strings.TrimSuffix(a.Target, ".")
			entry := fmt.Sprintf("%s → %s:%d (prio %d)", svc, target, a.Port, a.Priority)
			found = append(found, entry)
			log.Info("SRV: %s", entry)
		}
	}
	return found
}
