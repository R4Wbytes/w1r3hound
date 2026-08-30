package modules

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/R4Wbytes/w1r3hound/internal/core"
)

// ══════════════════════════════════════════════
//  RAW-UDP DNS BRUTE-FORCE ENGINE (P1)
//  Opt-in (-resolvers <file>) replacement for the
//  stdlib net.Resolver on the two high-volume DNS
//  paths: subdomain brute-force (dns.go) and
//  permutation (takeover.go RunPermute). Rotates
//  across a resolver pool, retries on a different
//  resolver on failure, and is gated by the shared
//  RateLimiter so -rate finally governs DNS too.
// ══════════════════════════════════════════════

// nameResolver is the minimal surface the brute-force/permutation loops
// need. *net.Resolver already satisfies it; *udpResolverPool is the second
// implementation. Selecting between them at one call site (selectResolver)
// means every filter/fingerprint/dangling-CNAME check downstream keeps
// working unmodified against whichever engine is active.
type nameResolver interface {
	LookupHost(ctx context.Context, host string) ([]string, error)
	LookupCNAME(ctx context.Context, host string) (string, error)
}

// selectResolver returns the raw-UDP pool when the operator supplied
// -resolvers, otherwise the existing stdlib resolver (cfg.Resolver) — zero
// behaviour change for anyone who hasn't opted in.
func selectResolver(cfg *core.Config) nameResolver {
	if len(cfg.Resolvers) > 0 {
		return newUDPResolverPool(cfg.Resolvers, cfg.RL)
	}
	return cfg.Resolver
}

// dnsQueryTimeout caps a single UDP query/response round trip, independent
// of -timeout: these are meant to be fast, and a resolver that doesn't
// answer within a couple of seconds should be retried against a different
// one, not waited out to the full per-request timeout budget. Mirrors the
// same reasoning as portscan's bannerWindow capping.
const dnsQueryTimeout = 2 * time.Second

// dnsMaxAttempts bounds retries across the pool: a dead/rate-limiting
// resolver shouldn't be allowed to sink a whole lookup when others in the
// pool might answer.
const dnsMaxAttempts = 3

type udpResolverPool struct {
	resolvers []string
	next      uint32 // atomic round-robin cursor
	rl        *core.RateLimiter
}

// newUDPResolverPool builds a pool over an already-loaded resolver list
// (core.ReadLines output). rl may be nil (unlimited — RateLimiter.Wait is a
// documented no-op on a nil receiver).
func newUDPResolverPool(resolvers []string, rl *core.RateLimiter) *udpResolverPool {
	return &udpResolverPool{resolvers: resolvers, rl: rl}
}

// pick returns the next resolver address in round-robin order.
func (p *udpResolverPool) pick() string {
	n := atomic.AddUint32(&p.next, 1)
	return p.resolvers[(int(n)-1)%len(p.resolvers)]
}

// LookupHost resolves A/AAAA records, matching *net.Resolver.LookupHost's
// contract: an empty result is reported as a "not found" error, never a nil
// slice with a nil error.
func (p *udpResolverPool) LookupHost(ctx context.Context, fqdn string) ([]string, error) {
	// Two queries (A then AAAA), like *net.Resolver.LookupHost does under the
	// hood — a v4-only query would silently miss IPv6-only hosts (some CDN
	// edges) that the stdlib path already finds today.
	v4, _, errV4 := p.resolve(ctx, fqdn, 1)
	v6, _, errV6 := p.resolve(ctx, fqdn, 28)
	ips := append(v4, v6...)
	if len(ips) == 0 {
		if errV4 != nil {
			return nil, errV4
		}
		if errV6 != nil {
			return nil, errV6
		}
		return nil, &net.DNSError{Err: "no such host", Name: fqdn, IsNotFound: true}
	}
	return ips, nil
}

// LookupCNAME matches *net.Resolver.LookupCNAME's contract: a host with no
// CNAME is not an error — it returns the (dot-terminated) query name itself,
// which is exactly the "cname == fqdn+\".\"" guard the callers already check.
func (p *udpResolverPool) LookupCNAME(ctx context.Context, fqdn string) (string, error) {
	_, cname, err := p.resolve(ctx, fqdn, 5) // CNAME
	if err != nil {
		return "", err
	}
	if cname == "" {
		return fqdn + ".", nil
	}
	return cname, nil
}

// resolve sends the query to successive resolvers in the pool (round-robin,
// up to dnsMaxAttempts) until one returns a validated answer. A resolver
// that times out, refuses, or returns a response that fails ID/QNAME
// validation is abandoned in favour of the next one rather than retried
// in place — a single bad resolver in the list shouldn't sink the lookup.
func (p *udpResolverPool) resolve(ctx context.Context, fqdn string, qtype uint16) (ips []string, cname string, err error) {
	fqdn = strings.TrimSuffix(fqdn, ".")
	var lastErr error
	for attempt := 0; attempt < dnsMaxAttempts; attempt++ {
		select {
		case <-ctx.Done():
			return nil, "", ctx.Err()
		default:
		}
		if p.rl != nil {
			p.rl.Wait()
		}
		ips, cname, err := p.query(ctx, p.pick(), fqdn, qtype)
		if err == nil {
			return ips, cname, nil
		}
		lastErr = err
	}
	return nil, "", lastErr
}

// query performs one UDP round trip against a single resolver: dial, send,
// read, validate, parse. One socket per call (see plan: simpler and safer
// than a shared demux'd socket for a first version, at the cost of some
// throughput ceiling versus massdns-style engines).
func (p *udpResolverPool) query(ctx context.Context, server, fqdn string, qtype uint16) ([]string, string, error) {
	addr, err := normalizeResolverAddr(server)
	if err != nil {
		return nil, "", err
	}

	conn, err := (&net.Dialer{}).DialContext(ctx, "udp", addr)
	if err != nil {
		return nil, "", err
	}
	defer conn.Close()

	deadline := time.Now().Add(dnsQueryTimeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, "", err
	}

	query := buildDNSQuery(fqdn, qtype, true) // RD=1: talking to a recursive resolver
	queryID := binary.BigEndian.Uint16(query[0:2])

	if _, err := conn.Write(query); err != nil {
		return nil, "", err
	}

	// A plain (no EDNS0) response is capped at 512 bytes by the DNS spec, but
	// some resolvers answer larger anyway; 4KB is comfortable headroom without
	// inviting a memory-amplification concern from an untrusted peer.
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, "", err
	}

	ips, cname, rcode, err := parseAnswer(buf[:n], queryID, fqdn)
	if err != nil {
		return nil, "", err
	}
	if rcode != 0 {
		return nil, "", fmt.Errorf("resolver %s: rcode %d for %s", server, rcode, fqdn)
	}
	return ips, cname, nil
}

// normalizeResolverAddr adds the default DNS port when the operator's
// -resolvers entry didn't include one — same SplitHostPort/JoinHostPort
// pattern as core.NewResolver, which also correctly brackets a bare IPv6
// resolver address.
func normalizeResolverAddr(server string) (string, error) {
	if server == "" {
		return "", errors.New("empty resolver address")
	}
	if _, _, err := net.SplitHostPort(server); err != nil {
		server = net.JoinHostPort(server, "53")
	}
	return server, nil
}

// parseAnswer parses a DNS response's question and answer sections per RFC
// 1035 §4.1, scoped to exactly what the brute-force/permutation loops need:
// A/AAAA addresses and a CNAME target. Two checks close the loop on D8
// (transaction ID hygiene): the response ID must match the query, and the
// echoed question name must match what was actually asked — an off-path
// attacker guessing the ID also has to guess the exact query name, and stray
// answers to a previous/unrelated query on a reused socket can't be
// mistaken for this one's.
func parseAnswer(msg []byte, wantID uint16, wantQName string) (ips []string, cname string, rcode int, err error) {
	if len(msg) < 12 {
		return nil, "", 0, errors.New("dns response shorter than header")
	}
	id := binary.BigEndian.Uint16(msg[0:2])
	if id != wantID {
		return nil, "", 0, errors.New("dns response transaction ID mismatch")
	}
	flags := binary.BigEndian.Uint16(msg[2:4])
	if flags&0x8000 == 0 {
		return nil, "", 0, errors.New("dns response QR bit not set (not a response)")
	}
	rcode = int(flags & 0x000F)

	qdcount := int(binary.BigEndian.Uint16(msg[4:6]))
	ancount := int(binary.BigEndian.Uint16(msg[6:8]))

	wantQName = strings.ToLower(strings.TrimSuffix(wantQName, "."))
	pos := 12
	for i := 0; i < qdcount; i++ {
		name, next := readDNSName(msg, pos)
		if next+4 > len(msg) {
			return nil, "", 0, errors.New("dns response question section truncated")
		}
		if i == 0 && strings.ToLower(strings.TrimSuffix(name, ".")) != wantQName {
			return nil, "", 0, errors.New("dns response question name mismatch")
		}
		pos = next + 4 // QTYPE(2) + QCLASS(2)
	}

	// A non-zero rcode (NXDOMAIN, SERVFAIL, REFUSED, …) legitimately carries
	// no useful answer section; the caller treats it as "not found" rather
	// than an error, so still return cleanly instead of trying to walk
	// (possibly absent) answer records.
	if rcode != 0 {
		return nil, "", rcode, nil
	}

	for i := 0; i < ancount; i++ {
		_, next := readDNSName(msg, pos)
		pos = next
		if pos+10 > len(msg) {
			return nil, "", 0, errors.New("dns response answer section truncated")
		}
		rtype := binary.BigEndian.Uint16(msg[pos : pos+2])
		rdlength := int(binary.BigEndian.Uint16(msg[pos+8 : pos+10]))
		rdataStart := pos + 10
		if rdataStart+rdlength > len(msg) {
			return nil, "", 0, errors.New("dns response RDATA truncated")
		}
		rdata := msg[rdataStart : rdataStart+rdlength]

		switch rtype {
		case 1: // A
			if rdlength == 4 {
				ips = append(ips, net.IP(rdata).String())
			}
		case 28: // AAAA
			if rdlength == 16 {
				ips = append(ips, net.IP(rdata).String())
			}
		case 5: // CNAME
			if cname == "" {
				name, _ := readDNSName(msg, rdataStart)
				cname = strings.TrimSuffix(name, ".") + "."
			}
		}
		pos = rdataStart + rdlength
	}

	return ips, cname, rcode, nil
}
