// Package discovery runs signed discovery scopes. A scope is accepted only
// with a valid signature from pf-netguardd's pinned key, before its expiry,
// and within the hard guards (private ranges, at most a /22, ICMP echo and
// TCP connect only, bounded rate), which no scope can lift.
package discovery

import (
	"context"
	"crypto/ed25519"
	"net"
	"net/netip"
	"os/exec"
	"strconv"
	"sync"
	"time"

	"github.com/commonvtake/parallelf/pkg/ngsensor"
)

// Prober sends the two allowed probes.
type Prober interface {
	Ping(ctx context.Context, ip netip.Addr) bool
	Connect(ctx context.Context, ip netip.Addr, port int) bool
}

// System probes with ping(8) and a TCP connect.
type System struct{}

// Ping sends one ICMP echo.
func (System) Ping(ctx context.Context, ip netip.Addr) bool {
	return exec.CommandContext(ctx, "ping", "-c", "1", "-W", "1", "-n", ip.String()).Run() == nil
}

// Connect completes (and closes) a TCP handshake.
func (System) Connect(ctx context.Context, ip netip.Addr, port int) bool {
	d := net.Dialer{Timeout: time.Second}
	c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), strconv.Itoa(port)))
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

// Runner runs each verified scope once.
type Runner struct {
	Key    ed25519.PublicKey
	Probe  Prober
	Now    func() time.Time
	mu     sync.Mutex
	done   map[string]bool
	refuse map[string]string
}

// Hosts lists the addresses a CIDR covers, without network and broadcast
// addresses for prefixes up to /30.
func Hosts(cidr string) []netip.Addr {
	p, err := netip.ParsePrefix(cidr)
	if err != nil {
		return nil
	}
	p = p.Masked()
	var out []netip.Addr
	for a := p.Addr(); p.Contains(a); a = a.Next() {
		out = append(out, a)
	}
	if p.Bits() <= 30 && len(out) > 2 {
		out = out[1 : len(out)-1]
	}
	return out
}

// Pending verifies new scopes and returns those to run. Refused scopes are
// remembered with their reason (and reported once by the caller).
func (r *Runner) Pending(scopes []ngsensor.SignedScope) (run []ngsensor.Scope, refused map[string]string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.done == nil {
		r.done, r.refuse = map[string]bool{}, map[string]string{}
	}
	refused = map[string]string{}
	for _, ss := range scopes {
		s, err := ngsensor.Verify(ss, r.Key, r.Now())
		if err != nil {
			key := ss.Signature
			if _, seen := r.refuse[key]; !seen {
				r.refuse[key] = err.Error()
				refused[key] = err.Error()
			}
			continue
		}
		if r.done[s.ID] {
			continue
		}
		r.done[s.ID] = true
		run = append(run, s)
	}
	return run, refused
}

// Run probes every host of s at its rate and returns what answered.
func (r *Runner) Run(ctx context.Context, s ngsensor.Scope) []ngsensor.Event {
	tick := time.NewTicker(time.Second / time.Duration(s.RatePPS))
	defer tick.Stop()
	var events []ngsensor.Event
	found := func(ip netip.Addr, port int, technique, result string) {
		events = append(events, ngsensor.Event{
			Time: r.Now().UTC(), Kind: ngsensor.KindDiscovery, DstIP: ip.String(), DstPort: port,
			Details:   map[string]string{"discovery.scope_id": s.ID, "discovery.technique": technique, "discovery.result": result},
			RawSHA256: hashOf(s.ID, ip.String(), strconv.Itoa(port), technique, r.Now().UTC().Format(time.RFC3339Nano)),
		})
	}
	wait := func() bool {
		select {
		case <-ctx.Done():
			return false
		case <-tick.C:
			return true
		}
	}
	for _, cidr := range s.CIDRs {
		for _, ip := range Hosts(cidr) {
			for _, t := range s.Techniques {
				switch t {
				case ngsensor.TechniqueICMPEcho:
					if !wait() {
						return events
					}
					if r.Probe.Ping(ctx, ip) {
						found(ip, 0, t, "up")
					}
				case ngsensor.TechniqueTCPConnect:
					for _, port := range s.Ports {
						if !wait() {
							return events
						}
						if r.Probe.Connect(ctx, ip, port) {
							found(ip, port, t, "open")
						}
					}
				}
			}
		}
	}
	return events
}
