// Package nft renders and applies the gateway's nftables table
// (inet parallelf_vpn).
//
// The table drops all traffic from the WireGuard interface unless the
// source address is in the active_peers set, whose elements carry a kernel
// timeout: when an activation expires the kernel removes the element, so
// access ends even if the control plane is unreachable (fail closed).
// After that check, compiled policies allow or deny by source set,
// destination set, protocol and port; everything else is dropped.
//
// The ruleset is generated from validated, structured values only; no
// input is ever spliced into it as text.
package nft

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/commonvtake/parallelf/pkg/vpnagent"
	"github.com/commonvtake/parallelf/services/vpn-agent/internal/hostexec"
)

// Table is the agent's nftables table; it never touches any other.
const (
	Family = "inet"
	Table  = "parallelf_vpn"
	Active = "active_peers"
)

var (
	portPattern  = regexp.MustCompile(`^([0-9]{1,5})(?:-([0-9]{1,5}))?$`)
	ifacePattern = regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,15}$`)
)

// Ruleset is a rendered table.
type Ruleset struct {
	// Structure is the table without active_peers elements. Its hash decides
	// whether the table must be replaced or only the set updated.
	Structure string
	Hash      string
	// Active holds the activations to install, with remaining lifetimes.
	Active map[string]time.Duration
}

func addr(s string) (netip.Addr, error) {
	a, err := netip.ParseAddr(s)
	if err != nil || !a.Is4() {
		return netip.Addr{}, fmt.Errorf("not an IPv4 address: %q", s)
	}
	return a, nil
}

func prefix(s string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(s)
	if err != nil || !p.Addr().Is4() {
		return netip.Prefix{}, fmt.Errorf("not an IPv4 CIDR: %q", s)
	}
	return p.Masked(), nil
}

func ports(in []string) (string, error) {
	if len(in) == 0 {
		return "", nil
	}
	out := make([]string, 0, len(in))
	for _, p := range in {
		m := portPattern.FindStringSubmatch(p)
		if m == nil {
			return "", fmt.Errorf("invalid port %q", p)
		}
		lo, _ := strconv.Atoi(m[1])
		hi := lo
		if m[2] != "" {
			hi, _ = strconv.Atoi(m[2])
		}
		if lo < 1 || hi > 65535 || hi < lo {
			return "", fmt.Errorf("invalid port %q", p)
		}
		if hi == lo {
			out = append(out, strconv.Itoa(lo))
		} else {
			out = append(out, strconv.Itoa(lo)+"-"+strconv.Itoa(hi))
		}
	}
	return "{ " + strings.Join(out, ", ") + " }", nil
}

func elements(items []string) string {
	if len(items) == 0 {
		return ""
	}
	return " elements = { " + strings.Join(items, ", ") + " };"
}

// Render builds the table for iface from the desired state. Activations
// that have already expired at now are left out.
func Render(iface string, s vpnagent.SyncResponse, now time.Time) (Ruleset, error) {
	if !ifacePattern.MatchString(iface) {
		return Ruleset{}, fmt.Errorf("invalid interface name %q", iface)
	}
	active := map[string]time.Duration{}
	for _, a := range s.Active {
		ip, err := addr(a.Address)
		if err != nil {
			return Ruleset{}, err
		}
		if left := a.ExpiresAt.Sub(now).Truncate(time.Second); left >= time.Second {
			if prev, ok := active[ip.String()]; !ok || left > prev {
				active[ip.String()] = left
			}
		}
	}

	policies := append([]vpnagent.Policy(nil), s.Policies...)
	sort.SliceStable(policies, func(i, j int) bool { return policies[i].Priority < policies[j].Priority })

	var b strings.Builder
	q := strconv.Quote(iface)
	fmt.Fprintf(&b, "table %s %s {\n", Family, Table)
	fmt.Fprintf(&b, "\tset %s { type ipv4_addr; flags timeout; }\n", Active)
	var rules []string
	for i, p := range policies {
		var src, dst []string
		for _, s := range p.Sources {
			a, err := addr(s)
			if err != nil {
				return Ruleset{}, fmt.Errorf("policy %d: %w", i, err)
			}
			src = append(src, a.String())
		}
		for _, d := range p.Destinations {
			pf, err := prefix(d)
			if err != nil {
				return Ruleset{}, fmt.Errorf("policy %d: %w", i, err)
			}
			dst = append(dst, pf.String())
		}
		sort.Strings(src)
		sort.Strings(dst)
		src, dst = unique(src), unique(dst)
		fmt.Fprintf(&b, "\tset s%d { type ipv4_addr;%s }\n", i, elements(src))
		fmt.Fprintf(&b, "\tset d%d { type ipv4_addr; flags interval; auto-merge;%s }\n", i, elements(dst))

		var verdict string
		switch p.Action {
		case vpnagent.ActionAllow:
			verdict = "accept"
		case vpnagent.ActionDeny:
			verdict = "drop"
		default:
			return Ruleset{}, fmt.Errorf("policy %d: invalid action %q", i, p.Action)
		}
		portSet, err := ports(p.Ports)
		if err != nil {
			return Ruleset{}, fmt.Errorf("policy %d: %w", i, err)
		}
		var l4 string
		switch p.Protocol {
		case vpnagent.ProtocolTCP, vpnagent.ProtocolUDP:
			if portSet != "" {
				l4 = p.Protocol + " dport " + portSet + " "
			} else {
				l4 = "meta l4proto " + p.Protocol + " "
			}
		case vpnagent.ProtocolICMP:
			if portSet != "" {
				return Ruleset{}, fmt.Errorf("policy %d: icmp takes no ports", i)
			}
			l4 = "ip protocol icmp "
		case vpnagent.ProtocolAny:
			if portSet != "" {
				return Ruleset{}, fmt.Errorf("policy %d: protocol any takes no ports", i)
			}
		default:
			return Ruleset{}, fmt.Errorf("policy %d: invalid protocol %q", i, p.Protocol)
		}
		rules = append(rules, fmt.Sprintf("iifname %s ip saddr @s%d ip daddr @d%d %scounter %s comment \"policy %d\"",
			q, i, i, l4, verdict, i))
	}
	for _, chain := range []string{"input", "forward"} {
		fmt.Fprintf(&b, "\tchain %s {\n\t\ttype filter hook %s priority 0; policy accept;\n", chain, chain)
		// The activation check comes before everything, established
		// connections included: deactivating a device cuts it off at once.
		fmt.Fprintf(&b, "\t\tiifname %s ip saddr != @%s counter drop\n", q, Active)
		fmt.Fprintf(&b, "\t\tiifname %s ct state established,related accept\n", q)
		for _, r := range rules {
			fmt.Fprintf(&b, "\t\t%s\n", r)
		}
		fmt.Fprintf(&b, "\t\tiifname %s counter drop comment \"default deny\"\n", q)
		if chain == "forward" {
			fmt.Fprintf(&b, "\t\toifname %s ct state established,related accept\n", q)
			fmt.Fprintf(&b, "\t\toifname %s counter drop\n", q)
		}
		b.WriteString("\t}\n")
	}
	b.WriteString("}\n")

	structure := b.String()
	sum := sha256.Sum256([]byte(structure))
	return Ruleset{Structure: structure, Hash: hex.EncodeToString(sum[:]), Active: active}, nil
}

func unique(sorted []string) []string {
	out := sorted[:0]
	for i, s := range sorted {
		if i == 0 || s != sorted[i-1] {
			out = append(out, s)
		}
	}
	return out
}

// activeElements renders the add-element statement for active, if any.
func activeElements(active map[string]time.Duration) string {
	if len(active) == 0 {
		return ""
	}
	ips := make([]string, 0, len(active))
	for ip := range active {
		ips = append(ips, ip)
	}
	sort.Strings(ips)
	items := make([]string, 0, len(ips))
	for _, ip := range ips {
		items = append(items, fmt.Sprintf("%s timeout %ds", ip, int(active[ip].Seconds())))
	}
	return fmt.Sprintf("add element %s %s %s { %s }\n", Family, Table, Active, strings.Join(items, ", "))
}

// Script returns the atomic replacement of the table: nft applies the
// whole file as one transaction, so the table never exists half-built.
func (r Ruleset) Script() string {
	return fmt.Sprintf("table %s %s {}\ndelete table %s %s\n%s%s", Family, Table, Family, Table, r.Structure, activeElements(r.Active))
}

// Applier applies rulesets with nft(8).
type Applier struct {
	Run hostexec.Runner
	// applied is the hash of the structure last installed.
	applied string
}

// Apply installs r. When the structure is unchanged only the active set is
// updated, element by element, so no connection is disturbed. It reports
// whether the whole table was replaced.
func (a *Applier) Apply(ctx context.Context, r Ruleset) (bool, error) {
	if a.applied != r.Hash || !a.tableExists(ctx) {
		if _, err := a.Run.Run(ctx, []byte(r.Script()), "nft", "-f", "-"); err != nil {
			a.applied = ""
			return false, err
		}
		a.applied = r.Hash
		return true, nil
	}
	have, err := a.ListActive(ctx)
	if err != nil {
		a.applied = ""
		return false, err
	}
	var script strings.Builder
	for ip, left := range have {
		want, ok := r.Active[ip]
		// Re-add when the desired expiry moved by more than a few seconds
		// (an extension or a shortening); otherwise leave the kernel's timer.
		if !ok || absDuration(want-left) > 5*time.Second {
			fmt.Fprintf(&script, "delete element %s %s %s { %s }\n", Family, Table, Active, ip)
		}
	}
	add := map[string]time.Duration{}
	for ip, want := range r.Active {
		left, ok := have[ip]
		if !ok || absDuration(want-left) > 5*time.Second {
			add[ip] = want
		}
	}
	script.WriteString(activeElements(add))
	if script.Len() == 0 {
		return false, nil
	}
	if _, err := a.Run.Run(ctx, []byte(script.String()), "nft", "-f", "-"); err != nil {
		a.applied = ""
		return false, err
	}
	return false, nil
}

func absDuration(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

func (a *Applier) tableExists(ctx context.Context) bool {
	_, err := a.Run.Run(ctx, nil, "nft", "list", "table", Family, Table)
	return err == nil
}

// ListActive returns the active_peers elements with their remaining time.
func (a *Applier) ListActive(ctx context.Context) (map[string]time.Duration, error) {
	out, err := a.Run.Run(ctx, nil, "nft", "-j", "list", "set", Family, Table, Active)
	if err != nil {
		return nil, err
	}
	return ParseActive(out)
}

// ParseActive reads `nft -j list set` output. Elements with a timeout are
// objects {"elem": {"val": ip, "timeout": s, "expires": s}}.
func ParseActive(out []byte) (map[string]time.Duration, error) {
	var doc struct {
		Nftables []struct {
			Set *struct {
				Elem []json.RawMessage `json:"elem"`
			} `json:"set"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		return nil, fmt.Errorf("parse nft json: %w", err)
	}
	active := map[string]time.Duration{}
	for _, item := range doc.Nftables {
		if item.Set == nil {
			continue
		}
		for _, raw := range item.Set.Elem {
			var plain string
			if json.Unmarshal(raw, &plain) == nil {
				active[plain] = 0
				continue
			}
			var e struct {
				Elem struct {
					Val     string `json:"val"`
					Expires int64  `json:"expires"`
				} `json:"elem"`
			}
			if err := json.Unmarshal(raw, &e); err != nil {
				return nil, fmt.Errorf("parse set element: %w", err)
			}
			active[e.Elem.Val] = time.Duration(e.Elem.Expires) * time.Second
		}
	}
	return active, nil
}

// Remove deletes the table (used when the agent is uninstalled).
func (a *Applier) Remove(ctx context.Context) error {
	if !a.tableExists(ctx) {
		return nil
	}
	_, err := a.Run.Run(ctx, nil, "nft", "delete", "table", Family, Table)
	return err
}
