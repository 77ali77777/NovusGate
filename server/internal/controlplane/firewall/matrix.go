package firewall

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/novusgate/novusgate/internal/netctl/nft"
)

// MatrixNetwork is one row and column of the policy matrix.
type MatrixNetwork struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// MatrixCell is what traffic from one network to another gets.
type MatrixCell struct {
	Verdict string `json:"verdict"` // allow, deny or partial
	Reason  string `json:"reason"`
	// ReasonKey says why, for translation: rule, same_network or isolated (both
	// engines keep networks apart by default); Rule names the deciding rule.
	ReasonKey string   `json:"reason_key"`
	Rule      string   `json:"rule,omitempty"`
	Rules     []string `json:"rules"` // names of the rules that touch the pair, in order
	// Limited: a node on either side has a limit profile (P9b) the firewall
	// enforces; the verdict is the same, the traffic is limited.
	Limited bool `json:"limited"`
}

// Matrix is the network policy matrix; Cells[from][to].
type Matrix struct {
	NftEnforcing bool                             `json:"nft_enforcing"`
	Networks     []MatrixNetwork                  `json:"networks"`
	Cells        map[string]map[string]MatrixCell `json:"cells"`
}

type scope int

const (
	scopeNone scope = iota
	scopeSome
	scopeWhole
)

// prefixScope says how much of network n a rule prefix p covers.
func prefixScope(p, n netip.Prefix) scope {
	switch {
	case p.Bits() <= n.Bits() && p.Contains(n.Addr()):
		return scopeWhole
	case n.Bits() <= p.Bits() && n.Contains(p.Addr()):
		return scopeSome
	}
	return scopeNone
}

// endScope is prefixScope for one side of a rule; a group set covers "some"
// of a network when one of its members is inside it, and the whole of a
// single address (one device, as the access check asks) that is a member.
func endScope(set string, p netip.Prefix, sets map[string][]netip.Addr, n netip.Prefix) scope {
	if set == "" {
		return prefixScope(p, n)
	}
	for _, a := range sets[set] {
		if n.Contains(a) {
			if n.IsSingleIP() {
				return scopeWhole
			}
			return scopeSome
		}
	}
	return scopeNone
}

func verdictOf(action string) string {
	if action == "accept" {
		return "allow"
	}
	return "deny"
}

// PolicyMatrix evaluates the VPN rules for every pair of networks the way
// the firewall does: enabled rules in stored order (priority, then
// creation), first match wins, with endpoints resolved to addresses (a node
// is its /32, so it only touches its own network). Both engines isolate
// networks by default (same network allowed); a mutual rule counts in both
// directions. nftEnforcing only marks rate limits. Rules that cannot be
// resolved are skipped, as the firewall skips them, and returned as warnings.
func PolicyMatrix(ctx context.Context, src Source, nftEnforcing bool) (Matrix, []error, error) {
	networks, err := src.ListNetworks(ctx)
	if err != nil {
		return Matrix{}, nil, fmt.Errorf("list networks: %w", err)
	}
	stored, err := src.ListVPNFirewallRules(ctx)
	if err != nil {
		return Matrix{}, nil, fmt.Errorf("list VPN rules: %w", err)
	}
	names := map[string]string{}
	for _, r := range stored {
		names[r.ID] = r.Name
	}
	rs, warnings, err := BuildRuleset(ctx, src, nil, "")
	if err != nil {
		return Matrix{}, nil, err
	}
	m := Matrix{NftEnforcing: nftEnforcing, Networks: []MatrixNetwork{}, Cells: map[string]map[string]MatrixCell{}}
	cidrs := map[string]netip.Prefix{}
	for _, n := range networks {
		p, err := netip.ParsePrefix(n.CIDR)
		if err != nil {
			continue
		}
		cidrs[n.ID] = p.Masked()
		m.Networks = append(m.Networks, MatrixNetwork{ID: n.ID, Name: n.Name})
	}
	sets := map[string][]netip.Addr{}
	for _, g := range rs.Groups {
		sets[g.Name] = g.Members
	}
	limited := map[string]bool{}
	if nftEnforcing {
		for _, l := range rs.Limits {
			for _, a := range l.Members {
				for id, p := range cidrs {
					if p.Contains(a) {
						limited[id] = true
					}
				}
			}
		}
	}
	for _, from := range m.Networks {
		m.Cells[from.ID] = map[string]MatrixCell{}
		for _, to := range m.Networks {
			c := matrixCell(from.ID == to.ID, cidrs[from.ID], cidrs[to.ID], rs.VPNRules, sets, names)
			c.Limited = limited[from.ID] || limited[to.ID]
			m.Cells[from.ID][to.ID] = c
		}
	}
	return m, warnings, nil
}

func matrixCell(same bool, from, to netip.Prefix, rules []nft.VPNRule, sets map[string][]netip.Addr, names map[string]string) MatrixCell {
	touched := []string{}
	var scoped []string
	final, reason, key, rule := "", "", "", ""
	for _, r := range rules {
		s, d := endScope(r.SrcSet, r.Src, sets, from), endScope(r.DstSet, r.Dst, sets, to)
		if s == scopeNone || d == scopeNone {
			continue
		}
		touched = append(touched, names[r.ID])
		allTraffic := (r.Proto == nft.All || r.Proto == "") && len(r.Ports) == 0
		if s == scopeWhole && d == scopeWhole && allTraffic {
			final, reason, key, rule = verdictOf(r.Action), fmt.Sprintf("rule %q", names[r.ID]), "rule", names[r.ID]
			break
		}
		scoped = append(scoped, verdictOf(r.Action))
	}
	if final == "" {
		switch {
		case same:
			final, reason, key = "allow", "default (same network)", "same_network"
		default:
			final, reason, key = "deny", "default (networks are isolated)", "isolated"
		}
	}
	for _, v := range scoped {
		if v != final {
			return MatrixCell{Verdict: "partial", Reason: "some traffic differs from " + reason, ReasonKey: key, Rule: rule, Rules: touched}
		}
	}
	return MatrixCell{Verdict: final, Reason: reason, ReasonKey: key, Rule: rule, Rules: touched}
}
