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
	Verdict string   `json:"verdict"` // allow, deny or partial
	Reason  string   `json:"reason"`
	Rules   []string `json:"rules"` // names of the rules that touch the pair, in order
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

func verdictOf(action string) string {
	if action == "accept" {
		return "allow"
	}
	return "deny"
}

// PolicyMatrix evaluates the VPN rules for every pair of networks the way
// the firewall does: enabled rules in stored order (priority, then
// creation), first match wins, with endpoints resolved to addresses (a node
// is its /32, so it only touches its own network). nftEnforcing selects the
// default: nftables isolates networks (same network allowed); iptables mode
// accepts VPN traffic no rule drops. Rules that cannot be resolved are
// skipped, as the firewall skips them, and returned as warnings.
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
	for _, from := range m.Networks {
		m.Cells[from.ID] = map[string]MatrixCell{}
		for _, to := range m.Networks {
			m.Cells[from.ID][to.ID] = matrixCell(from.ID == to.ID, cidrs[from.ID], cidrs[to.ID], rs.VPNRules, names, nftEnforcing)
		}
	}
	return m, warnings, nil
}

func matrixCell(same bool, from, to netip.Prefix, rules []nft.VPNRule, names map[string]string, nftEnforcing bool) MatrixCell {
	touched := []string{}
	var scoped []string
	final, reason := "", ""
	for _, r := range rules {
		s, d := prefixScope(r.Src, from), prefixScope(r.Dst, to)
		if s == scopeNone || d == scopeNone {
			continue
		}
		touched = append(touched, names[r.ID])
		allTraffic := (r.Proto == nft.All || r.Proto == "") && len(r.Ports) == 0
		if s == scopeWhole && d == scopeWhole && allTraffic {
			final, reason = verdictOf(r.Action), fmt.Sprintf("rule %q", names[r.ID])
			break
		}
		scoped = append(scoped, verdictOf(r.Action))
	}
	if final == "" {
		switch {
		case !nftEnforcing:
			final, reason = "allow", "default (iptables mode accepts VPN traffic no rule drops)"
		case same:
			final, reason = "allow", "default (same network)"
		default:
			final, reason = "deny", "default (networks are isolated)"
		}
	}
	for _, v := range scoped {
		if v != final {
			return MatrixCell{Verdict: "partial", Reason: "some traffic differs from " + reason, Rules: touched}
		}
	}
	return MatrixCell{Verdict: final, Reason: reason, Rules: touched}
}
