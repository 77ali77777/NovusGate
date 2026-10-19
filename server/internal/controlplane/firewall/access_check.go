package firewall

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	"github.com/novusgate/novusgate/internal/netctl/nft"
	"github.com/novusgate/novusgate/internal/shared/models"
)

// ErrEndpoint: an access check side names a kind it does not know or a
// network, device or group that does not exist.
var ErrEndpoint = errors.New("unknown endpoint")

// Endpoint is one side of an access check: Type network, node or group.
type Endpoint struct {
	Type string
	ID   string
}

// EndpointInfo is a resolved side: its name and the addresses it stands for.
type EndpointInfo struct {
	Type      string   `json:"type"`
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Addresses []string `json:"addresses"`
}

// AccessVerdict is what connections one side starts toward the other get.
type AccessVerdict struct {
	Verdict string `json:"verdict"` // allow, deny or partial
	Reason  string `json:"reason"`
	// ReasonKey: rule, same_network, isolated, mixed (the devices of a side
	// get different answers) or empty (a group without devices).
	ReasonKey string   `json:"reason_key"`
	Rule      string   `json:"rule,omitempty"`
	Rules     []string `json:"rules"` // rules that touch the pair, in order
}

// AccessResult answers "who can reach whom" for two sides, both ways:
// Forward is From starting connections to To, Reverse the other way.
// Replies to an allowed connection always come back.
type AccessResult struct {
	From    EndpointInfo  `json:"from"`
	To      EndpointInfo  `json:"to"`
	Forward AccessVerdict `json:"forward"`
	Reverse AccessVerdict `json:"reverse"`
}

// AccessCheck evaluates the VPN rules between two networks, devices or
// groups the way PolicyMatrix does for networks, device by device: a group
// is its members, a device its /32. Unresolvable rules are skipped and
// returned as warnings.
func AccessCheck(ctx context.Context, src Source, from, to Endpoint) (AccessResult, []error, error) {
	networks, err := src.ListNetworks(ctx)
	if err != nil {
		return AccessResult{}, nil, fmt.Errorf("list networks: %w", err)
	}
	var groups []*models.NodeGroup
	if gs, ok := src.(GroupSource); ok && (from.Type == "group" || to.Type == "group") {
		if groups, err = gs.ListNodeGroups(ctx); err != nil {
			return AccessResult{}, nil, fmt.Errorf("list groups: %w", err)
		}
	}
	fromInfo, fromPts, err := resolveEndpoint(ctx, src, networks, groups, from)
	if err != nil {
		return AccessResult{}, nil, err
	}
	toInfo, toPts, err := resolveEndpoint(ctx, src, networks, groups, to)
	if err != nil {
		return AccessResult{}, nil, err
	}

	stored, err := src.ListVPNFirewallRules(ctx)
	if err != nil {
		return AccessResult{}, nil, fmt.Errorf("list VPN rules: %w", err)
	}
	names := map[string]string{}
	for _, r := range stored {
		names[r.ID] = r.Name
	}
	rs, warnings, err := BuildRuleset(ctx, src, nil, "")
	if err != nil {
		return AccessResult{}, nil, err
	}
	sets := map[string][]netip.Addr{}
	for _, g := range rs.Groups {
		sets[g.Name] = g.Members
	}
	var cidrs []netip.Prefix
	for _, n := range networks {
		if p, err := netip.ParsePrefix(n.CIDR); err == nil {
			cidrs = append(cidrs, p.Masked())
		}
	}
	verdict := func(a, b []netip.Prefix) AccessVerdict {
		return accessVerdict(a, b, cidrs, rs, sets, names)
	}
	return AccessResult{From: fromInfo, To: toInfo, Forward: verdict(fromPts, toPts), Reverse: verdict(toPts, fromPts)}, warnings, nil
}

func resolveEndpoint(ctx context.Context, src Source, networks []*models.Network, groups []*models.NodeGroup, e Endpoint) (EndpointInfo, []netip.Prefix, error) {
	info := EndpointInfo{Type: e.Type, ID: e.ID, Addresses: []string{}}
	var pts []netip.Prefix
	switch e.Type {
	case "network":
		for _, n := range networks {
			if n.ID == e.ID {
				p, err := netip.ParsePrefix(n.CIDR)
				if err != nil {
					return info, nil, fmt.Errorf("network %s: %v", n.Name, err)
				}
				info.Name, pts = n.Name, []netip.Prefix{p.Masked()}
			}
		}
	case "node":
		n, err := src.GetNode(ctx, e.ID)
		if err != nil { // a missing device is (nil, nil)
			return info, nil, fmt.Errorf("get node: %w", err)
		}
		if n != nil {
			addr, ok := netip.AddrFromSlice(n.VirtualIP)
			if !ok {
				return info, nil, fmt.Errorf("%w: device %s has no address", ErrEndpoint, n.Name)
			}
			info.Name, pts = n.Name, []netip.Prefix{netip.PrefixFrom(addr.Unmap(), 32)}
		}
	case "group":
		for _, g := range groups {
			if g.ID != e.ID {
				continue
			}
			info.Name, pts = g.Name, []netip.Prefix{}
			for _, m := range g.Members {
				if a, err := netip.ParseAddr(m.VirtualIP); err == nil && a.Unmap().Is4() {
					pts = append(pts, netip.PrefixFrom(a.Unmap(), 32))
				}
			}
		}
	}
	if pts == nil {
		return info, nil, fmt.Errorf("%w: %s %q", ErrEndpoint, e.Type, e.ID)
	}
	for _, p := range pts {
		info.Addresses = append(info.Addresses, p.String())
	}
	return info, pts, nil
}

// accessVerdict evaluates every address pair; one answer for all is the
// verdict, different answers make it partial ("mixed").
func accessVerdict(from, to []netip.Prefix, cidrs []netip.Prefix, rs nft.Ruleset, sets map[string][]netip.Addr, names map[string]string) AccessVerdict {
	out := AccessVerdict{Rules: []string{}}
	if len(from) == 0 || len(to) == 0 {
		out.Verdict, out.ReasonKey, out.Reason = "deny", "empty", "a group without devices"
		return out
	}
	seen := map[string]bool{}
	first := true
	for _, a := range from {
		for _, b := range to {
			c := matrixCell(sameNetwork(a, b, cidrs), a, b, rs.VPNRules, sets, names)
			for _, r := range c.Rules {
				if !seen[r] {
					seen[r] = true
					out.Rules = append(out.Rules, r)
				}
			}
			switch {
			case first:
				out.Verdict, out.Reason, out.ReasonKey, out.Rule = c.Verdict, c.Reason, c.ReasonKey, c.Rule
				first = false
			case c.Verdict != out.Verdict && out.ReasonKey != "mixed":
				out.Verdict, out.Reason, out.ReasonKey, out.Rule = "partial", "devices on this side get different answers", "mixed", ""
			}
		}
	}
	return out
}

// sameNetwork: both sides lie wholly inside one VPN network.
func sameNetwork(a, b netip.Prefix, cidrs []netip.Prefix) bool {
	for _, n := range cidrs {
		if prefixScope(n, a) == scopeWhole && prefixScope(n, b) == scopeWhole {
			return true
		}
	}
	return false
}
