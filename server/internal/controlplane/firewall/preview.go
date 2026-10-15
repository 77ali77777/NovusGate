package firewall

import (
	"context"
	"fmt"
	"time"

	"github.com/novusgate/novusgate/internal/netctl/nft"
	"github.com/novusgate/novusgate/internal/shared/models"
)

// Source is the part of the store the firewall builder reads.
type Source interface {
	ListNetworks(ctx context.Context) ([]*models.Network, error)
	ListVPNFirewallRules(ctx context.Context) ([]*models.VPNFirewallRule, error)
	GetNode(ctx context.Context, id string) (*models.Node, error)
}

// GroupSource is a Source that also keeps node groups (P9a).
type GroupSource interface {
	ListNodeGroups(ctx context.Context) ([]*models.NodeGroup, error)
}

// LimitSource is a Source that also keeps limit profiles (P9b).
type LimitSource interface {
	ListLimitProfiles(ctx context.Context) ([]models.LimitProfile, error)
	ListNodeLimits(ctx context.Context) ([]models.NodeLimit, error)
}

// DetectHost reads the host facts a ruleset depends on: the ports SSH must
// stay reachable on and the interface that carries the default route.
func DetectHost(r nft.Runner) ([]uint16, string, error) {
	ports, err := nft.DetectSSHPorts(r)
	if err != nil {
		return nil, "", err
	}
	route, err := r.Run("", "ip", "route", "get", "8.8.8.8")
	if err != nil {
		return nil, "", fmt.Errorf("ip route get: %v: %s", err, route)
	}
	egress, err := nft.ParseRouteDevice(route)
	if err != nil {
		return nil, "", err
	}
	return ports, egress, nil
}

// BuildRuleset assembles the engine model from stored state. Services,
// blocked addresses, forwards and egress nodes are not stored yet (P3b), so
// they are empty here. Conversion problems are returned as warnings.
func BuildRuleset(ctx context.Context, src Source, sshPorts []uint16, egress string) (nft.Ruleset, []error, error) {
	return BuildRulesetAt(ctx, src, sshPorts, egress, time.Now())
}

// BuildRulesetAt is BuildRuleset at a given time; limit schedules (P9b) are
// turned into UTC windows for the week from now.
func BuildRulesetAt(ctx context.Context, src Source, sshPorts []uint16, egress string, now time.Time) (nft.Ruleset, []error, error) {
	networks, err := src.ListNetworks(ctx)
	if err != nil {
		return nft.Ruleset{}, nil, fmt.Errorf("list networks: %w", err)
	}
	rules, err := src.ListVPNFirewallRules(ctx)
	if err != nil {
		return nft.Ruleset{}, nil, fmt.Errorf("list VPN rules: %w", err)
	}
	byID := map[string]*models.Network{}
	for _, n := range networks {
		byID[n.ID] = n
	}
	nodes := map[string]*models.Node{}
	for _, r := range rules {
		for _, id := range []*string{r.SourceNodeID, r.DestNodeID} {
			if id == nil || nodes[*id] != nil {
				continue
			}
			node, err := src.GetNode(ctx, *id)
			if err != nil {
				return nft.Ruleset{}, nil, fmt.Errorf("get node %s: %w", *id, err)
			}
			if node != nil {
				nodes[*id] = node
			}
		}
	}
	// Node groups (P9a) come from sources that keep them (the store).
	var groups []*models.NodeGroup
	if gs, ok := src.(GroupSource); ok {
		if groups, err = gs.ListNodeGroups(ctx); err != nil {
			return nft.Ruleset{}, nil, fmt.Errorf("list node groups: %w", err)
		}
	}
	vpnNetworks, warnings := NetworksFromModels(networks)
	vpnRules, sets, ruleWarnings := vpnRulesWithGroups(rules, byID, nodes, groups)
	warnings = append(warnings, ruleWarnings...)
	var limits []nft.Limit
	if ls, ok := src.(LimitSource); ok {
		profiles, nodeLimits, err := listLimits(ctx, ls)
		if err != nil {
			return nft.Ruleset{}, nil, err
		}
		var limitWarnings []error
		limits, limitWarnings = LimitsFromModels(profiles, nodeLimits, now)
		warnings = append(warnings, limitWarnings...)
	}
	return nft.Ruleset{
		SSHPorts:        sshPorts,
		EgressInterface: egress,
		Networks:        vpnNetworks,
		VPNRules:        vpnRules,
		Groups:          sets,
		Limits:          limits,
	}, warnings, nil
}

func listLimits(ctx context.Context, ls LimitSource) ([]models.LimitProfile, []models.NodeLimit, error) {
	profiles, err := ls.ListLimitProfiles(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("list limit profiles: %w", err)
	}
	nodeLimits, err := ls.ListNodeLimits(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("list node limits: %w", err)
	}
	return profiles, nodeLimits, nil
}

// NextLimitReload is when the ruleset must be rebuilt so limit schedules
// keep matching local time: the earliest UTC offset change among the time
// zones of the scheduled profiles in use.
func NextLimitReload(ctx context.Context, src Source, now time.Time) (time.Time, bool, error) {
	ls, ok := src.(LimitSource)
	if !ok {
		return time.Time{}, false, nil
	}
	profiles, nodeLimits, err := listLimits(ctx, ls)
	if err != nil {
		return time.Time{}, false, err
	}
	used := map[string]bool{}
	for _, l := range nodeLimits {
		used[l.ProfileID] = true
	}
	var next time.Time
	found := false
	for _, p := range profiles {
		if !used[p.ID] || len(p.Schedule) == 0 {
			continue
		}
		loc, err := time.LoadLocation(p.Timezone)
		if err != nil {
			continue
		}
		if t, ok := NextOffsetChange(loc, now); ok && (!found || t.Before(next)) {
			next, found = t, true
		}
	}
	return next, found, nil
}
