package firewall

import (
	"context"
	"fmt"

	"github.com/novusgate/novusgate/internal/netctl/nft"
	"github.com/novusgate/novusgate/internal/shared/models"
)

// Source is the part of the store the firewall builder reads.
type Source interface {
	ListNetworks(ctx context.Context) ([]*models.Network, error)
	ListVPNFirewallRules(ctx context.Context) ([]*models.VPNFirewallRule, error)
	GetNode(ctx context.Context, id string) (*models.Node, error)
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
	vpnNetworks, warnings := NetworksFromModels(networks)
	vpnRules, ruleWarnings := VPNRulesFromModels(rules, byID, nodes)
	warnings = append(warnings, ruleWarnings...)
	return nft.Ruleset{
		SSHPorts:        sshPorts,
		EgressInterface: egress,
		Networks:        vpnNetworks,
		VPNRules:        vpnRules,
	}, warnings, nil
}
