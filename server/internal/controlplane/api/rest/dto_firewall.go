package rest

import (
	"time"

	"github.com/novusgate/novusgate/internal/controlplane/firewall"
	"github.com/novusgate/novusgate/internal/netctl/conntrack"
	"github.com/novusgate/novusgate/internal/netctl/nft"
	"github.com/novusgate/novusgate/internal/shared/models"
)

type OpenPortResponse struct {
	Status   string `json:"status"`
	Message  string `json:"message"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Source   string `json:"source"`
}

type ClosePortResponse struct {
	Status       string `json:"status"`
	Message      string `json:"message"`
	Port         int    `json:"port"`
	Protocol     string `json:"protocol"`
	RulesDeleted int    `json:"rules_deleted"`
}

// IPRuleResponse answers Block IP and Allow IP.
type IPRuleResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
	IP      string `json:"ip"`
	Ports   string `json:"ports"`
}

type DeleteRuleResponse struct {
	Status      string       `json:"status"`
	Message     string       `json:"message"`
	Chain       string       `json:"chain"`
	LineNumber  int          `json:"line_number"`
	DeletedRule FirewallRule `json:"deleted_rule"`
}

// PendingChange is a firewall change waiting for confirmation.
type PendingChange struct {
	ID       string    `json:"id"`
	Deadline time.Time `json:"deadline"`
}

// V2StateResponse: host_error and the ssh_ports/egress_interface pair are
// mutually exclusive; pending is null when nothing waits.
type V2StateResponse struct {
	Mode            firewall.Mode             `json:"mode"`
	Services        []*models.FirewallService `json:"services"`
	IPRules         []*models.FirewallIPRule  `json:"ip_rules"`
	Forwards        []*models.FirewallForward `json:"forwards"`
	EgressNodeIDs   []string                  `json:"egress_node_ids"`
	Pending         *PendingChange            `json:"pending"`
	HostError       string                    `json:"host_error,omitempty"`
	SSHPorts        *[]uint16                 `json:"ssh_ports,omitempty" openapi:"notnull"`
	EgressInterface *string                   `json:"egress_interface,omitempty" openapi:"notnull"`
}

type V2PreviewResponse struct {
	Script   string   `json:"script"`
	Warnings []string `json:"warnings"`
}

// V2ChangeResponse answers every v2 change; item is the created record,
// an IDItem for deletes, or an EgressItem.
type V2ChangeResponse struct {
	Item     any            `json:"item"`
	Pending  *PendingChange `json:"pending"`
	Warnings []string       `json:"warnings"`
}

type IDItem struct {
	ID string `json:"id"`
}

type EgressItem struct {
	NodeID string `json:"node_id"`
	Egress bool   `json:"egress"`
}

// V2LiveResponse is what the host's firewall shows now. counters and
// dropped come from table inet novusgate (empty when it is not loaded, e.g.
// in iptables mode); conntrack is read in every mode.
type V2LiveResponse struct {
	Mode        firewall.Mode       `json:"mode"`
	TableLoaded bool                `json:"table_loaded"`
	Counters    []nft.RuleCounter   `json:"counters"`
	Dropped     []nft.DroppedSource `json:"dropped"`
	Conntrack   conntrack.Summary   `json:"conntrack"`
	Error       string              `json:"error,omitempty"`
}
