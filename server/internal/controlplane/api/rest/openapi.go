package rest

import (
	"encoding/json"
	"net"
	"net/http"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/novusgate/novusgate/internal/controlplane/backup"
	"github.com/novusgate/novusgate/internal/controlplane/firewall"
	"github.com/novusgate/novusgate/internal/controlplane/hostadmin"
	"github.com/novusgate/novusgate/internal/shared/models"
)

// freeform documents a JSON object whose shape is not modelled yet
// (handler-local maps and anonymous request structs; P2d-3 turns them into DTOs).
type freeform struct{}

// mediaType documents a non-JSON body by its content type.
type mediaType string

// docOp documents one route. Request/Response are Go values whose types
// become schemas; nil Response means no body.
type docOp struct {
	Method, Path, Summary, Tag string
	Request                    any
	Status                     int
	Response                   any
	Public                     bool
}

// docParam is a documented query parameter.
type docParam struct {
	Name, Type, Description string
}

// docQueryParams documents the query parameters of an operation, keyed by
// "METHOD path".
var docQueryParams = map[string][]docParam{
	"GET /api/v1/system/fail2ban/logs":              {{"lines", "integer", "number of log lines (default 100)"}},
	"GET /api/v1/nodes/{id}/traffic":                {{"range", "string", "24h (default), 7d or 30d"}},
	"GET /api/v1/firewall/host/rules":               {{"chain", "string", "only this chain (INPUT, FORWARD, ...)"}},
	"GET /api/v1/system/fail2ban/jail/settings":     {{"jail", "string", "jail name (default sshd)"}},
	"GET /api/v1/system/fail2ban/whitelist":         {{"jail", "string", "jail name (default sshd)"}},
	"POST /api/v1/system/fail2ban/reload":           {{"jail", "string", "reload only this jail"}},
	"GET /api/v1/system/fail2ban/ban-history":       {{"jail", "string", "only this jail"}, {"limit", "integer", "newest entries to return (default 100)"}},
	"POST /api/v1/firewall/v2/services":             {confirmParam},
	"DELETE /api/v1/firewall/v2/services/{id}":      {confirmParam},
	"POST /api/v1/firewall/v2/ip-rules":             {confirmParam},
	"DELETE /api/v1/firewall/v2/ip-rules/{id}":      {confirmParam},
	"POST /api/v1/firewall/v2/forwards":             {confirmParam},
	"DELETE /api/v1/firewall/v2/forwards/{id}":      {confirmParam},
	"PUT /api/v1/firewall/v2/egress/{nodeId}":       {confirmParam},
	"DELETE /api/v1/firewall/v2/egress/{nodeId}":    {confirmParam},
	"GET /api/v1/audit":                             {{"limit", "integer", "entries to return (default 100, at most 500)"}, {"before", "string", "only entries older than this RFC 3339 time (paging)"}, {"before_id", "string", "with before: the id of the last entry shown, so entries with the same time are kept"}},
	"GET /api/v1/firewall/v2/history":               {{"limit", "integer", "newest entries to return (default 50, at most 200)"}},
	"POST /api/v1/firewall/v2/history/{id}/restore": {confirmParam},
}

var confirmParam = docParam{"confirm", "boolean", "false applies at once; otherwise the change rolls back unless confirmed"}

// docExtraResponses documents a second success status of an operation,
// keyed by "METHOD path".
var docExtraResponses = map[string]map[int]any{
	"PUT /api/v1/system/fail2ban/jail/settings": {http.StatusPartialContent: Fail2BanUpdateSettingsResponse{}},
}

// docOps lists every registered route; TestEveryRouteIsDocumented keeps it complete.
var docOps = []docOp{
	{"GET", "/health", "Liveness and component checks (always 200)", "meta", nil, 200, HealthResponse{}, true},
	{"GET", "/api/v1/openapi.json", "This document", "meta", nil, 200, freeform{}, false},
	{"POST", "/api/v1/auth/login", "Log in", "auth", LoginRequest{}, 200, LoginResponse{}, true},
	{"PUT", "/api/v1/auth/password", "Change a password", "auth", UpdatePasswordRequest{}, 200, StatusResponse{}, false},
	{"POST", "/api/v1/auth/logout", "Log out (revokes this session)", "auth", nil, 204, nil, false},
	{"GET", "/api/v1/users", "List users", "users", nil, 200, []models.User{}, false},
	{"POST", "/api/v1/users", "Create a user", "users", CreateUserRequest{}, 201, models.User{}, false},
	{"DELETE", "/api/v1/users/{id}", "Delete a user", "users", nil, 204, nil, false},
	{"GET", "/api/v1/networks", "List networks", "networks", nil, 200, []models.Network{}, false},
	{"POST", "/api/v1/networks", "Create a network", "networks", models.Network{}, 201, models.Network{}, false},
	{"GET", "/api/v1/networks/{id}", "Get a network", "networks", nil, 200, models.Network{}, false},
	{"DELETE", "/api/v1/networks/{id}", "Delete a network (not wg0)", "networks", nil, 204, nil, false},
	{"PUT", "/api/v1/networks/{id}/dns", "Set the DNS servers of the network's client configs (up to 3 IPs; empty: 1.1.1.1 for full tunnel, none for split)", "networks", ClientDNSRequest{}, 200, models.Network{}, false},
	{"GET", "/api/v1/networks/{networkId}/nodes", "List a network's nodes", "nodes", nil, 200, []models.Node{}, false},
	{"POST", "/api/v1/networks/{networkId}/servers", "Create a node with its WireGuard config", "nodes", CreateServerRequest{}, 201, CreateServerResponse{}, false},
	{"POST", "/api/v1/networks/{networkId}/sync", "Re-add missing peers of active nodes", "networks", nil, 200, SyncPeersResponse{}, false},
	{"GET", "/api/v1/nodes/{id}", "Get a node", "nodes", nil, 200, models.Node{}, false},
	{"PUT", "/api/v1/nodes/{id}", "Update a node", "nodes", UpdateNodeRequest{}, 200, models.Node{}, false},
	{"PATCH", "/api/v1/nodes/{id}", "Update a node (same as PUT)", "nodes", UpdateNodeRequest{}, 200, models.Node{}, false},
	{"DELETE", "/api/v1/nodes/{id}", "Delete a node", "nodes", nil, 200, StatusResponse{}, false},
	{"POST", "/api/v1/nodes/{id}/checkin", "Report node information (panel session, or the install script's X-Enrollment-Token)", "nodes", NodeCheckInRequest{}, 200, models.Node{}, false},
	{"GET", "/api/v1/nodes/{id}/config", "Download the client WireGuard config", "nodes", nil, 200, mediaType("text/plain"), false},
	{"GET", "/api/v1/nodes/{id}/qrcode", "Client config as a QR code", "nodes", nil, 200, mediaType("image/png"), false},
	{"GET", "/api/v1/nodes/{id}/install.sh", "Linux install script for the node", "nodes", nil, 200, mediaType("text/x-shellscript"), false},
	{"GET", "/api/v1/nodes/{id}/traffic", "Traffic history of the node (bytes per interval)", "nodes", nil, 200, NodeTrafficResponse{}, false},
	{"GET", "/api/v1/backups", "List the manual backups, newest first", "backups", nil, 200, BackupListResponse{}, false},
	{"POST", "/api/v1/backups", "Make a backup now (database dump and WireGuard configs)", "backups", nil, 201, backup.Info{}, false},
	{"GET", "/api/v1/backups/{name}", "Download a backup", "backups", nil, 200, mediaType("application/gzip"), false},
	{"DELETE", "/api/v1/backups/{name}", "Delete a backup", "backups", nil, 204, nil, false},
	{"GET", "/api/v1/auth/me", "The signed-in user and role", "auth", nil, 200, MeResponse{}, false},
	{"PUT", "/api/v1/users/{id}/role", "Change a user's role (admin, operator, viewer; 409 last_admin)", "users", SetUserRoleRequest{}, 200, models.User{}, false},
	{"GET", "/api/v1/groups", "Node groups with their members, by name", "groups", nil, 200, NodeGroupsResponse{}, false},
	{"POST", "/api/v1/groups", "Create a node group (409 group_name_taken)", "groups", NodeGroupRequest{}, 201, models.NodeGroup{}, false},
	{"PUT", "/api/v1/groups/{id}", "Rename a node group", "groups", NodeGroupRequest{}, 200, models.NodeGroup{}, false},
	{"DELETE", "/api/v1/groups/{id}", "Delete a node group (409 group_in_use while a VPN rule names it)", "groups", nil, 204, nil, false},
	{"PUT", "/api/v1/groups/{id}/members", "Replace a group's members; VPN rules are re-applied", "groups", NodeGroupMembersRequest{}, 200, models.NodeGroup{}, false},
	{"GET", "/api/v1/limits", "Limit profiles and the profile in force for each limited node (P9b)", "limits", nil, 200, LimitProfilesResponse{}, false},
	{"POST", "/api/v1/limits", "Create a limit profile (409 limit_name_taken)", "limits", LimitProfileRequest{}, 201, models.LimitProfile{}, false},
	{"PUT", "/api/v1/limits/{id}", "Replace a limit profile; bound nodes get it at once", "limits", LimitProfileRequest{}, 200, models.LimitProfile{}, false},
	{"DELETE", "/api/v1/limits/{id}", "Delete a limit profile (409 limit_in_use while bound)", "limits", nil, 204, nil, false},
	{"PUT", "/api/v1/limits/{id}/bindings", "Make these the nodes and groups bound to the profile", "limits", LimitBindingsRequest{}, 200, models.LimitProfile{}, false},
	{"POST", "/api/v1/auth/step-up", "Enter the password again: server changes are allowed for 5 minutes (400 invalid_password; 429 after 5 wrong passwords in 15 minutes)", "auth", StepUpRequest{}, 204, nil, false},
	{"GET", "/api/v1/server/services", "Managed services and their state (admin, P10a)", "server", nil, 200, ServicesResponse{}, false},
	{"POST", "/api/v1/server/services/{unit}/restart", "Restart docker, fail2ban or a wg-quick@ unit (step-up)", "server", nil, 204, nil, false},
	{"GET", "/api/v1/server/sysctl", "Managed kernel settings and their values", "server", nil, 200, SysctlResponse{}, false},
	{"PUT", "/api/v1/server/sysctl", "Change kernel settings; undone unless confirmed within confirm_within seconds (step-up)", "server", SysctlChangeRequest{}, 200, SysctlChangeResponse{}, false},
	{"POST", "/api/v1/server/sysctl/confirm", "Keep the last kernel settings change (step-up)", "server", nil, 204, nil, false},
	{"GET", "/api/v1/server/system", "Host name, time zone, NTP, kernel and OS", "server", nil, 200, hostadmin.SystemInfo{}, false},
	{"PUT", "/api/v1/server/system/hostname", "Change the host name (step-up)", "server", HostnameRequest{}, 200, hostadmin.SystemInfo{}, false},
	{"PUT", "/api/v1/server/system/timezone", "Set the time zone and NTP (step-up)", "server", TimezoneRequest{}, 200, hostadmin.SystemInfo{}, false},
	{"GET", "/api/v1/server/packages", "Upgradable packages", "server", nil, 200, PackagesResponse{}, false},
	{"GET", "/api/v1/server/packages/upgrade", "The last package upgrade and its output", "server", nil, 200, UpgradeJob{}, false},
	{"POST", "/api/v1/server/packages/upgrade", "Start apt-get upgrade; confirm must be \"upgrade\" (step-up, 409 upgrade_running)", "server", ConfirmRequest{}, 202, nil, false},
	{"POST", "/api/v1/server/reboot", "Reboot the host; confirm must be \"reboot\" (step-up)", "server", ConfirmRequest{}, 202, nil, false},
	{"GET", "/api/v1/server/network", "Addresses, routes and links as ip -j reports them (read-only)", "server", nil, 200, hostadmin.NetworkView{}, false},
	{"POST", "/api/v1/nodes/{id}/quota/reset", "Start a node's traffic quota count again and lift its block (P9c)", "limits", nil, 204, nil, false},
	{"GET", "/api/v1/audit", "Audit log: changes made through the API and login attempts, newest first", "audit", nil, 200, AuditLogResponse{}, false},
	{"GET", "/api/v1/auth/sessions", "Login sessions that have not expired (current marks the caller's)", "auth", nil, 200, SessionsResponse{}, false},
	{"DELETE", "/api/v1/auth/sessions/{id}", "End a login session", "auth", nil, 204, nil, false},
	{"GET", "/api/v1/notifications/settings", "Telegram notification settings (the bot token is never returned)", "notifications", nil, 200, models.NotificationSettings{}, false},
	{"PUT", "/api/v1/notifications/settings", "Update the Telegram notification settings; an empty bot_token keeps the stored one", "notifications", NotificationSettingsRequest{}, 200, models.NotificationSettings{}, false},
	{"POST", "/api/v1/notifications/test", "Send a test message to the configured chat", "notifications", nil, 200, StatusMessageResponse{}, false},
	{"GET", "/api/v1/debug/wireguard/{networkId}", "Compare DB nodes with live peers", "networks", nil, 200, DebugWireGuardResponse{}, false},
	{"GET", "/api/v1/stats/overview", "Dashboard counters", "system", nil, 200, StatsOverviewResponse{}, false},
	{"GET", "/api/v1/system/info", "Host CPU, memory, disk, uptime", "system", nil, 200, SystemInfoResponse{}, false},
	{"GET", "/api/v1/system/fail2ban/status", "fail2ban jails and bans", "fail2ban", nil, 200, Fail2BanStatusResponse{}, false},
	{"GET", "/api/v1/system/fail2ban/logs", "fail2ban log lines", "fail2ban", nil, 200, Fail2BanLogsResponse{}, false},
	{"POST", "/api/v1/system/fail2ban/unban", "Unban an IP", "fail2ban", Fail2BanJailIPRequest{}, 200, StatusMessageResponse{}, false},
	{"POST", "/api/v1/system/fail2ban/ban", "Ban an IP", "fail2ban", Fail2BanBanRequest{}, 200, Fail2BanBanResponse{}, false},
	{"GET", "/api/v1/system/fail2ban/jail/settings", "Jail settings", "fail2ban", nil, 200, Fail2BanJailSettingsResponse{}, false},
	{"PUT", "/api/v1/system/fail2ban/jail/settings", "Update jail settings; 206 when only some were applied", "fail2ban", Fail2BanJailSettingsRequest{}, 200, Fail2BanUpdateSettingsResponse{}, false},
	{"GET", "/api/v1/system/fail2ban/whitelist", "Ignored IPs of a jail", "fail2ban", nil, 200, Fail2BanWhitelistResponse{}, false},
	{"PUT", "/api/v1/system/fail2ban/whitelist", "Add or remove an ignored IP", "fail2ban", Fail2BanWhitelistRequest{}, 200, StatusMessageResponse{}, false},
	{"GET", "/api/v1/system/fail2ban/permanent-bans", "Permanent bans", "fail2ban", nil, 200, PermanentBansResponse{}, false},
	{"DELETE", "/api/v1/system/fail2ban/permanent-bans", "Remove a permanent ban", "fail2ban", Fail2BanIPRequest{}, 200, StatusMessageResponse{}, false},
	{"POST", "/api/v1/system/fail2ban/jail/control", "Start or stop a jail", "fail2ban", Fail2BanJailControlRequest{}, 200, StatusMessageResponse{}, false},
	{"POST", "/api/v1/system/fail2ban/reload", "Reload fail2ban", "fail2ban", nil, 200, Fail2BanReloadResponse{}, false},
	{"GET", "/api/v1/system/fail2ban/ping", "Is fail2ban alive", "fail2ban", nil, 200, Fail2BanPingResponse{}, false},
	{"GET", "/api/v1/system/fail2ban/ban-history", "Ban/unban history, newest first", "fail2ban", nil, 200, Fail2BanHistoryResponse{}, false},
	{"GET", "/api/v1/firewall/host/rules", "Host firewall chains (iptables, or a synthetic view in nft mode)", "firewall-host", nil, 200, FirewallStatus{}, false},
	{"POST", "/api/v1/firewall/host/port/open", "Open a port", "firewall-host", OpenPortRequest{}, 200, OpenPortResponse{}, false},
	{"POST", "/api/v1/firewall/host/port/close", "Close a port", "firewall-host", ClosePortRequest{}, 200, ClosePortResponse{}, false},
	{"POST", "/api/v1/firewall/host/ip/block", "Block an IP or CIDR", "firewall-host", BlockIPRequest{}, 200, IPRuleResponse{}, false},
	{"POST", "/api/v1/firewall/host/ip/allow", "Allow an IP or CIDR", "firewall-host", AllowIPRequest{}, 200, IPRuleResponse{}, false},
	{"POST", "/api/v1/firewall/host/rules/delete", "Delete a rule by chain and line number", "firewall-host", DeleteRuleRequest{}, 200, DeleteRuleResponse{}, false},
	{"GET", "/api/v1/firewall/host/export", "Export the ruleset", "firewall-host", nil, 200, mediaType("text/plain"), false},
	{"POST", "/api/v1/firewall/host/import", "Import iptables-save rules (iptables mode only)", "firewall-host", ImportRulesRequest{}, 200, StatusMessageResponse{}, false},
	{"POST", "/api/v1/firewall/host/reset", "Reset the host firewall to the installer baseline", "firewall-host", nil, 200, StatusMessageResponse{}, false},
	{"GET", "/api/v1/firewall/vpn/rules", "List VPN firewall rules", "firewall-vpn", nil, 200, []models.VPNFirewallRule{}, false},
	{"POST", "/api/v1/firewall/vpn/rules", "Create a VPN firewall rule", "firewall-vpn", VPNFirewallRuleRequest{}, 201, models.VPNFirewallRule{}, false},
	{"PUT", "/api/v1/firewall/vpn/rules/{id}", "Update a VPN firewall rule", "firewall-vpn", VPNFirewallRuleRequest{}, 200, models.VPNFirewallRule{}, false},
	{"DELETE", "/api/v1/firewall/vpn/rules/{id}", "Delete a VPN firewall rule", "firewall-vpn", nil, 204, nil, false},
	{"POST", "/api/v1/firewall/vpn/apply", "Re-apply all VPN firewall rules", "firewall-vpn", nil, 200, StatusMessageResponse{}, false},
	{"GET", "/api/v1/firewall/v2/state", "nftables engine state", "firewall-v2", nil, 200, V2StateResponse{}, false},
	{"GET", "/api/v1/firewall/v2/preview", "Compiled nftables ruleset", "firewall-v2", nil, 200, V2PreviewResponse{}, false},
	{"GET", "/api/v1/firewall/policy-matrix", "Network x network policy matrix from the VPN rules and the firewall mode", "firewall-vpn", nil, 200, firewall.Matrix{}, false},
	{"GET", "/api/v1/firewall/v2/history", "Applied firewall changes, newest first, with the lines each added and removed", "firewall-v2", nil, 200, V2HistoryResponse{}, false},
	{"POST", "/api/v1/firewall/v2/history/{id}/restore", "Restore the firewall state of a history entry (as a confirmable change)", "firewall-v2", nil, 200, V2ChangeResponse{}, false},
	{"GET", "/api/v1/firewall/v2/live", "Rule counters, sources dropped in the last hour and the conntrack table (any mode)", "firewall-v2", nil, 200, V2LiveResponse{}, false},
	{"POST", "/api/v1/firewall/v2/services", "Open a service (pending until confirmed unless ?confirm=false)", "firewall-v2", v2ServiceRequest{}, 200, V2ChangeResponse{}, false},
	{"DELETE", "/api/v1/firewall/v2/services/{id}", "Close a service", "firewall-v2", nil, 200, V2ChangeResponse{}, false},
	{"POST", "/api/v1/firewall/v2/ip-rules", "Add an IP block/allow rule", "firewall-v2", v2IPRuleRequest{}, 200, V2ChangeResponse{}, false},
	{"DELETE", "/api/v1/firewall/v2/ip-rules/{id}", "Remove an IP rule", "firewall-v2", nil, 200, V2ChangeResponse{}, false},
	{"POST", "/api/v1/firewall/v2/forwards", "Add a port forward to a VPN node", "firewall-v2", v2ForwardRequest{}, 200, V2ChangeResponse{}, false},
	{"DELETE", "/api/v1/firewall/v2/forwards/{id}", "Remove a port forward", "firewall-v2", nil, 200, V2ChangeResponse{}, false},
	{"PUT", "/api/v1/firewall/v2/egress/{nodeId}", "Allow a node's full-tunnel egress", "firewall-v2", nil, 200, V2ChangeResponse{}, false},
	{"DELETE", "/api/v1/firewall/v2/egress/{nodeId}", "Revoke a node's full-tunnel egress", "firewall-v2", nil, 200, V2ChangeResponse{}, false},
	{"POST", "/api/v1/firewall/v2/confirm/{id}", "Confirm a pending change", "firewall-v2", nil, 200, StatusResponse{}, false},
}

var (
	timeType = reflect.TypeOf(time.Time{})
	ipType   = reflect.TypeOf(net.IP{})
	// rawJSONType carries the lists `ip -j` prints (hostadmin.NetworkView),
	// passed through as they are: arrays of objects, not bytes.
	rawJSONType = reflect.TypeOf(json.RawMessage{})
	// nodeStatusType is documented as an enum of the NodeStatus constants.
	nodeStatusType = reflect.TypeOf(models.NodeStatus(""))
	pathVar        = regexp.MustCompile(`\{([^}]+)\}`)
)

// schemaGen turns Go types into OpenAPI 3.0 schemas; named structs become
// components referenced by $ref.
type schemaGen struct {
	components map[string]any
	inRequest  bool // request bodies: every field is optional on decode
}

func (g *schemaGen) schema(v any) map[string]any {
	if _, ok := v.(freeform); ok {
		return map[string]any{"type": "object"}
	}
	return g.typeSchema(reflect.TypeOf(v))
}

// notNull undoes nullable for a field that is omitted rather than null.
func notNull(s map[string]any) map[string]any {
	if all, ok := s["allOf"].([]any); ok && s["nullable"] == true {
		return all[0].(map[string]any)
	}
	delete(s, "nullable")
	return s
}

func nullable(s map[string]any) map[string]any {
	if _, isRef := s["$ref"]; isRef { // every component is an object
		return map[string]any{"type": "object", "allOf": []any{s}, "nullable": true}
	}
	s["nullable"] = true
	return s
}

func (g *schemaGen) typeSchema(t reflect.Type) map[string]any {
	switch t {
	case timeType:
		return map[string]any{"type": "string", "format": "date-time"}
	case nodeStatusType:
		return map[string]any{"type": "string", "enum": []any{"pending", "online", "offline", "expired"}}
	case rawJSONType:
		return nullable(map[string]any{"type": "array", "items": map[string]any{"type": "object", "additionalProperties": true}})
	case ipType:
		return map[string]any{"type": "string", "description": "IP address"}
	}
	switch t.Kind() {
	case reflect.Ptr:
		return nullable(g.typeSchema(t.Elem()))
	case reflect.Slice, reflect.Array:
		return nullable(map[string]any{"type": "array", "items": g.typeSchema(t.Elem())}) // a nil slice encodes as null
	case reflect.Map:
		return nullable(map[string]any{"type": "object", "additionalProperties": g.typeSchema(t.Elem())})
	case reflect.String:
		return map[string]any{"type": "string"}
	case reflect.Bool:
		return map[string]any{"type": "boolean"}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return map[string]any{"type": "integer"}
	case reflect.Float32, reflect.Float64:
		return map[string]any{"type": "number"}
	case reflect.Struct:
		name := t.Name()
		if name == "" {
			return g.structSchema(t)
		}
		if g.inRequest && !strings.HasSuffix(name, "Request") {
			// A type shared with responses (models.Network, models.NodeInfo) gets
			// its own request component, so it carries no required list.
			name += "Input"
		}
		if _, ok := g.components[name]; !ok {
			g.components[name] = map[string]any{} // break recursion
			g.components[name] = g.structSchema(t)
		}
		return map[string]any{"$ref": "#/components/schemas/" + name}
	}
	return map[string]any{} // interface{}: any value
}

func (g *schemaGen) structSchema(t reflect.Type) map[string]any {
	props := map[string]any{}
	var required []string
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		name, opts, _ := strings.Cut(f.Tag.Get("json"), ",")
		if name == "-" {
			continue
		}
		if name == "" {
			name = f.Name
		}
		props[name] = g.typeSchema(f.Type)
		if f.Tag.Get("openapi") == "notnull" { // optional, but never null when present
			props[name] = notNull(props[name].(map[string]any))
		}
		if !g.inRequest && !strings.Contains(opts, "omitempty") {
			required = append(required, name)
		}
	}
	s := map[string]any{"type": "object", "properties": props}
	if len(required) > 0 {
		sort.Strings(required)
		s["required"] = required
	}
	return s
}

// openAPIDocument builds the OpenAPI 3.0.3 document from docOps.
func openAPIDocument() map[string]any {
	g := &schemaGen{components: map[string]any{
		"Error": map[string]any{
			"type":     "object",
			"required": []string{"error"},
			"properties": map[string]any{"error": map[string]any{
				"type":     "object",
				"required": []string{"code", "message"},
				"properties": map[string]any{
					"code":    map[string]any{"type": "string", "description": "stable snake_case code, see docs/api.md"},
					"message": map[string]any{"type": "string"},
				},
			}},
		},
	}}
	errorRef := map[string]any{"description": "Error", "content": map[string]any{
		"application/json": map[string]any{"schema": map[string]any{"$ref": "#/components/schemas/Error"}}}}
	paths := map[string]any{}
	for _, op := range docOps {
		item, _ := paths[op.Path].(map[string]any)
		if item == nil {
			item = map[string]any{}
			paths[op.Path] = item
		}
		resp := map[string]any{"description": http.StatusText(op.Status)}
		switch body := op.Response.(type) {
		case nil:
		case mediaType:
			schema := map[string]any{"type": "string"}
			if strings.HasPrefix(string(body), "image/") {
				schema["format"] = "binary"
			}
			resp["content"] = map[string]any{string(body): map[string]any{"schema": schema}}
		default:
			resp["content"] = map[string]any{"application/json": map[string]any{"schema": g.schema(body)}}
		}
		responses := map[string]any{strconv.Itoa(op.Status): resp, "default": errorRef}
		for code, body := range docExtraResponses[op.Method+" "+op.Path] {
			responses[strconv.Itoa(code)] = map[string]any{"description": http.StatusText(code),
				"content": map[string]any{"application/json": map[string]any{"schema": g.schema(body)}}}
		}
		o := map[string]any{
			"summary":     op.Summary,
			"tags":        []string{op.Tag},
			"operationId": strings.ToLower(op.Method) + pathVar.ReplaceAllString(strings.NewReplacer("/api/v1", "", "/", "_", "-", "_", ".", "_").Replace(op.Path), "by_$1"),
			"responses":   responses,
		}
		var params []any
		for _, m := range pathVar.FindAllStringSubmatch(op.Path, -1) {
			params = append(params, map[string]any{"name": m[1], "in": "path", "required": true, "schema": map[string]any{"type": "string"}})
		}
		for _, q := range docQueryParams[op.Method+" "+op.Path] {
			params = append(params, map[string]any{"name": q.Name, "in": "query", "required": false,
				"description": q.Description, "schema": map[string]any{"type": q.Type}})
		}
		if params != nil {
			o["parameters"] = params
		}
		if op.Request != nil {
			o["requestBody"] = map[string]any{"required": true, "content": map[string]any{
				"application/json": map[string]any{"schema": g.requestSchema(op.Request)}}}
		}
		if op.Public {
			o["security"] = []any{}
		}
		if op.Method == "POST" && op.Path == "/api/v1/nodes/{id}/checkin" {
			// A panel session, or the install script's one-time token.
			o["security"] = []any{
				map[string]any{"bearer": []any{}, "apiKey": []any{}},
				map[string]any{"enrollmentToken": []any{}},
			}
		}
		item[strings.ToLower(op.Method)] = o
	}
	return map[string]any{
		"openapi":  "3.0.3",
		"info":     map[string]any{"title": "NovusGate Control Plane API", "version": "0.1.0"},
		"servers":  []any{map[string]any{"url": "/"}},
		"security": []any{map[string]any{"bearer": []any{}, "apiKey": []any{}}},
		"components": map[string]any{
			"schemas": g.components,
			"securitySchemes": map[string]any{
				"bearer": map[string]any{"type": "http", "scheme": "bearer"},
				// Required only when the server sets novusgate_API_KEY; the
				// panel's nginx adds it.
				"apiKey":          map[string]any{"type": "apiKey", "in": "header", "name": "X-API-Key"},
				"enrollmentToken": map[string]any{"type": "apiKey", "in": "header", "name": "X-Enrollment-Token"},
			},
		},
		"paths": paths,
	}
}

// handleOpenAPI serves the document (behind the same auth as the API).
func (s *Server) handleOpenAPI(w http.ResponseWriter, r *http.Request) {
	jsonResponse(w, http.StatusOK, openAPIDocument())
}

// requestSchema documents a request body. Go decodes every field as
// optional (handlers apply defaults), so request components list no
// required fields; only responses follow omitempty.
func (g *schemaGen) requestSchema(v any) map[string]any {
	g.inRequest = true
	defer func() { g.inRequest = false }()
	return g.schema(v)
}
