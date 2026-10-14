package rest

import (
	"net"
	"net/http"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

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

// docOps lists every registered route; TestEveryRouteIsDocumented keeps it complete.
var docOps = []docOp{
	{"GET", "/health", "Liveness and component checks (always 200)", "meta", nil, 200, freeform{}, true},
	{"GET", "/api/v1/openapi.json", "This document", "meta", nil, 200, freeform{}, false},
	{"POST", "/api/v1/auth/login", "Log in (body: username, password)", "auth", freeform{}, 200, freeform{}, true},
	{"PUT", "/api/v1/auth/password", "Change a password (body: username, oldPassword, newPassword)", "auth", freeform{}, 200, freeform{}, false},
	{"GET", "/api/v1/users", "List users", "users", nil, 200, []models.User{}, false},
	{"POST", "/api/v1/users", "Create a user (body: username, password)", "users", freeform{}, 201, models.User{}, false},
	{"DELETE", "/api/v1/users/{id}", "Delete a user", "users", nil, 204, nil, false},
	{"GET", "/api/v1/networks", "List networks", "networks", nil, 200, []models.Network{}, false},
	{"POST", "/api/v1/networks", "Create a network (body: name, cidr)", "networks", freeform{}, 201, models.Network{}, false},
	{"GET", "/api/v1/networks/{id}", "Get a network", "networks", nil, 200, models.Network{}, false},
	{"DELETE", "/api/v1/networks/{id}", "Delete a network (not wg0)", "networks", nil, 204, nil, false},
	{"GET", "/api/v1/networks/{networkId}/nodes", "List a network's nodes", "nodes", nil, 200, []models.Node{}, false},
	{"POST", "/api/v1/networks/{networkId}/servers", "Create a node with its WireGuard config (body: name, labels, expires_at)", "nodes", freeform{}, 201, freeform{}, false},
	{"POST", "/api/v1/networks/{networkId}/sync", "Re-add missing peers of active nodes", "networks", nil, 200, freeform{}, false},
	{"GET", "/api/v1/nodes/{id}", "Get a node", "nodes", nil, 200, models.Node{}, false},
	{"PUT", "/api/v1/nodes/{id}", "Update a node (body: name, expires_at, status, node_info)", "nodes", freeform{}, 200, models.Node{}, false},
	{"PATCH", "/api/v1/nodes/{id}", "Update a node (same as PUT)", "nodes", freeform{}, 200, models.Node{}, false},
	{"DELETE", "/api/v1/nodes/{id}", "Delete a node", "nodes", nil, 200, freeform{}, false},
	{"POST", "/api/v1/nodes/{id}/checkin", "Report node information (body: node_info)", "nodes", freeform{}, 200, models.Node{}, false},
	{"GET", "/api/v1/nodes/{id}/config", "Download the client WireGuard config", "nodes", nil, 200, mediaType("text/plain"), false},
	{"GET", "/api/v1/nodes/{id}/qrcode", "Client config as a QR code", "nodes", nil, 200, mediaType("image/png"), false},
	{"GET", "/api/v1/nodes/{id}/install.sh", "Linux install script for the node", "nodes", nil, 200, mediaType("text/x-shellscript"), false},
	{"GET", "/api/v1/debug/wireguard/{networkId}", "Compare DB nodes with live peers", "networks", nil, 200, freeform{}, false},
	{"GET", "/api/v1/stats/overview", "Dashboard counters", "system", nil, 200, freeform{}, false},
	{"GET", "/api/v1/system/info", "Host CPU, memory, disk, uptime", "system", nil, 200, freeform{}, false},
	{"GET", "/api/v1/system/fail2ban/status", "fail2ban jails and bans", "fail2ban", nil, 200, freeform{}, false},
	{"GET", "/api/v1/system/fail2ban/logs", "fail2ban log lines", "fail2ban", nil, 200, freeform{}, false},
	{"POST", "/api/v1/system/fail2ban/unban", "Unban an IP (body: jail, ip)", "fail2ban", freeform{}, 200, freeform{}, false},
	{"POST", "/api/v1/system/fail2ban/ban", "Ban an IP (body: jail, ip, permanent)", "fail2ban", freeform{}, 200, freeform{}, false},
	{"GET", "/api/v1/system/fail2ban/jail/settings", "Jail settings", "fail2ban", nil, 200, freeform{}, false},
	{"PUT", "/api/v1/system/fail2ban/jail/settings", "Update jail settings (206 when partly applied)", "fail2ban", freeform{}, 200, freeform{}, false},
	{"GET", "/api/v1/system/fail2ban/whitelist", "Ignored IPs of a jail", "fail2ban", nil, 200, freeform{}, false},
	{"PUT", "/api/v1/system/fail2ban/whitelist", "Add or remove an ignored IP (body: jail, action, ip)", "fail2ban", freeform{}, 200, freeform{}, false},
	{"GET", "/api/v1/system/fail2ban/permanent-bans", "Permanent bans", "fail2ban", nil, 200, freeform{}, false},
	{"DELETE", "/api/v1/system/fail2ban/permanent-bans", "Remove a permanent ban (body: ip)", "fail2ban", freeform{}, 200, freeform{}, false},
	{"POST", "/api/v1/system/fail2ban/jail/control", "Start or stop a jail (body: jail, action)", "fail2ban", freeform{}, 200, freeform{}, false},
	{"POST", "/api/v1/system/fail2ban/reload", "Reload fail2ban", "fail2ban", nil, 200, freeform{}, false},
	{"GET", "/api/v1/system/fail2ban/ping", "Is fail2ban alive", "fail2ban", nil, 200, freeform{}, false},
	{"GET", "/api/v1/system/fail2ban/ban-history", "Ban/unban history, newest first", "fail2ban", nil, 200, freeform{}, false},
	{"GET", "/api/v1/firewall/host/rules", "Host firewall chains (iptables, or a synthetic view in nft mode)", "firewall-host", nil, 200, FirewallStatus{}, false},
	{"POST", "/api/v1/firewall/host/port/open", "Open a port", "firewall-host", OpenPortRequest{}, 200, freeform{}, false},
	{"POST", "/api/v1/firewall/host/port/close", "Close a port", "firewall-host", ClosePortRequest{}, 200, freeform{}, false},
	{"POST", "/api/v1/firewall/host/ip/block", "Block an IP or CIDR", "firewall-host", BlockIPRequest{}, 200, freeform{}, false},
	{"POST", "/api/v1/firewall/host/ip/allow", "Allow an IP or CIDR", "firewall-host", AllowIPRequest{}, 200, freeform{}, false},
	{"POST", "/api/v1/firewall/host/rules/delete", "Delete a rule by chain and line number", "firewall-host", DeleteRuleRequest{}, 200, freeform{}, false},
	{"GET", "/api/v1/firewall/host/export", "Export the ruleset", "firewall-host", nil, 200, mediaType("text/plain"), false},
	{"POST", "/api/v1/firewall/host/import", "Import iptables-save rules (iptables mode only)", "firewall-host", ImportRulesRequest{}, 200, freeform{}, false},
	{"POST", "/api/v1/firewall/host/reset", "Reset the host firewall to the installer baseline", "firewall-host", nil, 200, freeform{}, false},
	{"GET", "/api/v1/firewall/vpn/rules", "List VPN firewall rules", "firewall-vpn", nil, 200, []models.VPNFirewallRule{}, false},
	{"POST", "/api/v1/firewall/vpn/rules", "Create a VPN firewall rule", "firewall-vpn", VPNFirewallRuleRequest{}, 201, models.VPNFirewallRule{}, false},
	{"PUT", "/api/v1/firewall/vpn/rules/{id}", "Update a VPN firewall rule", "firewall-vpn", VPNFirewallRuleRequest{}, 200, models.VPNFirewallRule{}, false},
	{"DELETE", "/api/v1/firewall/vpn/rules/{id}", "Delete a VPN firewall rule", "firewall-vpn", nil, 204, nil, false},
	{"POST", "/api/v1/firewall/vpn/apply", "Re-apply all VPN firewall rules", "firewall-vpn", nil, 200, freeform{}, false},
	{"GET", "/api/v1/firewall/v2/state", "nftables engine state", "firewall-v2", nil, 200, freeform{}, false},
	{"GET", "/api/v1/firewall/v2/preview", "Compiled nftables ruleset", "firewall-v2", nil, 200, freeform{}, false},
	{"POST", "/api/v1/firewall/v2/services", "Open a service (pending until confirmed unless ?confirm=false)", "firewall-v2", v2ServiceRequest{}, 200, freeform{}, false},
	{"DELETE", "/api/v1/firewall/v2/services/{id}", "Close a service", "firewall-v2", nil, 200, freeform{}, false},
	{"POST", "/api/v1/firewall/v2/ip-rules", "Add an IP block/allow rule", "firewall-v2", v2IPRuleRequest{}, 200, freeform{}, false},
	{"DELETE", "/api/v1/firewall/v2/ip-rules/{id}", "Remove an IP rule", "firewall-v2", nil, 200, freeform{}, false},
	{"POST", "/api/v1/firewall/v2/forwards", "Add a port forward to a VPN node", "firewall-v2", v2ForwardRequest{}, 200, freeform{}, false},
	{"DELETE", "/api/v1/firewall/v2/forwards/{id}", "Remove a port forward", "firewall-v2", nil, 200, freeform{}, false},
	{"PUT", "/api/v1/firewall/v2/egress/{nodeId}", "Allow a node's full-tunnel egress", "firewall-v2", nil, 200, freeform{}, false},
	{"DELETE", "/api/v1/firewall/v2/egress/{nodeId}", "Revoke a node's full-tunnel egress", "firewall-v2", nil, 200, freeform{}, false},
	{"POST", "/api/v1/firewall/v2/confirm/{id}", "Confirm a pending change", "firewall-v2", nil, 200, freeform{}, false},
}

var (
	timeType = reflect.TypeOf(time.Time{})
	ipType   = reflect.TypeOf(net.IP{})
	pathVar  = regexp.MustCompile(`\{([^}]+)\}`)
)

// schemaGen turns Go types into OpenAPI 3.0 schemas; named structs become
// components referenced by $ref.
type schemaGen struct{ components map[string]any }

func (g *schemaGen) schema(v any) map[string]any {
	if _, ok := v.(freeform); ok {
		return map[string]any{"type": "object"}
	}
	return g.typeSchema(reflect.TypeOf(v))
}

func nullable(s map[string]any) map[string]any {
	if _, isRef := s["$ref"]; isRef {
		return map[string]any{"allOf": []any{s}, "nullable": true}
	}
	s["nullable"] = true
	return s
}

func (g *schemaGen) typeSchema(t reflect.Type) map[string]any {
	switch t {
	case timeType:
		return map[string]any{"type": "string", "format": "date-time"}
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
		if !strings.Contains(opts, "omitempty") {
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
			resp["content"] = map[string]any{string(body): map[string]any{"schema": map[string]any{"type": "string"}}}
		default:
			resp["content"] = map[string]any{"application/json": map[string]any{"schema": g.schema(body)}}
		}
		o := map[string]any{
			"summary":     op.Summary,
			"tags":        []string{op.Tag},
			"operationId": strings.ToLower(op.Method) + pathVar.ReplaceAllString(strings.NewReplacer("/api/v1", "", "/", "_", "-", "_", ".", "_").Replace(op.Path), "by_$1"),
			"responses":   map[string]any{strconv.Itoa(op.Status): resp, "default": errorRef},
		}
		var params []any
		for _, m := range pathVar.FindAllStringSubmatch(op.Path, -1) {
			params = append(params, map[string]any{"name": m[1], "in": "path", "required": true, "schema": map[string]any{"type": "string"}})
		}
		if params != nil {
			o["parameters"] = params
		}
		if op.Request != nil {
			o["requestBody"] = map[string]any{"required": true, "content": map[string]any{
				"application/json": map[string]any{"schema": g.schema(op.Request)}}}
		}
		if op.Public {
			o["security"] = []any{}
		}
		item[strings.ToLower(op.Method)] = o
	}
	return map[string]any{
		"openapi":  "3.0.3",
		"info":     map[string]any{"title": "NovusGate Control Plane API", "version": "0.1.0"},
		"servers":  []any{map[string]any{"url": "/"}},
		"security": []any{map[string]any{"bearer": []any{}}},
		"components": map[string]any{
			"schemas":         g.components,
			"securitySchemes": map[string]any{"bearer": map[string]any{"type": "http", "scheme": "bearer"}},
		},
		"paths": paths,
	}
}

// handleOpenAPI serves the document (behind the same auth as the API).
func (s *Server) handleOpenAPI(w http.ResponseWriter, r *http.Request) {
	jsonResponse(w, http.StatusOK, openAPIDocument())
}
