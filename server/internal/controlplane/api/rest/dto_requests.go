package rest

import (
	"time"

	"github.com/novusgate/novusgate/internal/shared/models"
)

// Request DTOs. Field names, JSON tags and pointer-ness are exactly the
// anonymous structs the handlers decoded before, so request bodies decode
// the same way.

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type UpdatePasswordRequest struct {
	Username    string `json:"username"`
	OldPassword string `json:"oldPassword"`
	NewPassword string `json:"newPassword"`
}

type CreateUserRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Role     string `json:"role,omitempty"` // admin (default), operator or viewer
}

type UpdateNodeRequest struct {
	Name      *string          `json:"name"`
	ExpiresAt *string          `json:"expires_at"` // RFC 3339, "" removes the expiry
	Status    *string          `json:"status"`
	NodeInfo  *models.NodeInfo `json:"node_info"`
}

type NodeCheckInRequest struct {
	NodeInfo *models.NodeInfo  `json:"node_info"`
	Labels   map[string]string `json:"labels"`
}

type CreateServerRequest struct {
	Name      string            `json:"name"`
	Labels    map[string]string `json:"labels"`
	ExpiresAt *time.Time        `json:"expires_at,omitempty"`
}

type Fail2BanJailIPRequest struct {
	Jail string `json:"jail"`
	IP   string `json:"ip"`
}

type Fail2BanBanRequest struct {
	Jail      string `json:"jail"`
	IP        string `json:"ip"`
	Permanent bool   `json:"permanent"` // true: block in the host firewall instead of the jail
}

type Fail2BanJailSettingsRequest struct {
	Jail     string `json:"jail"`
	Bantime  string `json:"bantime"` // seconds, "-1" bans permanently
	Maxretry string `json:"maxretry"`
	Findtime string `json:"findtime"` // seconds
}

type Fail2BanWhitelistRequest struct {
	Jail   string `json:"jail"`
	Action string `json:"action"` // add | remove
	IP     string `json:"ip"`
}

type Fail2BanIPRequest struct {
	IP string `json:"ip"`
}

type Fail2BanJailControlRequest struct {
	Jail   string `json:"jail"`
	Action string `json:"action"` // start | stop
}
