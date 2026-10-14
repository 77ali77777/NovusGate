package rest

// Fail2BanStatusResponse: error is present only when fail2ban is missing
// or not responding.
type Fail2BanStatusResponse struct {
	Installed bool           `json:"installed"`
	Running   bool           `json:"running"`
	Jails     []Fail2BanJail `json:"jails"`
	Error     string         `json:"error,omitempty"`
}

// Fail2BanJail: counters are present only when the jail status had that
// line; 0 and [] are real values, hence pointers.
type Fail2BanJail struct {
	Name        string    `json:"name"`
	BannedCount *int      `json:"banned_count,omitempty"`
	TotalBanned *int      `json:"total_banned,omitempty"`
	BannedIPs   *[]string `json:"banned_ips,omitempty"`
	FailedCount *int      `json:"failed_count,omitempty"`
	TotalFailed *int      `json:"total_failed,omitempty"`
}

// Fail2BanLogsResponse: error (log missing, tail failed) and count
// (success) are mutually exclusive.
type Fail2BanLogsResponse struct {
	Logs  []Fail2BanLogEntry `json:"logs"`
	Count *int               `json:"count,omitempty"`
	Error string             `json:"error,omitempty"`
}

type Fail2BanLogEntry struct {
	Raw       string `json:"raw"`
	Timestamp string `json:"timestamp"`
	Action    string `json:"action,omitempty"` // ban | unban | found
}

type Fail2BanBanResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
	Type    string `json:"type"` // permanent | temporary
}

// Fail2BanJailSettingsResponse: each setting is present only when reading
// it worked; "" is a real value.
type Fail2BanJailSettingsResponse struct {
	Jail     string  `json:"jail"`
	Bantime  *string `json:"bantime,omitempty"`
	Maxretry *string `json:"maxretry,omitempty"`
	Findtime *string `json:"findtime,omitempty"`
	IgnoreIP *string `json:"ignoreip,omitempty"`
}

// Fail2BanUpdateSettingsResponse: 200 {status: success, updated}; 206
// {status: partial, updated, errors}.
type Fail2BanUpdateSettingsResponse struct {
	Status  string   `json:"status"`
	Updated []string `json:"updated"`
	Errors  []string `json:"errors,omitempty"`
}

type Fail2BanWhitelistResponse struct {
	Jail      string   `json:"jail"`
	Whitelist []string `json:"whitelist"`
}

type PermanentBan struct {
	LineNumber string `json:"line_number"`
	IP         string `json:"ip"`
	Target     string `json:"target"`
	Protocol   string `json:"protocol"`
}

type PermanentBansResponse struct {
	PermanentBans []PermanentBan `json:"permanent_bans"`
	Count         int            `json:"count"`
}

type Fail2BanReloadResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
	Output  string `json:"output"`
}

// Fail2BanPingResponse: error is present only when the ping failed.
type Fail2BanPingResponse struct {
	Alive   bool   `json:"alive"`
	Error   string `json:"error,omitempty"`
	Message string `json:"message"`
}

type Fail2BanHistoryResponse struct {
	History []Fail2BanHistoryEntry `json:"history"`
	Count   int                    `json:"count"`
	Jail    string                 `json:"jail"`
}

type Fail2BanHistoryEntry struct {
	Raw       string `json:"raw"`
	Timestamp string `json:"timestamp"`
	Jail      string `json:"jail"`
	Action    string `json:"action"`
	IP        string `json:"ip,omitempty"`
}
