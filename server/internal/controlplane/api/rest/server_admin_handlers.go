package rest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/novusgate/novusgate/internal/controlplane/hostadmin"
	"github.com/novusgate/novusgate/internal/netctl/nft"
	"golang.org/x/crypto/bcrypt"
)

// Server administration (P10a): admin only, and every change needs a step-up
// (the password entered again within stepUpTTL).

// stepUpTTL is how long a step-up lasts.
const stepUpTTL = 5 * time.Minute

// sysctlConfirmTimeout is how long a sysctl change waits for Confirm before
// the host undoes it.
const sysctlConfirmTimeout = 90 * time.Second

// StepUpRequest is the password, entered again.
type StepUpRequest struct {
	Password string `json:"password"`
}

// SysctlResponse lists the managed kernel settings and their values.
type SysctlResponse struct {
	Keys   []string          `json:"keys"`
	Values map[string]string `json:"values"`
	// Pending: a change waits for confirm (the host's rollback timer is
	// armed); PendingUntil is when it is undone, when this process knows it.
	Pending      bool       `json:"pending"`
	PendingUntil *time.Time `json:"pending_until"`
}

// SysctlChangeRequest sets kernel settings.
type SysctlChangeRequest struct {
	Values map[string]string `json:"values"`
}

// SysctlChangeResponse: the change is live; confirm within ConfirmWithin
// seconds or the host restores the old values.
type SysctlChangeResponse struct {
	ConfirmWithin int `json:"confirm_within"`
}

// HostnameRequest changes the host name.
type HostnameRequest struct {
	Hostname string `json:"hostname"`
}

// TimezoneRequest sets the time zone and NTP.
type TimezoneRequest struct {
	Timezone string `json:"timezone"`
	NTP      bool   `json:"ntp"`
}

// ConfirmRequest repeats what a dangerous action does ("reboot", "upgrade").
type ConfirmRequest struct {
	Confirm string `json:"confirm"`
}

// ServicesResponse lists the managed services.
type ServicesResponse struct {
	Services []hostadmin.ServiceStatus `json:"services"`
}

// PackagesResponse lists the upgradable packages.
type PackagesResponse struct {
	Packages []hostadmin.Package `json:"packages"`
}

// UpgradeJob is the last package upgrade.
type UpgradeJob struct {
	Running    bool       `json:"running"`
	StartedAt  *time.Time `json:"started_at"`
	FinishedAt *time.Time `json:"finished_at"`
	OK         bool       `json:"ok"`
	Output     string     `json:"output"`
}

// upgradeJobs keeps the last upgrade (one at a time).
type upgradeJobs struct {
	mu  sync.Mutex
	job UpgradeJob
}

var upgrades upgradeJobs

// hostRunner runs host commands; tests replace s.host.
func (s *Server) hostRunner() hostadmin.Runner {
	if s.host != nil {
		return s.host
	}
	return nft.NsenterRunner{}
}

// rebootDelay lets the 202 reach the panel before the host goes down.
var rebootDelay = 2 * time.Second

func (s *Server) registerServerAdminRoutes(api *mux.Router) {
	api.HandleFunc("/auth/step-up", s.handleStepUp).Methods("POST")
	api.HandleFunc("/server/services", s.handleServices).Methods("GET")
	api.HandleFunc("/server/services/{unit}/restart", s.requireStepUp(s.handleRestartService)).Methods("POST")
	api.HandleFunc("/server/sysctl", s.handleGetSysctl).Methods("GET")
	api.HandleFunc("/server/sysctl", s.requireStepUp(s.handleSetSysctl)).Methods("PUT")
	api.HandleFunc("/server/sysctl/confirm", s.requireStepUp(s.handleConfirmSysctl)).Methods("POST")
	api.HandleFunc("/server/system", s.handleSystem).Methods("GET")
	api.HandleFunc("/server/system/hostname", s.requireStepUp(s.handleSetHostname)).Methods("PUT")
	api.HandleFunc("/server/system/timezone", s.requireStepUp(s.handleSetTimezone)).Methods("PUT")
	api.HandleFunc("/server/packages", s.handlePackages).Methods("GET")
	api.HandleFunc("/server/packages/upgrade", s.handleUpgradeStatus).Methods("GET")
	api.HandleFunc("/server/packages/upgrade", s.requireStepUp(s.handleUpgrade)).Methods("POST")
	api.HandleFunc("/server/reboot", s.requireStepUp(s.handleReboot)).Methods("POST")
	api.HandleFunc("/server/network", s.handleNetwork).Methods("GET")
}

// stepUpLimit counts wrong step-up passwords per user (replaced in tests).
var stepUpLimit = newLoginLimiter(5, 15*time.Minute)

// handleStepUp checks the password again and steps the session up.
func (s *Server) handleStepUp(w http.ResponseWriter, r *http.Request) {
	user, hash := sessionFrom(r)
	if user == nil {
		errorWithCode(w, http.StatusUnauthorized, "invalid_token", "invalid token")
		return
	}
	var req StepUpRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		errorWithCode(w, http.StatusBadRequest, "invalid_request_body", "invalid request body")
		return
	}
	// Counted per user: a stolen session must not guess the password. Only
	// password checks count, not malformed bodies.
	key := "user:" + user.Username
	if wait, ok := stepUpLimit.begin(key, authNow()); !ok {
		w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
		errorWithCode(w, http.StatusTooManyRequests, "too_many_attempts", "too many wrong passwords, try again later")
		return
	}
	u, err := s.store.GetUserByUsername(r.Context(), user.Username)
	if err != nil || u == nil || bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(req.Password)) != nil {
		errorWithCode(w, http.StatusBadRequest, "invalid_password", "the password is not correct") // 400: a 401 logs the panel out
		return
	}
	stepUpLimit.succeed(key)
	if err := s.store.ElevateSession(r.Context(), hash, authNow().Add(stepUpTTL)); err != nil {
		slog.Error("step-up not stored", "error", err)
		errorResponse(w, http.StatusInternalServerError, "failed to step up")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// requireStepUp refuses a change unless the session stepped up recently.
func (s *Server) requireStepUp(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, hash := sessionFrom(r)
		until, err := s.store.SessionElevatedUntil(r.Context(), hash)
		if err != nil || !authNow().Before(until) {
			errorWithCode(w, http.StatusForbidden, "step_up_required", "enter your password again to change the server")
			return
		}
		next(w, r)
	}
}

func hostError(w http.ResponseWriter, what string, err error) {
	if errors.Is(err, hostadmin.ErrNotAllowed) {
		errorResponse(w, http.StatusBadRequest, err.Error())
		return
	}
	slog.Error(what+" failed", "error", err)
	// The tool output stays in the log: it names host paths and commands.
	errorResponse(w, http.StatusInternalServerError, what+" failed; see the server log")
}

func decodeAdminRequest(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(v); err != nil {
		errorWithCode(w, http.StatusBadRequest, "invalid_request_body", "invalid request body")
		return false
	}
	return true
}

func (s *Server) handleServices(w http.ResponseWriter, r *http.Request) {
	list, err := hostadmin.Services(s.hostRunner())
	if err != nil {
		hostError(w, "listing services", err)
		return
	}
	jsonResponse(w, http.StatusOK, ServicesResponse{Services: list})
}

func (s *Server) handleRestartService(w http.ResponseWriter, r *http.Request) {
	unit := mux.Vars(r)["unit"]
	if err := hostadmin.Restart(s.hostRunner(), unit); err != nil {
		hostError(w, "restart", err)
		return
	}
	s.restorePeersAfterUnitRestart(r.Context(), unit)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleGetSysctl(w http.ResponseWriter, r *http.Request) {
	resp := SysctlResponse{Keys: hostadmin.SysctlKeys(), Values: hostadmin.ReadSysctl(s.hostRunner())}
	resp.Pending = hostadmin.SysctlTimerWaiting(s.hostRunner())
	if until, ok := hostadmin.SysctlPendingUntil(); ok && resp.Pending {
		resp.PendingUntil = &until
	}
	jsonResponse(w, http.StatusOK, resp)
}

func (s *Server) handleSetSysctl(w http.ResponseWriter, r *http.Request) {
	var req SysctlChangeRequest
	if !decodeAdminRequest(w, r, &req) {
		return
	}
	if err := hostadmin.ValidateSysctl(req.Values); err != nil {
		errorResponse(w, http.StatusBadRequest, err.Error())
		return
	}
	sc := &hostadmin.Sysctl{Runner: s.hostRunner(), Timeout: sysctlConfirmTimeout}
	if err := sc.Apply(req.Values); err != nil {
		if errors.Is(err, hostadmin.ErrSysctlPending) {
			errorWithCode(w, http.StatusConflict, "sysctl_pending", "the last change waits for confirmation; keep it or let it undo first")
			return
		}
		hostError(w, "sysctl change", err)
		return
	}
	jsonResponse(w, http.StatusOK, SysctlChangeResponse{ConfirmWithin: int(sysctlConfirmTimeout / time.Second)})
}

func (s *Server) handleConfirmSysctl(w http.ResponseWriter, r *http.Request) {
	sc := &hostadmin.Sysctl{Runner: s.hostRunner()}
	if err := sc.Confirm(); err != nil {
		if errors.Is(err, hostadmin.ErrSysctlNotPending) {
			errorWithCode(w, http.StatusConflict, "sysctl_not_pending", "no change waits for confirmation; it may have been undone already")
			return
		}
		hostError(w, "sysctl confirm", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleSystem(w http.ResponseWriter, r *http.Request) {
	info, err := hostadmin.System(s.hostRunner())
	if err != nil {
		hostError(w, "reading the system", err)
		return
	}
	jsonResponse(w, http.StatusOK, info)
}

func (s *Server) handleSetHostname(w http.ResponseWriter, r *http.Request) {
	var req HostnameRequest
	if !decodeAdminRequest(w, r, &req) {
		return
	}
	if err := hostadmin.ValidHostname(req.Hostname); err != nil {
		errorResponse(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := hostadmin.SetHostname(s.hostRunner(), req.Hostname); err != nil {
		hostError(w, "hostname change", err)
		return
	}
	s.handleSystem(w, r)
}

func (s *Server) handleSetTimezone(w http.ResponseWriter, r *http.Request) {
	var req TimezoneRequest
	if !decodeAdminRequest(w, r, &req) {
		return
	}
	if err := hostadmin.ValidTimezone(req.Timezone); err != nil {
		errorResponse(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := hostadmin.SetTimezone(s.hostRunner(), req.Timezone, req.NTP); err != nil {
		hostError(w, "time zone change", err)
		return
	}
	s.handleSystem(w, r)
}

func (s *Server) handlePackages(w http.ResponseWriter, r *http.Request) {
	pkgs, err := hostadmin.Upgradable(s.hostRunner())
	if err != nil {
		hostError(w, "listing packages", err)
		return
	}
	jsonResponse(w, http.StatusOK, PackagesResponse{Packages: pkgs})
}

func (s *Server) handleUpgradeStatus(w http.ResponseWriter, r *http.Request) {
	upgrades.mu.Lock()
	job := upgrades.job
	upgrades.mu.Unlock()
	jsonResponse(w, http.StatusOK, job)
}

// handleUpgrade starts `apt-get upgrade` (two steps: the panel asks first,
// the request repeats "upgrade"); its output is kept for GET.
func (s *Server) handleUpgrade(w http.ResponseWriter, r *http.Request) {
	var req ConfirmRequest
	if !decodeAdminRequest(w, r, &req) {
		return
	}
	if req.Confirm != "upgrade" {
		errorResponse(w, http.StatusBadRequest, `confirm must be "upgrade"`)
		return
	}
	upgrades.mu.Lock()
	if upgrades.job.Running {
		upgrades.mu.Unlock()
		errorWithCode(w, http.StatusConflict, "upgrade_running", "an upgrade is running")
		return
	}
	now := time.Now()
	upgrades.job = UpgradeJob{Running: true, StartedAt: &now}
	upgrades.mu.Unlock()
	runner := s.hostRunner()
	go func() {
		var out bytes.Buffer
		// apt runs in its own transient host unit, not in this container's
		// cgroup: a docker restart during the upgrade cannot kill dpkg with
		// the container, and RuntimeMaxSec stops an apt that hangs.
		unit := func(name, max string, args ...string) []string {
			return append([]string{"--unit=" + name, "--wait", "--pipe", "--collect", "--quiet", "-p", "RuntimeMaxSec=" + max}, args...)
		}
		u, err := runner.Run("", "systemd-run", unit("novusgate-apt-update", "1800", "apt-get", "update")...)
		out.WriteString(u)
		if err == nil {
			var o string
			o, err = runner.Run("", "systemd-run", unit("novusgate-apt-upgrade", "3600",
				"--setenv=DEBIAN_FRONTEND=noninteractive", "apt-get", "-y",
				"-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold", "upgrade")...)
			out.WriteString(o)
		}
		if err != nil {
			out.WriteString(fmt.Sprintf("\nerror: %v\n", err))
		}
		done := time.Now()
		upgrades.mu.Lock()
		upgrades.job = UpgradeJob{Running: false, StartedAt: &now, FinishedAt: &done, OK: err == nil, Output: out.String()}
		upgrades.mu.Unlock()
	}()
	w.WriteHeader(http.StatusAccepted)
}

// handleReboot reboots the host (two steps: the request repeats "reboot").
func (s *Server) handleReboot(w http.ResponseWriter, r *http.Request) {
	var req ConfirmRequest
	if !decodeAdminRequest(w, r, &req) {
		return
	}
	if req.Confirm != "reboot" {
		errorResponse(w, http.StatusBadRequest, `confirm must be "reboot"`)
		return
	}
	upgrades.mu.Lock()
	running := upgrades.job.Running
	upgrades.mu.Unlock()
	if running {
		errorWithCode(w, http.StatusConflict, "upgrade_running", "an upgrade is running; reboot when it has finished")
		return
	}
	runner := s.hostRunner()
	time.AfterFunc(rebootDelay, func() {
		if _, err := runner.Run("", "systemctl", "reboot"); err != nil {
			slog.Error("reboot failed", "error", err)
		}
	})
	w.WriteHeader(http.StatusAccepted)
}

func (s *Server) handleNetwork(w http.ResponseWriter, r *http.Request) {
	v, err := hostadmin.Network(s.hostRunner())
	if err != nil {
		hostError(w, "reading the network", err)
		return
	}
	jsonResponse(w, http.StatusOK, v)
}
