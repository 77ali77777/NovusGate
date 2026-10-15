// Package hostadmin manages the VPN server itself (P10a): services, kernel
// settings (sysctl), hostname, time zone, package updates and a read-only
// view of the network. Every command runs on the host through a Runner (the
// control plane uses nsenter into the host's namespaces); input is checked
// against allow-lists before it reaches a command line.
package hostadmin

import (
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Runner runs a command on the host, feeding stdin; it returns stdout.
type Runner interface {
	Run(stdin string, name string, args ...string) (string, error)
}

// ErrNotAllowed: the unit, key or value is not on the allow-list.
var ErrNotAllowed = errors.New("not allowed")

// ServiceStatus is one managed service.
type ServiceStatus struct {
	Name  string `json:"name"`
	State string `json:"state"` // systemd ActiveState: active, inactive, failed, ...
}

var (
	wgUnitRe   = regexp.MustCompile(`^wg-quick@(wg[0-9]{1,4})$`)
	fixedUnits = []string{"docker", "fail2ban"}
)

// allowedUnit reports whether a unit may be listed and restarted.
func allowedUnit(name string) bool {
	for _, u := range fixedUnits {
		if name == u {
			return true
		}
	}
	return wgUnitRe.MatchString(name)
}

// Services lists the managed services: docker, fail2ban and every
// wg-quick@ unit systemd knows.
func Services(r Runner) ([]ServiceStatus, error) {
	var out []ServiceStatus
	for _, u := range fixedUnits {
		state, _ := r.Run("", "systemctl", "is-active", u) // non-zero exit for inactive units
		out = append(out, ServiceStatus{Name: u, State: firstField(state, "unknown")})
	}
	list, err := r.Run("", "systemctl", "list-units", "wg-quick@*", "--all", "--no-legend", "--plain")
	if err != nil {
		return nil, fmt.Errorf("list wg-quick units: %w", err)
	}
	for _, line := range strings.Split(list, "\n") {
		f := strings.Fields(line)
		if len(f) < 3 {
			continue
		}
		name := strings.TrimSuffix(f[0], ".service")
		if wgUnitRe.MatchString(name) {
			out = append(out, ServiceStatus{Name: name, State: f[2]})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func firstField(s, fallback string) string {
	if f := strings.Fields(s); len(f) > 0 {
		return f[0]
	}
	return fallback
}

// Restart restarts an allowed service.
func Restart(r Runner, unit string) error {
	if !allowedUnit(unit) {
		return fmt.Errorf("service %q: %w", unit, ErrNotAllowed)
	}
	if _, err := r.Run("", "systemctl", "restart", unit); err != nil {
		return fmt.Errorf("restart %s: %w", unit, err)
	}
	return nil
}

// sysctlRules are the kernel settings the panel may change, with their check.
var sysctlRules = map[string]func(string) bool{
	"net.ipv4.ip_forward":             oneOf("0", "1"),
	"net.ipv4.conf.all.rp_filter":     oneOf("0", "1", "2"),
	"net.netfilter.nf_conntrack_max":  intRange(1024, 16_777_216),
	"net.ipv4.tcp_congestion_control": oneOf("bbr", "cubic"),
	"net.core.default_qdisc":          oneOf("fq", "fq_codel", "pfifo_fast", "cake"),
}

// SysctlKeys lists the settings the panel manages, sorted.
func SysctlKeys() []string {
	keys := make([]string, 0, len(sysctlRules))
	for k := range sysctlRules {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func oneOf(values ...string) func(string) bool {
	return func(v string) bool {
		for _, x := range values {
			if v == x {
				return true
			}
		}
		return false
	}
}

var digitsRe = regexp.MustCompile(`^[0-9]{1,9}$`)

func intRange(min, max int) func(string) bool {
	return func(v string) bool {
		if !digitsRe.MatchString(v) {
			return false
		}
		var n int
		fmt.Sscanf(v, "%d", &n)
		return n >= min && n <= max
	}
}

// ValidateSysctl checks a change: allowed keys with allowed values only.
func ValidateSysctl(values map[string]string) error {
	if len(values) == 0 {
		return fmt.Errorf("no settings given")
	}
	for k, v := range values {
		check, ok := sysctlRules[k]
		if !ok {
			return fmt.Errorf("sysctl %q: %w", k, ErrNotAllowed)
		}
		if !check(v) {
			return fmt.Errorf("sysctl %s = %q: %w", k, v, ErrNotAllowed)
		}
	}
	return nil
}

// ReadSysctl returns the current value of every managed setting; a setting
// the kernel does not have (e.g. conntrack not loaded) is left out.
func ReadSysctl(r Runner) map[string]string {
	out := map[string]string{}
	for _, k := range SysctlKeys() {
		if v, err := r.Run("", "sysctl", "-n", k); err == nil {
			out[k] = strings.TrimSpace(v)
		}
	}
	return out
}

// Host paths of the managed sysctl file and its rollback script.
const (
	SysctlFile           = "/etc/sysctl.d/90-novusgate.conf"
	SysctlRollbackScript = "/var/lib/novusgate/sysctl-rollback.sh"
	sysctlRollbackUnit   = "novusgate-sysctl-rollback"
)

// Sysctl applies kernel settings safely: the old values are restored by a
// systemd timer unless Confirm is called within Timeout (so a setting that
// cuts the server off undoes itself).
type Sysctl struct {
	Runner  Runner
	Timeout time.Duration
}

// Apply writes the managed file with the given settings (merged over the
// ones it already manages), loads it and arms the rollback.
func (s *Sysctl) Apply(values map[string]string) error {
	if err := ValidateSysctl(values); err != nil {
		return err
	}
	// The rollback: the old values of the keys that change, then the old file.
	oldFile, _ := s.Runner.Run("", "cat", SysctlFile) // missing on a first change
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var rb strings.Builder
	rb.WriteString("#!/bin/sh\n# NovusGate: undo the last sysctl change (not confirmed in time).\n")
	for _, k := range keys {
		if old, err := s.Runner.Run("", "sysctl", "-n", k); err == nil {
			rb.WriteString(fmt.Sprintf("sysctl -w %s=%s\n", k, strings.TrimSpace(old)))
		}
	}
	if oldFile == "" {
		rb.WriteString("rm -f " + SysctlFile + "\n")
	} else {
		rb.WriteString("cat > " + SysctlFile + " <<'NOVUSGATE_EOF'\n" + strings.TrimRight(oldFile, "\n") + "\nNOVUSGATE_EOF\n")
	}
	if _, err := s.Runner.Run("", "mkdir", "-p", path.Dir(SysctlRollbackScript)); err != nil {
		return fmt.Errorf("create rollback directory: %w", err)
	}
	if _, err := s.Runner.Run(rb.String(), "tee", SysctlRollbackScript); err != nil {
		return fmt.Errorf("write rollback script: %w", err)
	}

	merged := parseSysctlFile(oldFile)
	for k, v := range values {
		merged[k] = v
	}
	if _, err := s.Runner.Run(renderSysctlFile(merged), "tee", SysctlFile); err != nil {
		return fmt.Errorf("write %s: %w", SysctlFile, err)
	}
	if _, err := s.Runner.Run("", "sysctl", "-p", SysctlFile); err != nil {
		// Undo at once: the kernel took part of it at most.
		if _, rbErr := s.Runner.Run("", "sh", SysctlRollbackScript); rbErr != nil {
			return fmt.Errorf("load %s: %v; the rollback failed too: %w", SysctlFile, err, rbErr)
		}
		return fmt.Errorf("load %s (rolled back): %w", SysctlFile, err)
	}
	s.Runner.Run("", "systemctl", "reset-failed", sysctlRollbackUnit+".service") // a previous run's leftovers
	secs := int(s.Timeout / time.Second)
	if secs < 1 {
		secs = 1
	}
	if _, err := s.Runner.Run("", "systemd-run", "--unit="+sysctlRollbackUnit,
		fmt.Sprintf("--on-active=%ds", secs), "--timer-property=AccuracySec=1s",
		"sh", SysctlRollbackScript); err != nil {
		// No safety net: undo now rather than keep an unguarded change.
		s.Runner.Run("", "sh", SysctlRollbackScript)
		return fmt.Errorf("arm the rollback (change undone): %w", err)
	}
	return nil
}

// Confirm keeps the applied settings: the rollback timer is stopped.
func (s *Sysctl) Confirm() error {
	if _, err := s.Runner.Run("", "systemctl", "stop", sysctlRollbackUnit+".timer"); err != nil && !strings.Contains(err.Error(), "not loaded") {
		return fmt.Errorf("stop the rollback timer: %w", err)
	}
	return nil
}

func parseSysctlFile(text string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if ok {
			if check, known := sysctlRules[k]; known && check(v) {
				out[k] = v
			}
		}
	}
	return out
}

func renderSysctlFile(values map[string]string) string {
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString("# Managed by the NovusGate panel (Server -> Kernel); edits here are overwritten.\n")
	for _, k := range keys {
		b.WriteString(fmt.Sprintf("%s = %s\n", k, values[k]))
	}
	return b.String()
}

var hostnameLabelRe = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)

// ValidHostname checks an RFC 1123 host name (dot-separated labels).
func ValidHostname(h string) error {
	if h == "" || len(h) > 253 {
		return fmt.Errorf("hostname must be 1-253 characters")
	}
	for _, label := range strings.Split(h, ".") {
		if !hostnameLabelRe.MatchString(label) {
			return fmt.Errorf("hostname %q: labels are letters, digits and inner hyphens, at most 63", h)
		}
	}
	return nil
}

var zoneRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_+-]*(/[A-Za-z0-9_+-]+){0,2}$`)

// ValidTimezone checks an IANA time zone name the system knows.
func ValidTimezone(z string) error {
	if !zoneRe.MatchString(z) {
		return fmt.Errorf("time zone %q is not an IANA name", z)
	}
	if _, err := time.LoadLocation(z); err != nil {
		return fmt.Errorf("unknown time zone %q", z)
	}
	return nil
}

// SetHostname changes the host name.
func SetHostname(r Runner, h string) error {
	if err := ValidHostname(h); err != nil {
		return err
	}
	if _, err := r.Run("", "hostnamectl", "set-hostname", h); err != nil {
		return fmt.Errorf("hostnamectl: %w", err)
	}
	return nil
}

// SetTimezone sets the time zone and turns NTP on or off.
func SetTimezone(r Runner, zone string, ntp bool) error {
	if err := ValidTimezone(zone); err != nil {
		return err
	}
	if _, err := r.Run("", "timedatectl", "set-timezone", zone); err != nil {
		return fmt.Errorf("timedatectl set-timezone: %w", err)
	}
	if _, err := r.Run("", "timedatectl", "set-ntp", fmt.Sprint(ntp)); err != nil {
		return fmt.Errorf("timedatectl set-ntp: %w", err)
	}
	return nil
}

// SystemInfo is the host's identity and clock.
type SystemInfo struct {
	Hostname        string `json:"hostname"`
	Timezone        string `json:"timezone"`
	NTP             bool   `json:"ntp"`
	NTPSynchronized bool   `json:"ntp_synchronized"`
	Kernel          string `json:"kernel"`
	OS              string `json:"os"`
}

// System reads the host name, clock settings, kernel and OS release.
func System(r Runner) (SystemInfo, error) {
	var info SystemInfo
	h, err := r.Run("", "hostname")
	if err != nil {
		return info, fmt.Errorf("hostname: %w", err)
	}
	info.Hostname = strings.TrimSpace(h)
	if td, err := r.Run("", "timedatectl", "show"); err == nil {
		kv := keyValues(td)
		info.Timezone, info.NTP, info.NTPSynchronized = kv["Timezone"], kv["NTP"] == "yes", kv["NTPSynchronized"] == "yes"
	}
	if k, err := r.Run("", "uname", "-r"); err == nil {
		info.Kernel = strings.TrimSpace(k)
	}
	if osr, err := r.Run("", "cat", "/etc/os-release"); err == nil {
		info.OS = strings.Trim(keyValues(osr)["PRETTY_NAME"], `"`)
	}
	return info, nil
}

func keyValues(text string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(text, "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok {
			out[k] = v
		}
	}
	return out
}

// Package is an upgradable package.
type Package struct {
	Name     string `json:"name"`
	Version  string `json:"version"`
	From     string `json:"from"`
	Security bool   `json:"security"` // comes from a -security pocket
}

var aptLineRe = regexp.MustCompile(`^([^/\s]+)/(\S+) (\S+) \S+ \[upgradable from: ([^\]]+)\]`)

// Upgradable lists the packages apt would upgrade.
func Upgradable(r Runner) ([]Package, error) {
	out, err := r.Run("", "apt", "list", "--upgradable")
	if err != nil {
		return nil, fmt.Errorf("apt list: %w", err)
	}
	pkgs := []Package{}
	for _, line := range strings.Split(out, "\n") {
		m := aptLineRe.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil {
			continue
		}
		pkgs = append(pkgs, Package{Name: m[1], Version: m[3], From: m[4], Security: strings.Contains(m[2], "-security")})
	}
	return pkgs, nil
}

// NetworkView is what `ip -j` reports, as is.
type NetworkView struct {
	Addresses json.RawMessage `json:"addresses"`
	Routes    json.RawMessage `json:"routes"`
	Links     json.RawMessage `json:"links"`
}

// Network reads the host's addresses, routes and links (read-only).
func Network(r Runner) (NetworkView, error) {
	var v NetworkView
	for _, item := range []struct {
		obj string
		dst *json.RawMessage
	}{{"addr", &v.Addresses}, {"route", &v.Routes}, {"link", &v.Links}} {
		out, err := r.Run("", "ip", "-j", item.obj)
		if err != nil {
			return v, fmt.Errorf("ip -j %s: %w", item.obj, err)
		}
		if !json.Valid([]byte(out)) {
			return v, fmt.Errorf("ip -j %s: not JSON", item.obj)
		}
		*item.dst = json.RawMessage(out)
	}
	return v, nil
}
