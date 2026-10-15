package firewall

import (
	"fmt"
	"sort"
	"strings"
)

// Describe renders st as sorted, human-readable lines, one per entry; the
// History view diffs these lines. nodeNames maps node IDs to names (a
// missing node is shown by its ID).
func Describe(st State, nodeNames map[string]string) []string {
	var out []string
	for _, s := range st.Services {
		ports := fmt.Sprint(s.PortFrom)
		if s.PortTo != s.PortFrom {
			ports = fmt.Sprintf("%d-%d", s.PortFrom, s.PortTo)
		}
		from := "any"
		if len(s.Sources) > 0 {
			from = strings.Join(s.Sources, ", ")
		}
		line := fmt.Sprintf("service %s %s from %s", s.Protocol, ports, from)
		if s.Interface != "" {
			line += " on " + s.Interface
		}
		out = append(out, withComment(line, s.Comment))
	}
	for _, r := range st.IPRules {
		line := r.Action + " " + r.Prefix
		if r.Protocol != "" {
			line += " " + r.Protocol
		}
		if r.Ports != "" {
			line += " " + r.Ports
		}
		if r.ExpiresAt != nil {
			line += " until " + r.ExpiresAt.UTC().Format("2006-01-02 15:04") + " UTC"
		}
		if r.Origin != "" && r.Origin != "panel" {
			line += " [" + r.Origin + "]"
		}
		out = append(out, withComment(line, r.Comment))
	}
	for _, f := range st.Forwards {
		out = append(out, withComment(fmt.Sprintf("forward %s %d -> %s:%d", f.Protocol, f.PublicPort, f.TargetIP, f.TargetPort), f.Comment))
	}
	for _, id := range st.EgressNodeIDs {
		name := nodeNames[id]
		if name == "" {
			name = id
		}
		out = append(out, "full tunnel: "+name)
	}
	sort.Strings(out)
	return out
}

func withComment(line, comment string) string {
	if comment == "" {
		return line
	}
	return line + " (" + comment + ")"
}

// DiffLines returns the lines of cur missing from prev (added) and the
// lines of prev missing from cur (removed), counting duplicates.
func DiffLines(prev, cur []string) (added, removed []string) {
	count := map[string]int{}
	for _, l := range prev {
		count[l]++
	}
	added, removed = []string{}, []string{}
	for _, l := range cur {
		if count[l] > 0 {
			count[l]--
			continue
		}
		added = append(added, l)
	}
	for _, l := range prev {
		if count[l] > 0 {
			count[l]--
			removed = append(removed, l)
		}
	}
	return added, removed
}
