package nft

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// RuleCounter is one rule of table inet novusgate with a counter. Rule is
// the rule as nft lists it, without the counter, comment and handle.
type RuleCounter struct {
	Chain   string `json:"chain"`
	Rule    string `json:"rule"`
	Comment string `json:"comment,omitempty"`
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
}

// DroppedSource is an address the input policy dropped recently.
type DroppedSource struct {
	Address    string `json:"address"`
	SecondsAgo int    `json:"seconds_ago"` // since its last dropped packet
}

var (
	chainLineRe = regexp.MustCompile(`^\s*chain (\S+) \{`)
	counterRe   = regexp.MustCompile(`\bcounter packets (\d+) bytes (\d+) ?`)
	commentRe   = regexp.MustCompile(`\s*\bcomment "((?:[^"\\]|\\.)*)"`)
	handleRe    = regexp.MustCompile(`\s*# handle \d+\s*$`)
)

// ParseCounters reads `nft -a list table inet novusgate` and returns the
// rules that carry a counter, in listing order.
func ParseCounters(text string) []RuleCounter {
	var out []RuleCounter
	chain := ""
	for _, line := range strings.Split(text, "\n") {
		if m := chainLineRe.FindStringSubmatch(line); m != nil {
			chain = m[1]
			continue
		}
		m := counterRe.FindStringSubmatch(line)
		if m == nil || chain == "" {
			continue
		}
		c := RuleCounter{Chain: chain}
		c.Packets, _ = strconv.ParseUint(m[1], 10, 64)
		c.Bytes, _ = strconv.ParseUint(m[2], 10, 64)
		rule := handleRe.ReplaceAllString(line, "")
		if cm := commentRe.FindStringSubmatch(rule); cm != nil {
			c.Comment = cm[1]
			rule = commentRe.ReplaceAllString(rule, "")
		}
		c.Rule = strings.Join(strings.Fields(counterRe.ReplaceAllString(rule, "")), " ")
		out = append(out, c)
	}
	return out
}

// ParseDropped reads `nft -j list table inet novusgate` and returns the
// elements of dropped_v4 and dropped_v6, IPv4 first.
func ParseDropped(js []byte) ([]DroppedSource, error) {
	var doc struct {
		Nftables []struct {
			Set *struct {
				Name    string            `json:"name"`
				Timeout int               `json:"timeout"`
				Elem    []json.RawMessage `json:"elem"`
			} `json:"set"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(js, &doc); err != nil {
		return nil, fmt.Errorf("parse nft JSON: %w", err)
	}
	var v4, v6 []DroppedSource
	for _, item := range doc.Nftables {
		set := item.Set
		if set == nil || (set.Name != "dropped_v4" && set.Name != "dropped_v6") {
			continue
		}
		for _, raw := range set.Elem {
			d, ok := droppedElem(raw, set.Timeout)
			if !ok {
				continue
			}
			if set.Name == "dropped_v4" {
				v4 = append(v4, d)
			} else {
				v6 = append(v6, d)
			}
		}
	}
	return append(v4, v6...), nil
}

// droppedElem reads {"elem": {"val": "1.2.3.4", "expires": 3599}}; an element
// without a timeout is a bare string.
func droppedElem(raw json.RawMessage, timeout int) (DroppedSource, bool) {
	var e struct {
		Elem struct {
			Val     string `json:"val"`
			Expires int    `json:"expires"`
		} `json:"elem"`
	}
	if json.Unmarshal(raw, &e) == nil && e.Elem.Val != "" {
		ago := timeout - e.Elem.Expires
		if ago < 0 {
			ago = 0
		}
		return DroppedSource{Address: e.Elem.Val, SecondsAgo: ago}, true
	}
	var s string
	if json.Unmarshal(raw, &s) == nil && s != "" {
		return DroppedSource{Address: s}, true
	}
	return DroppedSource{}, false
}
