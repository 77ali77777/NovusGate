package logging

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestNewJSONIsTheDefault(t *testing.T) {
	var buf bytes.Buffer
	l, err := New(&buf, "", "")
	if err != nil {
		t.Fatal(err)
	}
	l.Info("iptables INPUT handed over to nftables (2 rules removed)", "k", 1)
	l.Debug("hidden at info level")
	var line map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &line); err != nil {
		t.Fatalf("default output must be one JSON line: %v\n%s", err, buf.String())
	}
	if line["msg"] != "iptables INPUT handed over to nftables (2 rules removed)" || line["level"] != "INFO" || line["k"] != float64(1) {
		t.Fatalf("line = %v", line)
	}
	if strings.Contains(buf.String(), "hidden") {
		t.Fatal("debug must be filtered at the default info level")
	}
}

func TestNewTextAndLevels(t *testing.T) {
	var buf bytes.Buffer
	l, err := New(&buf, "TEXT", "warn")
	if err != nil {
		t.Fatal(err)
	}
	l.Info("dropped")
	l.Warn("kept")
	out := buf.String()
	if strings.Contains(out, "dropped") || !strings.Contains(out, "level=WARN msg=kept") {
		t.Fatalf("text/warn output = %q", out)
	}
	if _, err := New(&buf, "json", "debug"); err != nil {
		t.Fatal(err)
	}
}

func TestNewRejectsUnknownValues(t *testing.T) {
	var buf bytes.Buffer
	if _, err := New(&buf, "xml", "info"); err == nil {
		t.Error("unknown LOG_FORMAT must be an error")
	}
	if _, err := New(&buf, "json", "verbose"); err == nil {
		t.Error("unknown LOG_LEVEL must be an error")
	}
}
