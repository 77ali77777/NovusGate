// Package logging builds the control plane's structured logger.
package logging

import (
	"fmt"
	"io"
	"log/slog"
	"strings"
)

// New returns a logger writing JSON (format "" or "json") or logfmt-style
// text ("text") at level debug, info (default), warn or error.
func New(w io.Writer, format, level string) (*slog.Logger, error) {
	var lvl slog.Level
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "", "info":
		lvl = slog.LevelInfo
	case "debug":
		lvl = slog.LevelDebug
	case "warn", "warning":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		return nil, fmt.Errorf("unknown LOG_LEVEL %q (use debug, info, warn or error)", level)
	}
	opts := &slog.HandlerOptions{Level: lvl}
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", "json":
		return slog.New(slog.NewJSONHandler(w, opts)), nil
	case "text":
		return slog.New(slog.NewTextHandler(w, opts)), nil
	}
	return nil, fmt.Errorf("unknown LOG_FORMAT %q (use json or text)", format)
}
