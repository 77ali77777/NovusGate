package rest

import (
	"fmt"
	"log/slog"
	"net/http"
	"runtime/debug"
	"time"
)

// statusRecorder captures the response status and size for the request log.
type statusRecorder struct {
	http.ResponseWriter
	status, bytes int
}

func (r *statusRecorder) WriteHeader(code int) {
	if r.status == 0 {
		r.status = code
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	n, err := r.ResponseWriter.Write(b)
	r.bytes += n
	return n, err
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (r *statusRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

// LoggingMiddleware writes one structured line per request. Query strings,
// headers and bodies are never logged: they carry tokens and passwords.
func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w}
		next.ServeHTTP(rec, r)
		if rec.status == 0 {
			rec.status = http.StatusOK
		}
		level := slog.LevelInfo
		switch {
		case rec.status >= 500:
			level = slog.LevelError
		case r.URL.Path == "/health":
			level = slog.LevelDebug // polled; keep it out of info logs
		}
		slog.Log(r.Context(), level, "http request",
			"method", r.Method, "path", r.URL.Path, "status", rec.status, "bytes", rec.bytes,
			"duration_ms", time.Since(start).Milliseconds(), "remote", r.RemoteAddr)
	})
}

// RecoverMiddleware turns a handler panic into a 500 JSON error and logs it
// with its stack. http.ErrAbortHandler is re-panicked: net/http uses it to
// abort a response on purpose.
func RecoverMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tw := &headerTracker{ResponseWriter: w}
		defer func() {
			v := recover()
			if v == nil {
				return
			}
			if v == http.ErrAbortHandler {
				panic(v)
			}
			slog.Error("panic in handler", "method", r.Method, "path", r.URL.Path,
				"panic", fmt.Sprint(v), "stack", string(debug.Stack()))
			if tw.wrote { // the response has started; an error body would corrupt it
				return
			}
			errorResponse(w, http.StatusInternalServerError, "internal server error")
		}()
		next.ServeHTTP(tw, r)
	})
}

// headerTracker records whether the response has started.
type headerTracker struct {
	http.ResponseWriter
	wrote bool
}

func (h *headerTracker) WriteHeader(code int) {
	h.wrote = true
	h.ResponseWriter.WriteHeader(code)
}

func (h *headerTracker) Write(p []byte) (int, error) {
	h.wrote = true
	return h.ResponseWriter.Write(p)
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (h *headerTracker) Unwrap() http.ResponseWriter {
	return h.ResponseWriter
}
