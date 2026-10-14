package rest

import (
	"net/http"
	"strings"

	"github.com/gorilla/mux"
)

// fallbackMethods are tried to tell "wrong method" (405) from "no such
// path" (404) for an /api request no route matched.
var fallbackMethods = []string{"GET", "POST", "PUT", "PATCH", "DELETE"}

// handleAPIFallback answers /api requests that matched no route in the
// unified error format instead of falling through to the SPA.
func (s *Server) handleAPIFallback(w http.ResponseWriter, r *http.Request) {
	var allowed []string
	probe := new(http.Request) // one shallow copy; only the method changes per probe
	*probe = *r
	for _, m := range fallbackMethods {
		if m == r.Method {
			continue
		}
		probe.Method = m
		var match mux.RouteMatch
		if s.router.Match(probe, &match) && match.Route != nil {
			if name := match.Route.GetName(); name != "api-fallback" && name != "spa" {
				allowed = append(allowed, m)
				if m == http.MethodGet {
					allowed = append(allowed, http.MethodHead) // served by headAsGet
				}
			}
		}
	}
	if len(allowed) > 0 {
		w.Header().Set("Allow", strings.Join(allowed, ", "))
		errorResponse(w, http.StatusMethodNotAllowed, "method "+r.Method+" is not allowed for "+r.URL.Path)
		return
	}
	errorResponse(w, http.StatusNotFound, "no API endpoint at "+r.URL.Path)
}

// headAsGet answers HEAD requests with the GET handler, without a body.
func headAsGet(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodHead {
			next.ServeHTTP(w, r)
			return
		}
		get := r.Clone(r.Context())
		get.Method = http.MethodGet
		next.ServeHTTP(bodylessWriter{w}, get)
	})
}

// bodylessWriter drops the body; status and headers pass through.
type bodylessWriter struct{ http.ResponseWriter }

func (b bodylessWriter) Write(p []byte) (int, error) { return len(p), nil }
