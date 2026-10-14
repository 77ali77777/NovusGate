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
	for _, m := range fallbackMethods {
		if m == r.Method {
			continue
		}
		probe := r.Clone(r.Context())
		probe.Method = m
		var match mux.RouteMatch
		if s.router.Match(probe, &match) && match.Route != nil {
			if name := match.Route.GetName(); name != "api-fallback" && name != "spa" {
				allowed = append(allowed, m)
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
