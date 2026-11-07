package cauthy

import (
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/vennet-developers/cauthy-sdk-go/internal/cfgerr"
)

// CheckMount checks that Auth is what answers under its base path in the
// application's router h, and returns a *ConfigError naming the route when
// something else does: another catch-all, a proxy rule, a route registered
// first. Every answer of Auth carries Cauthy-Protocol and nothing else's
// does. Call it once at startup with the application's whole router; the
// three probes it sends never reach Cauthy.
func (a *Auth) CheckMount(h http.Handler) error {
	probes := []*http.Request{
		httptest.NewRequest(http.MethodGet, a.basePath+"/session", nil),
		httptest.NewRequest(http.MethodGet, a.basePath+"/cauthy-mount-check", nil),
		httptest.NewRequest(http.MethodPost, a.basePath+"/sign-out", strings.NewReader("{}")),
	}
	probes[0].Header.Set("Accept", "application/json")
	probes[2].Header.Set("Content-Type", "application/json")
	probes[2].Header.Set("X-Cauthy-Request", "1")
	probes[2].Header.Set("Origin", "http://example.com")
	for _, p := range probes {
		what := p.Method + " " + p.URL.Path
		w := httptest.NewRecorder()
		func() {
			defer func() {
				if recover() != nil {
					w.Code = http.StatusInternalServerError
				}
			}()
			h.ServeHTTP(w, p)
		}()
		if w.Header().Get("Cauthy-Protocol") == ProtocolVersion {
			continue
		}
		switch {
		case w.Code >= 300 && w.Code < 400:
			return cfgerr.New("%s: the mount redirects (%d to %s): a rule or a trailing-slash redirect sits in front of %s. Cauthy is not what answers.",
				what, w.Code, w.Header().Get("Location"), a.basePath)
		case w.Code >= 500:
			return cfgerr.New("%s answered %d without Cauthy-Protocol: %s: the application failed before or instead of the handler.", what, w.Code, ProtocolVersion)
		}
		return cfgerr.New("%s answered %d without Cauthy-Protocol: %s: something other than this handler answers under %s. "+
			"Move that route, mount Cauthy before it, or give Cauthy another BasePath.", what, w.Code, ProtocolVersion, a.basePath)
	}
	return nil
}
