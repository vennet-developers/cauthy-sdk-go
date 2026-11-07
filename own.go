package cauthy

import (
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"strings"
)

// The application's own screens: the routes of routes.yaml that sign people
// in and run their account through the application's server. Each group of
// routes registers its handlers in its file's init; ownRoute runs the gate
// every own route shares, in @cauthyhq/node's order.

// getHandler serves a route read with GET (or any method but POST).
type getHandler func(a *Auth, r *http.Request, route string) *reply

// postHandler serves a POST with its JSON object body.
type postHandler func(a *Auth, r *http.Request, route string, b map[string]any) *reply

// meHandler serves a POST under /me, as the signed-in person.
type meHandler func(a *Auth, r *http.Request, route string, b map[string]any, p *person) *reply

var (
	ownGET       = map[string]getHandler{}
	ownGETPrefix = map[string]getHandler{} // "/sign-in/social/" → handler of /sign-in/social/{provider}
	ownPOST      = map[string]postHandler{}
	ownMe        = map[string]meHandler{}
	// ownBare serves a POST before its body is read (sign-out takes none).
	ownBare = map[string]getHandler{}
)

// ownRoutes is every own route: routes.yaml's routes with tenant in needs.
var ownRoutes = map[string]bool{}

func init() {
	for _, r := range []string{
		"/sign-in/email", "/sign-in/mfa", "/sign-up/email", "/forgot-password", "/reset-password", "/verify-email",
		"/sign-in/magic-link", "/sign-in/magic-link/verify", "/sign-in/email-code", "/me", "/me/password", "/me/mfa/setup",
		"/me/mfa/verify", "/me/mfa/disable", "/me/mfa/recovery-codes", "/me/mfa/factors", "/me/mfa/phone", "/me/mfa/phone/verify",
		"/me/mfa/phone/remove", "/sign-in/mfa/methods", "/sign-in/mfa/send", "/sign-in/mfa/email", "/sign-in/mfa/push",
		"/sign-in/mfa/push/events", "/sign-in/mfa/push/finish", "/me/sessions", "/me/sessions/end", "/me/legal", "/me/legal/accept",
		"/me/email", "/me/identities", "/me/identities/unlink", "/sign-out", "/methods", "/look", "/sign-in/passkey/begin",
		"/sign-in/passkey/finish", "/sign-in/google-one-tap/begin", "/sign-in/google-one-tap", "/me/passkeys", "/me/passkeys/add/begin",
		"/me/passkeys/add/finish", "/me/passkeys/remove", "/me/agents", "/me/agents/disconnect", "/sign-in/anonymous", "/me/upgrade",
		"/me/organizations", "/me/organizations/members", "/me/organizations/roles", "/me/organizations/members/add",
		"/me/organizations/members/role", "/me/organizations/members/remove", "/me/organizations/members/invite",
		"/me/organizations/rename", "/me/organizations/archive", "/me/organizations/delete", "/invitation", "/invitation/accept",
		"/sign-in/sso", "/sign-in/sso/discover", "/sso/callback",
	} {
		ownRoutes[r] = true
	}
}

// ownPrefixes are the own routes with a {provider} segment.
var ownPrefixes = []string{"/sign-in/social/", "/callback/", "/me/identities/link/", "/me/upgrade/social/"}

func isOwn(route string) bool {
	return ownRoutes[route] || slices.ContainsFunc(ownPrefixes, func(p string) bool { return strings.HasPrefix(route, p) })
}

// deprecatedRoutes leave the protocol in version 2.
var deprecatedRoutes = map[string]string{"/sign-in/anonymous": "POST /sign-in/anonymous", "/me/upgrade": "POST /me/upgrade"}

// maxBody is the largest JSON body an own route reads.
const maxBody = 1 << 20

// readBody is the request's JSON object body, or nil when it is not one.
func readBody(r *http.Request) map[string]any {
	if !strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		return nil
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
	if err != nil || len(raw) > maxBody {
		return nil
	}
	var b map[string]any
	if json.Unmarshal(raw, &b) != nil {
		return nil
	}
	return b
}

// readStep is the step cookie, or nil when it is missing or not this key's.
func (a *Auth) readStep(r *http.Request) *step {
	sealed := readCookies(r)[a.stepCookie]
	var s step
	if sealed == "" || !unseal(sealed, a.flowRing, &s) {
		return nil
	}
	return &s
}

// stepCookieFor seals s into the step cookie for seconds.
func (a *Auth) stepCookieFor(r *http.Request, s step, seconds int) string {
	sealed, _ := seal(s, a.flowRing)
	return writeCookie(a.stepCookie, sealed, a.attrs(r).age(seconds))
}

func (a *Auth) clearStep(r *http.Request) string {
	return writeCookie(a.stepCookie, "", a.attrs(r).age(0))
}

func stepExpired(message string, h http.Header) *reply {
	return problem(http.StatusBadRequest, "step_expired", message, "", h, nil)
}

// withoutRequestHeader is the answer for a mutation without
// X-Cauthy-Request: 1, which another site cannot add without CORS; nil when
// it may go on.
func (a *Auth) withoutRequestHeader(r *http.Request, route string) *reply {
	if r.Header.Get("X-Cauthy-Request") == "1" {
		return nil
	}
	if a.requestHeader == "warn" {
		a.warnOnce("request-header", "cauthy: POST "+a.basePath+route+" arrived without X-Cauthy-Request: 1 and was let through (RequestHeader: \"warn\"). "+
			"Update the browser to cauthy-auth 0.43 or @cauthyhq/js, then remove RequestHeader.")
		return nil
	}
	return problem(http.StatusForbidden, "csrf_required", "This request did not come from this application's own client.", "", nil, nil)
}

// ownRequest reports whether this application's own page made the request:
// an Origin equal to the application's (or the request's own, behind a
// proxy), or no Origin and Sec-Fetch-Site absent or same-origin.
func (a *Auth) ownRequest(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin != "" {
		own := a.originOf(r)
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		if origin == own || origin == scheme+"://"+r.Host {
			return true
		}
		if hostOf(origin) != "" && hostOf(origin) == hostOf(own) {
			a.warnOnce("cross-site-explained", "cauthy: refused a request from "+origin+" as cross_site: this application sees itself as "+own+
				". Behind a proxy? Set BaseURL (CAUTHY_BASE_URL) to the public origin.")
		}
		return false
	}
	site := r.Header.Get("Sec-Fetch-Site")
	return site == "" || site == "same-origin"
}

func hostOf(origin string) string {
	_, rest, ok := strings.Cut(origin, "://")
	if !ok {
		return ""
	}
	host, _, _ := strings.Cut(rest, "/")
	if i := strings.LastIndex(host, ":"); i >= 0 && !strings.Contains(host[i:], "]") {
		host = host[:i]
	}
	return host
}

// ownRoute serves an own route, or answers nil when route is not one (or no
// handler serves it).
func (a *Auth) ownRoute(r *http.Request, route string) *reply {
	if !isOwn(route) {
		return nil
	}
	post := r.Method == http.MethodPost
	if post {
		if refused := a.withoutRequestHeader(r, route); refused != nil {
			return refused
		}
	}
	if name, ok := deprecatedRoutes[route]; ok {
		a.warnOnce("deprecated "+name, "cauthy: "+name+" is deprecated and leaves in 2.0. Guest sessions leave the auth-bff protocol in version 2.")
	}
	if strings.HasPrefix(route, "/me/upgrade/social/") {
		a.warnOnce("deprecated upgrade social", "cauthy: GET /me/upgrade/social/{provider} is deprecated and leaves in 2.0. Guest sessions leave the auth-bff protocol in version 2.")
	}
	if a.tenant == "" {
		return problem(http.StatusInternalServerError, "not_configured", "cauthy: tenant (CAUTHY_TENANT) is required for the application's own sign-in screens", "", nil, nil)
	}
	if !post {
		if h, ok := ownGET[route]; ok {
			return h(a, r, route)
		}
		for prefix, h := range ownGETPrefix {
			if strings.HasPrefix(route, prefix) {
				return h(a, r, route)
			}
		}
		return methodNotAllowed()
	}
	if !a.ownRequest(r) {
		return problem(http.StatusForbidden, "cross_site", "This request did not come from this application.", "", nil, nil)
	}
	if h, ok := ownBare[route]; ok {
		return h(a, r, route)
	}
	b := readBody(r)
	if b == nil {
		return problem(http.StatusBadRequest, "bad_request", "Send the form as JSON.", "", nil, nil)
	}
	if h, ok := ownPOST[route]; ok {
		return h(a, r, route, b)
	}
	if strings.HasPrefix(route, "/me") {
		p, refused := a.signedInAs(r)
		if refused != nil {
			return refused
		}
		if h, ok := ownMe[route]; ok {
			return h(a, r, route, b, p)
		}
	}
	return nil
}
