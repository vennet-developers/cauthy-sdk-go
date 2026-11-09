package cauthy

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/vennet-developers/cauthy-sdk-go/cauthykey"
	"github.com/vennet-developers/cauthy-sdk-go/keys"
	"github.com/vennet-developers/cauthy-sdk-go/system"
)

// ServeHTTP serves the auth-bff routes under the base path and the published
// keys at the JWKS path. Every answer goes out as protocol version 1 sends it.
func (a *Auth) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	route, inside := a.routeOf(r)
	get := r.Method == http.MethodGet || r.Method == http.MethodHead
	if a.pact != nil && r.URL.Path == a.contract.JWKSPath && get {
		send(w, "", a.jwksReply(r), true)
		return
	}
	if inside && a.identity != nil {
		if rep := a.identified(r); rep != nil {
			send(w, route, rep, false)
			return
		}
	}
	send(w, route, a.serve(r, route), false)
}

// routeOf is the route of r under the base path, without trailing slashes
// ("/" for the bare prefix), as the browser wrote it (percent-encoded).
func (a *Auth) routeOf(r *http.Request) (string, bool) {
	path := r.URL.EscapedPath()
	if path != a.basePath && !strings.HasPrefix(path, a.basePath+"/") {
		return "", false
	}
	route := withoutTrailingSlashes(path[len(a.basePath):])
	if route == "" {
		route = "/"
	}
	return route, true
}

func (a *Auth) serve(r *http.Request, route string) *reply {
	if _, inside := a.routeOf(r); !inside {
		return notFound()
	}
	if rep := a.ownRoute(r, route); rep != nil {
		return a.unverifiedOr(r, rep)
	}
	// The browser asking about a permission: outside the own screens, it
	// needs no tenant, only the person's session.
	if route == "/me/organizations/check" {
		return a.checkRoute(r)
	}
	get := r.Method == http.MethodGet || r.Method == http.MethodHead
	switch {
	case route == "/login" && get:
		return a.login(r)
	case route == "/callback" && get:
		return a.unverifiedOr(r, a.callback(r))
	case route == "/logout" && (get || r.Method == http.MethodPost):
		return a.logout(r)
	case route == "/session" && get:
		res := a.Resolve(r)
		var public any
		if res.Session != nil {
			p := a.ToPublic(r.Context(), res.Session)
			public = p
		}
		return ok(map[string]any{"session": public, "status": res.Status}, nil).with(res.Cookies...)
	case route == "/refresh" && get:
		res := a.Resolve(r)
		back := localPath(r.URL.Query().Get("return_to"), a.afterSignIn)
		switch res.Status {
		case StatusUnauthenticated:
			return redirect(a.SignInURL(back), res.Cookies...)
		case StatusExpired:
			return text(http.StatusServiceUnavailable, "Sign-in is unavailable right now. Try again in a moment.")
		}
		return redirect(back, res.Cookies...)
	case route == "/account" && get:
		q := url.Values{"client_id": {a.clientID}}
		if back := localPath(r.URL.Query().Get("return_to"), ""); back != "" {
			q.Set("return_to", a.originOf(r)+back)
		}
		if l := r.URL.Query().Get("locale"); localeRE.MatchString(l) {
			q.Set("ui_locales", l)
		}
		return redirect(a.issuer + "/v1/oauth/account?" + q.Encode())
	}
	return notFound()
}

// jwksReply is the published keys, cacheable for keys.JWKSMaxAge: on
// CAUTHY_KEY the key's public half (and the previous key's, while
// rotating), then the key store's while it is still passed.
func (a *Auth) jwksReply(r *http.Request) *reply {
	set := keys.JWKS{Keys: []map[string]any{}}
	if a.keyed != nil {
		for _, k := range []*cauthykey.Key{a.keyed.key, a.keyed.previous} {
			if k == nil || (k != a.keyed.key && k.Secret == a.keyed.key.Secret) {
				continue
			}
			d := k.Derive()
			set.Keys = append(set.Keys, map[string]any{"kty": "OKP", "crv": "Ed25519", "x": d.X, "kid": d.KID, "alg": "EdDSA", "use": "sig"})
		}
	}
	if a.ownKeys != nil {
		stored, err := a.ownKeys.Published(r.Context())
		if err != nil {
			return text(http.StatusServiceUnavailable, "The keys are unavailable right now.")
		}
		set.Keys = append(set.Keys, stored.Keys...)
	}
	rep := ok(set, nil)
	rep.header.Set("Cache-Control", fmt.Sprintf("public, max-age=%d", int(keys.JWKSMaxAge.Seconds())))
	return rep
}

// emailNotConfirmedReply marks a reply that stands for errEmailNotConfirmed:
// unverifiedOr turns it into the answer for the request.
var emailNotConfirmedReply = &reply{}

// unverifiedOr answers a sign-in Cauthy completed for an address the link
// requires confirmed, and it is not: a plain-text 403 for a page, the JSON
// error for anything else.
func (a *Auth) unverifiedOr(r *http.Request, rep *reply) *reply {
	if rep != emailNotConfirmedReply {
		return rep
	}
	mode := r.Header.Get("Sec-Fetch-Mode")
	if r.Method == http.MethodGet && (mode == "" || mode == "navigate") {
		return text(http.StatusForbidden, "Sign-in refused (email_not_confirmed). Confirm your email address first.")
	}
	return problem(http.StatusForbidden, "email_not_confirmed", "Confirm your email address first.", "", nil, nil)
}

// orUnverified is emailNotConfirmedReply for errEmailNotConfirmed, else nil.
func orUnverified(err error) *reply {
	if errors.Is(err, errEmailNotConfirmed) {
		return emailNotConfirmedReply
	}
	return nil
}

var localeRE = regexp.MustCompile(`^[a-zA-Z-]{2,10}$`)

// login sends the browser to Cauthy's sign-in page, with the question it
// asks sealed in a cookie: state and the PKCE verifier.
func (a *Auth) login(r *http.Request) *reply {
	q := r.URL.Query()
	f := flow{State: random(32), Verifier: random(48), ReturnTo: localPath(q.Get("return_to"), a.afterSignIn)}
	v := url.Values{
		"client_id": {a.clientID}, "redirect_uri": {a.originOf(r) + a.basePath + "/callback"}, "response_type": {"code"},
		"state": {f.State}, "code_challenge": {challenge(f.Verifier)}, "code_challenge_method": {"S256"},
	}
	if p := q.Get("prompt"); p == "login" || p == "none" {
		v.Set("prompt", p)
	}
	locale := q.Get("locale")
	if locale == "" {
		locale = q.Get("ui_locales")
	}
	if localeRE.MatchString(locale) {
		v.Set("ui_locales", locale)
	}
	fragment := ""
	if q.Get("method") == "passkey" {
		v.Set("method", "passkey")
		fragment = "#passkey"
	}
	sealed, err := seal(f, a.flowRing)
	if err != nil {
		return text(http.StatusInternalServerError, "Sign-in could not be started.")
	}
	return redirect(a.issuer+"/v1/oauth/authorize?"+v.Encode()+fragment, writeCookie(a.flowCookie, sealed, a.attrs(r).age(flowSeconds)))
}

func (a *Auth) failedSignIn(r *http.Request, reason string) *reply {
	return text(http.StatusBadRequest, "Sign-in could not be completed ("+reason+"). Go back and try again.").
		with(writeCookie(a.flowCookie, "", a.attrs(r).age(0)), writeCookie(a.againCookie, "", a.attrs(r).age(0)))
}

// callback trades the code Cauthy sent back for the session, when the answer
// is to the question THIS browser asked.
func (a *Auth) callback(r *http.Request) *reply {
	had := readCookies(r)
	q := r.URL.Query()
	var f flow
	known := had[a.flowCookie] != "" && unseal(had[a.flowCookie], a.flowRing, &f)
	clearFlow := writeCookie(a.flowCookie, "", a.attrs(r).age(0))
	if !known || q.Get("state") != f.State {
		// Not this browser's question, or asked so long ago it is forgotten:
		// the sign-in starts again, once.
		if _, again := had[a.againCookie]; !again {
			back := a.afterSignIn
			if known {
				back = f.ReturnTo
			}
			return redirect(a.basePath+"/login?return_to="+urlQueryEscape(back), writeCookie(a.againCookie, "1", a.attrs(r).age(againSeconds)))
		}
		return a.failedSignIn(r, "state_mismatch")
	}
	if e := q.Get("error"); e != "" {
		switch e {
		case "login_required": // prompt=none and nobody signed in: just "nobody"
			return redirect(f.ReturnTo, clearFlow)
		case "access_denied": // the person went back from Cauthy's page
			back := a.pages.SignIn
			if back == "" {
				back = f.ReturnTo
			}
			return redirect(withQuery(back, "auth_error", "cancelled"), clearFlow)
		}
		return a.failedSignIn(r, cut(e, 60))
	}
	code := q.Get("code")
	if code == "" {
		return a.failedSignIn(r, "no_code")
	}
	body, okay, _, refusal := a.token(r.Context(), url.Values{"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {a.originOf(r) + a.basePath + "/callback"}, "code_verifier": {f.Verifier}}, a.passedOn(r))
	// Back to the application's sign-in page with the reason, and the
	// question forgotten.
	unconfirmed := func() *reply {
		page := a.pages.SignIn
		if page == "" {
			page = "/"
		}
		return redirect(withQuery(page, "auth_error", "email_not_confirmed"), clearFlow, writeCookie(a.againCookie, "", a.attrs(r).age(0)))
	}
	// Cauthy refuses at the token endpoint when the client requires a
	// confirmed address…
	if !okay && refusal == "email_not_confirmed" {
		return unconfirmed()
	}
	if !okay {
		return a.failedSignIn(r, "exchange_failed")
	}
	// …and this side checks too, should an older Cauthy not.
	s, err := a.toStored(r.Context(), body, nil)
	if errors.Is(err, errEmailNotConfirmed) {
		return unconfirmed()
	}
	if s == nil {
		return a.failedSignIn(r, "exchange_failed")
	}
	return redirect(f.ReturnTo, append(a.write(r, s, had), clearFlow, writeCookie(a.againCookie, "", a.attrs(r).age(0)))...)
}

// logout ends the session here and at Cauthy, which ends its own session in
// this browser too.
func (a *Auth) logout(r *http.Request) *reply {
	had, value, _ := a.read(r)
	if value != nil {
		a.revoke(r.Context(), value.RT)
		a.forgetOrganizations(value.AT)
	}
	q := url.Values{"client_id": {a.clientID}, "post_logout_redirect_uri": {a.originOf(r) + a.afterSignOut}}
	return redirect(a.issuer+"/v1/oauth/logout?"+q.Encode(), a.clearSession(r, had)...)
}

// checkRoute is POST /me/organizations/check: Cauthy's decision for the
// signed-in person.
func (a *Auth) checkRoute(r *http.Request) *reply {
	if r.Method != http.MethodPost {
		return methodNotAllowed()
	}
	if refused := a.withoutRequestHeader(r, "/me/organizations/check"); refused != nil {
		return refused
	}
	if !a.ownRequest(r) {
		return problem(http.StatusForbidden, "cross_site", "This request did not come from this application.", "", nil, nil)
	}
	b := readBody(r)
	if b == nil {
		return problem(http.StatusBadRequest, "bad_request", "Send the question as JSON.", "", nil, nil)
	}
	p, refused := a.signedInAs(r)
	if refused != nil {
		return refused
	}
	org, _ := b["organizationId"].(string)
	if !looseUUID.MatchString(org) {
		return problem(http.StatusBadRequest, "invalid_organization", "Say which organization.", "", p.header, nil)
	}
	named := func(v any) bool { s, ok := v.(string); return ok && s != "" && utf16Len(s) <= 200 }
	if !named(b["resource"]) || !named(b["action"]) {
		return problem(http.StatusBadRequest, "bad_request", "Say which resource and action.", "", p.header, nil)
	}
	q := CheckQuestion{Organization: org, Resource: b["resource"].(string), Action: b["action"].(string)}
	if attrs, present := b["attributes"]; present {
		m, isObj := attrs.(map[string]any)
		if !isObj {
			return problem(http.StatusBadRequest, "bad_request", "The attributes are an object.", "", p.header, nil)
		}
		q.Attributes = m
	}
	q.ResourceID, _ = b["resourceId"].(string)
	q.OwnerID, _ = b["ownerId"].(string)
	res, err := a.decide(r.Context(), p.token, q)
	if err != nil {
		status, code, message := http.StatusServiceUnavailable, "unavailable", "Cauthy could not be reached."
		var e *system.APIError
		if errors.As(err, &e) {
			status, code, message = e.Status, e.Code, e.Message
		}
		return problem(status, code, message, "", p.header, nil)
	}
	out := map[string]any{"status": "decided", "allowed": res.Allowed, "reason": res.Reason}
	if res.Rule != nil {
		out["rule"] = res.Rule
	}
	return ok(out, p.header)
}

// Mount registers Auth on mux at its base path and its JWKS path.
func (a *Auth) Mount(mux *http.ServeMux) {
	mux.Handle(a.basePath, a)
	mux.Handle(a.basePath+"/", a)
	if !strings.HasPrefix(a.JWKSPath(), a.basePath+"/") {
		mux.Handle(a.JWKSPath(), a)
	}
}

// Router is the part of a chi router (or any like it) Auth mounts on.
type Router interface {
	Handle(pattern string, h http.Handler)
}

// MountRouter registers Auth on a chi-style router: the base path, the base
// path with /*, and the JWKS path.
func (a *Auth) MountRouter(r Router) {
	r.Handle(a.basePath, a)
	r.Handle(a.basePath+"/*", a)
	if !strings.HasPrefix(a.JWKSPath(), a.basePath+"/") {
		r.Handle(a.JWKSPath(), a)
	}
}

// SignInURL is the path that starts a sign-in and comes back to returnTo.
func (a *Auth) SignInURL(returnTo string) string {
	if returnTo == "" {
		return a.basePath + "/login"
	}
	return a.basePath + "/login?return_to=" + urlQueryEscape(returnTo)
}

// SignOutURL is the path that signs out.
func (a *Auth) SignOutURL() string { return a.basePath + "/logout" }

// AccountURL is the path that opens Cauthy's account page.
func (a *Auth) AccountURL(returnTo string) string {
	if returnTo == "" {
		return a.basePath + "/account"
	}
	return a.basePath + "/account?return_to=" + urlQueryEscape(returnTo)
}

// SessionURL is the path of GET /session.
func (a *Auth) SessionURL() string { return a.basePath + "/session" }
