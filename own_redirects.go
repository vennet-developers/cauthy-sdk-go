package cauthy

import (
	"net/http"
	"net/url"
	"strings"
)

// The sign-ins that leave the site and come back: a person's company
// (SSO), a provider (social), a provider linked to the signed-in account,
// and a guest becoming a provider's account. Their failures are redirects
// with ?auth_error=<code>.

func init() {
	ownGET["/sign-in/sso"] = (*Auth).ssoStart
	ownGET["/sso/callback"] = (*Auth).ssoCallback
	ownGETPrefix["/sign-in/social/"] = (*Auth).socialStart
	ownGETPrefix["/callback/"] = (*Auth).providerCallback
	ownGETPrefix["/me/upgrade/social/"] = (*Auth).upgradeSocialStart
	ownGETPrefix["/me/identities/link/"] = (*Auth).linkStart
}

// failedTo is a redirect failure: back to path with auth_error.
func failedTo(path, code string, cookies ...string) *reply {
	return redirect(withQuery(path, "auth_error", code), cookies...)
}

// ssoStart sends the person to their company's sign-in. Cauthy ends the
// flow on this site with a code only the browser holding the sealed PKCE
// verifier can trade.
func (a *Auth) ssoStart(r *http.Request, _ string) *reply {
	q := r.URL.Query()
	returnTo := localPath(q.Get("return_to"), a.afterSignIn)
	email, connection := strings.TrimSpace(q.Get("email")), strings.TrimSpace(q.Get("connection"))
	if email == "" && connection == "" {
		return failedTo(returnTo, "sso_not_found")
	}
	verifier := random(48)
	callback := a.basePath + "/sso/callback"
	remember := wants(q.Get("remember"))
	payload := map[string]any{"redirect_uri": a.originOf(r) + callback, "code_challenge": challenge(verifier)}
	if connection != "" {
		payload["connection"] = connection
	} else {
		payload["email"] = email
	}
	n := a.ask(r, http.MethodPost, "/v1/auth/sso/start", payload, askOpts{page: callback, remember: remember})
	target, isStr := at(n.data, "redirect_url").(string)
	if n.err != nil || !isStr {
		code := "sso_unavailable"
		if n.err != nil {
			code = n.err.code
		}
		return failedTo(returnTo, code)
	}
	return redirect(target, a.stepCookieFor(r, step{Kind: "sso", Token: verifier, ReturnTo: returnTo, Remember: remember}, stepSeconds))
}

func (a *Auth) ssoCallback(r *http.Request, _ string) *reply {
	s := a.readStep(r)
	clear := a.clearStep(r)
	back := a.afterSignIn
	if s != nil {
		back = s.ReturnTo
	}
	if s == nil || s.Kind != "sso" {
		return failedTo(back, "state_mismatch", clear)
	}
	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		return failedTo(back, cut(e, 60), clear)
	}
	code := q.Get("code")
	if code == "" {
		return failedTo(back, "sso_failed", clear)
	}
	n := a.ask(r, http.MethodPost, "/v1/auth/sso/token", map[string]any{"code": code, "redirect_uri": a.originOf(r) + a.basePath + "/sso/callback",
		"code_verifier": s.Token}, askOpts{remember: s.Remember})
	if n.err != nil {
		return failedTo(back, n.err.code, clear)
	}
	return a.signedInBack(r, n.data, nil, back, clear)
}

// signedInBack keeps the session Cauthy's answer starts and goes back.
func (a *Auth) signedInBack(r *http.Request, data any, was *stored, back string, cookies ...string) *reply {
	st, err := a.toStored(r.Context(), data, was)
	if rep := orUnverified(err); rep != nil {
		return rep
	}
	if st == nil {
		return failedTo(back, "unavailable", cookies...)
	}
	return redirect(back, append(a.write(r, st, readCookies(r)), cookies...)...)
}

// provider is the provider of a route with a {provider} segment, and
// whether it is well-formed.
func provider(route, prefix string) (string, bool) {
	p := providerIn(strings.TrimPrefix(route, prefix))
	return p, providerRE.MatchString(p)
}

// socialStart sends the browser to a provider. The state is this browser's,
// kept sealed.
func (a *Auth) socialStart(r *http.Request, route string) *reply {
	p, wellFormed := provider(route, "/sign-in/social/")
	if !wellFormed {
		return notFound()
	}
	q := r.URL.Query()
	returnTo := localPath(q.Get("return_to"), a.afterSignIn)
	callback := a.basePath + "/callback/" + p
	remember := wants(q.Get("remember"))
	n := a.ask(r, http.MethodGet, "/v1/auth/social/"+p+"?redirect_uri="+url.QueryEscape(a.originOf(r)+callback), nil, askOpts{page: callback, remember: remember})
	return a.leaveFor(r, n, step{Kind: "social", Provider: p, ReturnTo: returnTo, Remember: remember}, returnTo, nil)
}

// leaveFor goes to the provider's address Cauthy answered, keeping s (with
// Cauthy's state) in the step cookie; a failure goes back to returnTo.
func (a *Auth) leaveFor(r *http.Request, n asked, s step, returnTo string, h http.Header) *reply {
	target, isStr := at(n.data, "redirect_url").(string)
	if n.err != nil || !isStr {
		code := "provider_unavailable"
		if n.err != nil {
			code = n.err.code
		}
		// A session renewed on the way here is kept: its old refresh token
		// is spent.
		return failedTo(returnTo, code, h.Values("Set-Cookie")...)
	}
	s.Token = str(at(n.data, "state"))
	return redirect(target, append(h.Values("Set-Cookie"), a.stepCookieFor(r, s, stepSeconds))...)
}

// providerCallback is a provider answering: a sign-in, a link to the
// signed-in account, or a guest's upgrade, as the step says.
func (a *Auth) providerCallback(r *http.Request, route string) *reply {
	p, _ := provider(route, "/callback/")
	s := a.readStep(r)
	clear := a.clearStep(r)
	back := a.afterSignIn
	if s != nil {
		back = s.ReturnTo
	}
	q := r.URL.Query()
	if s == nil || (s.Kind != "social" && s.Kind != "link" && s.Kind != "upgrade") || s.Provider != p || q.Get("state") != s.Token {
		return failedTo(back, "state_mismatch", clear)
	}
	code := q.Get("code")
	if code == "" {
		reason := "provider_refused"
		if q.Get("error") == "access_denied" {
			reason = "cancelled"
		}
		return failedTo(back, reason, clear)
	}
	v := url.Values{"code": {code}, "state": {s.Token}, "redirect_uri": {a.originOf(r) + a.basePath + "/callback/" + p}}
	switch s.Kind {
	case "upgrade":
		mine, refused := a.signedInAs(r)
		if refused != nil {
			return failedTo(back, "unauthenticated", clear)
		}
		n := a.ask(r, http.MethodGet, "/v1/auth/anonymous/upgrade/"+p+"/callback?"+v.Encode(), nil, askOpts{bearer: mine.token})
		if n.err != nil {
			return failedTo(back, n.err.code, append(mine.header.Values("Set-Cookie"), clear)...)
		}
		_, was, _ := a.read(r)
		return a.signedInBack(r, n.data, was, back, clear)
	case "link":
		mine, refused := a.signedInAs(r)
		if refused != nil {
			return failedTo(back, "unauthenticated", clear)
		}
		n := a.ask(r, http.MethodGet, "/v1/auth/identities/"+p+"/link/callback?"+v.Encode(), nil, askOpts{bearer: mine.token})
		if n.err != nil {
			return failedTo(back, n.err.code, append(mine.header.Values("Set-Cookie"), clear)...)
		}
		return redirect(withQuery(back, "linked", p), append(mine.header.Values("Set-Cookie"), clear)...)
	}
	n := a.ask(r, http.MethodGet, "/v1/auth/social/"+p+"/callback?"+v.Encode(), nil, askOpts{remember: s.Remember})
	if n.err != nil {
		return failedTo(back, n.err.code, clear)
	}
	return a.signedInBack(r, n.data, nil, back, clear)
}

// upgradeSocialStart: a guest becoming the account of a provider's address.
func (a *Auth) upgradeSocialStart(r *http.Request, route string) *reply {
	p, wellFormed := provider(route, "/me/upgrade/social/")
	if !wellFormed {
		return notFound()
	}
	returnTo := localPath(r.URL.Query().Get("return_to"), a.afterSignIn)
	mine, refused := a.signedInAs(r)
	if refused != nil {
		return failedTo(returnTo, "unauthenticated")
	}
	callback := a.basePath + "/callback/" + p
	n := a.ask(r, http.MethodGet, "/v1/auth/anonymous/upgrade/"+p+"?redirect_uri="+url.QueryEscape(a.originOf(r)+callback), nil, askOpts{page: callback, bearer: mine.token})
	return a.leaveFor(r, n, step{Kind: "upgrade", Provider: p, ReturnTo: returnTo}, returnTo, mine.header)
}

// linkStart: a provider linked to the signed-in account, to it and back.
func (a *Auth) linkStart(r *http.Request, route string) *reply {
	p, wellFormed := provider(route, "/me/identities/link/")
	if !wellFormed {
		return notFound()
	}
	returnTo := localPath(r.URL.Query().Get("return_to"), a.afterSignIn)
	mine, refused := a.signedInAs(r)
	if refused != nil {
		return failedTo(returnTo, "unauthenticated")
	}
	callback := a.basePath + "/callback/" + p
	n := a.ask(r, http.MethodGet, "/v1/auth/identities/"+p+"/link?redirect_uri="+url.QueryEscape(a.originOf(r)+callback), nil, askOpts{page: callback, bearer: mine.token})
	return a.leaveFor(r, n, step{Kind: "link", Provider: p, ReturnTo: returnTo}, returnTo, mine.header)
}
