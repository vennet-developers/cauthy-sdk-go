package cauthy

import "net/http"

// Signing in on the application's own screens: with a password, the second
// step, signing up, recovering a password, a company's address, a guest
// session; and signing out.

func init() {
	ownBare["/sign-out"] = (*Auth).signOutRoute
	for route, h := range map[string]postHandler{
		"/sign-in/sso/discover": (*Auth).ssoDiscover, "/sign-in/anonymous": (*Auth).anonymous, "/sign-in/email": (*Auth).signInEmail,
		"/sign-in/mfa": (*Auth).secondStep, "/sign-in/mfa/push": (*Auth).push, "/sign-in/mfa/push/finish": (*Auth).push,
		"/sign-in/mfa/methods": (*Auth).secondStepWays, "/sign-in/mfa/send": (*Auth).secondStepWays, "/sign-in/mfa/email": (*Auth).secondStepWays,
		"/sign-up/email": (*Auth).signUp, "/forgot-password": (*Auth).forgotPassword,
	} {
		ownPOST[route] = h
	}
}

// signedIn: Cauthy answered with tokens, so the person is signed in here.
// extra cookies go along; more fields join the answer.
func (a *Auth) signedIn(r *http.Request, tokens any, extra []string, more map[string]any, was *stored) *reply {
	s, err := a.toStored(r.Context(), tokens, was)
	if rep := orUnverified(err); rep != nil {
		return rep
	}
	if s == nil {
		return problem(http.StatusBadGateway, "unavailable", "Sign-in is unavailable right now. Try again in a moment.", "", nil, nil)
	}
	body := map[string]any{"status": "signed_in", "session": a.ToPublic(r.Context(), s.session())}
	for k, v := range more {
		body[k] = v
	}
	return ok(body, nil).with(a.write(r, s, readCookies(r))...).with(extra...)
}

// loggedIn is Cauthy's answer to a password: signed in, or the second step
// next, its token sealed in the step cookie and never shown to the page.
func (a *Auth) loggedIn(r *http.Request, data any, remember bool) *reply {
	if yes(at(data, "mfa_required")) {
		cookie := a.stepCookieFor(r, step{Kind: "mfa", Token: str(at(data, "mfa_token")), ReturnTo: a.afterSignIn, Remember: remember}, stepSeconds)
		body := map[string]any{"status": "mfa_required"}
		if at(data, "mfa_method") == "email" {
			body["method"] = "email"
		}
		return ok(body, nil).with(cookie)
	}
	return a.signedIn(r, data, nil, nil, nil)
}

func (a *Auth) signOutRoute(r *http.Request, _ string) *reply {
	had, value, _ := a.read(r)
	if value != nil {
		a.revoke(r.Context(), value.RT)
		a.forgetOrganizations(value.AT)
	}
	return ok(map[string]any{"status": "signed_out"}, nil).with(a.clearSession(r, had)...)
}

// ssoDiscover says which company's sign-in an address uses: said of its
// domain, never of whether the address has an account.
func (a *Auth) ssoDiscover(r *http.Request, _ string, b map[string]any) *reply {
	if bad := checkEmail(b["email"]); bad != nil {
		return invalid(bad)
	}
	n := a.ask(r, http.MethodPost, "/v1/auth/sso/discover", map[string]any{"email": trimmed(b["email"])}, askOpts{})
	if n.err != nil {
		return problem(n.status, n.err.code, n.err.message, "", nil, nil)
	}
	c := at(n.data, "connection")
	if c == nil {
		return ok(map[string]any{"status": "none"}, nil)
	}
	return ok(map[string]any{"status": "found", "connection": map[string]any{"id": str(at(c, "slug")), "name": str(at(c, "display_name")), "enforced": yes(at(c, "enforced"))}}, nil)
}

// anonymous is a guest session, before the visitor signs up. Deprecated.
func (a *Auth) anonymous(r *http.Request, _ string, _ map[string]any) *reply {
	n := a.ask(r, http.MethodPost, "/v1/auth/anonymous", map[string]any{}, askOpts{})
	if n.err != nil {
		return problem(n.status, n.err.code, n.err.message, "", nil, nil)
	}
	return a.signedIn(r, n.data, nil, nil, nil)
}

func (a *Auth) signInEmail(r *http.Request, _ string, b map[string]any) *reply {
	if bad := firstProblem(checkEmail(b["email"]), checkPassword(b["password"])); bad != nil {
		return invalid(bad)
	}
	remember := wants(b["remember"])
	n := a.ask(r, http.MethodPost, "/v1/auth/login", map[string]any{"email": trimmed(b["email"]), "password": b["password"]}, askOpts{remember: remember})
	if n.err != nil {
		return problem(n.status, n.err.code, n.err.message, "", nil, nil)
	}
	return a.loggedIn(r, n.data, remember)
}

const mfaExpired = "Sign in again: the code was asked for too long ago."

// secondStep takes the code of the second step.
func (a *Auth) secondStep(r *http.Request, _ string, b map[string]any) *reply {
	if bad := checkCode(b["code"]); bad != nil {
		return invalid(bad)
	}
	s := a.readStep(r)
	if s == nil || s.Kind != "mfa" {
		return stepExpired(mfaExpired, nil)
	}
	n := a.ask(r, http.MethodPost, "/v1/auth/mfa/challenge", map[string]any{"mfa_token": s.Token, "code": trimmed(b["code"])}, askOpts{remember: s.Remember})
	if n.err != nil {
		return problem(n.status, n.err.code, n.err.message, "code", nil, nil)
	}
	return a.signedIn(r, n.data, []string{a.clearStep(r)}, nil, nil)
}

// push sends the second step to the phone (/push), then signs in once the
// phone approved it (/push/finish).
func (a *Auth) push(r *http.Request, route string, _ map[string]any) *reply {
	s := a.readStep(r)
	if s == nil || s.Kind != "mfa" {
		return stepExpired(mfaExpired, nil)
	}
	if route == "/sign-in/mfa/push" {
		n := a.ask(r, http.MethodPost, "/v1/auth/mfa/push", map[string]any{"mfa_token": s.Token}, askOpts{remember: s.Remember})
		if n.err != nil {
			return problem(n.status, n.err.code, n.err.message, "", nil, nil)
		}
		return ok(map[string]any{"status": "sent", "number": num(at(n.data, "number"))}, nil)
	}
	n := a.ask(r, http.MethodPost, "/v1/auth/mfa/challenge", map[string]any{"mfa_token": s.Token, "push": true}, askOpts{remember: s.Remember})
	if n.err != nil {
		return problem(n.status, n.err.code, n.err.message, "", nil, nil)
	}
	return a.signedIn(r, n.data, []string{a.clearStep(r)}, nil, nil)
}

// secondStepWays: which ways the account has, and a code sent to its phone
// or its address.
func (a *Auth) secondStepWays(r *http.Request, route string, _ map[string]any) *reply {
	s := a.readStep(r)
	if s == nil || s.Kind != "mfa" {
		return stepExpired(mfaExpired, nil)
	}
	path := map[string]string{"/sign-in/mfa/methods": "/v1/auth/mfa/methods", "/sign-in/mfa/email": "/v1/auth/mfa/email", "/sign-in/mfa/send": "/v1/auth/mfa/send"}[route]
	n := a.ask(r, http.MethodPost, path, map[string]any{"mfa_token": s.Token}, askOpts{remember: s.Remember})
	if n.err != nil {
		return problem(n.status, n.err.code, n.err.message, "", nil, nil)
	}
	d := n.data
	switch route {
	case "/sign-in/mfa/methods":
		var phone, push, mail any
		if p := at(d, "phone"); p != nil {
			phone = map[string]any{"number": str(at(p, "number")), "channel": strOr(at(p, "channel"), "sms")}
		}
		if p := at(d, "push"); p != nil {
			push = map[string]any{"devices": num(at(p, "devices"))}
		}
		if m := at(d, "email"); m != nil {
			mail = map[string]any{"to": str(at(m, "to"))}
		}
		return ok(map[string]any{"status": "ok", "totp": yes(at(d, "totp")), "phone": phone, "push": push, "email": mail}, nil)
	case "/sign-in/mfa/email":
		return ok(map[string]any{"status": "sent", "sentTo": str(at(d, "sent_to"))}, nil)
	}
	return ok(map[string]any{"status": "sent", "sentTo": str(at(d, "sent_to")), "channel": strOr(at(d, "channel"), "sms")}, nil)
}

func (a *Auth) signUp(r *http.Request, _ string, b map[string]any) *reply {
	if bad := firstProblem(checkName(b["name"]), checkEmail(b["email"]), a.newPasswordProblem(r, b["password"]), checkOrganization(b["organization"])); bad != nil {
		return invalid(bad)
	}
	email := trimmed(b["email"])
	payload := map[string]any{"email": email, "password": b["password"], "display_name": trimmed(b["name"])}
	if org := trimmed(b["organization"]); org != "" {
		payload["organization"] = map[string]any{"name": org}
	}
	if b["acceptLegal"] == true {
		payload["accept_legal"] = true
	}
	if consents, isObj := b["consents"].(map[string]any); isObj {
		payload["consents"] = consents
	}
	made := a.ask(r, http.MethodPost, "/v1/auth/register", payload, askOpts{page: a.pages.VerifyEmail})
	if made.err != nil {
		field := ""
		if made.err.code == "weak_password" {
			field = "password"
		}
		return refusedWith(made, field, nil)
	}
	// An account that must confirm its address first cannot sign in yet.
	if yes(at(made.data, "verification_required")) {
		return ok(map[string]any{"status": "verification_required", "email": email}, nil)
	}
	n := a.ask(r, http.MethodPost, "/v1/auth/login", map[string]any{"email": email, "password": b["password"]}, askOpts{})
	if n.err != nil || yes(at(n.data, "mfa_required")) {
		return ok(map[string]any{"status": "verification_required", "email": email}, nil)
	}
	return a.signedIn(r, n.data, nil, nil, nil)
}

// forgotPassword answers the same whether or not the address has an account.
func (a *Auth) forgotPassword(r *http.Request, _ string, b map[string]any) *reply {
	if bad := checkEmail(b["email"]); bad != nil {
		return invalid(bad)
	}
	a.ask(r, http.MethodPost, "/v1/auth/password/reset", map[string]any{"email": trimmed(b["email"])}, askOpts{page: a.pages.ResetPassword})
	return ok(map[string]any{"status": "sent"}, nil)
}
