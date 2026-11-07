package cauthy

import (
	"net/http"
	"net/url"
	"slices"
	"strings"
)

// What a mailed link carries back (a reset, a confirmation, an invitation,
// a sign-in link or its code), and the ceremonies that run on the page: a
// passkey and Google One Tap.

func init() {
	for route, h := range map[string]postHandler{
		"/reset-password": (*Auth).resetPassword, "/verify-email": (*Auth).verifyEmail, "/invitation/accept": (*Auth).acceptInvitation,
		"/sign-in/passkey/begin": (*Auth).passkeyBegin, "/sign-in/passkey/finish": (*Auth).passkeyFinish,
		"/sign-in/google-one-tap/begin": (*Auth).oneTapBegin, "/sign-in/google-one-tap": (*Auth).oneTap,
		"/sign-in/magic-link": (*Auth).magicLink, "/sign-in/email-code": (*Auth).emailCode, "/sign-in/magic-link/verify": (*Auth).magicLinkVerify,
	} {
		ownPOST[route] = h
	}
}

// isToken is a link's token: a string of 1 to 512 characters.
func isToken(v any) bool {
	s, isStr := v.(string)
	return isStr && s != "" && utf16Len(s) <= 512
}

func badLink() *reply {
	return problem(422, "invalid_token", "This link is not valid, or it has expired.", "", nil, nil)
}

// weakField is "password" for Cauthy's weak_password, else "".
func weakField(code string) string {
	if code == "weak_password" {
		return "password"
	}
	return ""
}

func (a *Auth) resetPassword(r *http.Request, _ string, b map[string]any) *reply {
	if !isToken(b["token"]) {
		return badLink()
	}
	if bad := a.newPasswordProblem(r, b["password"]); bad != nil {
		return invalid(bad)
	}
	n := a.ask(r, http.MethodPost, "/v1/auth/password/change", map[string]any{"token": b["token"], "new_password": b["password"]}, askOpts{})
	if n.err != nil {
		return refusedWith(n, weakField(n.err.code), nil)
	}
	return ok(map[string]any{"status": "changed"}, nil)
}

// verifyEmail confirms an address; Cauthy signs the person in from the link
// unless their account asks a second step.
func (a *Auth) verifyEmail(r *http.Request, _ string, b map[string]any) *reply {
	if !isToken(b["token"]) {
		return badLink()
	}
	n := a.ask(r, http.MethodPost, "/v1/auth/email/verify", map[string]any{"token": b["token"]}, askOpts{})
	if n.err != nil {
		return problem(n.status, n.err.code, n.err.message, "", nil, nil)
	}
	if str(at(n.data, "access_token")) != "" {
		return a.signedIn(r, n.data, nil, nil, nil)
	}
	return ok(map[string]any{"status": "verified"}, nil)
}

// acceptInvitation takes the password the person chose and signs them in
// like a password sign-in. A refused password does not spend the invitation.
func (a *Auth) acceptInvitation(r *http.Request, _ string, b map[string]any) *reply {
	if !isToken(b["token"]) {
		return problem(422, "invalid_token", "This invitation is not valid, or it has expired.", "", nil, nil)
	}
	if bad := a.newPasswordProblem(r, b["password"]); bad != nil {
		return invalid(bad)
	}
	n := a.ask(r, http.MethodPost, "/v1/auth/invitation/accept", map[string]any{"token": b["token"], "password": b["password"]}, askOpts{})
	if n.err != nil {
		return refusedWith(n, weakField(n.err.code), nil)
	}
	return a.loggedIn(r, n.data, false)
}

// options is what the browser is asked for in a passkey ceremony.
func options(d any) any {
	if pk := at(d, "options", "publicKey"); pk != nil {
		return pk
	}
	return at(d, "options")
}

// isCredential is what the browser answered a passkey ceremony with.
func isCredential(v any) bool {
	m, isObj := v.(map[string]any)
	if !isObj {
		return false
	}
	_, idOK := m["id"].(string)
	_, resOK := m["response"].(map[string]any)
	return idOK && resOK
}

func (a *Auth) passkeyBegin(r *http.Request, _ string, b map[string]any) *reply {
	payload := map[string]any{}
	if _, isStr := b["email"].(string); isStr && checkEmail(b["email"]) == nil {
		payload["email"] = trimmed(b["email"])
	}
	remember := wants(b["remember"])
	n := a.ask(r, http.MethodPost, "/v1/auth/webauthn/login/begin", payload, askOpts{remember: remember})
	if n.err != nil {
		return problem(n.status, n.err.code, n.err.message, "", nil, nil)
	}
	cookie := a.stepCookieFor(r, step{Kind: "passkey", Token: str(at(n.data, "session_id")), ReturnTo: a.afterSignIn, Remember: remember}, passkeySeconds)
	return ok(map[string]any{"status": "started", "options": options(n.data)}, nil).with(cookie)
}

// passkeyFailed are Cauthy's codes for a ceremony that did not hold: which
// check failed is Cauthy's to log; the page says only that it did.
var passkeyFailed = []string{"assertion_invalid", "session_expired", "clone_detected", "not_found"}

func (a *Auth) passkeyFinish(r *http.Request, _ string, b map[string]any) *reply {
	s := a.readStep(r)
	if s == nil || s.Kind != "passkey" {
		return stepExpired("Try the passkey again: it was asked for too long ago.", nil)
	}
	if !isCredential(b["credential"]) {
		return problem(http.StatusBadRequest, "bad_request", "Send the passkey the browser answered with.", "", nil, nil)
	}
	n := a.ask(r, http.MethodPost, "/v1/auth/webauthn/login/finish", map[string]any{"session_id": s.Token, "credential": b["credential"]},
		askOpts{remember: s.Remember || wants(b["remember"])})
	clear := a.clearStep(r)
	if n.err != nil {
		if slices.Contains(passkeyFailed, n.err.code) {
			return problem(n.status, "passkey_failed", "The passkey sign-in could not be completed. Try again, or sign in another way.", "", nil, nil).with(clear)
		}
		return problem(n.status, n.err.code, n.err.message, "", nil, nil).with(clear)
	}
	return a.signedIn(r, n.data, []string{clear}, nil, nil)
}

func (a *Auth) oneTapBegin(r *http.Request, _ string, _ map[string]any) *reply {
	n := a.ask(r, http.MethodPost, "/v1/auth/google/one-tap/begin", map[string]any{}, askOpts{})
	if n.err != nil {
		return problem(n.status, n.err.code, n.err.message, "", nil, nil)
	}
	return ok(map[string]any{"status": "started", "clientId": str(at(n.data, "client_id")), "nonce": str(at(n.data, "nonce"))}, nil)
}

func (a *Auth) oneTap(r *http.Request, _ string, b map[string]any) *reply {
	cred, isStr := b["credential"].(string)
	if !isStr || cred == "" {
		return problem(http.StatusBadRequest, "bad_request", "Send the credential Google gave the page.", "", nil, nil)
	}
	n := a.ask(r, http.MethodPost, "/v1/auth/google/one-tap", map[string]any{"credential": cred}, askOpts{remember: wants(b["remember"])})
	if n.err != nil {
		return problem(n.status, n.err.code, n.err.message, "", nil, nil)
	}
	return a.signedIn(r, n.data, nil, nil, nil)
}

// magicLink asks Cauthy to mail a sign-in link (and its code), opened on the
// application's sign-in page. The same answer whether or not the address has
// an account.
func (a *Auth) magicLink(r *http.Request, _ string, b map[string]any) *reply {
	if bad := checkEmail(b["email"]); bad != nil {
		return invalid(bad)
	}
	if a.pages.SignIn == "" {
		return problem(http.StatusInternalServerError, "not_configured", "cauthy: Pages.SignIn is required for sign-in links: it is the page the link opens", "", nil, nil)
	}
	email := trimmed(b["email"])
	back := a.afterSignIn
	if s, isStr := b["returnTo"].(string); isStr {
		back = localPath(s, a.afterSignIn)
	}
	remember := wants(b["remember"])
	q := url.Values{}
	if back != a.afterSignIn {
		q.Set("return_to", back)
	}
	if remember {
		q.Set("remember", "1")
	}
	page := a.pages.SignIn
	if len(q) > 0 {
		sep := "?"
		if strings.Contains(page, "?") {
			sep = "&"
		}
		page += sep + q.Encode()
	}
	payload := map[string]any{"email": email}
	if b["create"] == true {
		payload["create_account"] = true
	}
	a.ask(r, http.MethodPost, "/v1/auth/magic-link/request", payload, askOpts{page: page})
	// Whose code it is stays sealed here, so the page asks only for the code.
	cookie := a.stepCookieFor(r, step{Kind: "code", Token: email, ReturnTo: back, Remember: remember}, stepSeconds)
	return ok(map[string]any{"status": "sent"}, nil).with(cookie)
}

func (a *Auth) emailCode(r *http.Request, _ string, b map[string]any) *reply {
	if bad := checkCode(b["code"]); bad != nil {
		return invalid(bad)
	}
	s := a.readStep(r)
	if s == nil || s.Kind != "code" {
		return stepExpired("Ask for a new link: this one was asked for too long ago.", nil)
	}
	n := a.ask(r, http.MethodPost, "/v1/auth/magic-link/verify-code", map[string]any{"email": s.Token, "code": trimmed(b["code"])}, askOpts{remember: s.Remember})
	if n.err != nil {
		return problem(n.status, n.err.code, n.err.message, "code", nil, nil)
	}
	return a.signedIn(r, n.data, []string{a.clearStep(r)}, map[string]any{"returnTo": s.ReturnTo}, nil)
}

func (a *Auth) magicLinkVerify(r *http.Request, _ string, b map[string]any) *reply {
	if !isToken(b["token"]) {
		return badLink()
	}
	n := a.ask(r, http.MethodPost, "/v1/auth/magic-link/verify", map[string]any{"token": b["token"]}, askOpts{remember: wants(b["remember"])})
	if n.err != nil {
		return problem(n.status, n.err.code, n.err.message, "", nil, nil)
	}
	return a.signedIn(r, n.data, nil, nil, nil)
}
