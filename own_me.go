package cauthy

import (
	"net/http"
	"slices"
)

// The person's own account, changed: name, legal acceptance, password,
// second step, address, linked providers, passkeys, and a guest becoming an
// account. Every route runs as the signed-in person (ownRoute's /me gate).

func init() {
	for route, h := range map[string]meHandler{
		"/me": (*Auth).saveAccount, "/me/legal/accept": (*Auth).acceptLegal, "/me/password": (*Auth).changePassword,
		"/me/mfa/setup": (*Auth).mfaChange, "/me/mfa/verify": (*Auth).mfaChange, "/me/mfa/phone": (*Auth).mfaChange,
		"/me/mfa/phone/verify": (*Auth).mfaChange, "/me/mfa/phone/remove": (*Auth).mfaChange, "/me/mfa/disable": (*Auth).mfaChange,
		"/me/mfa/recovery-codes": (*Auth).mfaChange, "/me/email": (*Auth).changeEmail, "/me/identities/unlink": (*Auth).unlink,
		"/me/passkeys/add/begin": (*Auth).passkeyAddBegin, "/me/passkeys/add/finish": (*Auth).passkeyAddFinish,
		"/me/passkeys/remove": (*Auth).passkeyRemove, "/me/upgrade": (*Auth).upgrade,
	} {
		ownMe[route] = h
	}
}

// as asks Cauthy for path as the person.
func (a *Auth) as(r *http.Request, p *person, method, path string, payload any) asked {
	return a.ask(r, method, path, payload, askOpts{bearer: p.token})
}

// passwordOf is the current password a route that weakens the account asks
// for again; "" for an account with none.
func passwordOf(b map[string]any) string {
	s, _ := b["password"].(string)
	return s
}

// stepUpField is "password" when Cauthy asked for the password again.
func stepUpField(code string) string {
	if code == "step_up_required" {
		return "password"
	}
	return ""
}

func (a *Auth) saveAccount(r *http.Request, _ string, b map[string]any, p *person) *reply {
	if bad := checkName(b["name"]); bad != nil {
		return invalid(bad)
	}
	n := a.as(r, p, http.MethodPatch, "/v1/auth/me", map[string]any{"name": trimmed(b["name"])})
	if n.err != nil {
		return refusedWith(n, "name", p.header)
	}
	// The name is part of the session: the cookie says the new one at once.
	rep := ok(map[string]any{"status": "saved", "account": accountOf(n.data)}, p.header)
	if p.kept != nil {
		again, err := a.toStored(r.Context(), map[string]any{"access_token": p.kept.AT, "refresh_token": p.kept.RT,
			"expires_in": float64(max(1, p.kept.Exp-a.now().Unix()))}, p.kept)
		if rep := orUnverified(err); rep != nil {
			return rep
		}
		if again != nil {
			rep.with(a.write(r, again, readCookies(r))...)
		}
	}
	return rep
}

func (a *Auth) acceptLegal(r *http.Request, _ string, b map[string]any, p *person) *reply {
	kinds := []string{}
	for _, k := range arr(b["kinds"]) {
		if s, isStr := k.(string); isStr {
			kinds = append(kinds, s)
		}
	}
	n := a.as(r, p, http.MethodPost, "/v1/auth/me/legal/accept", map[string]any{"kinds": kinds})
	if n.err != nil {
		return refusedWith(n, "", p.header)
	}
	return ok(map[string]any{"status": "accepted"}, p.header)
}

// changePassword ends every session of the account; Cauthy answers a new one
// for this browser, which just proved the password.
func (a *Auth) changePassword(r *http.Request, _ string, b map[string]any, p *person) *reply {
	if bad := a.newPasswordProblem(r, b["newPassword"]); bad != nil {
		return problem(http.StatusBadRequest, bad.code, bad.message, "newPassword", nil, nil)
	}
	n := a.as(r, p, http.MethodPost, "/v1/auth/me/password", map[string]any{"current_password": passwordOf(b), "new_password": b["newPassword"]})
	if n.err != nil {
		field := map[string]string{"wrong_password": "password", "weak_password": "newPassword"}[n.err.code]
		return refusedWith(n, field, p.header)
	}
	had, was, _ := a.read(r)
	next, err := a.toStored(r.Context(), n.data, was)
	if rep := orUnverified(err); rep != nil {
		return rep
	}
	rep := ok(map[string]any{"status": "changed", "signedIn": next != nil}, nil)
	if next != nil {
		return rep.with(a.write(r, next, had)...)
	}
	return rep.with(a.clearSession(r, had)...)
}

func recoveryCodes(d any) []string { return strs(at(d, "recovery_codes")) }

// mfaChange turns the second step on and off.
func (a *Auth) mfaChange(r *http.Request, route string, b map[string]any, p *person) *reply {
	password := passwordOf(b)
	switch route {
	case "/me/mfa/setup":
		n := a.as(r, p, http.MethodPost, "/v1/auth/mfa/setup", map[string]any{"password": password})
		if n.err != nil {
			return refusedWith(n, stepUpField(n.err.code), p.header)
		}
		// The QR comes drawn by Cauthy; only a PNG data: URI goes on to the page.
		qr := str(at(n.data, "qr"))
		if len(qr) < 22 || qr[:22] != "data:image/png;base64," {
			qr = ""
		}
		return ok(map[string]any{"status": "started", "secret": str(at(n.data, "secret")), "otpauthUri": str(at(n.data, "otpauth_uri")), "qr": qr}, p.header)
	case "/me/mfa/verify", "/me/mfa/phone/verify":
		if bad := checkCode(b["code"]); bad != nil {
			return invalid(bad)
		}
		path := map[string]string{"/me/mfa/verify": "/v1/auth/mfa/verify", "/me/mfa/phone/verify": "/v1/auth/mfa/phone/verify"}[route]
		n := a.as(r, p, http.MethodPost, path, map[string]any{"code": trimmed(b["code"])})
		if n.err != nil {
			return refusedWith(n, "code", p.header)
		}
		return ok(map[string]any{"status": "enabled", "recoveryCodes": recoveryCodes(n.data)}, p.header)
	case "/me/mfa/phone":
		phone, _ := b["phone"].(string)
		channel, isStr := b["channel"].(string)
		if !isStr {
			channel = "sms"
		}
		n := a.as(r, p, http.MethodPost, "/v1/auth/mfa/phone", map[string]any{"phone": phone, "channel": channel, "password": password})
		if n.err != nil {
			field := map[string]string{"step_up_required": "password", "validation_error": "phone"}[n.err.code]
			return refusedWith(n, field, p.header)
		}
		return ok(map[string]any{"status": "sent", "sentTo": str(at(n.data, "sent_to")), "channel": str(at(n.data, "channel"))}, p.header)
	}
	done := map[string][2]string{
		"/me/mfa/phone/remove":   {"/v1/auth/mfa/phone/remove", "removed"},
		"/me/mfa/disable":        {"/v1/auth/me/mfa/disable", "disabled"},
		"/me/mfa/recovery-codes": {"/v1/auth/me/mfa/recovery-codes", "renewed"},
	}[route]
	n := a.as(r, p, http.MethodPost, done[0], map[string]any{"password": password})
	if n.err != nil {
		return refusedWith(n, stepUpField(n.err.code), p.header)
	}
	body := map[string]any{"status": done[1]}
	if route == "/me/mfa/recovery-codes" {
		body["recoveryCodes"] = recoveryCodes(n.data)
	}
	return ok(body, p.header)
}

// changeEmail asks to change the address; nothing changes until the new
// address confirms it from the link it is sent.
func (a *Auth) changeEmail(r *http.Request, _ string, b map[string]any, p *person) *reply {
	if bad := checkEmail(b["email"]); bad != nil {
		return invalid(bad)
	}
	email := trimmed(b["email"])
	n := a.as(r, p, http.MethodPost, "/v1/auth/me/email", map[string]any{"email": email, "password": passwordOf(b)})
	if n.err != nil {
		field := stepUpField(n.err.code)
		if slices.Contains([]string{"invalid_email", "email_unchanged", "email_taken"}, n.err.code) {
			field = "email"
		}
		return refusedWith(n, field, p.header)
	}
	return ok(map[string]any{"status": "sent", "email": email}, p.header)
}

func (a *Auth) unlink(r *http.Request, _ string, b map[string]any, p *person) *reply {
	prov, _ := b["provider"].(string)
	if !providerRE.MatchString(prov) {
		return problem(http.StatusBadRequest, "invalid_provider", "Say which provider to unlink.", "provider", p.header, nil)
	}
	n := a.as(r, p, http.MethodDelete, "/v1/auth/identities/"+prov, nil)
	if n.err != nil {
		return refusedWith(n, "", p.header)
	}
	return ok(map[string]any{"status": "unlinked", "provider": prov}, p.header)
}

// passkeyAddBegin starts a passkey made on this page; the ceremony's id
// stays sealed here between its two calls.
func (a *Auth) passkeyAddBegin(r *http.Request, _ string, b map[string]any, p *person) *reply {
	payload := map[string]any{"password": passwordOf(b)}
	if kind := b["kind"]; kind == "device" || kind == "security_key" {
		payload["kind"] = kind
	}
	n := a.as(r, p, http.MethodPost, "/v1/auth/webauthn/register/begin", payload)
	if n.err != nil {
		return refusedWith(n, stepUpField(n.err.code), p.header)
	}
	cookie := a.stepCookieFor(r, step{Kind: "enrol", Token: str(at(n.data, "session_id")), ReturnTo: a.afterSignIn}, passkeySeconds)
	return ok(map[string]any{"status": "started", "options": options(n.data)}, p.header).with(cookie)
}

func (a *Auth) passkeyAddFinish(r *http.Request, _ string, b map[string]any, p *person) *reply {
	s := a.readStep(r)
	if s == nil || s.Kind != "enrol" {
		return stepExpired("Start adding the passkey again: it was asked for too long ago.", p.header)
	}
	if !isCredential(b["credential"]) {
		return problem(http.StatusBadRequest, "bad_request", "Send the passkey the browser made.", "", p.header, nil)
	}
	name := trimmed(b["name"])
	if runes := []rune(name); len(runes) > 60 {
		name = string(runes[:60])
	}
	n := a.as(r, p, http.MethodPost, "/v1/auth/webauthn/register/finish", map[string]any{"session_id": s.Token, "nickname": name, "credential": b["credential"]})
	clear := a.clearStep(r)
	if n.err != nil {
		if n.err.code == "attestation_invalid" {
			return problem(n.status, "passkey_failed", "The passkey could not be added. Try again.", "", p.header, nil).with(clear)
		}
		return problem(n.status, n.err.code, n.err.message, "", p.header, nil).with(clear)
	}
	return ok(map[string]any{"status": "added", "passkey": passkeyOf(n.data)}, p.header).with(clear)
}

func (a *Auth) passkeyRemove(r *http.Request, _ string, b map[string]any, p *person) *reply {
	id, _ := b["id"].(string)
	if !looseUUID.MatchString(id) {
		return problem(http.StatusBadRequest, "invalid_passkey", "Say which passkey to remove.", "", p.header, nil)
	}
	n := a.as(r, p, http.MethodDelete, "/v1/auth/webauthn/credentials/"+id, nil)
	if n.err != nil {
		return refusedWith(n, "", p.header)
	}
	return ok(map[string]any{"status": "removed", "id": id}, p.header)
}

// upgrade: a guest becoming an account of their own. Deprecated.
func (a *Auth) upgrade(r *http.Request, _ string, b map[string]any, p *person) *reply {
	if bad := firstProblem(checkName(b["name"]), checkEmail(b["email"]), a.newPasswordProblem(r, b["password"])); bad != nil {
		return invalid(bad)
	}
	n := a.as(r, p, http.MethodPost, "/v1/auth/anonymous/upgrade", map[string]any{"email": trimmed(b["email"]), "password": b["password"], "display_name": trimmed(b["name"])})
	if n.err != nil {
		field := "email"
		if n.err.code == "weak_password" {
			field = "password"
		}
		return refusedWith(n, field, p.header)
	}
	_, was, _ := a.read(r)
	return a.signedIn(r, n.data, nil, nil, was)
}
