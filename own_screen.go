package cauthy

import (
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// What the sign-in form reads before anything is typed: how the workspace
// looks, which methods it offers, and an invitation.

const lookTTL = time.Minute

func init() {
	ownGET["/look"] = (*Auth).lookRoute
	ownGET["/methods"] = (*Auth).methodsRoute
	ownGET["/invitation"] = (*Auth).invitationRoute
}

// lookRoute is how the forms look, as a person set it in Cauthy's
// dashboard. Kept a minute.
func (a *Auth) lookRoute(r *http.Request, _ string) *reply {
	a.cacheMu.Lock()
	hit := a.look
	a.cacheMu.Unlock()
	if hit == nil || a.now().After(hit.until) {
		n := a.ask(r, http.MethodGet, "/v1/auth/look/"+url.PathEscape(a.clientID), nil, askOpts{})
		look := n.data
		if n.err != nil || look == nil {
			look = map[string]any{}
		}
		hit = &timed{until: a.now().Add(lookTTL), value: look}
		a.cacheMu.Lock()
		a.look = hit
		a.cacheMu.Unlock()
	}
	return ok(hit.value, nil)
}

// keepPolicy keeps the workspace's password policy a minute, from the
// settings Cauthy answered; nil when Cauthy did not say.
func (a *Auth) keepPolicy(settings asked) *PasswordPolicy {
	var p *PasswordPolicy
	if settings.err == nil && at(settings.data, "password_policy") != nil {
		pp := policyOf(at(settings.data, "password_policy"))
		p = &pp
	}
	a.cacheMu.Lock()
	a.policy = &timed{until: a.now().Add(lookTTL), value: p}
	a.cacheMu.Unlock()
	return p
}

// workspacePolicy is the workspace's password policy; nil when Cauthy
// cannot say, and then only Cauthy checks.
func (a *Auth) workspacePolicy(r *http.Request) *PasswordPolicy {
	a.cacheMu.Lock()
	hit := a.policy
	a.cacheMu.Unlock()
	if hit != nil && !a.now().After(hit.until) {
		p, _ := hit.value.(*PasswordPolicy)
		return p
	}
	return a.keepPolicy(a.ask(r, http.MethodGet, "/v1/auth/settings", nil, askOpts{}))
}

// newPasswordProblem checks a new password against the workspace's rule
// when it is known; otherwise only what no workspace accepts (8–128).
func (a *Auth) newPasswordProblem(r *http.Request, v any) *fieldProblem {
	if p := a.workspacePolicy(r); p != nil {
		return checkNewPassword(v, *p)
	}
	return checkNewPassword(v, loosePolicy())
}

// methodsRoute says what the screen may offer.
func (a *Auth) methodsRoute(r *http.Request, _ string) *reply {
	var providers, settings, place, sso asked
	var wg sync.WaitGroup
	for _, c := range []struct {
		into *asked
		path string
	}{
		{&providers, "/v1/auth/social/providers"}, {&settings, "/v1/auth/settings"},
		{&place, "/v1/auth/webauthn/place?origin=" + url.QueryEscape(a.originOf(r))}, {&sso, "/v1/auth/sso/connections"},
	} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			*c.into = a.ask(r, http.MethodGet, c.path, nil, askOpts{})
		}()
	}
	wg.Wait()
	password := a.keepPolicy(settings)
	s := settings.data
	passkeys := at(s, "allow_passkeys") != false
	here := passkeys && yes(at(place.data, "here"))
	list := []any{}
	for _, p := range arr(providers.data) {
		id := str(at(p, "provider"))
		if id == "" {
			id = str(at(p, "id"))
		}
		if id == "" {
			continue
		}
		name := str(at(p, "label"))
		if name == "" {
			name = str(at(p, "name"))
		}
		if name == "" {
			name = id
		}
		item := map[string]any{"id": id, "name": name}
		if icon := a.iconOf(p); icon != "" {
			item["iconUrl"] = icon
		}
		list = append(list, item)
	}
	discoverable := false
	for _, c := range arr(sso.data) {
		if yes(at(c, "discoverable")) {
			discoverable = true
		}
	}
	out := map[string]any{
		"providers":       list,
		"passwordSignIn":  at(s, "allow_password") != false,
		"signUp":          at(s, "allow_signup") != false && at(s, "signup", "mode") != "invite_only",
		"magicLink":       yes(at(s, "allow_magic_link")) && a.pages.SignIn != "",
		"passkey":         passkeys && (place.err != nil || here || yes(at(place.data, "on_cauthy"))),
		"passkeyHere":     here,
		"passkeyOnCauthy": passkeys && (place.err != nil || yes(at(place.data, "on_cauthy"))),
		"sso":             discoverable,
	}
	if yes(at(s, "signup", "organization", "ask")) {
		out["organization"] = map[string]any{"ask": true, "required": yes(at(s, "signup", "organization", "required"))}
	}
	if p, isBool := at(s, "persistent_sessions").(bool); isBool {
		out["persistentSessions"] = p
	}
	if legal := at(s, "legal"); legal != nil {
		out["legal"] = legalOf(legal)
	}
	if yes(at(s, "captcha_enabled")) && str(at(s, "captcha_site_key")) != "" {
		out["captchaSiteKey"] = str(at(s, "captcha_site_key"))
	}
	if password != nil {
		out["password"] = password
	}
	return ok(out, nil)
}

// iconOf is a provider's logo: an address of Cauthy's own path read against
// the issuer; only http(s) passed on.
func (a *Auth) iconOf(p any) string {
	raw := strings.TrimSpace(str(at(p, "icon_url")))
	if raw == "" {
		return ""
	}
	if strings.HasPrefix(raw, "/") && !strings.HasPrefix(raw, "//") {
		raw = a.issuer + raw
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return ""
	}
	return u.String()
}

// legalOf is what a sign-up form shows for the law.
func legalOf(raw any) map[string]any {
	docs, purposes := []any{}, []any{}
	for _, d := range arr(at(raw, "documents")) {
		docs = append(docs, map[string]any{"kind": str(at(d, "kind")), "version": str(at(d, "version")), "url": str(at(d, "url"))})
	}
	for _, p := range arr(at(raw, "consent_purposes")) {
		purposes = append(purposes, map[string]any{"key": str(at(p, "key")), "label": str(at(p, "label")), "required": yes(at(p, "required"))})
	}
	return map[string]any{"documents": docs, "consentPurposes": purposes}
}

// invitationRoute reads an invitation before the person chooses a
// password: who is invited to what. Reading it does not spend it.
func (a *Auth) invitationRoute(r *http.Request, _ string) *reply {
	token := strings.TrimSpace(r.URL.Query().Get("token"))
	if token == "" || utf16Len(token) > 512 {
		return problem(422, "invalid_token", "This invitation is not valid, or it has expired.", "", nil, nil)
	}
	n := a.ask(r, http.MethodGet, "/v1/auth/invitation?token="+url.QueryEscape(token), nil, askOpts{})
	if n.err != nil {
		return refusedWith(n, "", nil)
	}
	inv := map[string]any{"email": str(at(n.data, "email")), "workspace": str(at(n.data, "workspace"))}
	if o, isStr := at(n.data, "organization").(string); isStr && o != "" {
		inv["organization"] = o
	}
	return ok(map[string]any{"status": "ok", "invitation": inv}, nil)
}
