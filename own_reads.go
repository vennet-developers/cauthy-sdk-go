package cauthy

import (
	"context"
	"net/http"
	"net/url"
	"strings"
)

// The person's own account, read: identities, passkeys, agents,
// organizations and their people, second-step factors, sessions, the legal
// documents pending, the account itself; and the push approval as it streams.

func init() {
	for route, h := range map[string]getHandler{
		"/me/identities": (*Auth).identitiesRoute, "/me/passkeys": (*Auth).passkeysRoute, "/me/agents": (*Auth).agentsRoute,
		"/me/organizations": (*Auth).organizationsRoute, "/me/organizations/members": (*Auth).organizationsRoute,
		"/me/organizations/roles": (*Auth).organizationsRoute, "/me/mfa/factors": (*Auth).factorsRoute,
		"/me": (*Auth).accountRoute, "/me/sessions": (*Auth).accountRoute, "/me/legal": (*Auth).accountRoute,
		"/sign-in/mfa/push/events": (*Auth).pushEvents,
	} {
		ownGET[route] = h
	}
}

// readAs asks Cauthy for path as the signed-in person and answers what it
// put under data, or the reply to give instead.
func (a *Auth) readAs(r *http.Request, path string) (any, *person, *reply) {
	mine, refused := a.signedInAs(r)
	if refused != nil {
		return nil, nil, refused
	}
	n := a.ask(r, http.MethodGet, path, nil, askOpts{bearer: mine.token})
	if n.err != nil {
		return nil, nil, problem(n.status, n.err.code, n.err.message, "", mine.header, nil)
	}
	return n.data, mine, nil
}

func mapList(v any, f func(any) map[string]any) []any {
	out := []any{}
	for _, x := range arr(v) {
		out = append(out, f(x))
	}
	return out
}

func (a *Auth) identitiesRoute(r *http.Request, _ string) *reply {
	data, mine, rep := a.readAs(r, "/v1/auth/identities")
	if rep != nil {
		return rep
	}
	return ok(map[string]any{"identities": mapList(data, func(x any) map[string]any {
		return map[string]any{"provider": str(at(x, "provider")), "email": str(at(x, "email")), "name": str(at(x, "name")), "linkedAt": str(at(x, "linked_at"))}
	})}, mine.header)
}

// passkeyOf is a passkey as the page reads it.
func passkeyOf(d any) map[string]any {
	kind := str(at(d, "kind"))
	if kind != "security_key" && kind != "synced" && kind != "device" {
		kind = "unknown"
	}
	var last any
	if s := str(at(d, "last_used_at")); s != "" {
		last = s
	}
	return map[string]any{"id": str(at(d, "id")), "name": str(at(d, "nickname")), "kind": kind, "createdAt": str(at(d, "created_at")), "lastUsedAt": last}
}

func (a *Auth) passkeysRoute(r *http.Request, _ string) *reply {
	data, mine, rep := a.readAs(r, "/v1/auth/webauthn/credentials")
	if rep != nil {
		return rep
	}
	return ok(map[string]any{"passkeys": mapList(data, passkeyOf)}, mine.header)
}

func (a *Auth) agentsRoute(r *http.Request, _ string) *reply {
	data, mine, rep := a.readAs(r, "/v1/auth/me/agents")
	if rep != nil {
		return rep
	}
	return ok(map[string]any{"agents": mapList(data, func(d any) map[string]any {
		scopes := mapList(at(d, "scopes"), func(s any) map[string]any {
			return map[string]any{"name": str(at(s, "name")), "description": str(at(s, "description"))}
		})
		return map[string]any{"id": str(at(d, "id")), "name": str(at(d, "agent", "name")), "redirectHost": str(at(d, "agent", "redirect_host")),
			"resource": map[string]any{"name": str(at(d, "resource", "name")), "uri": str(at(d, "resource", "uri"))},
			"scopes":   scopes, "connectedAt": str(at(d, "created_at")), "lastUsedAt": str(at(d, "last_used_at"))}
	})}, mine.header)
}

// seatOf is an organization the person belongs to, with what they may do
// with it and its people.
func seatOf(d any) map[string]any {
	c := func(name string) bool { return yes(at(d, "can", name)) }
	return map[string]any{"id": str(at(d, "id")), "system": str(at(d, "system")), "name": str(at(d, "name")), "kind": str(at(d, "kind")),
		"role": str(at(d, "role")), "can": map[string]any{"readMembers": c("read_members"), "manageMembers": c("manage_members"),
			"removeMembers": c("remove_members"), "update": c("update"), "archive": c("archive"), "delete": c("delete")}}
}

// orgMemberOf is a person of an organization, as a member who may see them reads it.
func orgMemberOf(d any) map[string]any {
	return map[string]any{"userId": str(at(d, "user_id")), "email": str(at(d, "email")), "name": str(at(d, "name")), "role": str(at(d, "role")),
		"status": str(at(d, "status")), "invited": yes(at(d, "invited")), "manager": yes(at(d, "manager")), "you": yes(at(d, "you")), "since": str(at(d, "since"))}
}

func orgRoleOf(d any) map[string]any {
	return map[string]any{"role": str(at(d, "role")), "name": str(at(d, "name")), "description": str(at(d, "description")), "manager": yes(at(d, "manager"))}
}

// organizationsRoute: the person's organizations, and the people and roles
// of one, as far as their role lets them see.
func (a *Auth) organizationsRoute(r *http.Request, route string) *reply {
	mine, refused := a.signedInAs(r)
	if refused != nil {
		return refused
	}
	path := "/v1/auth/me/organizations"
	q := r.URL.Query()
	if route != "/me/organizations" {
		id := q.Get("id")
		if !looseUUID.MatchString(id) {
			return problem(http.StatusBadRequest, "invalid_organization", "Say which organization.", "", mine.header, nil)
		}
		kind := "members"
		if strings.HasSuffix(route, "/roles") {
			kind = "roles"
		}
		path += "/" + id + "/" + kind
	} else if sys := q.Get("system"); sys != "" {
		path += "?system=" + url.QueryEscape(sys)
	}
	n := a.ask(r, http.MethodGet, path, nil, askOpts{bearer: mine.token})
	if n.err != nil {
		return problem(n.status, n.err.code, n.err.message, "", mine.header, nil)
	}
	switch route {
	case "/me/organizations":
		return ok(map[string]any{"organizations": mapList(n.data, seatOf)}, mine.header)
	case "/me/organizations/roles":
		return ok(map[string]any{"roles": mapList(n.data, orgRoleOf)}, mine.header)
	}
	return ok(map[string]any{"members": mapList(n.data, orgMemberOf)}, mine.header)
}

// factorsOf is how an account takes its second step.
func factorsOf(d any) map[string]any {
	var phone any
	if p := at(d, "phone"); p != nil {
		phone = map[string]any{"number": str(at(p, "number")), "channel": strOr(at(p, "channel"), "sms")}
	}
	return map[string]any{"totp": yes(at(d, "totp")), "phone": phone, "phoneChannels": strs(at(d, "phone_channels"))}
}

func (a *Auth) factorsRoute(r *http.Request, _ string) *reply {
	data, mine, rep := a.readAs(r, "/v1/auth/mfa/factors")
	if rep != nil {
		return rep
	}
	return ok(factorsOf(data), mine.header)
}

// accountOf is the account as the page reads it.
func accountOf(d any) map[string]any {
	return map[string]any{"id": str(at(d, "id")), "email": str(at(d, "email")), "name": str(at(d, "name")),
		"emailVerified": yes(at(d, "email_verified")), "hasPassword": yes(at(d, "has_password")), "mfaEnabled": yes(at(d, "mfa_enabled"))}
}

func (a *Auth) accountRoute(r *http.Request, route string) *reply {
	path := map[string]string{"/me": "/v1/auth/me", "/me/legal": "/v1/auth/me/legal", "/me/sessions": "/v1/auth/me/sessions"}[route]
	data, mine, rep := a.readAs(r, path)
	if rep != nil {
		return rep
	}
	switch route {
	case "/me/legal":
		return ok(map[string]any{"pending": mapList(at(data, "pending"), func(d any) map[string]any {
			return map[string]any{"kind": str(at(d, "kind")), "version": str(at(d, "version")), "url": str(at(d, "url"))}
		})}, mine.header)
	case "/me/sessions":
		return ok(map[string]any{"sessions": mapList(data, func(x any) map[string]any {
			return map[string]any{"device": str(at(x, "device")), "ip": str(at(x, "ip")), "createdAt": str(at(x, "created_at")), "expiresAt": str(at(x, "expires_at"))}
		})}, mine.header)
	}
	return ok(map[string]any{"account": accountOf(data)}, mine.header)
}

// pushEvents passes Cauthy's server-sent events of a push approval through
// to the page that waits on them. The request's deadline covers the first
// answer only; the stream lives as long as the page does.
func (a *Auth) pushEvents(r *http.Request, _ string) *reply {
	s := a.readStep(r)
	if s == nil || s.Kind != "mfa" {
		return stepExpired("Sign in again: the code was asked for too long ago.", nil)
	}
	ctx, cancel := context.WithCancel(r.Context())
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, a.issuer+"/v1/auth/mfa/push/events", nil)
	req.Header = http.Header{"X-Tenant-Key": {a.tenant}, "X-Mfa-Token": {s.Token}, "Accept": {"text/event-stream"}}
	type result struct {
		res *http.Response
		err error
	}
	first := make(chan result, 1)
	go func() {
		res, err := a.http.Do(req)
		first <- result{res, err}
	}()
	var got result
	select {
	case got = <-first:
	case <-timeAfter(a.requestTimeout):
		cancel()
		got = <-first
	}
	if got.err != nil {
		cancel()
		return problem(http.StatusServiceUnavailable, "unavailable", "Cauthy could not be reached.", "", nil, nil)
	}
	if got.res.StatusCode < 200 || got.res.StatusCode > 299 {
		defer cancel()
		defer got.res.Body.Close()
		n := answerOf(got.res)
		code, message := "error", "The request could not be completed."
		if list := arr(at(n, "errors")); len(list) > 0 {
			code, message = strOr(at(list[0], "code"), code), strOr(at(list[0], "message"), message)
		}
		return problem(got.res.StatusCode, code, message, "", nil, nil)
	}
	rep := newReply(http.StatusOK, nil)
	rep.header.Set("Content-Type", "text/event-stream")
	rep.header.Set("Cache-Control", "no-cache, no-store")
	rep.header.Set("X-Accel-Buffering", "no")
	rep.stream = cancelOnClose{got.res.Body, cancel}
	return rep
}
