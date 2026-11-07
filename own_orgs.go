package cauthy

import "net/http"

// A member administering their organization and its people, AI agents the
// person connected, and signing out everywhere. Cauthy decides each by the
// person's role.

func init() {
	for _, route := range []string{"/me/organizations/rename", "/me/organizations/archive", "/me/organizations/delete"} {
		ownMe[route] = (*Auth).organizationChange
	}
	for _, route := range []string{"/me/organizations/members/add", "/me/organizations/members/role", "/me/organizations/members/remove", "/me/organizations/members/invite"} {
		ownMe[route] = (*Auth).memberChange
	}
	ownMe["/me/agents/disconnect"] = (*Auth).disconnectAgent
	ownMe["/me/sessions/end"] = (*Auth).endSessions
}

func (a *Auth) organizationChange(r *http.Request, route string, b map[string]any, p *person) *reply {
	org, _ := b["organizationId"].(string)
	if !looseUUID.MatchString(org) {
		return problem(http.StatusBadRequest, "invalid_organization", "Say which organization.", "", p.header, nil)
	}
	path := "/v1/auth/me/organizations/" + org
	if route == "/me/organizations/rename" {
		if bad := checkOrganizationName(b["name"]); bad != nil {
			return invalid(bad)
		}
		n := a.as(r, p, http.MethodPatch, path, map[string]any{"name": trimmed(b["name"])})
		if n.err != nil {
			field := ""
			if n.err.code == "validation_error" {
				field = "name"
			}
			return refusedWith(n, field, p.header)
		}
		a.forgetOrganizations(p.token) // the session's organizations carry the name
		return ok(map[string]any{"status": "renamed", "organization": seatOf(n.data)}, p.header)
	}
	var n asked
	status := "deleted"
	if route == "/me/organizations/archive" {
		n, status = a.as(r, p, http.MethodPost, path+"/archive", nil), "archived"
	} else {
		n = a.as(r, p, http.MethodDelete, path, nil)
	}
	if n.err != nil {
		return refusedWith(n, "", p.header)
	}
	a.forgetOrganizations(p.token)
	return ok(map[string]any{"status": status, "organizationId": org}, p.header)
}

func (a *Auth) memberChange(r *http.Request, route string, b map[string]any, p *person) *reply {
	org, _ := b["organizationId"].(string)
	if !looseUUID.MatchString(org) {
		return problem(http.StatusBadRequest, "invalid_organization", "Say which organization.", "", p.header, nil)
	}
	base := "/v1/auth/me/organizations/" + org + "/members"
	locale, _ := b["locale"].(string)
	if route == "/me/organizations/members/add" {
		if bad := checkEmail(b["email"]); bad != nil {
			return invalid(bad)
		}
		role, _ := b["role"].(string)
		if role == "" {
			return problem(http.StatusBadRequest, "invalid_role", "Choose a role.", "role", p.header, nil)
		}
		// Adding never changes the role of somebody already there; a person
		// new to the workspace is invited, the mail opening this
		// application's page for it when it has one.
		payload := map[string]any{"email": trimmed(b["email"]), "role": role, "name": trimmed(b["name"]), "client_id": a.clientID, "only_new": true}
		if locale != "" {
			payload["locale"] = locale
		}
		n := a.ask(r, http.MethodPost, base, payload, askOpts{page: a.pages.AcceptInvite, bearer: p.token})
		if n.err != nil && n.err.code == "already_member" {
			n.err.code = "member_exists" // one code, whichever route answered it
		}
		if n.err != nil {
			field := "email"
			if n.err.code == "unknown_role" {
				field = "role"
			}
			return refusedWith(n, field, p.header)
		}
		return ok(map[string]any{"status": "added", "member": orgMemberOf(n.data)}, p.header)
	}
	user, _ := b["userId"].(string)
	if !looseUUID.MatchString(user) {
		return problem(http.StatusBadRequest, "invalid_member", "Say which member.", "", p.header, nil)
	}
	switch route {
	case "/me/organizations/members/role":
		role, _ := b["role"].(string)
		if role == "" {
			return problem(http.StatusBadRequest, "invalid_role", "Choose a role.", "role", p.header, nil)
		}
		n := a.as(r, p, http.MethodPut, base+"/"+user, map[string]any{"role": role})
		if n.err != nil {
			return refusedWith(n, "role", p.header)
		}
		return ok(map[string]any{"status": "changed", "userId": user, "role": role}, p.header)
	case "/me/organizations/members/remove":
		n := a.as(r, p, http.MethodDelete, base+"/"+user, nil)
		if n.err != nil {
			return refusedWith(n, "", p.header)
		}
		a.forgetOrganizations(p.token)
		return ok(map[string]any{"status": "removed", "userId": user}, p.header)
	}
	payload := map[string]any{"client_id": a.clientID}
	if locale != "" {
		payload["locale"] = locale
	}
	n := a.ask(r, http.MethodPost, base+"/"+user+"/invite", payload, askOpts{page: a.pages.AcceptInvite, bearer: p.token})
	if n.err != nil {
		return refusedWith(n, "", p.header)
	}
	return ok(map[string]any{"status": "sent", "userId": user}, p.header)
}

func (a *Auth) disconnectAgent(r *http.Request, _ string, b map[string]any, p *person) *reply {
	id, _ := b["id"].(string)
	if !looseUUID.MatchString(id) {
		return problem(http.StatusBadRequest, "invalid_agent", "Say which agent to disconnect.", "", p.header, nil)
	}
	n := a.as(r, p, http.MethodDelete, "/v1/auth/me/agents/"+id, nil)
	if n.err != nil {
		return refusedWith(n, "", p.header)
	}
	return ok(map[string]any{"status": "disconnected", "id": id}, p.header)
}

// endSessions signs the person out everywhere, here too.
func (a *Auth) endSessions(r *http.Request, _ string, _ map[string]any, p *person) *reply {
	n := a.as(r, p, http.MethodDelete, "/v1/auth/me/sessions", nil)
	if n.err != nil {
		return refusedWith(n, "", p.header)
	}
	a.forgetOrganizations(p.token)
	return ok(map[string]any{"status": "signed_out"}, nil).with(a.clearSession(r, readCookies(r))...)
}
