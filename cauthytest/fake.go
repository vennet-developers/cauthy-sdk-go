// Package cauthytest is a Cauthy that lives in memory and a browser that
// keeps cookies: what an application's tests sign in against. For tests
// only: it signs in anyone it was told about, and checks nothing a real
// Cauthy does.
package cauthytest

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
)

// User is an account of the fake Cauthy.
type User struct {
	Sub        string
	Email      string
	Name       string
	Active     bool
	Restricted bool
	Anonymous  bool
	// Verified is email_verified; nil is "verified unless a guest".
	Verified *bool
}

// Call is one request the fake received.
type Call struct {
	Method string
	Path   string
	Query  url.Values
	Header http.Header
	// Form is a form body; JSON a JSON object body.
	Form url.Values
	JSON map[string]any
}

// Reply is what a scripted route answers: Body as JSON with Status.
type Reply struct {
	Status int
	Body   any
}

// Data is {"data": v}, Cauthy's envelope.
func Data(v any) Reply { return Reply{Status: 200, Body: map[string]any{"data": v}} }

// Refuse is Cauthy's error envelope.
func Refuse(status int, code, message string) Reply {
	return Reply{Status: status, Body: map[string]any{"errors": []any{map[string]any{"code": code, "message": message}}}}
}

// Fake is Cauthy in memory. Use Client as the application's HTTP client and
// Issuer as Cauthy's address.
type Fake struct {
	// Issuer is the fake's address: https://id.test.
	Issuer string
	// Tenant is the workspace X-Tenant-Key must name: "acme".
	Tenant string
	// OwnScreens serves the API the application's own screens use (/v1/auth/*).
	OwnScreens bool
	// Down makes every call fail as if Cauthy were unreachable.
	Down bool
	// ExpiresIn is the access token's life in seconds. Default 600.
	ExpiresIn int
	// Persistent is what token answers say of the session's kind; nil says nothing.
	Persistent *bool
	// Settings is what GET /v1/auth/settings answers. Change it before the
	// fake serves, or with SetSetting while it does.
	Settings map[string]any
	// AdminToken is the bearer the admin API takes (settings, the
	// application's client, accounts); "" refuses every admin call.
	AdminToken string
	// ClientID is the application's client, as the admin API lists it; its
	// allow_persistent_sessions is Settings["persistent_sessions"]. A key
	// IssueKey makes is for this client.
	ClientID string
	// System is what GET /v1/connect/self says the application is: "acme-crm".
	System string
	// AppURLs are the application's addresses GET /v1/connect/self answers.
	// Default http://localhost:3000.
	AppURLs []string

	mu        sync.Mutex
	users     map[string]*User
	passwords map[string]string
	orgs      map[string][]map[string]any
	codes     map[string]code
	refresh   map[string]string
	access    map[string]string
	revoked   []string
	calls     []Call
	scripted  map[string]func(Call) Reply
	n         int

	// CAUTHY_KEY (keys.go)
	keyring      map[string]*fakeKey
	kids         []string
	keyClients   map[string]bool
	jtis         map[string]bool
	systemTokens map[string]string
}

type code struct{ sub, challenge, redirectURI string }

// New is a fake Cauthy with one account, ana@example.com (u1), and no password.
func New() *Fake {
	f := &Fake{
		Issuer: "https://id.test", Tenant: "acme", ExpiresIn: 600, ClientID: "acme-crm", System: "acme-crm", AppURLs: []string{"http://localhost:3000"},
		Settings: map[string]any{"allow_password": true, "allow_signup": false, "allow_passkeys": false, "persistent_sessions": false},
		users:    map[string]*User{}, passwords: map[string]string{}, orgs: map[string][]map[string]any{},
		codes: map[string]code{}, refresh: map[string]string{}, access: map[string]string{}, scripted: map[string]func(Call) Reply{},
		keyring: map[string]*fakeKey{}, keyClients: map[string]bool{}, jtis: map[string]bool{}, systemTokens: map[string]string{},
	}
	f.AddUser(User{Sub: "u1", Email: "ana@example.com", Name: "Ana", Active: true}, "")
	return f
}

// AddUser adds an account; a password lets it sign in on the own screens.
func (f *Fake) AddUser(u User, password string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.users[u.Sub] = &u
	if password != "" {
		f.passwords[u.Email] = password
	}
}

// SetAdminToken sets AdminToken. A program that may be built against a
// cauthytest older than the admin API (the conformance target, whose module
// requires a released version) asks for this method instead of the field.
func (f *Fake) SetAdminToken(token string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.AdminToken = token
}

// SetSetting changes one setting GET /v1/auth/settings answers, safely while the fake serves.
func (f *Fake) SetSetting(key string, value any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	next := maps.Clone(f.Settings)
	next[key] = value
	f.Settings = next
}

// Setting reads one setting, safely while the fake serves.
func (f *Fake) Setting(key string) any {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.Settings[key]
}

// HasUser says whether an account is there (the admin API may delete one).
func (f *Fake) HasUser(sub string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.users[sub] != nil
}

// SetActive turns an account on or off.
func (f *Fake) SetActive(sub string, active bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if u := f.users[sub]; u != nil {
		u.Active = active
	}
}

// SetOrganizations sets what GET /v1/oauth/organizations answers for sub.
func (f *Fake) SetOrganizations(sub string, orgs []map[string]any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.orgs[sub] = orgs
}

// On scripts a route: "POST /v1/auth/mfa/challenge". It wins over the
// built-in ones.
func (f *Fake) On(route string, fn func(Call) Reply) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.scripted[route] = fn
}

// Calls are the requests received, in order.
func (f *Fake) Calls() []Call {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Call(nil), f.calls...)
}

// Last is the last call to route ("POST /v1/auth/login"), or nil.
func (f *Fake) Last(route string) *Call {
	calls := f.Calls()
	for i := len(calls) - 1; i >= 0; i-- {
		if calls[i].Method+" "+calls[i].Path == route {
			return &calls[i]
		}
	}
	return nil
}

// Revoked are the refresh tokens revoked, in order.
func (f *Fake) Revoked() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.revoked...)
}

// Authorize is what the hosted page does once the person signed in: it
// answers the redirect, with a code, to the application's callback.
func (f *Fake) Authorize(location, sub string) (string, error) {
	u, err := url.Parse(location)
	if err != nil {
		return "", err
	}
	q := u.Query()
	if q.Get("response_type") != "code" {
		return "", errors.New("cauthytest: response_type=code is required")
	}
	f.mu.Lock()
	f.n++
	c := fmt.Sprintf("code-%d", f.n)
	f.codes[c] = code{sub: sub, challenge: q.Get("code_challenge"), redirectURI: q.Get("redirect_uri")}
	f.mu.Unlock()
	return q.Get("redirect_uri") + "?code=" + c + "&state=" + url.QueryEscape(q.Get("state")), nil
}

// Issue makes a token answer for sub, as Cauthy's token endpoint gives it.
func (f *Fake) Issue(sub string) map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.issue(sub)
}

func (f *Fake) issue(sub string) map[string]any { return f.issueKind(sub, nil) }

// issueKind is a token answer; kind is what a sign-in asked for (remember)
// when the client allows long sessions. Persistent wins when set.
func (f *Fake) issueKind(sub string, kind *bool) map[string]any {
	f.n++
	at := fmt.Sprintf("at-%d", f.n)
	f.n++
	rt := fmt.Sprintf("rt-%d", f.n)
	f.access[at], f.refresh[rt] = sub, sub
	out := map[string]any{"access_token": at, "refresh_token": rt, "token_type": "Bearer", "expires_in": f.ExpiresIn, "scope": ""}
	switch {
	case f.Persistent != nil:
		out["persistent"] = *f.Persistent
	case kind != nil:
		out["persistent"] = *kind
	}
	return out
}

// Client is an HTTP client whose every request the fake answers in process.
func (f *Fake) Client() *http.Client { return &http.Client{Transport: transport{f}} }

type transport struct{ f *Fake }

func (t transport) RoundTrip(r *http.Request) (*http.Response, error) {
	if t.f.isDown() {
		return nil, errors.New("cauthytest: Cauthy is down")
	}
	w := httptest.NewRecorder()
	t.f.ServeHTTP(w, r)
	res := w.Result()
	res.Request = r
	return res, nil
}

// SetDown sets Down, safely while the fake serves.
func (f *Fake) SetDown(down bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Down = down
}

func (f *Fake) isDown() bool { f.mu.Lock(); defer f.mu.Unlock(); return f.Down }

func reply(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

var checkPath = regexp.MustCompile(`^/v1/oauth/organizations/([^/]+)/check$`)

// ServeHTTP is the fake Cauthy.
func (f *Fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var raw []byte
	if r.Body != nil {
		raw, _ = io.ReadAll(r.Body)
	}
	c := Call{Method: r.Method, Path: r.URL.Path, Query: r.URL.Query(), Header: r.Header.Clone()}
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
		c.Form, _ = url.ParseQuery(string(raw))
	} else if len(raw) > 0 {
		_ = json.Unmarshal(raw, &c.JSON)
	}
	f.mu.Lock()
	f.calls = append(f.calls, c)
	fn := f.scripted[r.Method+" "+r.URL.Path]
	f.mu.Unlock()
	if fn != nil {
		out := fn(c)
		if out.Status == 0 {
			out.Status = 200
		}
		if out.Status == 204 {
			w.WriteHeader(204)
			return
		}
		reply(w, out.Status, out.Body)
		return
	}
	if f.admin(w, c) {
		return
	}
	if f.OwnScreens && strings.HasPrefix(r.URL.Path, "/v1/auth/") {
		f.ownScreen(w, c)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	switch r.URL.Path {
	case "/v1/oauth/token":
		kid, ok := f.clientAuth(w, c)
		if !ok {
			return
		}
		if kid != "" && c.Form.Get("grant_type") == "client_credentials" {
			f.systemToken(w, kid)
			return
		}
		f.tokenEndpoint(w, c)
		return
	case "/v1/connect/self":
		f.self(w, r)
		return
	case "/v1/oauth/revoke":
		if _, ok := f.clientAuth(w, c); !ok {
			return
		}
		f.revoked = append(f.revoked, c.Form.Get("token"))
		delete(f.refresh, c.Form.Get("token"))
		reply(w, 200, map[string]any{})
		return
	}
	user := f.users[f.access[bearer]]
	if r.URL.Path == "/v1/oauth/userinfo" {
		if user == nil {
			reply(w, 401, map[string]any{})
			return
		}
		verified := !user.Anonymous
		if user.Verified != nil {
			verified = *user.Verified
		}
		body := map[string]any{"sub": user.Sub, "tid": "t1", "email": user.Email, "name": user.Name, "email_verified": verified,
			"restricted": user.Restricted, "roles": []string{"member"}}
		if user.Anonymous {
			body["anonymous"] = true
		}
		reply(w, 200, body)
		return
	}
	if m := checkPath.FindStringSubmatch(r.URL.Path); m != nil && r.Method == http.MethodPost {
		if user == nil {
			reply(w, 401, map[string]any{"errors": []any{map[string]any{"code": "unauthorized", "message": "invalid or expired token"}}})
			return
		}
		member := false
		for _, o := range f.orgs[user.Sub] {
			if o["id"] == m[1] {
				member = true
			}
		}
		if !member {
			reply(w, 404, map[string]any{"errors": []any{map[string]any{"code": "organization_not_found", "message": "organization not found"}}})
			return
		}
		amount, _ := c.JSON["attributes"].(map[string]any)["amount"].(float64)
		allowed := c.JSON["resource"] == "invoices" && c.JSON["action"] == "approve" && amount <= 1_000_000
		if allowed {
			reply(w, 200, map[string]any{"data": map[string]any{"allowed": true, "reason": "allowed by role accountant: invoices:approve",
				"rule": map[string]any{"source": "role", "role": "accountant", "kind": "*", "resource": "invoices", "action": "approve", "effect": "allow"}}})
		} else {
			reply(w, 200, map[string]any{"data": map[string]any{"allowed": false, "reason": "no rule allows it"}})
		}
		return
	}
	if r.URL.Path == "/v1/oauth/organizations" {
		if user == nil {
			reply(w, 401, map[string]any{})
			return
		}
		system := r.URL.Query().Get("system")
		data := []map[string]any{}
		for _, o := range f.orgs[user.Sub] {
			if system == "" || o["system"] == system {
				data = append(data, o)
			}
		}
		reply(w, 200, map[string]any{"data": data, "total_count": len(data)})
		return
	}
	reply(w, 404, map[string]any{})
}

func (f *Fake) tokenEndpoint(w http.ResponseWriter, c Call) {
	invalid := map[string]any{"error": "invalid_grant", "error_description": "the grant is invalid, expired or already used"}
	switch c.Form.Get("grant_type") {
	case "authorization_code":
		got, ok := f.codes[c.Form.Get("code")]
		delete(f.codes, c.Form.Get("code"))
		sum := sha256.Sum256([]byte(c.Form.Get("code_verifier")))
		if !ok || got.challenge != base64.RawURLEncoding.EncodeToString(sum[:]) || got.redirectURI != c.Form.Get("redirect_uri") {
			reply(w, 400, invalid)
			return
		}
		reply(w, 200, f.issue(got.sub))
	case "refresh_token":
		sub, ok := f.refresh[c.Form.Get("refresh_token")]
		delete(f.refresh, c.Form.Get("refresh_token")) // used once
		if u := f.users[sub]; !ok || u == nil || !u.Active {
			reply(w, 400, invalid)
			return
		}
		reply(w, 200, f.issue(sub))
	default:
		reply(w, 400, map[string]any{"error": "unsupported_grant_type", "error_description": "supported grant types: authorization_code, refresh_token"})
	}
}

// ownScreen is the part of /v1/auth/* a password sign-in and the sign-in
// form read.
func (f *Fake) ownScreen(w http.ResponseWriter, c Call) {
	f.mu.Lock()
	defer f.mu.Unlock()
	refuse := func(status int, code, message string) {
		reply(w, status, map[string]any{"errors": []any{map[string]any{"code": code, "message": message}}})
	}
	if c.Header.Get("X-Tenant-Key") != f.Tenant {
		refuse(404, "tenant_not_found", "no such workspace")
		return
	}
	switch c.Method + " " + c.Path {
	case "POST /v1/auth/login":
		if f.Settings["allow_password"] == false {
			refuse(403, "password_disabled", "this workspace does not take passwords: sign in another way")
			return
		}
		email, _ := c.JSON["email"].(string)
		password, _ := c.JSON["password"].(string)
		var user *User
		for _, u := range f.users {
			if u.Email == email {
				user = u
			}
		}
		want, has := f.passwords[email]
		if user == nil || !user.Active || !has || want != password {
			refuse(401, "invalid_credentials", "invalid email or password")
			return
		}
		// A long session only when the person asked and the client allows it.
		var kind *bool
		if f.Settings["persistent_sessions"] == true {
			remember := c.Header.Get("X-Cauthy-Remember") == "1"
			kind = &remember
		}
		reply(w, 200, map[string]any{"data": f.issueKind(user.Sub, kind)})
	case "POST /v1/auth/register":
		email, _ := c.JSON["email"].(string)
		password, _ := c.JSON["password"].(string)
		name, _ := c.JSON["display_name"].(string)
		switch {
		case f.Settings["allow_signup"] == false:
			refuse(403, "signups_disabled", "this workspace is not accepting new accounts")
			return
		case f.Settings["allow_password"] == false:
			refuse(403, "password_disabled", "this workspace does not take passwords: sign in another way")
			return
		case email == "" || password == "":
			refuse(400, "validation_error", "email and password are required")
			return
		}
		for _, u := range f.users {
			if u.Email == email {
				refuse(409, "email_taken", "an account with this email exists")
				return
			}
		}
		// With confirm_email the account waits for its address (verify_grace_days 0 in the fake).
		confirm := f.Settings["confirm_email"] == true
		f.n++
		sub := fmt.Sprintf("u-%d", f.n)
		verified := !confirm
		f.users[sub] = &User{Sub: sub, Email: email, Name: name, Active: !confirm, Verified: &verified}
		f.passwords[email] = password
		data := map[string]any{"user_id": sub, "email": email}
		if confirm {
			data["verification_required"] = true
		}
		reply(w, 201, map[string]any{"data": data})
	case "GET /v1/auth/settings":
		reply(w, 200, map[string]any{"data": f.Settings})
	case "GET /v1/auth/social/providers", "GET /v1/auth/sso/connections":
		reply(w, 200, map[string]any{"data": []any{}})
	case "GET /v1/auth/webauthn/place":
		reply(w, 200, map[string]any{"data": map[string]any{"here": false, "on_cauthy": false}})
	default:
		refuse(404, "not_found", "not found")
	}
}

// adminSettings are the settings the admin API changes, as the dashboard's switches do.
var adminSettings = []string{"allow_signup", "allow_password", "allow_magic_link", "allow_passkeys", "confirm_email", "verify_grace_days"}

var (
	clientPath = regexp.MustCompile(`^/v1/oauth/clients/([^/]+)$`)
	userPath   = regexp.MustCompile(`^/v1/users/([^/]+)$`)
)

// admin answers the part of Cauthy's admin API the conformance runner's
// dashboard-switch checks drive: GET and PUT /v1/settings/auth, GET
// /v1/oauth/clients, PATCH /v1/oauth/clients/{id}, GET /v1/users and DELETE
// /v1/users/{id}. It answers false, writing nothing, for any other request.
func (f *Fake) admin(w http.ResponseWriter, c Call) bool {
	route := c.Method + " " + c.Path
	client := clientPath.FindStringSubmatch(c.Path)
	user := userPath.FindStringSubmatch(c.Path)
	switch {
	case route == "GET /v1/settings/auth", route == "PUT /v1/settings/auth", route == "GET /v1/oauth/clients", route == "GET /v1/users":
	case c.Method == http.MethodPatch && client != nil, c.Method == http.MethodDelete && user != nil:
	default:
		return false
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	refuse := func(status int, code, message string) {
		reply(w, status, map[string]any{"errors": []any{map[string]any{"code": code, "message": message}}})
	}
	if f.AdminToken == "" || c.Header.Get("Authorization") != "Bearer "+f.AdminToken {
		refuse(401, "unauthorized", "invalid or expired token")
		return true
	}
	if c.Header.Get("X-Tenant-Key") != f.Tenant {
		refuse(404, "tenant_not_found", "no such workspace")
		return true
	}
	persistent := func() bool { return f.Settings["persistent_sessions"] == true }
	switch {
	case route == "GET /v1/settings/auth":
		reply(w, 200, map[string]any{"data": f.Settings})
	case route == "PUT /v1/settings/auth":
		next := maps.Clone(f.Settings)
		for _, k := range adminSettings {
			if v, ok := c.JSON[k]; ok && v != nil {
				next[k] = v
			}
		}
		if next["allow_password"] == false && next["allow_magic_link"] != true && next["allow_passkeys"] != true {
			refuse(409, "last_method", "the change would leave no way to sign in")
			return true
		}
		f.Settings = next
		reply(w, 200, map[string]any{"data": f.Settings})
	case route == "GET /v1/oauth/clients":
		reply(w, 200, map[string]any{"data": []any{map[string]any{"client_id": f.ClientID, "allow_persistent_sessions": persistent()}}, "total_count": 1})
	case client != nil:
		if client[1] != f.ClientID {
			refuse(404, "client_not_found", "no such client")
			return true
		}
		if on, ok := c.JSON["allow_persistent_sessions"].(bool); ok {
			next := maps.Clone(f.Settings)
			next["persistent_sessions"] = on
			f.Settings = next
		}
		reply(w, 200, map[string]any{"data": map[string]any{"client_id": f.ClientID, "allow_persistent_sessions": persistent()}})
	case route == "GET /v1/users":
		q := strings.ToLower(c.Query.Get("q"))
		data := []any{}
		for _, u := range f.users {
			if strings.Contains(strings.ToLower(u.Email), q) {
				data = append(data, map[string]any{"id": u.Sub, "email": u.Email, "name": u.Name})
			}
		}
		reply(w, 200, map[string]any{"data": data, "total_count": len(data)})
	default: // DELETE /v1/users/{id}
		u := f.users[user[1]]
		if u == nil {
			refuse(404, "user_not_found", "no such user")
			return true
		}
		delete(f.users, user[1])
		delete(f.passwords, u.Email)
		w.WriteHeader(204)
	}
	return true
}
