package cauthy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/vennet-developers/cauthy-sdk-go/cauthykey"
	"github.com/vennet-developers/cauthy-sdk-go/internal/jose"
	"github.com/vennet-developers/cauthy-sdk-go/system"
)

// SessionUser is the person signed in. Moments are UTC.
type SessionUser struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	Name          string `json:"name"`
	EmailVerified bool   `json:"emailVerified"`
	// Restricted is an account that ran out of time to confirm its address:
	// let it read and refuse its writes.
	Restricted bool `json:"restricted"`
	// EmailVerifyBy is when an unconfirmed address stops being enough.
	EmailVerifyBy string `json:"emailVerifyBy,omitempty"`
	Locale        string `json:"locale,omitempty"`
	IsAnonymous   bool   `json:"isAnonymous,omitempty"`
}

// Session is a signed-in person, as the server sees them.
type Session struct {
	User     SessionUser
	TenantID string
	// Roles are the person's roles in the workspace, never a business role.
	Roles []string
	// AccessToken is Cauthy's access token for the person, to send as
	// Authorization: Bearer to another service that verifies Cauthy's
	// tokens. Never give it to the browser.
	AccessToken string
	// ExpiresAt is when the access token expires (UTC, ISO 8601).
	ExpiresAt string
}

// ConditionalPermission is a permission Cauthy decides per question.
type ConditionalPermission struct {
	Resource string `json:"resource"`
	Action   string `json:"action"`
	Effect   string `json:"effect"`
}

// Organization is an organization the person belongs to, with their role.
type Organization struct {
	ID         string
	System     string
	Name       string
	Kind       string
	ExternalID string
	Role       string
	Metadata   map[string]any
	// Permissions are "resource:action" entries; nil when the system keeps
	// no catalog of roles in Cauthy. Denied and Conditional come with them.
	Permissions []string
	Denied      []string
	Conditional []ConditionalPermission
}

// MarshalJSON writes the organization as auth-bff.md's PublicSession has it.
func (o Organization) MarshalJSON() ([]byte, error) {
	m := map[string]any{"id": o.ID, "system": o.System, "name": o.Name, "kind": o.Kind, "role": o.Role, "metadata": o.Metadata}
	if o.Metadata == nil {
		m["metadata"] = map[string]any{}
	}
	if o.ExternalID != "" {
		m["externalId"] = o.ExternalID
	}
	if o.Permissions != nil {
		m["permissions"], m["denied"], m["conditional"] = o.Permissions, nonNil(o.Denied), o.Conditional
		if o.Conditional == nil {
			m["conditional"] = []ConditionalPermission{}
		}
	}
	return json.Marshal(m)
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// PublicSession is what the browser is told of a session: never a token.
type PublicSession struct {
	User          SessionUser    `json:"user"`
	TenantID      string         `json:"tenantId"`
	Roles         []string       `json:"roles"`
	Organizations []Organization `json:"organizations"`
	ExpiresAt     string         `json:"expiresAt"`
}

// Status says whether somebody is signed in.
type Status string

const (
	StatusAuthenticated   Status = "authenticated"
	StatusUnauthenticated Status = "unauthenticated"
	// StatusExpired: signed in, but the session must be renewed first.
	StatusExpired Status = "expired"
)

// Resolved is who is there, and the cookies that must go back with the
// answer (Set-Cookie values; empty when nothing changed).
type Resolved struct {
	Session *Session
	Status  Status
	Cookies []string
}

// stored is what the session cookie holds; the names are @cauthyhq/node's.
type stored struct {
	AT    string      `json:"at"`
	RT    string      `json:"rt"`
	Exp   int64       `json:"exp"`
	U     SessionUser `json:"u"`
	TID   string      `json:"tid"`
	Roles []string    `json:"roles"`
	P     int         `json:"p,omitempty"`
}

// flow is the hosted sign-in in progress.
type flow struct {
	State    string `json:"state"`
	Verifier string `json:"verifier"`
	ReturnTo string `json:"returnTo"`
}

// step is what the own screens carry between two calls.
type step struct {
	Kind     string `json:"kind"`
	Token    string `json:"token"`
	Provider string `json:"provider,omitempty"`
	ReturnTo string `json:"returnTo"`
	Remember bool   `json:"remember,omitempty"`
}

const (
	persistentSeconds = 30 * 86_400
	flowSeconds       = 3600
	againSeconds      = 120
	stepSeconds       = 600
	passkeySeconds    = 300
	skewSeconds       = 30
	organizationsTTL  = time.Minute
	maxAnswer         = 1 << 20
)

// errEmailNotConfirmed: Cauthy signed in a person whose address the link
// requires confirmed, and it is not.
var errEmailNotConfirmed = errors.New("cauthy: email_not_confirmed")

// seal seals v with the first key of ring.
func seal(v any, ring [][]byte) (string, error) {
	plain, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return jose.Seal(plain, ring[0])
}

// unseal opens a value any key of ring sealed into v.
func unseal(sealed string, ring [][]byte, v any) bool {
	plain, _, err := jose.OpenAny(sealed, ring)
	return err == nil && json.Unmarshal(plain, v) == nil
}

// answer is what Cauthy answered: its status and its JSON body (nil when it
// is none), or err when it could not be asked.
type answer struct {
	status int
	body   any
	err    error
}

// fetch calls Cauthy with the request deadline. The call is detached from
// the browser's request: a refresh token Cauthy spends must not be lost
// because the browser went away.
func (a *Auth) fetch(ctx context.Context, method, target string, header http.Header, body []byte) answer {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), a.requestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(body))
	if err != nil {
		return answer{err: err}
	}
	req.Header = header
	res, err := a.http.Do(req)
	if err != nil {
		return answer{err: err}
	}
	defer res.Body.Close()
	return answer{status: res.StatusCode, body: answerOf(res)}
}

func (n answer) ok() bool { return n.err == nil && n.status >= 200 && n.status < 300 }

// token asks Cauthy's token endpoint. ended is true when Cauthy answered 4xx:
// the grant is no good, and code is the OAuth error it named
// ("email_not_confirmed", "invalid_grant"…). Anything else is a failure to
// ask.
func (a *Auth) token(ctx context.Context, form url.Values, proof http.Header) (body any, ok, ended bool, code string) {
	if err := a.authenticate(form); err != nil {
		return nil, false, false, ""
	}
	h := http.Header{"Content-Type": {"application/x-www-form-urlencoded"}, "Accept": {"application/json"}}
	for k, v := range proof {
		h[k] = v
	}
	n := a.fetch(ctx, http.MethodPost, a.issuer+"/v1/oauth/token", h, []byte(form.Encode()))
	if n.ok() {
		return n.body, true, false, ""
	}
	ended = n.err == nil && n.status >= 400 && n.status < 500
	if ended {
		code = str(at(n.body, "error"))
	}
	return nil, false, ended, code
}

// authenticate says which client a call to the token or revoke endpoint is
// for, and proves it: on CAUTHY_KEY a fresh assertion signed with the key
// (never a secret), else the client's secret when it has one.
func (a *Auth) authenticate(form url.Values) error {
	form.Set("client_id", a.clientID)
	if a.signer != nil && a.signer.ClientID == a.clientID {
		assertion, err := a.signer.Assertion(a.issuer+"/v1/oauth/token", a.now())
		if err != nil {
			return err
		}
		form.Set("client_assertion_type", cauthykey.AssertionType)
		form.Set("client_assertion", assertion)
		return nil
	}
	if a.clientSecret != "" {
		form.Set("client_secret", a.clientSecret)
	}
	return nil
}

type who struct {
	u     SessionUser
	tid   string
	roles []string
}

func (a *Auth) userinfo(ctx context.Context, accessToken string) *who {
	n := a.fetch(ctx, http.MethodGet, a.issuer+"/v1/oauth/userinfo", http.Header{"Authorization": {"Bearer " + accessToken}}, nil)
	if !n.ok() {
		return nil
	}
	b := n.body
	w := &who{tid: str(at(b, "tid")), roles: []string{}, u: SessionUser{
		ID: str(at(b, "sub")), Email: str(at(b, "email")), Name: str(at(b, "name")),
		EmailVerified: yes(at(b, "email_verified")), Restricted: yes(at(b, "restricted")), IsAnonymous: yes(at(b, "anonymous")),
	}}
	if s, ok := at(b, "email_verify_by").(string); ok {
		w.u.EmailVerifyBy = s
	}
	if s, ok := at(b, "locale").(string); ok {
		w.u.Locale = s
	}
	for _, r := range arr(at(b, "roles")) {
		if s, ok := r.(string); ok {
			w.roles = append(w.roles, s)
		}
	}
	return w
}

// revoke tells Cauthy, best effort, that a refresh token is no longer wanted.
func (a *Auth) revoke(ctx context.Context, refreshToken string) {
	form := url.Values{"token": {refreshToken}}
	if a.authenticate(form) != nil {
		return
	}
	a.fetch(ctx, http.MethodPost, a.issuer+"/v1/oauth/revoke", http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}, []byte(form.Encode()))
}

// unverified: a link that requires a verified address lets nobody in whose
// address is not, whatever Cauthy issued.
func (a *Auth) unverified(u SessionUser) bool {
	return a.contract != nil && a.contract.RequireVerifiedEmail && !u.EmailVerified
}

// persistent is whether the session stays signed in: as Cauthy says, or as
// it was when an older Cauthy says nothing.
func persistent(body any, was *stored) int {
	if p, ok := at(body, "persistent").(bool); ok {
		if p {
			return 1
		}
		return 0
	}
	if was != nil {
		return was.P
	}
	return 0
}

func lifetime(body any) int64 {
	if n := num(at(body, "expires_in")); n > 0 {
		return int64(n)
	}
	return 300
}

// toStored is what Cauthy's token answer becomes in the cookie; nil when it
// cannot be used.
func (a *Auth) toStored(ctx context.Context, body any, was *stored) (*stored, error) {
	at1, ok1 := at(body, "access_token").(string)
	rt, ok2 := at(body, "refresh_token").(string)
	if !ok1 || !ok2 {
		return nil, nil
	}
	w := a.userinfo(ctx, at1)
	if w == nil || w.u.ID == "" {
		return nil, nil
	}
	if a.unverified(w.u) {
		// The session these tokens would have started never begins.
		a.revoke(ctx, rt)
		return nil, errEmailNotConfirmed
	}
	return &stored{AT: at1, RT: rt, Exp: a.now().Unix() + lifetime(body), U: w.u, TID: w.tid, Roles: w.roles, P: persistent(body, was)}, nil
}

func (s *stored) session() *Session {
	roles := s.Roles
	if roles == nil {
		roles = []string{}
	}
	return &Session{User: s.U, TenantID: s.TID, Roles: roles, AccessToken: s.AT, ExpiresAt: isoUTC(time.Unix(s.Exp, 0))}
}

// read is the session cookie: the cookies the request carries, the value
// (nil when none or not this key's), and whether a cookie was there at all.
func (a *Auth) read(r *http.Request) (map[string]string, *stored, bool) {
	had := readCookies(r)
	raw, present := readParts(had, a.cookieName)
	if !present {
		return had, nil, false
	}
	var probe struct {
		AT  *string  `json:"at"`
		RT  *string  `json:"rt"`
		Exp *float64 `json:"exp"`
	}
	var s stored
	if !unseal(raw, a.cookieRing, &probe) || probe.AT == nil || probe.RT == nil || probe.Exp == nil || !unseal(raw, a.cookieRing, &s) {
		return had, nil, true
	}
	return had, &s, true
}

// stale reports whether the session cookie was sealed with a key of the ring
// other than the first, the one that writes.
func (a *Auth) stale(had map[string]string) bool {
	if len(a.cookieRing) < 2 {
		return false
	}
	raw, present := readParts(had, a.cookieName)
	if !present {
		return false
	}
	_, err := jose.Open(raw, a.cookieRing[0])
	return err != nil
}

// write is the Set-Cookie values that store s.
func (a *Auth) write(r *http.Request, s *stored, had map[string]string) []string {
	sealed, err := seal(s, a.cookieRing)
	if err != nil {
		return nil
	}
	attrs := a.attrs(r)
	if s.P == 1 {
		attrs = attrs.age(persistentSeconds)
	}
	return writeParts(a.cookieName, sealed, attrs, had)
}

func (a *Auth) clearSession(r *http.Request, had map[string]string) []string {
	return clearParts(a.cookieName, a.attrs(r).age(0), had)
}

func (a *Auth) fresh(s *stored) bool { return s.Exp-a.now().Unix() > skewSeconds }

type renewOutcome int

const (
	renewed renewOutcome = iota
	renewEnded
	renewUnreachable
)

type renewal struct {
	done    chan struct{}
	s       *stored
	outcome renewOutcome
}

// renew renews was with Cauthy. One renewal per refresh token at a time in
// this process: requests that arrive together share it, and a renewal that
// worked is remembered five seconds for requests still carrying the old
// cookie.
func (a *Auth) renew(ctx context.Context, was *stored) (*stored, renewOutcome) {
	a.renewMu.Lock()
	run, running := a.renewing[was.RT]
	if !running {
		run = &renewal{done: make(chan struct{})}
		a.renewing[was.RT] = run
	}
	a.renewMu.Unlock()
	if running {
		<-run.done
		return run.s, run.outcome
	}
	run.s, run.outcome = a.renewOnce(ctx, was)
	close(run.done)
	forget := func() { a.renewMu.Lock(); delete(a.renewing, was.RT); a.renewMu.Unlock() }
	if run.outcome == renewUnreachable {
		forget()
	} else {
		time.AfterFunc(5*time.Second, forget)
	}
	return run.s, run.outcome
}

func (a *Auth) renewOnce(ctx context.Context, was *stored) (*stored, renewOutcome) {
	body, ok, ended, _ := a.token(ctx, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {was.RT}}, nil)
	if !ok {
		if ended {
			return nil, renewEnded
		}
		return nil, renewUnreachable
	}
	next, err := a.toStored(ctx, body, was)
	if errors.Is(err, errEmailNotConfirmed) {
		return nil, renewEnded
	}
	if next != nil {
		return next, renewed
	}
	// Renewed, but who it is could not be read just now: the new tokens are
	// kept all the same (the old refresh token is spent), with what was known.
	at1, ok1 := at(body, "access_token").(string)
	rt, ok2 := at(body, "refresh_token").(string)
	if !ok1 || !ok2 {
		return nil, renewUnreachable
	}
	kept := *was
	kept.AT, kept.RT, kept.Exp, kept.P = at1, rt, a.now().Unix()+lifetime(body), persistent(body, was)
	return &kept, renewed
}

// Resolve is the session, renewed when it has to be, and the cookies the
// caller MUST send with its answer.
func (a *Auth) Resolve(r *http.Request) Resolved {
	had, value, present := a.read(r)
	if value == nil {
		var cookies []string
		if present {
			cookies = a.clearSession(r, had) // a cookie this key did not make
			warnOnce(a.log, "unopened session cookie", "cauthy: a session cookie arrived that no key of this application opens; it was cleared and the person is signed out. "+
				"Moving to CAUTHY_KEY, keep the secret that sealed the old sessions (CAUTHY_SECRET, or PACT_ROOT_KEY and PACT_ROOT_KEY_PREVIOUS) beside it for the rotation window; "+
				"rotating the key, set CAUTHY_KEY_PREVIOUS.")
		}
		return Resolved{Status: StatusUnauthenticated, Cookies: cookies}
	}
	if a.unverified(value.U) {
		return Resolved{Status: StatusUnauthenticated, Cookies: a.clearSession(r, had)}
	}
	if a.fresh(value) {
		// Sealed with a key that only reads (CAUTHY_KEY_PREVIOUS, or the
		// CAUTHY_SECRET / PACT_ROOT_KEY of before the move): sealed again now
		// with the current one, so the session outlives the old secret.
		var cookies []string
		if a.stale(had) {
			cookies = a.write(r, value, had)
		}
		return Resolved{Session: value.session(), Status: StatusAuthenticated, Cookies: cookies}
	}
	next, outcome := a.renew(r.Context(), value)
	switch outcome {
	case renewEnded:
		return Resolved{Status: StatusUnauthenticated, Cookies: a.clearSession(r, had)}
	case renewUnreachable:
		// Cauthy could not be asked: the cookie stays, nobody is let in.
		return Resolved{Status: StatusExpired}
	}
	return Resolved{Session: next.session(), Status: StatusAuthenticated, Cookies: a.write(r, next, had)}
}

// Session is who is signed in, or nil. With w, a session that must be
// renewed is renewed and its new cookie set on w's headers; with w nil an
// expired session reads as nil (see Status).
func (a *Auth) Session(w http.ResponseWriter, r *http.Request) *Session {
	if w == nil {
		_, value, _ := a.read(r)
		if value == nil || !a.fresh(value) || a.unverified(value.U) {
			return nil
		}
		return value.session()
	}
	res := a.Resolve(r)
	for _, c := range res.Cookies {
		w.Header().Add("Set-Cookie", c)
	}
	return res.Session
}

// Status is whether somebody is signed in, nobody is, or the session must
// be renewed first.
func (a *Auth) Status(r *http.Request) Status {
	_, value, _ := a.read(r)
	if value == nil || a.unverified(value.U) {
		return StatusUnauthenticated
	}
	if a.fresh(value) {
		return StatusAuthenticated
	}
	return StatusExpired
}

type orgEntry struct {
	at    time.Time
	value []Organization
}

// Organizations are the organizations the person belongs to (of the
// application's system, when it has one), with their role in each. Kept a
// minute per token.
func (a *Auth) Organizations(ctx context.Context, s *Session) ([]Organization, error) {
	a.orgMu.Lock()
	hit, ok := a.orgCache[s.AccessToken]
	a.orgMu.Unlock()
	if ok && a.now().Sub(hit.at) < organizationsTTL {
		return hit.value, nil
	}
	target := a.issuer + "/v1/oauth/organizations"
	if system := a.systemName(); system != "" {
		target += "?system=" + url.QueryEscape(system)
	}
	n := a.fetch(ctx, http.MethodGet, target, http.Header{"Authorization": {"Bearer " + s.AccessToken}}, nil)
	if n.err != nil {
		return nil, n.err
	}
	if !n.ok() {
		return nil, &system.APIError{Status: n.status, Code: "error", Message: "reading organizations"}
	}
	value := []Organization{}
	for _, o := range arr(at(n.body, "data")) {
		org := Organization{ID: str(at(o, "id")), System: str(at(o, "system")), Name: str(at(o, "name")), Kind: str(at(o, "kind")),
			Role: str(at(o, "role")), ExternalID: str(at(o, "external_id")), Metadata: obj(at(o, "metadata"))}
		if org.Metadata == nil {
			org.Metadata = map[string]any{}
		}
		if perms, ok := at(o, "permissions").([]any); ok {
			org.Permissions, org.Denied, org.Conditional = strs(perms), strs(at(o, "denied")), []ConditionalPermission{}
			for _, c := range arr(at(o, "conditional")) {
				effect := "allow"
				if at(c, "effect") == "deny" {
					effect = "deny"
				}
				org.Conditional = append(org.Conditional, ConditionalPermission{Resource: str(at(c, "resource")), Action: str(at(c, "action")), Effect: effect})
			}
		}
		value = append(value, org)
	}
	a.orgMu.Lock()
	if len(a.orgCache) > 5000 {
		clear(a.orgCache)
	}
	a.orgCache[s.AccessToken] = orgEntry{at: a.now(), value: value}
	a.orgMu.Unlock()
	return value, nil
}

func (a *Auth) forgetOrganizations(token string) {
	a.orgMu.Lock()
	defer a.orgMu.Unlock()
	if token == "" {
		clear(a.orgCache)
		return
	}
	delete(a.orgCache, token)
}

// ToPublic is what the browser may be told of a session. Organizations that
// cannot be read just now come back on the next read.
func (a *Auth) ToPublic(ctx context.Context, s *Session) PublicSession {
	orgs, err := a.Organizations(ctx, s)
	if err != nil {
		orgs = []Organization{}
	}
	return PublicSession{User: s.User, TenantID: s.TenantID, Roles: s.Roles, Organizations: orgs, ExpiresAt: s.ExpiresAt}
}

// Can reports whether an organization of the session lets the person do
// action on resource, as its Permissions and Denied say. A permission with a
// condition is never counted here: ask Check.
func Can(o *Organization, resource, action string) bool {
	if o == nil || o.Permissions == nil {
		return false
	}
	match := func(p string) bool {
		r, act, _ := strings.Cut(p, ":")
		return (r == "*" || r == resource) && (act == "*" || act == action)
	}
	for _, d := range o.Denied {
		if match(d) {
			return false
		}
	}
	for _, p := range o.Permissions {
		if match(p) {
			return true
		}
	}
	return false
}

// CheckQuestion asks Cauthy whether the person may do Action on Resource in
// Organization, with what its conditions read.
type CheckQuestion struct {
	Organization string
	Resource     string
	Action       string
	Attributes   map[string]any
	ResourceID   string
	OwnerID      string
}

// Check asks Cauthy whether the person of s may do what q asks. Nobody signed
// in (s nil), an organization the person is not in, or a disabled account
// answer Allowed false. An error is Cauthy refusing the question itself, or
// not answering.
func (a *Auth) Check(ctx context.Context, s *Session, q CheckQuestion) (system.CheckResult, error) {
	if s == nil {
		return system.CheckResult{Allowed: false, Reason: "not signed in"}, nil
	}
	return a.decide(ctx, s.AccessToken, q)
}

func (a *Auth) decide(ctx context.Context, token string, q CheckQuestion) (system.CheckResult, error) {
	if q.Organization == "" {
		return system.CheckResult{Allowed: false, Reason: "no organization named"}, nil
	}
	wire := map[string]any{"resource": q.Resource, "action": q.Action}
	if q.ResourceID != "" {
		wire["resource_id"] = q.ResourceID
	}
	if q.OwnerID != "" {
		wire["owner_id"] = q.OwnerID
	}
	if q.Attributes != nil {
		wire["attributes"] = q.Attributes
	}
	payload, _ := json.Marshal(wire)
	n := a.fetch(ctx, http.MethodPost, a.issuer+"/v1/oauth/organizations/"+url.PathEscape(q.Organization)+"/check",
		http.Header{"Authorization": {"Bearer " + token}, "Content-Type": {"application/json"}, "Accept": {"application/json"}}, payload)
	if n.err != nil {
		return system.CheckResult{}, &system.APIError{Status: 503, Code: "unavailable", Message: "Cauthy could not be reached to check a permission"}
	}
	if n.ok() {
		return checkResultOf(at(n.body, "data")), nil
	}
	first := arr(at(n.body, "errors"))
	var code, message string
	if len(first) > 0 {
		code, message = str(at(first[0], "code")), str(at(first[0], "message"))
	}
	switch n.status {
	case 401, 403, 404:
		// About the person, not the question: each is a plain no.
		if message == "" {
			message = map[int]string{401: "not signed in", 403: "refused", 404: "not a member of the organization"}[n.status]
		}
		return system.CheckResult{Allowed: false, Reason: message}, nil
	}
	if code == "" {
		code = "error"
	}
	return system.CheckResult{}, &system.APIError{Status: n.status, Code: code, Message: "Cauthy refused to check a permission: " + message}
}

func checkResultOf(d any) system.CheckResult {
	out := system.CheckResult{Allowed: yes(at(d, "allowed")), Reason: str(at(d, "reason"))}
	if r := obj(at(d, "rule")); r != nil {
		rule := &system.CheckRule{Source: "role", Role: str(r["role"]), Kind: strOr(r["kind"], "*"), Resource: str(r["resource"]),
			Action: str(r["action"]), Effect: "deny", Condition: str(r["condition"])}
		if r["source"] == "exception" {
			rule.Source = "exception"
		}
		if r["effect"] == "allow" {
			rule.Effect = "allow"
		}
		out.Rule = rule
	}
	return out
}

// person is who is signed in, for a route about their own account.
type person struct {
	token string
	// kept is the session as the request's cookie holds it; nil when it was
	// renewed just now (then header carries the new cookie).
	kept   *stored
	header http.Header
}

// signedInAs is the person, or the 401 to answer with.
func (a *Auth) signedInAs(r *http.Request) (*person, *reply) {
	res := a.Resolve(r)
	h := http.Header{}
	for _, c := range res.Cookies {
		h.Add("Set-Cookie", c)
	}
	if res.Session == nil {
		return nil, problem(http.StatusUnauthorized, "unauthenticated", "Sign in first.", "", h, nil)
	}
	p := &person{token: res.Session.AccessToken, header: h}
	if len(res.Cookies) == 0 {
		_, p.kept, _ = a.read(r)
	}
	return p, nil
}

// answerOf decodes an answer's JSON body (at most maxAnswer); nil when it is not JSON.
func answerOf(res *http.Response) any {
	raw, _ := io.ReadAll(io.LimitReader(res.Body, maxAnswer))
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return nil
	}
	return v
}

// cancelOnClose is a stream that ends its request when it is closed.
type cancelOnClose struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (c cancelOnClose) Close() error {
	defer c.cancel()
	return c.ReadCloser.Close()
}
