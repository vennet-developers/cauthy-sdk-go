package cauthy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vennet-developers/cauthy-sdk-go/cauthytest"
)

// sessionClock is a clock the session tests move by hand.
type sessionClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *sessionClock) now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *sessionClock) add(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

func TestASessionIsReadRenewedAndEnded(t *testing.T) {
	f := cauthytest.New()
	clk := &sessionClock{t: time.Date(2026, 1, 1, 9, 0, 0, 0, time.UTC)}
	a := newAuth(t, f, func(o *Options) { o.Now = clk.now })
	b := cauthytest.NewBrowser("")
	signIn(t, a, f, b, "u1")

	r := b.Request("GET", "/", nil)
	if s := a.Session(nil, r); s == nil || s.User.Email != "ana@example.com" || s.AccessToken == "" || s.ExpiresAt != "2026-01-01T09:10:00.000Z" {
		t.Fatalf("%+v", s)
	}
	if a.Status(r) != StatusAuthenticated {
		t.Fatal("authenticated")
	}

	clk.add(10 * time.Minute)
	r = b.Request("GET", "/", nil)
	if a.Session(nil, r) != nil || a.Status(r) != StatusExpired {
		t.Fatal("an expired session is nobody until renewed")
	}
	w := httptest.NewRecorder()
	s := a.Session(w, r)
	if s == nil || len(w.Header().Values("Set-Cookie")) == 0 {
		t.Fatal("renewed, with its new cookie on the answer")
	}
	b.Take(w.Header())

	f.SetActive("u1", false)
	clk.add(10 * time.Minute)
	res := a.Resolve(b.Request("GET", "/", nil))
	if res.Session != nil || res.Status != StatusUnauthenticated || !strings.Contains(strings.Join(res.Cookies, ";"), "Max-Age=0") {
		t.Fatalf("an account disabled at Cauthy is signed out here at the next renewal: %+v", res)
	}
}

func TestCauthyUnreachableIsExpiredNotSignedOut(t *testing.T) {
	f := cauthytest.New()
	clk := &sessionClock{t: time.Date(2026, 1, 1, 9, 0, 0, 0, time.UTC)}
	a := newAuth(t, f, func(o *Options) { o.Now = clk.now })
	b := cauthytest.NewBrowser("")
	signIn(t, a, f, b, "u1")
	clk.add(time.Hour)
	f.Down = true
	res := a.Resolve(b.Request("GET", "/", nil))
	if res.Status != StatusExpired || len(res.Cookies) != 0 {
		t.Fatalf("%+v", res)
	}
}

func TestRequestsArrivingTogetherShareOneRenewal(t *testing.T) {
	f := cauthytest.New()
	clk := &sessionClock{t: time.Date(2026, 1, 1, 9, 0, 0, 0, time.UTC)}
	a := newAuth(t, f, func(o *Options) { o.Now = clk.now })
	b := cauthytest.NewBrowser("")
	signIn(t, a, f, b, "u1")
	clk.add(time.Hour)
	var wg sync.WaitGroup
	for range 5 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if a.Resolve(b.Request("GET", "/", nil)).Session == nil {
				t.Error("a request lost the session")
			}
		}()
	}
	wg.Wait()
	n := 0
	for _, c := range f.Calls() {
		if c.Path == "/v1/oauth/token" && c.Form.Get("grant_type") == "refresh_token" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("%d renewals, want 1", n)
	}
}

func TestATamperedCookieIsCleared(t *testing.T) {
	a := newAuth(t, cauthytest.New(), nil)
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Cookie", "cauthy_session.0=forged")
	res := a.Resolve(r)
	if res.Status != StatusUnauthenticated || len(res.Cookies) != 1 || !strings.HasPrefix(res.Cookies[0], "cauthy_session.0=; ") {
		t.Fatalf("%+v", res)
	}
}

func TestReadsACookieNodeSealed(t *testing.T) {
	// internal/jose/testdata/node-fixtures.json: @cauthyhq/node sealed this
	// session with SHA-256 of testSecret.
	raw := nodeFixture(t, "secretSealed")
	a := newAuth(t, cauthytest.New(), func(o *Options) { o.Now = func() time.Time { return time.Unix(1767226000, 0) } })
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Cookie", "cauthy_session.0="+raw)
	s := a.Session(nil, r)
	if s == nil || s.AccessToken != "at-1" || s.User.Email != "ana@example.com" || s.TenantID != "8a6e0804-2bd0-4672-b79a-d97027f5f2a1" {
		t.Fatalf("%+v", s)
	}
}

func TestOrganizationsAreKeptAMinuteAndCheckIsAskedOfCauthy(t *testing.T) {
	f := cauthytest.New()
	f.SetOrganizations("u1", []map[string]any{{"id": "o1", "system": "acme-crm", "name": "Acme", "kind": "customer", "role": "accountant",
		"permissions": []any{"invoices:*"}, "denied": []any{"invoices:delete"}}})
	a := newAuth(t, f, func(o *Options) { o.System = "acme-crm" })
	b := cauthytest.NewBrowser("")
	signIn(t, a, f, b, "u1")
	s := a.Session(nil, b.Request("GET", "/", nil))
	ctx := context.Background()
	orgs, err := a.Organizations(ctx, s)
	if err != nil || len(orgs) != 1 || orgs[0].Role != "accountant" || !Can(&orgs[0], "invoices", "approve") || Can(&orgs[0], "invoices", "delete") {
		t.Fatalf("%+v %v", orgs, err)
	}
	a.Organizations(ctx, s)
	if n := len(callsTo(f, "GET /v1/oauth/organizations")); n != 1 {
		t.Fatalf("%d reads, want 1", n)
	}
	if f.Last("GET /v1/oauth/organizations").Query.Get("system") != "acme-crm" {
		t.Fatal("the system's organizations")
	}
	r, err := a.Check(ctx, s, CheckQuestion{Organization: "o1", Resource: "invoices", Action: "approve", Attributes: map[string]any{"amount": 500}})
	if err != nil || !r.Allowed || r.Rule.Role != "accountant" {
		t.Fatalf("%+v %v", r, err)
	}
	if r, _ := a.Check(ctx, s, CheckQuestion{Organization: "o9", Resource: "invoices", Action: "approve"}); r.Allowed || r.Reason != "organization not found" {
		t.Fatalf("not a member is a no: %+v", r)
	}
	if r, _ := a.Check(ctx, nil, CheckQuestion{Organization: "o1"}); r.Allowed {
		t.Fatal("nobody signed in is a no")
	}
	pub := a.ToPublic(ctx, s)
	if pub.User.ID != "u1" || len(pub.Organizations) != 1 || pub.Roles == nil {
		t.Fatalf("%+v", pub)
	}
}

func callsTo(f *cauthytest.Fake, route string) []cauthytest.Call {
	var out []cauthytest.Call
	for _, c := range f.Calls() {
		if c.Method+" "+c.Path == route {
			out = append(out, c)
		}
	}
	return out
}

// roundTripper is a transport made of a function.
type roundTripper func(*http.Request) (*http.Response, error)

func (f roundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestCallsToCauthyNeverFollowARedirectOffItsHost(t *testing.T) {
	f := cauthytest.New()
	var elsewhere atomic.Int32
	client := &http.Client{Transport: roundTripper(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host != "id.test" {
			elsewhere.Add(1)
			return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(`{"sub":"stolen"}`)), Request: r}, nil
		}
		if r.URL.Path == "/v1/oauth/userinfo" {
			return &http.Response{StatusCode: 302, Header: http.Header{"Location": {"https://elsewhere.example.com/collect"}}, Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
		}
		return f.Client().Transport.RoundTrip(r)
	})}
	a := newAuth(t, f, func(o *Options) { o.HTTPClient = client })
	n := a.fetch(context.Background(), http.MethodGet, a.issuer+"/v1/oauth/userinfo", http.Header{"Authorization": {"Bearer at-1"}}, nil)
	if elsewhere.Load() != 0 || n.ok() {
		t.Fatalf("followed a redirect off Cauthy's host: %d calls elsewhere, %+v", elsewhere.Load(), n)
	}
}
