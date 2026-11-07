package system

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// TestRedirectsAreNeverFollowed: a redirect from Cauthy's address must not
// carry the application's secret or token anywhere else.
func TestRedirectsAreNeverFollowed(t *testing.T) {
	var elsewhere atomic.Int32
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		elsewhere.Add(1)
		w.Write([]byte(`{"access_token":"stolen","expires_in":600,"data":{}}`))
	}))
	defer evil.Close()
	for _, redirectToken := range []bool{true, false} {
		cy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/v1/oauth/token" && !redirectToken {
				w.Write([]byte(`{"access_token":"sys-1","expires_in":600}`))
				return
			}
			http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusTemporaryRedirect)
		}))
		c, _ := New(Options{Issuer: cy.URL, ClientID: "acme-crm", ClientSecret: "s3cret"})
		if _, err := c.GetOrganization(context.Background(), "o1"); err == nil {
			t.Errorf("redirect token=%v: want an error", redirectToken)
		}
		cy.Close()
	}
	if n := elsewhere.Load(); n != 0 {
		t.Fatalf("a redirect was followed %d times", n)
	}
}

// TestATokenIsKeptHalfItsLifeAtLeast: a short-lived token is not asked for
// again on every call.
func TestATokenIsKeptHalfItsLifeAtLeast(t *testing.T) {
	var issued atomic.Int32
	cy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		issued.Add(1)
		w.Write([]byte(`{"access_token":"sys","expires_in":40}`))
	}))
	defer cy.Close()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	c, _ := New(Options{Issuer: cy.URL, ClientID: "acme-crm", ClientSecret: "s3cret", Now: func() time.Time { return now }})
	c.Token(context.Background())
	now = now.Add(15 * time.Second)
	c.Token(context.Background())
	if n := issued.Load(); n != 1 {
		t.Fatalf("a 40 s token was asked for again after 15 s: %d tokens", n)
	}
	now = now.Add(6 * time.Second)
	c.Token(context.Background())
	if n := issued.Load(); n != 2 {
		t.Fatalf("after half its life the token is renewed: %d tokens", n)
	}
}

// TestDotIdsAreRefusedBeforeAnyCall: "." and ".." would make the path name
// another route.
func TestDotIdsAreRefusedBeforeAnyCall(t *testing.T) {
	var calls atomic.Int32
	cy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Write([]byte(`{"access_token":"sys","expires_in":600,"data":{}}`))
	}))
	defer cy.Close()
	c, _ := New(Options{Issuer: cy.URL, ClientID: "acme-crm", ClientSecret: "s3cret"})
	ctx := context.Background()
	for _, id := range []string{".", ".."} {
		if _, err := c.GetOrganization(ctx, id); err == nil {
			t.Errorf("GetOrganization(%q): want an error", id)
		}
		if err := c.RemoveOrganization(ctx, id); err == nil {
			t.Errorf("RemoveOrganization(%q): want an error", id)
		}
		if err := c.RemoveMember(ctx, "o1", id); err == nil {
			t.Errorf("RemoveMember(o1, %q): want an error", id)
		}
		if _, err := c.SetMemberRole(ctx, id, "u1", "owner"); err == nil {
			t.Errorf("SetMemberRole(%q): want an error", id)
		}
	}
	if n := calls.Load(); n != 0 {
		t.Fatalf("%d calls reached Cauthy", n)
	}
}
