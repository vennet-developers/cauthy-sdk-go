package system

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vennet-developers/cauthy-sdk-go/internal/jose"
	"github.com/vennet-developers/cauthy-sdk-go/keys"
)

// cauthy is a token endpoint and a few routes, recording what it was sent.
type cauthy struct {
	*httptest.Server
	mu       sync.Mutex
	forms    []url.Values
	requests []*http.Request
	bodies   []string
	tokens   atomic.Int32
	reject   atomic.Bool // the next API call answers 401 once
	slow     time.Duration
}

func newCauthy(t *testing.T) *cauthy {
	c := &cauthy{}
	c.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c.slow > 0 {
			time.Sleep(c.slow)
		}
		w.Header().Set("Content-Type", "application/json")
		body, _ := io.ReadAll(r.Body)
		c.mu.Lock()
		c.requests = append(c.requests, r)
		c.bodies = append(c.bodies, string(body))
		c.mu.Unlock()
		if r.URL.Path == "/v1/oauth/token" {
			form, _ := url.ParseQuery(string(body))
			c.mu.Lock()
			c.forms = append(c.forms, form)
			c.mu.Unlock()
			if form.Get("client_secret") == "wrong" {
				w.WriteHeader(401)
				w.Write([]byte(`{"error":"invalid_client","error_description":"client authentication failed"}`))
				return
			}
			n := c.tokens.Add(1)
			w.Write([]byte(`{"access_token":"sys-` + string(rune('0'+n)) + `","expires_in":600}`))
			return
		}
		if c.reject.CompareAndSwap(true, false) {
			w.WriteHeader(401)
			return
		}
		switch {
		case r.URL.Path == "/v1/organizations" && r.Method == "GET":
			w.Write([]byte(`{"data":[{"id":"o1","system":"acme-crm","name":"Acme","kind":"customer","status":"active","metadata":{},"members":2}],"total_count":1}`))
		case r.URL.Path == "/v1/organizations/o1/members" && r.Method == "POST":
			w.Write([]byte(`{"data":{"user_id":"u1","email":"ana@example.com","name":"Ana","status":"active","role":"owner","invited":true}}`))
		case r.URL.Path == "/v1/organizations/o1" && r.Method == "DELETE":
			w.WriteHeader(204)
		case r.URL.Path == "/v1/systems/acme-crm/check":
			w.Write([]byte(`{"data":{"allowed":true,"reason":"allowed by role owner","rule":{"source":"role","role":"owner","kind":"*","resource":"invoices","action":"approve","effect":"allow"}}}`))
		case r.URL.Path == "/v1/pact/status":
			w.Write([]byte(`{"data":{"system":"acme-crm","in_step":true,"outside":[],"missing":[]}}`))
		default:
			w.WriteHeader(404)
			w.Write([]byte(`{"errors":[{"code":"organization_not_found","message":"organization not found"}]}`))
		}
	}))
	t.Cleanup(c.Close)
	return c
}

func (c *cauthy) form(i int) url.Values { c.mu.Lock(); defer c.mu.Unlock(); return c.forms[i] }

func TestTokenWithTheSecretIsKeptUntilItRunsOut(t *testing.T) {
	cy := newCauthy(t)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	c, _ := New(Options{Issuer: cy.URL + "/", ClientID: "acme-crm", ClientSecret: "s3cret", Now: func() time.Time { return now }})
	for range 3 {
		if tok, err := c.Token(context.Background()); err != nil || tok != "sys-1" {
			t.Fatalf("%q %v", tok, err)
		}
	}
	f := cy.form(0)
	if f.Get("grant_type") != "client_credentials" || f.Get("client_id") != "acme-crm" || f.Get("client_secret") != "s3cret" {
		t.Fatalf("%v", f)
	}
	now = now.Add(10*time.Minute - 29*time.Second)
	if tok, _ := c.Token(context.Background()); tok != "sys-2" {
		t.Fatalf("renewed 30 s before the end: %q", tok)
	}
}

func TestTokenWithTheApplicationsOwnKeysSignsTheAssertion(t *testing.T) {
	cy := newCauthy(t)
	rings, _ := keys.Derive("acme-root-key-for-tests-only-0123456789", "")
	own := keys.New(keys.Memory(), rings.Seal, nil)
	c, _ := New(Options{Issuer: cy.URL, Keys: own, KeysClientID: "pact.acme-crm-signs-in-with-cauthy.service"})
	if _, err := c.Token(context.Background()); err != nil {
		t.Fatal(err)
	}
	f := cy.form(0)
	if f.Get("client_id") != "pact.acme-crm-signs-in-with-cauthy.service" || f.Get("client_assertion_type") != assertionType || f.Get("client_secret") != "" {
		t.Fatalf("%v", f)
	}
	a, err := jose.ParseCompact(f.Get("client_assertion"))
	if err != nil {
		t.Fatal(err)
	}
	kid, key, _ := own.Current(context.Background())
	if err := a.VerifyRS256(&key.PublicKey); err != nil || string(a.Header["kid"]) != `"`+kid+`"` || string(a.Header["alg"]) != `"RS256"` {
		t.Fatalf("signature or header: %v %s", err, a.Header)
	}
	var claims struct {
		Iss, Sub, Aud, Jti string
		Iat, Exp           int64
	}
	json.Unmarshal(a.Payload, &claims)
	if claims.Iss != "pact.acme-crm-signs-in-with-cauthy.service" || claims.Sub != claims.Iss || claims.Aud != cy.URL+"/v1/oauth/token" ||
		len(claims.Jti) != 36 || claims.Exp-claims.Iat != 120 {
		t.Fatalf("%+v", claims)
	}
}

func TestTokenWithAPEMKey(t *testing.T) {
	cy := newCauthy(t)
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	pemKey := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	c, _ := New(OptionsFromEnv(func(k string) string {
		return map[string]string{"CAUTHY_ISSUER": cy.URL, "CAUTHY_CLIENT_ID": "acme-crm", "CAUTHY_SYSTEM_KEY": pemKey, "CAUTHY_SYSTEM_KEY_ID": "k1"}[k]
	}))
	if _, err := c.Token(context.Background()); err != nil {
		t.Fatal(err)
	}
	a, _ := jose.ParseCompact(cy.form(0).Get("client_assertion"))
	if a.VerifyRS256(&key.PublicKey) != nil || string(a.Header["kid"]) != `"k1"` {
		t.Fatal("not signed with the PEM key")
	}
	set, _ := c.PublicJWKS(context.Background())
	if len(set.Keys) != 1 || set.Keys[0]["kid"] != "k1" || set.Keys[0]["e"] != "AQAB" {
		t.Fatalf("%+v", set)
	}
}

func TestRefusalsAndMissingCredentialsAreNamed(t *testing.T) {
	cy := newCauthy(t)
	c, _ := New(Options{Issuer: cy.URL, ClientID: "acme-crm", ClientSecret: "wrong"})
	_, err := c.Token(context.Background())
	var api *APIError
	if !errors.As(err, &api) || api.Status != 401 || api.Code != "invalid_client" || !strings.Contains(api.Message, "client authentication failed") {
		t.Fatalf("%v", err)
	}
	none, _ := New(Options{Issuer: cy.URL, ClientID: "acme-crm"})
	if _, err := none.Token(context.Background()); err == nil || !strings.Contains(err.Error(), "CAUTHY_CLIENT_SECRET") {
		t.Fatalf("%v", err)
	}
	contracted, _ := New(Options{Issuer: cy.URL, Keys: &keys.Keys{}})
	if _, err := contracted.Token(context.Background()); err == nil || !strings.Contains(err.Error(), "service block") {
		t.Fatalf("%v", err)
	}
}

func TestADeadlineIs503(t *testing.T) {
	cy := newCauthy(t)
	cy.slow = 200 * time.Millisecond
	c, _ := New(Options{Issuer: cy.URL, ClientID: "acme-crm", ClientSecret: "s3cret", Timeout: 50 * time.Millisecond})
	_, err := c.Token(context.Background())
	var api *APIError
	if !errors.As(err, &api) || api.Status != 503 || api.Code != "unavailable" {
		t.Fatalf("%v", err)
	}
}

func TestOrganizationsMembersCheckAndStatus(t *testing.T) {
	cy := newCauthy(t)
	changes := 0
	c, _ := New(Options{Issuer: cy.URL, ClientID: "acme-crm", ClientSecret: "s3cret", System: "acme-crm", AcceptInviteURL: "https://crm.example.com/accept-invite",
		Changed: func() { changes++ }})
	ctx := context.Background()
	orgs, total, err := c.ListOrganizations(ctx, Query{Status: "active", Limit: 10})
	if err != nil || total != 1 || orgs[0].ID != "o1" || orgs[0].Members != 2 {
		t.Fatalf("%+v %d %v", orgs, total, err)
	}
	cy.reject.Store(true)
	m, err := c.AddMember(ctx, "o1", NewMember{Email: "ana@example.com", Role: "owner"})
	if err != nil || m.UserID != "u1" || !m.Invited {
		t.Fatalf("a 401 is retried once with a new token: %+v %v", m, err)
	}
	cy.mu.Lock()
	var add *http.Request
	var addBody string
	for i, r := range cy.requests {
		if r.URL.Path == "/v1/organizations/o1/members" {
			add, addBody = r, cy.bodies[i]
		}
	}
	cy.mu.Unlock()
	if add.Header.Get("X-Cauthy-Link-To") != "https://crm.example.com/accept-invite" || add.Header.Get("Authorization") != "Bearer sys-2" ||
		!strings.Contains(addBody, `"only_new":true`) || !strings.Contains(addBody, `"client_id":"acme-crm"`) {
		t.Fatalf("%v %s", add.Header, addBody)
	}
	if err := c.RemoveOrganization(ctx, "o1"); err != nil {
		t.Fatal(err)
	}
	if changes != 2 {
		t.Fatalf("a member added and an organization removed are two changes, got %d", changes)
	}
	if _, err := c.GetOrganization(ctx, "missing"); err == nil || err.(*APIError).Code != "organization_not_found" {
		t.Fatalf("%v", err)
	}
	r, err := c.Check(ctx, CheckQuestion{OrganizationID: "o1", UserID: "u1", Resource: "invoices", Action: "approve", Attributes: map[string]any{"amount": 500}})
	if err != nil || !r.Allowed || r.Rule == nil || r.Rule.Role != "owner" {
		t.Fatalf("%+v %v", r, err)
	}
	s, err := c.PactStatus(ctx, "acme-crm")
	if err != nil || !s.InStep || s.System != "acme-crm" {
		t.Fatalf("%+v %v", s, err)
	}
}
