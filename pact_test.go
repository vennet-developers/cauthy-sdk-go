package cauthy

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vennet-developers/cauthy-sdk-go/cauthytest"
	"github.com/vennet-developers/cauthy-sdk-go/keys"
)

const testRootKey = "acme-root-key-for-tests-only-0123456789"

// acmeGraph is a Pact graph with Acme CRM linked to the fake Cauthy, its
// keys published at /.well-known/pact-jwks.json.
func acmeGraph(f *cauthytest.Fake, verifiedEmail bool) []byte {
	g := map[string]any{
		"nodes": []any{
			map[string]any{"id": "cauthy", "type": "system", "url": f.Issuer, "tenants": []any{map[string]any{"id": "8a6e0804-2bd0-4672-b79a-d97027f5f2a1", "slug": "acme"}}},
			map[string]any{"id": "acme-crm", "type": "system", "url": "https://app.test", "jwks_url": "https://app.test/.well-known/pact-jwks.json"},
		},
		"edges": []any{map[string]any{"from": "acme-crm", "relation": "links", "to": "cauthy", "link": "acme-crm-signs-in-with-cauthy",
			"identity": map[string]any{"tenant": "acme", "tenant_id": "8a6e0804-2bd0-4672-b79a-d97027f5f2a1"},
			"sign_in":  map[string]any{"redirect_uris": []any{"https://app.test/api/auth/callback"}, "system_proof": "auto", "require_verified_email": verifiedEmail},
			"service":  map[string]any{}}},
	}
	raw, _ := json.Marshal(g)
	return raw
}

func contractAuth(t *testing.T, f *cauthytest.Fake, store keys.Store, verifiedEmail bool) (*Auth, error) {
	t.Helper()
	return New(Options{Contract: &Contract{Graph: acmeGraph(f, verifiedEmail), System: "acme-crm"}, Keys: store, RootKey: testRootKey,
		HTTPClient: f.Client(), Getenv: noEnv, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
}

func TestContractModeStartsFromTheGraphAndPublishesItsKeys(t *testing.T) {
	f := cauthytest.New()
	store := keys.Memory()
	var (
		mu    sync.Mutex
		clock = time.Now()
	)
	now := func() time.Time { mu.Lock(); defer mu.Unlock(); return clock }
	a, err := New(Options{Contract: &Contract{Graph: acmeGraph(f, false), System: "acme-crm"}, Keys: store, RootKey: testRootKey,
		HTTPClient: f.Client(), Getenv: noEnv, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if a.ClientID() != "pact.acme-crm-signs-in-with-cauthy" || a.tenant != "acme" || a.JWKSPath() != "/.well-known/pact-jwks.json" || a.Pact() == nil {
		t.Fatalf("%+v", a)
	}
	if list, _ := store.List(context.Background()); len(list) != 1 {
		t.Fatal("the key is made at start (contract/pact.md, rule 10)")
	}
	b := cauthytest.NewBrowser("")
	res := b.Send(a, "GET", "/.well-known/pact-jwks.json", nil)
	var set keys.JWKS
	json.NewDecoder(res.Body).Decode(&set)
	if res.StatusCode != 200 || res.Header.Get("Cache-Control") != "public, max-age=300" || res.Header.Get("Cauthy-Protocol") != "1" || len(set.Keys) != 1 {
		t.Fatalf("%d %v %+v", res.StatusCode, res.Header, set)
	}
	// The key made at start does not sign yet: rotating now is refused.
	if _, err := a.Pact().Keys().Rotate(context.Background()); !errors.Is(err, keys.ErrRotateTooSoon) {
		t.Fatalf("a rotation before the first key signs: want ErrRotateTooSoon, got %v", err)
	}
	mu.Lock()
	clock = clock.Add(keys.SignAfter)
	mu.Unlock()
	kid, err := a.Pact().Keys().Rotate(context.Background())
	if err != nil || kid == set.Keys[0]["kid"] {
		t.Fatalf("%s %v", kid, err)
	}
	if n, err := a.Pact().Keys().Reseal(context.Background()); err != nil || n != 0 {
		t.Fatalf("%d %v", n, err)
	}
	if a.Pact().Contract().SystemProof != "auto" {
		t.Fatal("system proof")
	}
}

func TestContractModeRefusesASecondSource(t *testing.T) {
	f := cauthytest.New()
	g := acmeGraph(f, false)
	cases := map[string]Options{
		"a CAUTHY_ variable": {Contract: &Contract{Graph: g, System: "acme-crm"}, Keys: keys.Memory(), RootKey: testRootKey,
			Getenv: func(k string) string { return map[string]string{"CAUTHY_SECRET": "x"}[k] }},
		"an option the contract owns": {Contract: &Contract{Graph: g, System: "acme-crm"}, Keys: keys.Memory(), RootKey: testRootKey, ClientID: "x", Getenv: noEnv},
		"no root key":                 {Contract: &Contract{Graph: g, System: "acme-crm"}, Keys: keys.Memory(), Getenv: noEnv},
		"a short root key":            {Contract: &Contract{Graph: g, System: "acme-crm"}, Keys: keys.Memory(), RootKey: "short", Getenv: noEnv},
		"no key store":                {Contract: &Contract{Graph: g, System: "acme-crm"}, RootKey: testRootKey, Getenv: noEnv},
	}
	for name, o := range cases {
		o.HTTPClient = f.Client()
		_, err := New(o)
		var ce *ConfigError
		if !errors.As(err, &ce) {
			t.Errorf("%s: want a config error, got %v", name, err)
		}
	}
	store := keys.Memory()
	if _, err := contractAuth(t, f, store, false); err != nil {
		t.Fatal(err)
	}
	f2 := cauthytest.New()
	_, err := New(Options{Contract: &Contract{Graph: acmeGraph(f2, false), System: "acme-crm"}, Keys: store, RootKey: "another-root-key-for-tests-only-012345",
		HTTPClient: f2.Client(), Getenv: noEnv})
	if err == nil || !strings.Contains(err.Error(), "PACT_ROOT_KEY_PREVIOUS") {
		t.Fatalf("a key the root cannot open stops the start: %v", err)
	}
}

func TestALinkThatRequiresAVerifiedAddressLetsNobodyElseIn(t *testing.T) {
	f := cauthytest.New()
	unverified := false
	f.AddUser(cauthytest.User{Sub: "u2", Email: "new@example.com", Name: "New", Active: true, Verified: &unverified}, "")
	a, err := contractAuth(t, f, keys.Memory(), true)
	if err != nil {
		t.Fatal(err)
	}
	b := cauthytest.NewBrowser("")
	res := b.Send(a, "GET", "/api/auth/login?return_to=/x", nil)
	back, _ := f.Authorize(res.Header.Get("Location"), "u2")
	res = b.Send(a, "GET", strings.TrimPrefix(back, "https://app.test"), nil)
	if res.Header.Get("Location") != "/?auth_error=email_not_verified" || b.Jar["cauthy_session.0"] != "" || len(f.Revoked()) != 1 {
		t.Fatalf("refused and the tokens revoked: %v %v %v", res.Header, b.Jar, f.Revoked())
	}
}
