package cauthy

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/vennet-developers/cauthy-sdk-go/cauthykey"
	"github.com/vennet-developers/cauthy-sdk-go/cauthytest"
	"github.com/vennet-developers/cauthy-sdk-go/keys"
)

const acmeLink = "acme-crm-signs-in-with-cauthy"

// contractKey is a fake whose key client is the link's service client, and a
// CAUTHY_KEY it issued for it.
func contractKey() (*cauthytest.Fake, string) {
	f := cauthytest.New()
	f.ClientID = "pact." + acmeLink + ".service"
	return f, f.IssueKey()
}

func keyContractAuth(t *testing.T, f *cauthytest.Fake, env map[string]string) (*Auth, error) {
	t.Helper()
	return New(Options{Contract: &Contract{Graph: acmeGraph(f, false), System: "acme-crm"}, Getenv: envOf(env), HTTPClient: f.Client(),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
}

func jwksOf(t *testing.T, a *Auth) []map[string]any {
	t.Helper()
	res := cauthytest.NewBrowser("").Send(a, "GET", "/.well-known/pact-jwks.json", nil)
	if res.StatusCode != 200 || res.Header.Get("Cache-Control") != "public, max-age=300" {
		t.Fatalf("%d %v", res.StatusCode, res.Header)
	}
	var set keys.JWKS
	if err := json.NewDecoder(res.Body).Decode(&set); err != nil {
		t.Fatal(err)
	}
	return set.Keys
}

func TestKeyContractNeedsNoKeyStoreAndPublishesTheKey(t *testing.T) {
	f, key := contractKey()
	a, err := keyContractAuth(t, f, map[string]string{"CAUTHY_KEY": key})
	if err != nil {
		t.Fatal(err)
	}
	k, _ := cauthykey.Parse(key)
	d := k.Derive()
	set := jwksOf(t, a)
	if len(set) != 1 || set[0]["kty"] != "OKP" || set[0]["crv"] != "Ed25519" || set[0]["x"] != d.X || set[0]["kid"] != d.KID ||
		set[0]["alg"] != "EdDSA" || set[0]["use"] != "sig" || len(set[0]) != 6 {
		t.Fatalf("%v", set)
	}
	if a.Pact() == nil || a.Pact().Keys() != nil {
		t.Fatal("a key application has a pact and no key store")
	}
	res := cauthytest.NewBrowser("").Do(a.Pact().JWKS(), cauthytest.NewBrowser("").Request("GET", "/.well-known/pact-jwks.json", nil))
	if res.StatusCode != 200 || !strings.Contains(string(mustRead(res.Body)), d.KID) {
		t.Fatal("Pact().JWKS() does not serve the key")
	}
}

func mustRead(r io.Reader) []byte {
	b, _ := io.ReadAll(r)
	return b
}

func TestKeyContractSignsInThroughTheLinkWithTheServiceClientsProof(t *testing.T) {
	f, key := contractKey()
	a, err := keyContractAuth(t, f, map[string]string{"CAUTHY_KEY": key})
	if err != nil {
		t.Fatal(err)
	}
	if a.ClientID() != "pact."+acmeLink || a.tenantSlug() != "acme" || a.identity != nil {
		t.Fatalf("%s %s", a.ClientID(), a.tenantSlug())
	}
	b := cauthytest.NewBrowser("https://app.test")
	signIn(t, a, f, b, "u1")
	var exchange, credentials *cauthytest.Call
	for _, c := range f.Calls() {
		switch c.Form.Get("grant_type") {
		case "authorization_code":
			exchange = &c
		case "client_credentials":
			credentials = &c
		}
	}
	if exchange == nil || exchange.Form.Get("client_id") != "pact."+acmeLink || exchange.Form.Has("client_assertion") ||
		exchange.Form.Has("client_secret") || exchange.Header.Get("X-Cauthy-System-Token") == "" {
		t.Fatalf("exchange %+v", exchange)
	}
	if credentials == nil || credentials.Form.Get("client_id") != "pact."+acmeLink+".service" ||
		credentials.Form.Get("client_assertion_type") != cauthykey.AssertionType || !strings.HasPrefix(credentials.Form.Get("client_assertion"), "eyJhbGciOiJFZERTQSIs") {
		t.Fatalf("credentials %+v", credentials)
	}
}

func TestKeyContractRefusesAKeyForAnotherCauthy(t *testing.T) {
	f := cauthytest.New()
	f.Issuer, f.ClientID = "https://other.test", "pact."+acmeLink+".service"
	key := f.IssueKey()
	f.Issuer = "https://id.test"
	_, err := keyContractAuth(t, f, map[string]string{"CAUTHY_KEY": key})
	var e *cauthykey.Error
	if !errors.As(err, &e) || e.Reason != "key_contract_issuer" || !strings.Contains(err.Error(), "https://other.test") {
		t.Fatalf("%v", err)
	}
}

func TestKeyContractRefusesTheVariablesTheKeyReplaces(t *testing.T) {
	f, key := contractKey()
	_, err := keyContractAuth(t, f, map[string]string{"CAUTHY_KEY": key, "CAUTHY_ISSUER": "https://id.test"})
	if err == nil || !strings.Contains(err.Error(), "CAUTHY_ISSUER is also set") {
		t.Fatalf("%v", err)
	}
}

// otherKey is CAUTHY_KEY's issuer and client with another secret, registered.
func otherKey(t *testing.T, f *cauthytest.Fake, key string) string {
	t.Helper()
	k, _ := cauthykey.Parse(key)
	raw := make([]byte, 32)
	_, _ = rand.Read(raw)
	other, err := cauthykey.Compose(k.Issuer, k.ClientID, base64.RawURLEncoding.EncodeToString(raw))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.RegisterKey(other); err != nil {
		t.Fatal(err)
	}
	return other
}

func TestKeyContractPublishesThePreviousKeyDuringARotation(t *testing.T) {
	f, key := contractKey()
	previous := otherKey(t, f, key)
	a, err := keyContractAuth(t, f, map[string]string{"CAUTHY_KEY": key, "CAUTHY_KEY_PREVIOUS": previous})
	if err != nil {
		t.Fatal(err)
	}
	set := jwksOf(t, a)
	k, _ := cauthykey.Parse(key)
	p, _ := cauthykey.Parse(previous)
	if len(set) != 2 || set[0]["kid"] != k.Derive().KID || set[1]["kid"] != p.Derive().KID || set[1]["alg"] != "EdDSA" {
		t.Fatalf("%v", set)
	}
}

func TestKeyContractLegacyRootKeyStillWorks(t *testing.T) {
	f := cauthytest.New()
	a, err := contractAuth(t, f, keys.Memory(), false)
	if err != nil {
		t.Fatal(err)
	}
	if set := jwksOf(t, a); len(set) != 1 || set[0]["kty"] != "RSA" {
		t.Fatalf("%v", set)
	}
}
