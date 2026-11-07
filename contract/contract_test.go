package contract

import (
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/vennet-developers/cauthy-sdk-go/internal/cfgerr"
)

const acmeTenant = "8a6e0804-2bd0-4672-b79a-d97027f5f2a1"

// graph is a context graph with Acme CRM linked to Cauthy; change edits the
// link (sign_in, service, identity…) before it is written.
func graph(t *testing.T, change func(link, acme, cauthy map[string]any)) []byte {
	t.Helper()
	cauthy := map[string]any{"id": "cauthy", "type": "system", "url": "https://id.example.com/",
		"tenants": []any{map[string]any{"id": acmeTenant, "slug": "acme"}}}
	acme := map[string]any{"id": "acme-crm", "type": "system", "url": "https://crm.example.com",
		"jwks_url": "https://crm.example.com/.well-known/pact-jwks.json"}
	capability := map[string]any{"id": "cauthy.identity.v1", "type": "capability",
		"token": map[string]any{"algorithm": "RS256", "audience": "cauthy"}}
	link := map[string]any{"from": "acme-crm", "relation": "links", "to": "cauthy", "link": "acme-crm-signs-in-with-cauthy",
		"capability": "cauthy.identity.v1", "identity": map[string]any{"tenant": acmeTenant},
		"sign_in": map[string]any{"redirect_uris": []any{"https://crm.example.com/api/auth/callback"}, "require_system_proof": false},
		"service": map[string]any{}}
	if change != nil {
		change(link, acme, cauthy)
	}
	raw, err := json.Marshal(map[string]any{"nodes": []any{cauthy, acme, capability}, "edges": []any{link}})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func read(t *testing.T, g []byte) (*Resolved, error) {
	t.Helper()
	return Read(Options{Graph: g, System: "acme-crm"})
}

func TestReadsTheLink(t *testing.T) {
	r, err := read(t, graph(t, nil))
	if err != nil {
		t.Fatal(err)
	}
	want := Resolved{
		System: "acme-crm", Link: "acme-crm-signs-in-with-cauthy", Issuer: "https://id.example.com", TenantID: acmeTenant, Tenant: "acme",
		ClientID: "pact.acme-crm-signs-in-with-cauthy", SystemProof: "off",
		ServiceClientID: "pact.acme-crm-signs-in-with-cauthy.service",
		JWKSURL:         "https://crm.example.com/.well-known/pact-jwks.json", JWKSPath: "/.well-known/pact-jwks.json",
		Audience: "cauthy", TokenAlgorithm: "RS256",
	}
	if !slices.Equal(r.RedirectURIs, []string{"https://crm.example.com/api/auth/callback"}) {
		t.Fatalf("redirects %v", r.RedirectURIs)
	}
	r.RedirectURIs = nil
	if !reflect.DeepEqual(*r, want) {
		t.Fatalf("got  %+v\nwant %+v", *r, want)
	}
}

func TestReadsTheProofTheVerifiedEmailAndALinkNamedBySlug(t *testing.T) {
	r, err := read(t, graph(t, func(link, _, _ map[string]any) {
		link["identity"] = map[string]any{"tenant": "acme", "tenant_id": acmeTenant}
		link["sign_in"] = map[string]any{"client_id": "acme-web", "redirect_uris": []any{"https://crm.example.com/cb"},
			"require_system_proof": false, "system_proof": "auto", "require_verified_email": true, "persistent_sessions": true}
	}))
	if err != nil {
		t.Fatal(err)
	}
	if r.TenantID != acmeTenant || r.Tenant != "acme" || r.ClientID != "acme-web" || r.SystemProof != "auto" || r.RequireSystemProof ||
		!r.RequireVerifiedEmail || !r.PersistentSessions {
		t.Fatalf("%+v", r)
	}
	r, err = read(t, graph(t, func(link, _, _ map[string]any) {
		link["sign_in"] = map[string]any{"redirect_uris": []any{"https://crm.example.com/cb"}, "require_system_proof": true}
	}))
	if err != nil || r.SystemProof != "required" || !r.RequireSystemProof {
		t.Fatalf("the old boolean: %+v %v", r, err)
	}
}

func TestRefusesWhatPactMdLists(t *testing.T) {
	cases := map[string]struct {
		change func(link, acme, cauthy map[string]any)
		says   string
	}{
		"no link":            {func(l, _, _ map[string]any) { l["to"] = "elsewhere" }, "no link of the graph"},
		"nil tenant":         {func(l, _, _ map[string]any) { l["identity"] = map[string]any{"tenant": nilUUID} }, "nil UUID"},
		"unlisted tenant":    {func(_, _, c map[string]any) { c["tenants"] = []any{} }, "does not name the slug"},
		"slug, no tenant_id": {func(l, _, _ map[string]any) { l["identity"] = map[string]any{"tenant": "acme"} }, "pull the graph again"},
		"new workspace":      {func(l, _, _ map[string]any) { l["identity"] = map[string]any{"tenant": "acme", "create_tenant": true} }, "new workspace"},
		"tenant_id mismatch": {func(l, _, _ map[string]any) {
			l["identity"] = map[string]any{"tenant": acmeTenant, "tenant_id": "3f2a9c41-7d4b-4e8a-a1c2-5b6d7e8f9a0b"}
		}, "does not match"},
		"no redirect": {func(l, _, _ map[string]any) { l["sign_in"] = map[string]any{} }, "no redirect URI"},
		"http issuer": {func(_, _, c map[string]any) { c["url"] = "http://id.example.com" }, "must be https"},
		"http jwks":   {func(_, a, _ map[string]any) { a["jwks_url"] = "http://crm.example.com/jwks" }, "must be https"},
		"http events": {func(_, a, _ map[string]any) { a["events_url"] = "http://crm.example.com/events" }, "must be https"},
		"unknown proof": {func(l, _, _ map[string]any) {
			l["sign_in"] = map[string]any{"redirect_uris": []any{"https://x.example.com"}, "system_proof": "sometimes"}
		}, "off, auto or required"},
		"proof, no service": {func(l, _, _ map[string]any) {
			l["service"] = nil
			l["sign_in"] = map[string]any{"redirect_uris": []any{"https://x.example.com"}, "system_proof": "auto"}
		}, "needs a service block"},
		"service, no jwks_url": {func(_, a, _ map[string]any) { delete(a, "jwks_url") }, "names no jwks_url"},
	}
	for name, c := range cases {
		_, err := read(t, graph(t, c.change))
		var ce *cfgerr.Error
		if !errors.As(err, &ce) || !strings.Contains(err.Error(), c.says) {
			t.Errorf("%s: want a config error saying %q, got %v", name, c.says, err)
		}
	}
	if _, err := Read(Options{Graph: []byte(`{}`), System: "acme-crm"}); err == nil {
		t.Error("not a graph: want an error")
	}
	if _, err := Read(Options{Graph: graph(t, nil), System: "Acme CRM"}); err == nil {
		t.Error("bad system id: want an error")
	}
}

func TestLocalhostMayUseHTTP(t *testing.T) {
	r, err := read(t, graph(t, func(_, a, c map[string]any) {
		c["url"] = "http://localhost:8080"
		a["jwks_url"] = "http://127.0.0.1:3000/.well-known/pact-jwks.json"
	}))
	if err != nil || r.Issuer != "http://localhost:8080" {
		t.Fatalf("%+v %v", r, err)
	}
}

func TestSeveralLinksMustBeNamed(t *testing.T) {
	var raw map[string]any
	_ = json.Unmarshal(graph(t, nil), &raw)
	second := map[string]any{}
	for k, v := range raw["edges"].([]any)[0].(map[string]any) {
		second[k] = v
	}
	second["link"] = "acme-crm-admin"
	raw["edges"] = append(raw["edges"].([]any), second)
	g, _ := json.Marshal(raw)
	if _, err := Read(Options{Graph: g, System: "acme-crm"}); err == nil || !strings.Contains(err.Error(), "name the one to read") {
		t.Fatalf("%v", err)
	}
	r, err := Read(Options{Graph: g, System: "acme-crm", Link: "acme-crm-admin"})
	if err != nil || r.Link != "acme-crm-admin" {
		t.Fatalf("%+v %v", r, err)
	}
}

func TestFailClosedNamesEveryVariable(t *testing.T) {
	env := map[string]string{"CAUTHY_SECRET": "x", "CAUTHY_TENANT": "acme"}
	err := FailClosed(func(k string) string { return env[k] })
	if err == nil || !strings.Contains(err.Error(), "CAUTHY_SECRET, CAUTHY_TENANT are also set") {
		t.Fatalf("%v", err)
	}
	if err := FailClosed(func(string) string { return "" }); err != nil {
		t.Fatal(err)
	}
}
