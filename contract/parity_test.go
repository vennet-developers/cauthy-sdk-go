package contract

import (
	"encoding/json"
	"strings"
	"testing"
)

// with adds nodes and edges to a graph as they are, whatever their shape.
func with(t *testing.T, g []byte, nodes, edges []any) []byte {
	t.Helper()
	var m map[string][]any
	if err := json.Unmarshal(g, &m); err != nil {
		t.Fatal(err)
	}
	m["nodes"] = append(m["nodes"], nodes...)
	m["edges"] = append(m["edges"], edges...)
	raw, _ := json.Marshal(m)
	return raw
}

func TestANullSystemProofIsRefusedAsNodeRefusesIt(t *testing.T) {
	_, err := read(t, graph(t, func(l, _, _ map[string]any) {
		l["sign_in"] = map[string]any{"redirect_uris": []any{"https://crm.example.com/cb"}, "system_proof": nil}
	}))
	if err == nil || !strings.Contains(err.Error(), "off, auto or required") {
		t.Fatalf("system_proof null: want a refusal, got %v", err)
	}
}

func TestAWrongTypeElsewhereDoesNotRejectTheGraph(t *testing.T) {
	g := with(t, graph(t, nil),
		[]any{"not a node", 7, map[string]any{"id": "billing", "type": "system", "tenants": "acme", "url": 9},
			map[string]any{"id": "other.v1", "type": "capability", "token": "RS256"}},
		[]any{"not an edge", map[string]any{"from": "billing", "relation": "links", "to": "cauthy", "identity": "x", "sign_in": "yes"}})
	if _, err := read(t, g); err != nil {
		t.Fatalf("a malformed node or edge of another system: %v", err)
	}
	r, err := read(t, graph(t, func(l, _, c map[string]any) {
		c["tenants"] = []any{"junk", map[string]any{"id": 1}, map[string]any{"id": acmeTenant, "slug": "acme"}}
	}))
	if err != nil || r.Tenant != "acme" {
		t.Fatalf("junk beside the workspace: %+v %v", r, err)
	}
}

func TestSignInFalseIsNoLink(t *testing.T) {
	for _, v := range []any{false, 0, ""} {
		_, err := read(t, graph(t, func(l, _, _ map[string]any) { l["sign_in"] = v }))
		if err == nil || !strings.Contains(err.Error(), "no link of the graph") {
			t.Errorf("sign_in %#v: want no link, got %v", v, err)
		}
	}
}

func TestTheIssuerIsNormalizedAsAURL(t *testing.T) {
	for url, want := range map[string]string{
		"https://ID.Example.com:443/": "https://id.example.com",
		"https://id.example.com:8443": "https://id.example.com:8443",
		"http://LOCALHOST:80":         "http://localhost",
	} {
		r, err := read(t, graph(t, func(_, _, c map[string]any) { c["url"] = url }))
		if err != nil || r.Issuer != want {
			t.Errorf("%s: want %s, got %+v %v", url, want, r, err)
		}
	}
	r, err := read(t, graph(t, func(_, a, _ map[string]any) { a["jwks_url"] = "https://CRM.example.com:443/.well-known/pact-jwks.json" }))
	if err != nil || r.JWKSURL != "https://crm.example.com/.well-known/pact-jwks.json" {
		t.Fatalf("jwks_url: %+v %v", r, err)
	}
}

func TestFieldNamesAreExact(t *testing.T) {
	_, err := read(t, graph(t, func(_, _, c map[string]any) {
		delete(c, "url")
		c["URL"] = "https://id.example.com"
	}))
	if err == nil || !strings.Contains(err.Error(), "not an address") {
		t.Fatalf(`"URL" is not "url": got %v`, err)
	}
	_, err = read(t, graph(t, func(l, _, _ map[string]any) {
		l["Sign_In"] = l["sign_in"]
		delete(l, "sign_in")
	}))
	if err == nil || !strings.Contains(err.Error(), "no link of the graph") {
		t.Fatalf(`"Sign_In" is not "sign_in": got %v`, err)
	}
}
