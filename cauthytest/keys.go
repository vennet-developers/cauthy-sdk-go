package cauthytest

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/vennet-developers/cauthy-sdk-go/cauthykey"
)

// TenantID is the workspace's id GET /v1/connect/self answers.
const TenantID = "8a6e0804-2bd0-4672-b79a-d97027f5f2a1"

// fakeKey is a CAUTHY_KEY's public half, as Cauthy keeps it.
type fakeKey struct {
	pub      ed25519.PublicKey
	clientID string
	issuer   string
	revoked  bool
}

// IssueKey makes a CAUTHY_KEY for ClientID on Issuer, as Cauthy's dashboard
// does: a random secret, and only the public half registered. ClientID
// becomes a key client: its code exchanges, refreshes and revocations need
// the key's assertion. Set Issuer and ClientID first (a contract's service
// client is pact.<link>.service).
func (f *Fake) IssueKey() string {
	raw := make([]byte, 32)
	_, _ = rand.Read(raw)
	f.mu.Lock()
	defer f.mu.Unlock()
	key, err := cauthykey.Compose(f.Issuer, f.ClientID, base64.RawURLEncoding.EncodeToString(raw))
	if err != nil {
		panic("cauthytest: " + err.Error()) // Issuer or ClientID is no valid key part
	}
	k, _ := cauthykey.Parse(key)
	d := k.Derive()
	f.keyring[d.KID] = &fakeKey{pub: d.Public, clientID: k.ClientID, issuer: k.Issuer}
	f.kids = append(f.kids, d.KID)
	f.keyClients[k.ClientID] = true
	return key
}

// RegisterKey registers the public half of a key made elsewhere (a key with
// another secret, for a rotation), as Cauthy's dashboard would.
func (f *Fake) RegisterKey(key string) error {
	k, err := cauthykey.Parse(key)
	if err != nil {
		return err
	}
	d := k.Derive()
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, known := f.keyring[d.KID]; !known {
		f.kids = append(f.kids, d.KID)
	}
	f.keyring[d.KID] = &fakeKey{pub: d.Public, clientID: k.ClientID, issuer: k.Issuer}
	f.keyClients[k.ClientID] = true
	return nil
}

// SetAppURLs sets AppURLs, safely while the fake serves.
func (f *Fake) SetAppURLs(urls ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.AppURLs = urls
}

// RevokeKey revokes a key by its kid: its assertions are refused with 401
// invalid_client, and the system tokens it bought no longer answer.
func (f *Fake) RevokeKey(kid string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if k := f.keyring[kid]; k != nil {
		k.revoked = true
	}
}

// RegisteredKids are the kids of the keys issued or registered, in order.
func (f *Fake) RegisteredKids() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.kids...)
}

// kidOf reads the kid of a compact JWS's header.
func kidOf(jws string) string {
	head, _, _ := strings.Cut(jws, ".")
	raw, err := base64.RawURLEncoding.DecodeString(head)
	if err != nil {
		return ""
	}
	var h struct {
		Kid string `json:"kid"`
	}
	_ = json.Unmarshal(raw, &h)
	return h.Kid
}

// clientAuth checks how a call to the token or revoke endpoint
// authenticates, as Cauthy does (key/cauthy-key.md §6): an RFC 7523
// assertion is verified (key registered and not revoked, signature, iss =
// sub = the key's client = client_id, aud the key's token endpoint, exp at
// most 330 s ahead, jti unseen); a key client without one is refused. On a
// refusal it has answered 401 invalid_client and ok is false. f.mu is held.
func (f *Fake) clientAuth(w http.ResponseWriter, c Call) (kid string, ok bool) {
	refuse := func() (string, bool) {
		reply(w, 401, map[string]any{"error": "invalid_client", "error_description": "client authentication failed"})
		return "", false
	}
	if c.Form.Get("client_assertion_type") == "" && c.Form.Get("client_assertion") == "" {
		if f.keyClients[c.Form.Get("client_id")] {
			return refuse()
		}
		return "", true
	}
	if c.Form.Get("client_assertion_type") != cauthykey.AssertionType || c.Form.Get("client_secret") != "" {
		return refuse()
	}
	a := c.Form.Get("client_assertion")
	kid = kidOf(a)
	k := f.keyring[kid]
	if k == nil || k.revoked {
		return refuse()
	}
	claims, err := cauthykey.VerifyAssertion(k.pub, a)
	now := time.Now().Unix()
	if err != nil || claims.Iss != k.clientID || claims.Sub != claims.Iss || claims.Aud != k.issuer+"/v1/oauth/token" ||
		(c.Form.Get("client_id") != "" && c.Form.Get("client_id") != claims.Iss) ||
		claims.Exp < now-30 || claims.Exp > now+330 || claims.Jti == "" || f.jtis[claims.Jti] {
		return refuse()
	}
	f.jtis[claims.Jti] = true
	return kid, true
}

// systemToken answers client_credentials bought with a key's assertion: a
// token /v1/connect/self answers. f.mu is held.
func (f *Fake) systemToken(w http.ResponseWriter, kid string) {
	f.n++
	tok := fmt.Sprintf("sys-%d", f.n)
	f.systemTokens[tok] = kid
	reply(w, 200, map[string]any{"access_token": tok, "token_type": "Bearer", "expires_in": f.ExpiresIn})
}

// self answers GET /v1/connect/self for a key's system token. f.mu is held.
func (f *Fake) self(w http.ResponseWriter, r *http.Request) {
	kid, ok := f.systemTokens[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]
	if !ok || f.keyring[kid] == nil || f.keyring[kid].revoked {
		reply(w, 401, map[string]any{"errors": []any{map[string]any{"code": "unauthorized", "message": "invalid or expired token"}}})
		return
	}
	urls := f.AppURLs
	if urls == nil {
		urls = []string{}
	}
	body, _ := json.Marshal(map[string]any{"data": map[string]any{
		"issuer": f.keyring[kid].issuer, "audience": f.keyring[kid].issuer, "tenant": map[string]any{"id": TenantID, "slug": f.Tenant},
		"system": f.System, "client_id": f.keyring[kid].clientID, "sign_in_client_id": f.keyring[kid].clientID,
		"app_urls": urls, "callback_path": "/api/auth/callback", "key": map[string]any{"kid": kid, "retires_at": nil}, "contract": nil,
	}})
	sum := sha256.Sum256(body)
	etag := `"` + base64.RawURLEncoding.EncodeToString(sum[:12]) + `"`
	w.Header().Set("ETag", etag)
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	_, _ = w.Write(body)
}
