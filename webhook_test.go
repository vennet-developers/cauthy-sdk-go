package cauthy

import (
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/vennet-developers/cauthy-sdk-go/internal/jose"
)

const hookURL = "https://crm.example.com/hooks/cauthy"

func delivery(t *testing.T, body string, change func(h, c map[string]any)) (*http.Request, WebhookOptions) {
	t.Helper()
	strong, _ := testKeys(t)
	sum := sha256.Sum256([]byte(body))
	h := map[string]any{"kid": "k", "typ": "cauthy-webhook+jwt"}
	c := map[string]any{"iss": "https://id.example.com", "aud": hookURL, "iat": now.Unix(), "exp": now.Unix() + 300,
		"jti": "d1", "evt": "organization.member_added", "tid": goodConfig.Tenant, "body_sha256": jose.Encode(sum[:])}
	if change != nil {
		change(h, c)
	}
	sig, err := jose.SignRS256(strong, h, c)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/hooks/cauthy", strings.NewReader(body))
	r.Header.Set("X-Cauthy-Signature-JWT", sig)
	return r, WebhookOptions{Issuer: "https://id.example.com", URL: hookURL, Keys: staticKeys("k", &strong.PublicKey),
		Now: func() time.Time { return now }}
}

const hookBody = `{"id":"d1","event":"organization.member_added","tenant_id":"8a6e0804-2bd0-4672-b79a-d97027f5f2a1",` +
	`"data":{"created_at":"2026-01-01T00:00:00Z","user_id":"u1","actor_id":"u2","data":{"organization_id":"o1","role":"owner"}}}`

func TestVerifyWebhookAnswersTheEvent(t *testing.T) {
	r, o := delivery(t, hookBody, nil)
	o.Replay = MemoryReplay(func() time.Time { return now })
	ev, err := VerifyWebhook(r, o)
	if err != nil {
		t.Fatal(err)
	}
	if ev.ID != "d1" || ev.Type != "organization.member_added" || ev.UserID != "u1" || ev.ActorID != "u2" || ev.Data["role"] != "owner" || ev.CreatedAt != "2026-01-01T00:00:00Z" {
		t.Fatalf("%+v", ev)
	}
	r2, _ := delivery(t, hookBody, nil)
	r2.Header.Set("X-Cauthy-Signature-JWT", r.Header.Get("X-Cauthy-Signature-JWT"))
	if _, err := VerifyWebhook(r2, o); err == nil || !strings.Contains(err.Error(), "already taken") {
		t.Fatalf("the same delivery twice: %v", err)
	}
}

func TestVerifyWebhookRefuses(t *testing.T) {
	cases := map[string]struct {
		body   string
		change func(h, c map[string]any)
		says   string
	}{
		"another endpoint": {hookBody, func(_, c map[string]any) { c["aud"] = "https://evil.example/hook" }, "aud"},
		"another issuer":   {hookBody, func(_, c map[string]any) { c["iss"] = "https://evil.example" }, "iss"},
		"an access token":  {hookBody, func(h, _ map[string]any) { h["typ"] = "JWT" }, "typ"},
		"expired":          {hookBody, func(_, c map[string]any) { c["exp"] = now.Unix() - 60 }, "exp"},
		"from the future":  {hookBody, func(_, c map[string]any) { c["iat"] = now.Unix() + 120 }, "future"},
		"a changed body":   {strings.Replace(hookBody, "owner", "admin", 1), func(_, c map[string]any) {}, "not the one"},
		"body disagrees":   {hookBody, func(_, c map[string]any) { c["evt"] = "user.deleted" }, "disagree"},
		"no body hash":     {hookBody, func(_, c map[string]any) { delete(c, "body_sha256") }, "body_sha256"},
		"unknown key":      {hookBody, func(h, _ map[string]any) { h["kid"] = "other" }, "no key"},
	}
	for name, c := range cases {
		r, o := delivery(t, hookBody, c.change)
		if c.body != hookBody {
			r2 := httptest.NewRequest("POST", "/hooks/cauthy", strings.NewReader(c.body))
			r2.Header = r.Header
			r = r2
		}
		if _, err := VerifyWebhook(r, o); err == nil || !strings.Contains(err.Error(), c.says) {
			t.Errorf("%s: want %q, got %v", name, c.says, err)
		}
	}
	r, o := delivery(t, hookBody, nil)
	r.Header.Del("X-Cauthy-Signature-JWT")
	if _, err := VerifyWebhook(r, o); err == nil || !strings.Contains(err.Error(), "no signature") {
		t.Fatalf("%v", err)
	}
}
