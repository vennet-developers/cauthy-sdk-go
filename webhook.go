package cauthy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/vennet-developers/cauthy-sdk-go/internal/jose"
)

// Event is something that happened in Cauthy, as a subscriber is told.
// Moments are UTC.
type Event struct {
	// ID is this delivery's id: the same event delivered again carries it.
	ID string
	// Type is what happened: "organization.member_added".
	Type      string
	TenantID  string
	CreatedAt string
	// UserID is the person it happened to, when it is about one.
	UserID string
	// ActorID is who did it.
	ActorID string
	Data    map[string]any
}

// WebhookError is a delivery refused: answer it 401 and nothing else.
type WebhookError struct{ Reason string }

func (e *WebhookError) Error() string { return "cauthy: webhook refused: " + e.Reason }

// ReplayStore remembers deliveries already taken. Claim answers true the
// first time a key is claimed and false after, until until passes.
type ReplayStore interface {
	Claim(ctx context.Context, key string, until time.Time) (bool, error)
}

// MemoryReplay remembers deliveries in this process: enough with one instance.
func MemoryReplay(now func() time.Time) ReplayStore {
	if now == nil {
		now = time.Now
	}
	return &memoryReplay{seen: map[string]time.Time{}, now: now}
}

type memoryReplay struct {
	mu   sync.Mutex
	seen map[string]time.Time
	now  func() time.Time
}

func (m *memoryReplay) Claim(_ context.Context, key string, until time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t := m.now()
	if len(m.seen) > 10_000 {
		for k, u := range m.seen {
			if !u.After(t) {
				delete(m.seen, k)
			}
		}
	}
	if held, ok := m.seen[key]; ok && held.After(t) {
		return false, nil
	}
	m.seen[key] = until
	return true, nil
}

// WebhookOptions configure VerifyWebhook.
type WebhookOptions struct {
	// Issuer is Cauthy's address. Default CAUTHY_ISSUER.
	Issuer string
	// URL is this endpoint's public address, exactly as registered in
	// Cauthy. Default: the request's URL without its query.
	URL string
	// Keys are Cauthy's keys. Default: fetched from Issuer and cached.
	Keys KeySet
	// Now is the clock. Default time.Now.
	Now func() time.Time
	// Replay refuses the same signed delivery twice. Default: none.
	Replay ReplayStore
}

// maxWebhookBody is the largest delivery read.
const maxWebhookBody = 1 << 20

var webhookKeys sync.Map // issuer → *RemoteKeys

func keysOfIssuer(issuer string) KeySet {
	if k, ok := webhookKeys.Load(issuer); ok {
		return k.(KeySet)
	}
	k, _ := webhookKeys.LoadOrStore(issuer, NewRemoteKeys(HTTPFetcher(issuer+"/.well-known/jwks.json", nil), DefaultCooldown, nil))
	return k.(KeySet)
}

func requestURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host + r.URL.EscapedPath()
}

// VerifyWebhook verifies a delivery from Cauthy and answers the event it
// carries. No secret is involved: Cauthy signs every delivery with its own
// key. Checked: the signature (RS256, typ cauthy-webhook+jwt), that it was
// meant for this endpoint (aud), that it is recent (exp, iat, 30 s of
// leeway), the issuer, and that the body is byte for byte the one signed.
// The body is read and put back on r.
func VerifyWebhook(r *http.Request, o WebhookOptions) (*Event, error) {
	issuer := withoutTrailingSlashes(o.Issuer)
	if issuer == "" {
		issuer = withoutTrailingSlashes(os.Getenv("CAUTHY_ISSUER"))
	}
	if issuer == "" {
		return nil, &WebhookError{"issuer (CAUTHY_ISSUER) is not set"}
	}
	signature := r.Header.Get("X-Cauthy-Signature-JWT")
	if signature == "" {
		return nil, &WebhookError{"no signature"}
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxWebhookBody+1))
	if err != nil || len(raw) > maxWebhookBody {
		return nil, &WebhookError{"the body could not be read"}
	}
	r.Body = io.NopCloser(bytes.NewReader(raw))
	audience := o.URL
	if audience == "" {
		audience = requestURL(r)
	}
	now := time.Now
	if o.Now != nil {
		now = o.Now
	}
	keys := o.Keys
	if keys == nil {
		keys = keysOfIssuer(issuer)
	}

	c, err := jose.ParseCompact(signature)
	if err != nil {
		return nil, &WebhookError{err.Error()}
	}
	var alg, typ, kid string
	_ = json.Unmarshal(c.Header["alg"], &alg)
	_ = json.Unmarshal(c.Header["typ"], &typ)
	_ = json.Unmarshal(c.Header["kid"], &kid)
	if alg != "RS256" {
		return nil, &WebhookError{"alg must be RS256"}
	}
	if !strings.EqualFold(strings.TrimPrefix(strings.ToLower(typ), "application/"), "cauthy-webhook+jwt") {
		return nil, &WebhookError{`unexpected "typ" JWT header value`}
	}
	key, err := keys.Key(r.Context(), kid)
	if err != nil {
		return nil, &WebhookError{"no key of Cauthy's signed it"}
	}
	if c.VerifyRS256(key) != nil {
		return nil, &WebhookError{"signature verification failed"}
	}
	var claims map[string]any
	if json.Unmarshal(c.Payload, &claims) != nil || claims == nil {
		return nil, &WebhookError{"the claims are not a JSON object"}
	}
	for _, name := range []string{"exp", "iat", "jti", "body_sha256"} {
		if _, ok := claims[name]; !ok {
			return nil, &WebhookError{fmt.Sprintf("missing required %q claim", name)}
		}
	}
	if !audienceHolds(claims["aud"], audience) {
		return nil, &WebhookError{`unexpected "aud" claim value`}
	}
	if claims["iss"] != issuer && claims["domain_iss"] != issuer {
		return nil, &WebhookError{`unexpected "iss" claim value`}
	}
	t := float64(now().Unix())
	exp, expOK := claims["exp"].(float64)
	iat, iatOK := claims["iat"].(float64)
	if !expOK || t >= exp+30 {
		return nil, &WebhookError{`"exp" claim timestamp check failed`}
	}
	if nbf, present := claims["nbf"].(float64); present && t < nbf-30 {
		return nil, &WebhookError{`"nbf" claim timestamp check failed`}
	}
	if !iatOK || iat > t+30 {
		return nil, &WebhookError{"signed in the future"}
	}
	sum := sha256.Sum256(raw)
	if claims["body_sha256"] != jose.Encode(sum[:]) {
		return nil, &WebhookError{"the body is not the one that was signed"}
	}
	var body map[string]any
	if json.Unmarshal(raw, &body) != nil || body == nil {
		return nil, &WebhookError{"the body is not JSON"}
	}
	if body["id"] != claims["jti"] || body["event"] != claims["evt"] || body["tenant_id"] != claims["tid"] {
		return nil, &WebhookError{"the body and its signature disagree"}
	}
	if o.Replay != nil {
		key := fmt.Sprintf("%s:%s", str(claims["jti"]), str(claims["iat"]))
		fresh, err := o.Replay.Claim(r.Context(), key, time.Unix(int64(exp), 0))
		if err != nil {
			return nil, err
		}
		if !fresh {
			return nil, &WebhookError{"this delivery was already taken"}
		}
	}
	inner := obj(body["data"])
	created := str(inner["created_at"])
	if created == "" {
		created = str(body["created_at"])
	}
	data := obj(inner["data"])
	if data == nil {
		data = map[string]any{}
	}
	return &Event{ID: str(body["id"]), Type: str(body["event"]), TenantID: str(body["tenant_id"]), CreatedAt: created,
		UserID: str(inner["user_id"]), ActorID: str(inner["actor_id"]), Data: data}, nil
}

func audienceHolds(aud any, want string) bool {
	switch a := aud.(type) {
	case string:
		return a == want
	case []any:
		for _, x := range a {
			if x == want {
				return true
			}
		}
	}
	return false
}
