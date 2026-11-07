// Package system is the application acting on its own in Cauthy, with no
// person's token: its own token (the system proof), its organizations, their
// members, invitations, permission checks, and how it stands against its
// Pact contract.
//
// It proves who it is with the client's secret, or with a key it holds:
// a key of its own given as Options.Key, or, by contract, the keys it keeps
// itself (keys.Keys), signing a private_key_jwt assertion (RFC 7523).
package system

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/vennet-developers/cauthy-sdk-go/internal/cfgerr"
	"github.com/vennet-developers/cauthy-sdk-go/internal/jose"
	"github.com/vennet-developers/cauthy-sdk-go/keys"
)

const (
	assertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
	// DefaultTimeout bounds every call to Cauthy.
	DefaultTimeout = 2 * time.Second
	// skew: a new token is asked for this long before the one held runs out.
	skew = 30 * time.Second
	// maxAnswer is the largest answer read from Cauthy.
	maxAnswer = 1 << 20
)

// Key is a key the application proves who it is with, instead of a secret.
type Key struct {
	// PrivateKey is an RSA private key: PKCS#8 PEM, or a JWK as JSON.
	PrivateKey string
	// KeyID is the id its public half is published under.
	KeyID string
	// ClientID is the client the key belongs to, when it is not Options.ClientID.
	ClientID string
}

// Options configure the system client.
type Options struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	Key          *Key
	// Keys are the application's own keys (contract mode); KeysClientID is
	// the client they prove: pact.<link>.service. They take the place of Key.
	Keys         *keys.Keys
	KeysClientID string
	// System is the application's system, which Check asks about.
	System string
	// AcceptInviteURL is the application's own page for accepting an
	// invitation, absolute; the invitations AddMember and Invite send open it.
	AcceptInviteURL string
	HTTPClient      *http.Client
	// Timeout bounds every call. Zero is DefaultTimeout.
	Timeout time.Duration
	Now     func() time.Time
	// Changed is called after the client changed who belongs where (a
	// member added, a role set, an organization updated or removed), so a
	// cache of people's organizations can be emptied.
	Changed func()
}

// OptionsFromEnv reads CAUTHY_ISSUER, CAUTHY_CLIENT_ID,
// CAUTHY_CLIENT_SECRET, CAUTHY_SYSTEM_KEY, CAUTHY_SYSTEM_KEY_ID,
// CAUTHY_SYSTEM and CAUTHY_ACCEPT_INVITE_URL. getenv nil is os.Getenv.
func OptionsFromEnv(getenv func(string) string) Options {
	if getenv == nil {
		getenv = os.Getenv
	}
	o := Options{
		Issuer: getenv("CAUTHY_ISSUER"), ClientID: getenv("CAUTHY_CLIENT_ID"), ClientSecret: getenv("CAUTHY_CLIENT_SECRET"),
		System: getenv("CAUTHY_SYSTEM"), AcceptInviteURL: getenv("CAUTHY_ACCEPT_INVITE_URL"),
	}
	if pk := getenv("CAUTHY_SYSTEM_KEY"); pk != "" {
		o.Key = &Key{PrivateKey: pk, KeyID: getenv("CAUTHY_SYSTEM_KEY_ID")}
	}
	return o
}

// APIError is Cauthy refusing a request, or not answering (503 unavailable).
type APIError struct {
	Status  int
	Code    string
	Message string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("cauthy: %s (%d %s)", e.Message, e.Status, e.Code)
}

// Client is the application acting on its own.
type Client struct {
	o        Options
	issuer   string
	endpoint string
	http     *http.Client
	timeout  time.Duration
	now      func() time.Time

	keyOnce sync.Once
	key     *rsa.PrivateKey
	keyErr  error

	mu    sync.Mutex // held while a token is asked for: one request at a time
	held  string
	until time.Time
}

// New makes the client. Credentials are checked when first used, not here:
// an application that only signs people in never needs them.
func New(o Options) (*Client, error) {
	if o.Timeout < 0 {
		return nil, cfgerr.New("the system client's timeout must be positive")
	}
	c := &Client{o: o, issuer: strings.TrimRight(o.Issuer, "/"), http: o.HTTPClient, timeout: o.Timeout, now: o.Now}
	// Never follow a redirect: the secret, the assertion and the token go to
	// Cauthy's address and nowhere else. A redirect answers as a refusal.
	hc := &http.Client{}
	if c.http != nil {
		copied := *c.http
		hc = &copied
	}
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	c.http = hc
	if c.timeout == 0 {
		c.timeout = DefaultTimeout
	}
	if c.now == nil {
		c.now = time.Now
	}
	c.endpoint = c.issuer + "/v1/oauth/token"
	return c, nil
}

func (c *Client) configured() error {
	if !strings.HasPrefix(c.issuer, "https://") && !strings.HasPrefix(c.issuer, "http://") {
		return cfgerr.New("issuer (CAUTHY_ISSUER) must be Cauthy's address")
	}
	if c.o.ClientID == "" && c.o.Keys == nil {
		return cfgerr.New("clientId (CAUTHY_CLIENT_ID) is required")
	}
	if c.o.Keys != nil {
		if c.o.KeysClientID == "" {
			return cfgerr.New("the contract gives the system no identity of its own: its link needs a service block")
		}
		return nil
	}
	if c.o.Key != nil {
		if c.o.Key.KeyID == "" {
			return cfgerr.New("the key needs its id (CAUTHY_SYSTEM_KEY_ID)")
		}
		return nil
	}
	if c.o.ClientSecret == "" {
		return cfgerr.New("to act on its own the application needs its secret (CAUTHY_CLIENT_SECRET) or a key (CAUTHY_SYSTEM_KEY)")
	}
	return nil
}

// parseKey reads a PKCS#8 PEM or a JWK.
func parseKey(s string) (*rsa.PrivateKey, error) {
	if !strings.Contains(s, "BEGIN") {
		return jose.ParsePrivateJWK([]byte(s))
	}
	block, _ := pem.Decode([]byte(s))
	if block == nil {
		return nil, errors.New("cauthy: the system key is not PEM")
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("cauthy: the system key: %w", err)
	}
	rk, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("cauthy: the system key is not RSA")
	}
	return rk, nil
}

// self is the client the application signs in as, and the key it signs
// with (nil with a secret).
func (c *Client) self(ctx context.Context) (string, string, *rsa.PrivateKey, error) {
	switch {
	case c.o.Keys != nil:
		kid, key, err := c.o.Keys.Current(ctx)
		return c.o.KeysClientID, kid, key, err
	case c.o.Key != nil:
		c.keyOnce.Do(func() { c.key, c.keyErr = parseKey(c.o.Key.PrivateKey) })
		id := c.o.Key.ClientID
		if id == "" {
			id = c.o.ClientID
		}
		return id, c.o.Key.KeyID, c.key, c.keyErr
	default:
		return c.o.ClientID, "", nil, nil
	}
}

func uuid4() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6], b[8] = b[6]&0x0f|0x40, b[8]&0x3f|0x80
	h := hex.EncodeToString(b)
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

// Assertion signs the client assertion contract/pact.md describes: RS256
// with kid; iss and sub the client; aud the token endpoint; jti; iat; exp
// two minutes later.
func Assertion(key *rsa.PrivateKey, kid, clientID, tokenEndpoint string, now time.Time) (string, error) {
	return jose.SignRS256(key, map[string]any{"kid": kid}, map[string]any{
		"iss": clientID, "sub": clientID, "aud": tokenEndpoint, "jti": uuid4(),
		"iat": now.Unix(), "exp": now.Add(2 * time.Minute).Unix(),
	})
}

// call sends one request with the client's deadline and decodes the answer.
func (c *Client) call(ctx context.Context, req *http.Request) (int, []byte, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	res, err := c.http.Do(req.WithContext(ctx))
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return 0, nil, &APIError{Status: 503, Code: "unavailable", Message: fmt.Sprintf("Cauthy did not answer within %s", c.timeout)}
		}
		if req.Context().Err() != nil {
			return 0, nil, req.Context().Err()
		}
		return 0, nil, &APIError{Status: 503, Code: "unavailable", Message: "Cauthy could not be reached: " + err.Error()}
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, maxAnswer))
	if err != nil {
		return 0, nil, &APIError{Status: 503, Code: "unavailable", Message: "Cauthy's answer was cut short"}
	}
	return res.StatusCode, raw, nil
}

// refused reads Cauthy's refusal: the token endpoint answers as OAuth does
// ({error, error_description}), every other route in Cauthy's envelope
// ({errors: [{code, message}]}).
func refused(status int, raw []byte, what string) *APIError {
	var b struct {
		Error       any    `json:"error"`
		Description string `json:"error_description"`
		Errors      []struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"errors"`
	}
	_ = json.Unmarshal(raw, &b)
	code, message := "error", http.StatusText(status)
	if s, ok := b.Error.(string); ok {
		code, message = s, b.Description
	} else if len(b.Errors) > 0 {
		code, message = b.Errors[0].Code, b.Errors[0].Message
	}
	return &APIError{Status: status, Code: code, Message: fmt.Sprintf("Cauthy refused %s (%d): %s", what, status, message)}
}

// Token is the application's own token, asked for when needed and kept until
// shortly before it runs out. It is what the system proof carries.
func (c *Client) Token(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.held != "" && c.now().Before(c.until) {
		return c.held, nil
	}
	if err := c.configured(); err != nil {
		return "", err
	}
	id, kid, key, err := c.self(ctx)
	if err != nil {
		return "", err
	}
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {id}}
	if key != nil {
		a, err := Assertion(key, kid, id, c.endpoint, c.now())
		if err != nil {
			return "", err
		}
		form.Set("client_assertion_type", assertionType)
		form.Set("client_assertion", a)
	} else {
		form.Set("client_secret", c.o.ClientSecret)
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	status, raw, err := c.call(ctx, req)
	if err != nil {
		return "", err
	}
	if status < 200 || status > 299 {
		return "", refused(status, raw, "the application's own token")
	}
	var t struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if json.Unmarshal(raw, &t) != nil || t.AccessToken == "" {
		return "", &APIError{Status: 502, Code: "unavailable", Message: "Cauthy answered no token"}
	}
	// Kept until skew before it runs out, and at least half its life, so a
	// short-lived token is not asked for again on every call.
	life := time.Duration(t.ExpiresIn) * time.Second
	c.held, c.until = t.AccessToken, c.now().Add(max(life/2, life-skew))
	return c.held, nil
}

func (c *Client) forget() {
	c.mu.Lock()
	c.held = ""
	c.mu.Unlock()
}

// Request calls any route the application's token may call and decodes what
// Cauthy put under "data" into out (nil: ignored). extra headers are added.
func (c *Client) Request(ctx context.Context, method, path string, body, out any, extra ...http.Header) error {
	raw, err := c.send(ctx, method, path, body, extra...)
	if err != nil || out == nil || len(raw) == 0 {
		return err
	}
	var env struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return &APIError{Status: 502, Code: "unavailable", Message: "Cauthy's answer is not JSON"}
	}
	if len(env.Data) == 0 {
		return nil
	}
	return json.Unmarshal(env.Data, out)
}

// send makes one call with the application's token, and once more with a
// new token when Cauthy took the first back early (401). It answers the
// body of a 2xx, or the refusal.
func (c *Client) send(ctx context.Context, method, path string, body any, extra ...http.Header) ([]byte, error) {
	if err := checkPath(path); err != nil {
		return nil, err
	}
	var payload []byte
	if body != nil {
		var err error
		if payload, err = json.Marshal(body); err != nil {
			return nil, err
		}
	}
	once := func() (int, []byte, error) {
		tok, err := c.Token(ctx)
		if err != nil {
			return 0, nil, err
		}
		req, _ := http.NewRequestWithContext(ctx, method, c.issuer+path, bytes.NewReader(payload))
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Accept", "application/json")
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		for _, h := range extra {
			for k, v := range h {
				req.Header[k] = v
			}
		}
		return c.call(ctx, req)
	}
	status, raw, err := once()
	if err == nil && status == http.StatusUnauthorized {
		c.forget()
		status, raw, err = once()
	}
	if err != nil {
		return nil, err
	}
	if status < 200 || status > 299 {
		return nil, refused(status, raw, method+" "+path)
	}
	if status == http.StatusNoContent {
		return nil, nil
	}
	return raw, nil
}

// checkPath refuses a path with a "." or ".." segment: an id of "." or ".."
// passes url.PathEscape unchanged and would name another route.
func checkPath(path string) error {
	p, _, _ := strings.Cut(path, "?")
	for _, seg := range strings.Split(p, "/") {
		if seg == "." || seg == ".." {
			return fmt.Errorf("cauthy: %q is not an id", seg)
		}
	}
	return nil
}
