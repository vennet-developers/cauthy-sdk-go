package cauthy

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

type identityKey struct{}

// WithIdentity is ctx carrying id, as Require leaves it: for tests of the
// handlers behind it.
func WithIdentity(ctx context.Context, id *Identity) context.Context {
	return context.WithValue(ctx, identityKey{}, id)
}

// FromContext is the Identity Require attached to the request's context.
func FromContext(ctx context.Context) (*Identity, bool) {
	id, ok := ctx.Value(identityKey{}).(*Identity)
	return id, ok && id != nil
}

// Bearer is the token of an "Authorization: Bearer" header, or "".
func Bearer(r *http.Request) string {
	const prefix = "bearer "
	h := r.Header.Get("Authorization")
	if len(h) <= len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return ""
	}
	return strings.TrimSpace(h[len(prefix):])
}

// VerifyRequest verifies the request's bearer token.
func (v *Verifier) VerifyRequest(r *http.Request) (*Identity, error) {
	tok := Bearer(r)
	if tok == "" {
		return nil, refuse(NoToken, "no Authorization: Bearer header")
	}
	return v.Verify(r.Context(), tok)
}

// Require is middleware for net/http and any router that takes
// func(http.Handler) http.Handler (chi's r.Use, for one): a request with a
// valid token goes on with its Identity in the context (FromContext);
// anything else is answered by Refuse.
func (v *Verifier) Require(next http.Handler) http.Handler {
	return v.RequireFunc(Refuse)(next)
}

// RequireFunc is Require with another answer for a refused request.
func (v *Verifier) RequireFunc(refused func(w http.ResponseWriter, r *http.Request, err error)) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id, err := v.VerifyRequest(r)
			if err != nil {
				var te *TokenError
				if errors.As(err, &te) {
					v.log.DebugContext(r.Context(), "cauthy: token refused", "reason", string(te.Reason), "detail", te.Detail)
				}
				refused(w, r, err)
				return
			}
			next.ServeHTTP(w, r.WithContext(WithIdentity(r.Context(), id)))
		})
	}
}

// Refusal is the answer for a refused token: its status, headers and JSON
// body. A token Cauthy's keys could not be fetched to check is 503
// unavailable: an outage signs nobody out. Every other refusal is the same
// 401 unauthenticated, whatever its reason: telling "expired" from "forged"
// would make the answer a probe. Adapters for other frameworks write it.
func Refusal(err error) (int, http.Header, []byte) {
	h := http.Header{"Content-Type": {"application/json; charset=utf-8"}, "Cache-Control": {"no-store"}}
	status, code, message := http.StatusUnauthorized, "unauthenticated", "Sign in first."
	var te *TokenError
	switch {
	case errors.Is(err, ErrNoKeySet):
		status, code, message = http.StatusServiceUnavailable, "unavailable", "Sign-in cannot be checked right now. Try again in a moment."
	case errors.As(err, &te) && te.Reason == NoToken:
		h.Set("WWW-Authenticate", "Bearer")
	default:
		h.Set("WWW-Authenticate", `Bearer error="invalid_token"`)
	}
	body, _ := json.Marshal(map[string]any{"error": map[string]string{"code": code, "message": message}})
	return status, h, body
}

// Refuse writes Refusal(err): the default answer of Require.
func Refuse(w http.ResponseWriter, _ *http.Request, err error) {
	status, h, body := Refusal(err)
	for k, v := range h {
		w.Header()[k] = v
	}
	w.WriteHeader(status)
	_, _ = w.Write(body)
}
