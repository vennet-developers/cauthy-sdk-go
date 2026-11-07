package cauthy

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
)

type sessionKey struct{}

// SessionFromContext is the Session Protect attached to the request.
func SessionFromContext(ctx context.Context) (*Session, bool) {
	s, ok := ctx.Value(sessionKey{}).(*Session)
	return s, ok && s != nil
}

// Protect is middleware for a route only a signed-in person may see. A page
// (a GET navigation that accepts HTML) is sent to sign in, or to renew and
// come back; anything else gets 401 with X-Cauthy-Session: none | expired,
// and its caller decides. A session the link does not let in (an address not
// confirmed) is none.
func (a *Auth) Protect(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, value, _ := a.read(r)
		if value != nil && a.unverified(value.U) {
			value = nil
		}
		if value != nil && a.fresh(value) {
			next.ServeHTTP(w, r.WithContext(WithSession(r.Context(), value.session())))
			return
		}
		state := "none"
		if value != nil {
			state = "expired"
		}
		mode, accept := r.Header.Get("Sec-Fetch-Mode"), r.Header.Get("Accept")
		page := r.Method == http.MethodGet && (mode == "" || mode == "navigate") && (accept == "" || strings.Contains(accept, "text/html"))
		w.Header().Set("Cache-Control", "no-store")
		if !page {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Header().Set("X-Cauthy-Session", state)
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "unauthenticated", "session": state})
			return
		}
		back := r.URL.RequestURI()
		to := a.SignInURL(back)
		if value != nil {
			to = a.basePath + "/refresh?return_to=" + urlQueryEscape(back)
		}
		http.Redirect(w, r, to, http.StatusFound)
	})
}

// Webhook verifies a delivery from Cauthy and answers the event it carries
// (VerifyWebhook, with this application's issuer and replay store). The
// endpoint's address is the application's origin with the request's path.
func (a *Auth) Webhook(r *http.Request) (*Event, error) {
	return VerifyWebhook(r, WebhookOptions{Issuer: a.issuer, URL: a.originOf(r) + r.URL.EscapedPath(), Replay: a.replay, Now: a.now})
}

// WithSession is ctx carrying s, as Protect leaves it: for adapters and for
// tests of the handlers behind it.
func WithSession(ctx context.Context, s *Session) context.Context {
	return context.WithValue(ctx, sessionKey{}, s)
}
