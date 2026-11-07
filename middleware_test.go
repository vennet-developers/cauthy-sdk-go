package cauthy

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func serve(h http.Handler, authorization string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, "/invoices", nil)
	if authorization != "" {
		r.Header.Set("Authorization", authorization)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestRequireLetsAVerifiedPersonThrough(t *testing.T) {
	v := verifier(t, func(c *VerifierConfig) { c.Now = func() time.Time { return now } })
	var seen *Identity
	h := v.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen, _ = FromContext(r.Context())
		w.WriteHeader(http.StatusNoContent)
	}))
	for _, scheme := range []string{"Bearer ", "bearer ", "BEARER  "} {
		w := serve(h, scheme+token(t, nil))
		if w.Code != http.StatusNoContent || seen == nil || seen.Subject != "5c1b2f4e-9a3d-4b7e-8c6f-0d1e2f3a4b5c" {
			t.Fatalf("%q: %d %+v", scheme, w.Code, seen)
		}
	}
}

func TestRequireAnswersEveryRefusalTheSame(t *testing.T) {
	v := verifier(t, func(c *VerifierConfig) { c.Now = func() time.Time { return now } })
	h := v.Require(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("reached the handler") }))
	expired := token(t, map[string]any{"exp": now.Unix() - 3600})
	forged := token(t, nil)[:len(token(t, nil))-4] + "AAAA"
	var bodies []string
	for _, auth := range []string{"Bearer " + expired, "Bearer " + forged, "Basic abc"} {
		w := serve(h, auth)
		if w.Code != http.StatusUnauthorized || w.Header().Get("Cache-Control") != "no-store" ||
			!strings.HasPrefix(w.Header().Get("WWW-Authenticate"), "Bearer") {
			t.Fatalf("%q: %d %v", auth[:10], w.Code, w.Header())
		}
		bodies = append(bodies, w.Body.String())
	}
	if bodies[0] != bodies[1] || !strings.Contains(bodies[0], `"code":"unauthenticated"`) {
		t.Fatalf("refusals differ or lack the code: %v", bodies)
	}
}

func TestRequireAnswers503WhileCauthysKeysNeverArrived(t *testing.T) {
	v := verifier(t, func(c *VerifierConfig) {
		c.Now = func() time.Time { return now }
		c.Keys = NewRemoteKeys(func(context.Context) ([]byte, time.Duration, error) { return nil, 0, errors.New("down") }, 0, nil)
	})
	w := serve(v.Require(http.NotFoundHandler()), "Bearer "+token(t, nil))
	if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), `"unavailable"`) {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}

func TestRequireFuncAnswersAsTheApplicationSays(t *testing.T) {
	v := verifier(t, nil)
	var got error
	h := v.RequireFunc(func(w http.ResponseWriter, _ *http.Request, err error) {
		got = err
		w.WriteHeader(http.StatusTeapot)
	})(http.NotFoundHandler())
	if w := serve(h, ""); w.Code != http.StatusTeapot || reasonOf(got) != NoToken {
		t.Fatalf("%d %v", w.Code, got)
	}
}

func TestRequireAnswers503WhenTheRequestEndsBeforeTheFirstKeys(t *testing.T) {
	gate := make(chan struct{})
	defer close(gate)
	v := verifier(t, func(c *VerifierConfig) {
		c.Now = func() time.Time { return now }
		c.Keys = NewRemoteKeys(func(context.Context) ([]byte, time.Duration, error) {
			<-gate
			return nil, 0, errors.New("slow")
		}, 0, nil)
	})
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	r := httptest.NewRequest(http.MethodGet, "/invoices", nil).WithContext(ctx)
	r.Header.Set("Authorization", "Bearer "+token(t, nil))
	w := httptest.NewRecorder()
	v.Require(http.NotFoundHandler()).ServeHTTP(w, r)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}
