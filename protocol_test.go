package cauthy

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNextPerRouteAndStatus(t *testing.T) {
	for _, c := range [][3]string{
		{"/sign-in/email", "signed_in", "done"}, {"/sign-in/email", "mfa_required", "mfa"}, {"/sign-up/email", "verification_required", "verify_email"},
		{"/sign-in/mfa/send", "sent", "mfa"}, {"/sign-in/magic-link", "sent", "code"}, {"/sign-in/google-one-tap/begin", "started", "one_tap"},
		{"/sign-in/passkey/begin", "started", "passkey"}, {"/sign-in/email", "changed", ""},
	} {
		if got := nextOf(c[0], c[1]); string(got) != c[2] {
			t.Errorf("%s %s: %q, want %q", c[0], c[1], got, c[2])
		}
	}
}

func TestSendGivesEveryAnswerTheProtocolsHeaders(t *testing.T) {
	w := httptest.NewRecorder()
	send(w, "/sign-in/email", ok(map[string]any{"status": "signed_in", "session": nil}, nil).with("a=1"), false)
	var body map[string]any
	json.Unmarshal(w.Body.Bytes(), &body)
	if w.Header().Get("Cauthy-Protocol") != "1" || w.Header().Get("Cache-Control") != "no-store" || body["next"] != "done" ||
		w.Header().Get("Set-Cookie") != "a=1" || w.Header().Get("Content-Type") != "application/json; charset=utf-8" {
		t.Fatalf("%v %s", w.Header(), w.Body)
	}

	w = httptest.NewRecorder()
	send(w, "", notFound(), false)
	if w.Code != 404 || w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Cauthy-Protocol") != "1" || w.Body.String() != "Not found" {
		t.Fatalf("the plain-text 404 is no-store at strict: %v", w.Header())
	}

	w = httptest.NewRecorder()
	keys := ok(map[string]any{"keys": []any{}}, nil)
	keys.header.Set("Cache-Control", "public, max-age=300")
	send(w, "", keys, true)
	if w.Header().Get("Cache-Control") != "public, max-age=300" {
		t.Fatal("the published keys keep their cache")
	}

	w = httptest.NewRecorder()
	send(w, "/sign-in/email", problem(401, "invalid_credentials", "Wrong.", "", nil, nil), false)
	if strings.Contains(w.Body.String(), "next") {
		t.Fatal("an error carries no next")
	}

	w = httptest.NewRecorder()
	r := newReply(200, nil)
	r.header.Set("Content-Type", "text/event-stream")
	r.stream = io.NopCloser(strings.NewReader("data: approved\n\n"))
	send(w, "/sign-in/mfa/push/events", r, false)
	if w.Body.String() != "data: approved\n\n" || !w.Flushed {
		t.Fatalf("%q", w.Body)
	}
	if m := methodNotAllowed(); m.status != 405 || m.header.Get("Allow") != "POST" {
		t.Fatal("405")
	}
}

func TestSendCachesOnlyASuccessfulKeySet(t *testing.T) {
	w := httptest.NewRecorder()
	send(w, "", text(http.StatusServiceUnavailable, "The keys are unavailable right now."), true)
	if w.Code != 503 || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("a 503 for the keys must not be cached: %d %v", w.Code, w.Header())
	}
	w = httptest.NewRecorder()
	rep := ok(map[string]any{"keys": []any{}}, nil)
	rep.header.Set("Cache-Control", "public, max-age=300")
	send(w, "", rep, true)
	if w.Header().Get("Cache-Control") != "public, max-age=300" {
		t.Fatalf("the keys are cacheable: %v", w.Header())
	}
}

func TestSendTellsTheBrowserNotToSniff(t *testing.T) {
	for _, rep := range []*reply{ok(map[string]any{}, nil), text(400, "x"), redirect("/")} {
		w := httptest.NewRecorder()
		send(w, "/session", rep, false)
		if w.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Fatalf("%d: %v", rep.status, w.Header())
		}
	}
}
