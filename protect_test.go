package cauthy

import (
	"net/http"
	"testing"
	"time"

	"github.com/vennet-developers/cauthy-sdk-go/cauthytest"
)

func TestProtectLetsTheSessionThroughAndSendsOthersToSignIn(t *testing.T) {
	f := cauthytest.New()
	clk := &sessionClock{t: time.Date(2026, 1, 1, 9, 0, 0, 0, time.UTC)}
	a := newAuth(t, f, func(o *Options) { o.Now = clk.now })
	var seen *Session
	h := a.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen, _ = SessionFromContext(r.Context())
		w.WriteHeader(204)
	}))
	b := cauthytest.NewBrowser("")
	page := b.Request("GET", "/invoices?page=2", nil)
	page.Header.Set("Accept", "text/html")
	if res := b.Do(h, page); res.StatusCode != 302 || res.Header.Get("Location") != "/api/auth/login?return_to=%2Finvoices%3Fpage%3D2" {
		t.Fatalf("a page goes to sign in: %d %v", res.StatusCode, res.Header)
	}
	fetch := b.Request("GET", "/api/invoices", nil)
	fetch.Header.Set("Sec-Fetch-Mode", "cors")
	if res := b.Do(h, fetch); res.StatusCode != 401 || res.Header.Get("X-Cauthy-Session") != "none" {
		t.Fatalf("anything else is told: %d %v", res.StatusCode, res.Header)
	}
	signIn(t, a, f, b, "u1")
	if res := b.Send(h, "GET", "/api/invoices", nil); res.StatusCode != 204 || seen == nil || seen.User.ID != "u1" {
		t.Fatalf("%d %+v", res.StatusCode, seen)
	}
	clk.add(time.Hour)
	page = b.Request("GET", "/invoices", nil)
	if res := b.Do(h, page); res.Header.Get("Location") != "/api/auth/refresh?return_to=%2Finvoices" {
		t.Fatalf("an expired session renews and comes back: %v", res.Header)
	}
}

func TestCheckMountSaysWhoElseAnswers(t *testing.T) {
	a := newAuth(t, cauthytest.New(), nil)
	mux := http.NewServeMux()
	a.Mount(mux)
	if err := a.CheckMount(mux); err != nil {
		t.Fatal(err)
	}
	taken := http.NewServeMux()
	taken.Handle("/api/auth/session", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte(`{}`)) }))
	a.Mount(taken)
	if err := a.CheckMount(taken); err == nil {
		t.Fatal("another handler answers GET /api/auth/session")
	}
	redirecting := http.RedirectHandler("https://elsewhere.example.com/", http.StatusMovedPermanently)
	if err := a.CheckMount(redirecting); err == nil {
		t.Fatal("a redirect in front")
	}
}
