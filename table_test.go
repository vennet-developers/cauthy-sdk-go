package cauthy

import (
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/vennet-developers/cauthy-sdk-go/cauthytest"
	"github.com/vennet-developers/cauthy-sdk-go/internal/spec"
)

// TestEveryRouteOfTheTableIsServed is the conformance runner's table check,
// in process: every route of routes.yaml answers its method with something
// other than 405 or the plain-text 404, and the routes Go serves are the
// table's, all 75.
func TestEveryRouteOfTheTableIsServed(t *testing.T) {
	routes, err := spec.Routes()
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 75 {
		t.Fatalf("%d routes, want 75: sync testdata with scripts/sync-spec.sh", len(routes))
	}
	a, _ := ownAuth(t, nil)
	b := cauthytest.NewBrowser("")
	for _, r := range routes {
		path := "/api/auth" + strings.ReplaceAll(r.Path, "{provider}", "google")
		if r.ID == "sign-in.invitation" {
			path += "?token=x"
		}
		var res *http.Response
		switch {
		case r.Method == "GET":
			res = b.Send(a, "GET", path, nil)
		case slices.Contains(r.Needs, "json"):
			res = b.Send(a, "POST", path, "[]")
		default:
			res = b.Send(a, "POST", path, map[string]any{})
		}
		body := cauthytest.JSON(res)
		served := res.StatusCode != 405 && !(res.StatusCode == 404 && body["error"] == nil)
		if !served || res.Header.Get("Cauthy-Protocol") != "1" || !strings.Contains(res.Header.Get("Cache-Control"), "no-store") {
			t.Errorf("%s %s (%s): %d %v", r.Method, r.Path, r.ID, res.StatusCode, res.Header)
		}
		if slices.Contains(r.Needs, "json") && res.StatusCode != 400 {
			t.Errorf("%s %s: an array is not an object: %d", r.Method, r.Path, res.StatusCode)
		}
	}
}
