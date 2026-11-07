package cauthy

import (
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

func TestCookiesAreWrittenInPartsAndReadBack(t *testing.T) {
	long := strings.Repeat("a", partSize) + strings.Repeat("b", 10)
	set := writeParts("cauthy_session", long, cookieAttrs{secure: true}, map[string]string{"cauthy_session.2": "old"})
	want := []string{
		"cauthy_session.0=" + strings.Repeat("a", partSize) + "; Path=/; HttpOnly; SameSite=Lax; Secure",
		"cauthy_session.1=bbbbbbbbbb; Path=/; HttpOnly; SameSite=Lax; Secure",
		"cauthy_session.2=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0; Secure",
	}
	if !slices.Equal(set, want) {
		t.Fatalf("two parts, and the old .2 deleted: %q", set)
	}
	set = writeParts("s", "short", cookieAttrs{}.age(2592000), map[string]string{"s.0": "x", "s.1": "y"})
	if !slices.Equal(set, []string{"s.0=short; Path=/; HttpOnly; SameSite=Lax; Max-Age=2592000", "s.1=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"}) {
		t.Fatalf("%v", set)
	}
	if got := clearParts("s", cookieAttrs{}, map[string]string{}); !slices.Equal(got, []string{"s.0=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"}) {
		t.Fatalf("%v", got)
	}

	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Add("Cookie", "s.0=ab; other=1")
	r.Header.Add("Cookie", "s.1=cd; s.3=zz")
	c := readCookies(r)
	if v, ok := readParts(c, "s"); !ok || v != "abcd" {
		t.Fatalf("%q", v)
	}
	if _, ok := readParts(c, "none"); ok {
		t.Fatal("absent")
	}
}
