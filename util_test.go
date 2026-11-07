package cauthy

import "testing"

func TestLocalPathRefusesEveryOtherSite(t *testing.T) {
	for in, want := range map[string]string{
		"/invoices?x=1": "/invoices?x=1", "": "/", "invoices": "/", "//evil.example": "/", `/\evil.example`: "/",
		"/\t/evil.example": "/", "https://evil.example": "/", "/ok#frag": "/ok#frag", "/a\x7f": "/",
	} {
		if got := localPath(in, "/"); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
	if withQuery("/x", "auth_error", "a b") != "/x?auth_error=a+b" || withQuery("/x?y=1", "a", "b") != "/x?y=1&a=b" {
		t.Error("withQuery")
	}
}

func TestOwnNetwork(t *testing.T) {
	for _, a := range []string{"127.0.0.1", "10.1.2.3", "172.16.0.1", "172.31.9.9", "192.168.1.1", "169.254.0.1", "::1", "fd00::1", "fe80::1", "::ffff:127.0.0.1"} {
		if !ownNetwork(a) {
			t.Errorf("%s is the network's own", a)
		}
	}
	for _, a := range []string{"203.0.113.9", "172.32.0.1", "172.15.0.1", "2001:db8::1", "8.8.8.8"} {
		if ownNetwork(a) {
			t.Errorf("%s is a person's", a)
		}
	}
}

func TestLooseJSONReaders(t *testing.T) {
	v := map[string]any{"a": map[string]any{"b": 3.0, "c": true, "l": []any{"x", 2.0}}}
	if str(at(v, "a", "b")) != "3" || !yes(at(v, "a", "c")) || yes(at(v, "a", "b")) || str(at(v, "nope", "x")) != "" ||
		len(strs(at(v, "a", "l"))) != 2 || strs(nil) == nil || strOr(nil, "sms") != "sms" || num(at(v, "a", "b")) != 3 {
		t.Fatal("readers")
	}
	if !wants(true) || !wants("on") || wants("no") || wants(1.0) {
		t.Fatal("wants")
	}
	if !providerRE.MatchString("custom:acme") || providerRE.MatchString("Google") || providerIn("custom%3Aacme") != "custom:acme" {
		t.Fatal("providers")
	}
	if challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk") != "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" {
		t.Fatal("PKCE S256 (RFC 7636 appendix B)")
	}
}
