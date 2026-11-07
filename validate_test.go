package cauthy

import (
	"slices"
	"testing"
)

func TestFormChecks(t *testing.T) {
	cases := []struct {
		got  *fieldProblem
		want string // field:code, or "" for none
	}{
		{checkEmail(""), "email:required"}, {checkEmail("not-an-email"), "email:invalid_email"}, {checkEmail(" ana@example.com "), ""},
		{checkEmail(7.0), "email:required"}, {checkPassword(""), "password:required"}, {checkPassword("x"), ""},
		{checkName(nil), ""}, {checkName(3.0), "name:too_long"}, {checkCode(" 123456 "), ""}, {checkCode(""), "code:required"},
		{checkOrganization(""), ""}, {checkOrganizationName(" "), "name:required"},
		{checkNewPassword("short", defaultPolicy()), "password:too_short"}, {checkNewPassword("long enough pass", defaultPolicy()), ""},
	}
	for i, c := range cases {
		got := ""
		if c.got != nil {
			got = c.got.field + ":" + c.got.code
		}
		if got != c.want {
			t.Errorf("case %d: %q, want %q", i, got, c.want)
		}
	}
	if firstProblem(nil, checkEmail(""), checkPassword("")).field != "email" || firstProblem(nil, nil) != nil {
		t.Fatal("firstProblem")
	}
}

func TestPasswordPolicyIsReadSafelyAndExplained(t *testing.T) {
	p := policyOf(map[string]any{"min_length": 4.0, "max_length": 500.0, "requires": []any{"digit", "symbol", "emoji"}, "min_classes": 9.0, "reject_breached": true})
	if p.Min != 8 || p.Max != 128 || !slices.Equal(p.Requires, []string{"digit", "symbol"}) || p.MinClasses != 4 || !p.RejectBreached {
		t.Fatalf("%+v", p)
	}
	if policyOf(nil).Min != 12 {
		t.Fatal("default min")
	}
	got := passwordProblems("abcdefgh", p)
	if !slices.Equal(got, []string{"needs_digit", "needs_symbol", "needs_classes"}) {
		t.Fatalf("%v", got)
	}
	if describePolicy(p) != "Between 8 and 128 characters. Include a digit and a symbol. Use at least 4 of these: lowercase letters, uppercase letters, digits, symbols. Passwords found in known data breaches are not accepted." {
		t.Fatalf("%q", describePolicy(p))
	}
	if pr := checkNewPassword("abcdefgh", p); pr.code != "needs_digit" || pr.message != "Include a digit. Include a symbol. Use at least 4 of these: lowercase letters, uppercase letters, digits, symbols." {
		t.Fatalf("%+v", pr)
	}
}
