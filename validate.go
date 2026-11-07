package cauthy

import (
	"math"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// fieldProblem is a value of a form that cannot be sent as it is.
type fieldProblem struct {
	field, code, message string
}

// PasswordPolicy is what a new password must be in the workspace, as GET
// /methods says it. Length counts bytes of UTF-8, as Cauthy counts it.
type PasswordPolicy struct {
	Min            int      `json:"min"`
	Max            int      `json:"max"`
	Requires       []string `json:"requires"`
	MinClasses     int      `json:"min_classes"`
	RejectBreached bool     `json:"reject_breached"`
}

const (
	minPassword   = 12
	maxPassword   = 128
	floorPassword = 8
	maxName       = 120
	maxOrgName    = 120
)

var passwordClasses = []string{"lowercase", "uppercase", "digit", "symbol"}

// defaultPolicy is the policy of a workspace that set none.
func defaultPolicy() PasswordPolicy {
	return PasswordPolicy{Min: minPassword, Max: maxPassword, Requires: []string{}}
}

// loosePolicy is what any workspace accepts: when the workspace's own policy
// cannot be read, only this is refused here, and Cauthy checks the rest.
func loosePolicy() PasswordPolicy {
	return PasswordPolicy{Min: floorPassword, Max: maxPassword, Requires: []string{}}
}

func intOf(v any, fallback int) int {
	f, ok := v.(float64)
	if !ok || math.IsNaN(f) || math.IsInf(f, 0) {
		return fallback
	}
	return int(f)
}

// policyOf is a policy as Cauthy sent it ({min_length, max_length…} from the
// settings), made safe: defaults where nothing is said, never outside 8–128.
func policyOf(raw any) PasswordPolicy {
	r := obj(raw)
	pick := func(a, b string) any {
		if v, ok := r[a]; ok && v != nil {
			return v
		}
		return r[b]
	}
	minLen := intOf(pick("min", "min_length"), minPassword)
	if minLen == 0 {
		minLen = minPassword
	}
	minLen = min(max(minLen, floorPassword), maxPassword)
	maxLen := intOf(pick("max", "max_length"), maxPassword)
	if maxLen == 0 {
		maxLen = maxPassword
	}
	maxLen = max(min(maxLen, maxPassword), minLen)
	asked := arr(r["requires"])
	p := PasswordPolicy{Min: minLen, Max: maxLen, Requires: []string{}}
	for _, c := range passwordClasses {
		if slices.Contains(asked, any(c)) {
			p.Requires = append(p.Requires, c)
		}
	}
	p.MinClasses = min(max(intOf(pick("min_classes", "minClasses"), 0), 0), len(passwordClasses))
	p.RejectBreached = yes(pick("reject_breached", "rejectBreached"))
	return p
}

// classesOf is which of the four kinds a password carries.
func classesOf(v string) map[string]bool {
	has := map[string]bool{}
	for _, ch := range v {
		switch {
		case unicode.IsLower(ch):
			has["lowercase"] = true
		case unicode.IsUpper(ch):
			has["uppercase"] = true
		case unicode.Is(unicode.Nd, ch):
			has["digit"] = true
		case !unicode.IsLetter(ch):
			has["symbol"] = true
		}
	}
	return has
}

// passwordProblems is every rule of p a new password fails, as the API
// names them.
func passwordProblems(v string, p PasswordPolicy) []string {
	var out []string
	if len(v) < p.Min {
		out = append(out, "too_short")
	}
	if len(v) > p.Max {
		out = append(out, "too_long")
	}
	has := classesOf(v)
	for _, c := range p.Requires {
		if !has[c] {
			out = append(out, "needs_"+c)
		}
	}
	n := 0
	for _, c := range passwordClasses {
		if has[c] {
			n++
		}
	}
	if p.MinClasses > 0 && n < p.MinClasses {
		out = append(out, "needs_classes")
	}
	return out
}

var reasonText = map[string]string{
	"too_short": "Use at least {min} characters.", "too_long": "Use at most {max} characters.",
	"needs_lowercase": "Include a lowercase letter.", "needs_uppercase": "Include an uppercase letter.",
	"needs_digit": "Include a digit.", "needs_symbol": "Include a symbol.",
	"needs_classes": "Use at least {n} of these: lowercase letters, uppercase letters, digits, symbols.",
}

var kindText = map[string]string{"lowercase": "a lowercase letter", "uppercase": "an uppercase letter", "digit": "a digit", "symbol": "a symbol"}

func fill(s string, p PasswordPolicy) string {
	return strings.NewReplacer("{min}", strconv.Itoa(p.Min), "{max}", strconv.Itoa(p.Max), "{n}", strconv.Itoa(p.MinClasses)).Replace(s)
}

// describePolicy says the rule: "Between 12 and 128 characters. Include a digit."
func describePolicy(p PasswordPolicy) string {
	parts := []string{fill("Between {min} and {max} characters.", p)}
	if len(p.Requires) > 0 {
		kinds := make([]string, len(p.Requires))
		for i, c := range p.Requires {
			kinds[i] = kindText[c]
		}
		listed := kinds[0]
		if len(kinds) > 1 {
			listed = strings.Join(kinds[:len(kinds)-1], ", ") + " and " + kinds[len(kinds)-1]
		}
		parts = append(parts, "Include "+listed+".")
	}
	if p.MinClasses > 0 {
		parts = append(parts, fill(reasonText["needs_classes"], p))
	}
	if p.RejectBreached {
		parts = append(parts, "Passwords found in known data breaches are not accepted.")
	}
	return strings.Join(parts, " ")
}

func explainProblems(reasons []string, p PasswordPolicy) string {
	var said []string
	for _, r := range reasons {
		if t, ok := reasonText[r]; ok {
			said = append(said, fill(t, p))
		}
	}
	if len(said) == 0 {
		return describePolicy(p)
	}
	return strings.Join(said, " ")
}

var emailRE = regexp.MustCompile(`^[^\s@]+@[^\s@]+\.[^\s@]+$`)

// trimmed is a string value trimmed, or "" for anything else.
func trimmed(v any) string {
	s, _ := v.(string)
	return strings.TrimSpace(s)
}

func checkEmail(v any) *fieldProblem {
	s := trimmed(v)
	if s == "" {
		return &fieldProblem{"email", "required", "Enter your email address."}
	}
	if utf8.RuneCountInString(s) > 254 || !emailRE.MatchString(s) {
		return &fieldProblem{"email", "invalid_email", "That does not look like an email address."}
	}
	return nil
}

func checkPassword(v any) *fieldProblem {
	s, ok := v.(string)
	if !ok || s == "" {
		return &fieldProblem{"password", "required", "Enter your password."}
	}
	if utf16Len(s) > maxPassword {
		return &fieldProblem{"password", "too_long", "That password is too long."}
	}
	return nil
}

// checkNewPassword holds a chosen password to p.
func checkNewPassword(v any, p PasswordPolicy) *fieldProblem {
	s, ok := v.(string)
	if !ok || s == "" {
		return &fieldProblem{"password", "required", "Enter your password."}
	}
	if reasons := passwordProblems(s, p); len(reasons) > 0 {
		return &fieldProblem{"password", reasons[0], explainProblems(reasons, p)}
	}
	return nil
}

func checkName(v any) *fieldProblem {
	if v == nil || v == "" {
		return nil
	}
	s, ok := v.(string)
	if !ok || utf16Len(strings.TrimSpace(s)) > maxName {
		return &fieldProblem{"name", "too_long", "Use at most 120 characters."}
	}
	return nil
}

func checkOrganization(v any) *fieldProblem {
	s := trimmed(v)
	if utf16Len(s) > maxOrgName {
		return &fieldProblem{"organization", "too_long", "Use at most 120 characters."}
	}
	return nil
}

func checkOrganizationName(v any) *fieldProblem {
	s := trimmed(v)
	if s == "" {
		return &fieldProblem{"name", "required", "Enter the organization's name."}
	}
	if utf16Len(s) > maxOrgName {
		return &fieldProblem{"name", "too_long", "Use at most 120 characters."}
	}
	return nil
}

func checkCode(v any) *fieldProblem {
	s := trimmed(v)
	if s == "" {
		return &fieldProblem{"code", "required", "Enter the code."}
	}
	if utf16Len(s) > 40 {
		return &fieldProblem{"code", "too_long", "That is not a code."}
	}
	return nil
}

// firstProblem is the first of checks that is a problem, or nil.
func firstProblem(checks ...*fieldProblem) *fieldProblem {
	for _, c := range checks {
		if c != nil {
			return c
		}
	}
	return nil
}

// utf16Len is JavaScript's string length.
func utf16Len(s string) int {
	n := 0
	for _, r := range s {
		if r >= 0x10000 {
			n += 2
		} else {
			n++
		}
	}
	return n
}
