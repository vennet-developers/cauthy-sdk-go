package cauthy

import "fmt"

// Reason says why a token was refused: the closed list of the spec's
// verification/rules.md, and NoToken when there was none to check.
type Reason string

const (
	NoToken           Reason = "no_token"
	TooLarge          Reason = "too_large"
	Malformed         Reason = "malformed"
	AlgNotAllowed     Reason = "alg_not_allowed"
	UnsupportedHeader Reason = "unsupported_header"
	MissingKid        Reason = "missing_kid"
	UnknownKid        Reason = "unknown_kid"
	WeakKey           Reason = "weak_key"
	BadSignature      Reason = "bad_signature"
	MissingClaim      Reason = "missing_claim"
	InvalidClaim      Reason = "invalid_claim"
	WrongIssuer       Reason = "wrong_issuer"
	WrongAudience     Reason = "wrong_audience"
	Expired           Reason = "expired"
	NotYetValid       Reason = "not_yet_valid"
	IssuedInFuture    Reason = "issued_in_future"
	WrongTenant       Reason = "wrong_tenant"
	SystemToken       Reason = "system_token"
	ClientToken       Reason = "client_token"
	AnonymousToken    Reason = "anonymous_token"
	WrongClient       Reason = "wrong_client"
)

// Reasons is every reason of rules.md, in the order the checks run.
var Reasons = []Reason{
	TooLarge, Malformed, AlgNotAllowed, UnsupportedHeader, MissingKid, UnknownKid, WeakKey,
	BadSignature, MissingClaim, InvalidClaim, WrongIssuer, WrongAudience, Expired, NotYetValid,
	IssuedInFuture, WrongTenant, SystemToken, ClientToken, AnonymousToken, WrongClient,
}

// TokenError is a refused token: the reason, a detail for logs that never
// quotes the token, and the error underneath when there is one (a key set
// that could not be fetched, for example).
type TokenError struct {
	Reason Reason
	Detail string
	cause  error
}

func (e *TokenError) Error() string {
	return fmt.Sprintf("cauthy: token refused: %s: %s", e.Reason, e.Detail)
}

func (e *TokenError) Unwrap() error { return e.cause }

func refuse(r Reason, format string, a ...any) *TokenError {
	return &TokenError{Reason: r, Detail: fmt.Sprintf(format, a...)}
}
