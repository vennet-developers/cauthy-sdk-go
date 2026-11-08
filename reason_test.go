package cauthy

import (
	"errors"
	"testing"
)

func TestTokenErrorNamesTheReasonAndUnwraps(t *testing.T) {
	err := refuse(Expired, "exp %d is past", 5)
	if err.Error() != "cauthy: token refused: expired: exp 5 is past" {
		t.Fatalf("got %q", err.Error())
	}
	inner := errors.New("inner")
	e := &TokenError{Reason: UnknownKid, cause: inner}
	if !errors.Is(e, inner) {
		t.Fatal("does not unwrap")
	}
	if len(Reasons) != 19 || Reasons[0] != TooLarge || Reasons[17] != ClientToken || Reasons[18] != AnonymousToken {
		t.Fatalf("Reasons: %v", Reasons)
	}
}
