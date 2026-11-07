// Package cfgerr is the configuration error every package of the SDK
// returns at start, before it serves anything.
package cfgerr

import "fmt"

// Error is a configuration the SDK refuses. Its message names what to change.
type Error struct{ Msg string }

func (e *Error) Error() string { return "cauthy: " + e.Msg }

// New formats the message.
func New(format string, a ...any) *Error { return &Error{Msg: fmt.Sprintf(format, a...)} }
