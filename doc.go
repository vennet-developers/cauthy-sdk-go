// Package cauthy is Cauthy for Go backends.
//
// Two ways to use it:
//
//   - An API behind a backend that already signs people in (a Node BFF on
//     @cauthyhq/node, for example) verifies Cauthy's access tokens with a
//     Verifier and its middleware. Nothing else is needed: no secret, no call
//     to Cauthy per request.
//
//   - A Go application that is its own backend for the browser serves the
//     auth-bff protocol with Auth (cauthy.New): cookie sessions, every
//     sign-in method, the account, organizations, the system client and
//     webhooks, at protocol level strict.
//
// The rules a token is checked by are cauthy-sdk-spec's
// verification/rules.md; the routes Auth serves are its protocol/routes.yaml.
package cauthy
