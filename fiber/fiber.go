// Package cauthyfiber is cauthy-sdk-go for Fiber: Mount serves the auth-bff
// routes and the published keys, Require verifies a bearer token, Protect
// lets only a signed-in person through.
//
// Fiber runs on fasthttp, not net/http: Mount goes through Fiber's adaptor,
// which buffers an answer whole. Every route works; the push approval's
// event stream (GET /sign-in/mfa/push/events) arrives at the end instead of
// as it happens, so a page on Fiber polls POST /sign-in/mfa/push/finish.
package cauthyfiber

import (
	"net/http"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/adaptor"
	cauthy "github.com/vennet-developers/cauthy-sdk-go"
)

const identityKey = "cauthy.identity"

// Mount serves auth at its base path and its JWKS path.
func Mount(app *fiber.App, auth *cauthy.Auth) {
	h := adaptor.HTTPHandler(auth)
	app.All(auth.BasePath(), h)
	app.All(auth.BasePath()+"/*", h)
	app.Get(auth.JWKSPath(), h)
}

// Require lets a request with a valid Cauthy token through, its Identity in
// c.Locals (Identity).
func Require(v *cauthy.Verifier) fiber.Handler {
	return func(c *fiber.Ctx) error {
		r, err := adaptor.ConvertRequest(c, false)
		if err != nil {
			return err
		}
		id, err := v.VerifyRequest(r.WithContext(c.UserContext()))
		if err != nil {
			status, h, body := cauthy.Refusal(err)
			for k := range h {
				c.Set(k, h.Get(k))
			}
			return c.Status(status).Send(body)
		}
		c.Locals(identityKey, id)
		c.SetUserContext(cauthy.WithIdentity(c.UserContext(), id))
		return c.Next()
	}
}

// Identity is the Identity Require attached.
func Identity(c *fiber.Ctx) (*cauthy.Identity, bool) {
	id, ok := c.Locals(identityKey).(*cauthy.Identity)
	return id, ok && id != nil
}

// Protect lets only a signed-in person through (Auth.Protect); the Session
// is cauthy.SessionFromContext(c.UserContext()). A page without one is sent
// to sign in, anything else answered 401, as Auth.Protect does.
func Protect(auth *cauthy.Auth) fiber.Handler {
	refuse := adaptor.HTTPHandler(auth.Protect(http.NotFoundHandler()))
	return func(c *fiber.Ctx) error {
		r, err := adaptor.ConvertRequest(c, false)
		if err != nil {
			return err
		}
		s := auth.Session(nil, r)
		if s == nil {
			return refuse(c)
		}
		c.SetUserContext(cauthy.WithSession(c.UserContext(), s))
		return c.Next()
	}
}
