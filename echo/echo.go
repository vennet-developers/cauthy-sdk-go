// Package cauthyecho is cauthy-sdk-go for Echo: Mount serves the auth-bff
// routes and the published keys, Require verifies a bearer token, Protect
// lets only a signed-in person through.
package cauthyecho

import (
	"net/http"

	"github.com/labstack/echo/v4"
	cauthy "github.com/vennet-developers/cauthy-sdk-go"
)

const identityKey = "cauthy.identity"

// Mount serves auth at its base path and its JWKS path.
func Mount(e *echo.Echo, auth *cauthy.Auth) {
	h := echo.WrapHandler(auth)
	e.Any(auth.BasePath(), h)
	e.Any(auth.BasePath()+"/*", h)
	e.GET(auth.JWKSPath(), h)
	e.HEAD(auth.JWKSPath(), h)
}

// Require lets a request with a valid Cauthy token through, its Identity in
// the context (Identity, and cauthy.FromContext on the request's context).
func Require(v *cauthy.Verifier) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			id, err := v.VerifyRequest(c.Request())
			if err != nil {
				status, h, body := cauthy.Refusal(err)
				for k, vals := range h {
					c.Response().Header()[k] = vals
				}
				return c.Blob(status, h.Get("Content-Type"), body)
			}
			c.Set(identityKey, id)
			c.SetRequest(c.Request().WithContext(cauthy.WithIdentity(c.Request().Context(), id)))
			return next(c)
		}
	}
}

// Identity is the Identity Require attached.
func Identity(c echo.Context) (*cauthy.Identity, bool) {
	id, ok := c.Get(identityKey).(*cauthy.Identity)
	return id, ok && id != nil
}

// Protect lets only a signed-in person through (Auth.Protect); the Session
// is cauthy.SessionFromContext(c.Request().Context()).
func Protect(auth *cauthy.Auth) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			var err error
			passed := false
			auth.Protect(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				passed = true
				c.SetRequest(r)
			})).ServeHTTP(c.Response(), c.Request())
			if passed {
				err = next(c)
			}
			return err
		}
	}
}
