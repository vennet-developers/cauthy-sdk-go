// Package cauthygin is cauthy-sdk-go for Gin: Mount serves the auth-bff
// routes and the published keys, Require verifies a bearer token, Protect
// lets only a signed-in person through.
package cauthygin

import (
	"net/http"

	"github.com/gin-gonic/gin"
	cauthy "github.com/vennet-developers/cauthy-sdk-go"
)

const identityKey = "cauthy.identity"

// Mount serves auth at its base path and its JWKS path.
func Mount(r gin.IRoutes, auth *cauthy.Auth) {
	h := gin.WrapH(auth)
	r.Any(auth.BasePath(), h)
	r.Any(auth.BasePath()+"/*path", h)
	r.GET(auth.JWKSPath(), h)
	r.HEAD(auth.JWKSPath(), h)
}

// Require lets a request with a valid Cauthy token through, its Identity in
// the context (Identity, and cauthy.FromContext on the request's context).
func Require(v *cauthy.Verifier) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, err := v.VerifyRequest(c.Request)
		if err != nil {
			status, h, body := cauthy.Refusal(err)
			for k, vals := range h {
				c.Writer.Header()[k] = vals
			}
			c.AbortWithStatus(status)
			_, _ = c.Writer.Write(body)
			return
		}
		c.Set(identityKey, id)
		c.Request = c.Request.WithContext(cauthy.WithIdentity(c.Request.Context(), id))
		c.Next()
	}
}

// Identity is the Identity Require attached.
func Identity(c *gin.Context) (*cauthy.Identity, bool) {
	v, ok := c.Get(identityKey)
	id, _ := v.(*cauthy.Identity)
	return id, ok && id != nil
}

// Protect lets only a signed-in person through (Auth.Protect); the Session
// is cauthy.SessionFromContext(c.Request.Context()).
func Protect(auth *cauthy.Auth) gin.HandlerFunc {
	return func(c *gin.Context) {
		passed := false
		auth.Protect(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			passed = true
			c.Request = r
		})).ServeHTTP(c.Writer, c.Request)
		if !passed {
			c.Abort()
			return
		}
		c.Next()
	}
}
