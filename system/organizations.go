package system

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/vennet-developers/cauthy-sdk-go/internal/cfgerr"
	"github.com/vennet-developers/cauthy-sdk-go/internal/jose"
	"github.com/vennet-developers/cauthy-sdk-go/keys"
)

// Organization is an organization of the application's system. Moments are UTC.
type Organization struct {
	ID         string         `json:"id"`
	System     string         `json:"system"`
	Name       string         `json:"name"`
	Kind       string         `json:"kind"`
	ExternalID string         `json:"external_id,omitempty"`
	Status     string         `json:"status"`
	Metadata   map[string]any `json:"metadata"`
	Members    int            `json:"members"`
	CreatedAt  string         `json:"created_at"`
	UpdatedAt  string         `json:"updated_at"`
}

// Member is a person of an organization.
type Member struct {
	UserID  string `json:"user_id"`
	Email   string `json:"email"`
	Name    string `json:"name"`
	Status  string `json:"status"`
	Role    string `json:"role"`
	Invited bool   `json:"invited,omitempty"`
}

// NewMember is who to add: an account by UserID, or anybody by Email
// (invited when new). With AllowExisting false (the default) a person who
// already belongs keeps their role and the call fails with member_exists.
type NewMember struct {
	UserID        string
	Email         string
	Role          string
	Name          string
	Locale        string
	AllowExisting bool
}

// Query narrows ListOrganizations.
type Query struct {
	Q      string
	Status string
	Limit  int
	Offset int
}

// OrganizationPatch changes an organization; nil fields are left as they are.
type OrganizationPatch struct {
	Name     *string        `json:"name,omitempty"`
	Kind     *string        `json:"kind,omitempty"`
	Status   *string        `json:"status,omitempty"`
	Metadata map[string]any `json:"metadata,omitempty"`
}

// CheckQuestion asks whether a member may do an action on a resource.
type CheckQuestion struct {
	OrganizationID string
	UserID         string
	System         string // default: Options.System
	Resource       string
	Action         string
	Attributes     map[string]any
	ResourceID     string
	OwnerID        string
}

// CheckRule is the rule that decided a check.
type CheckRule struct {
	Source    string `json:"source"`
	Role      string `json:"role,omitempty"`
	Kind      string `json:"kind"`
	Resource  string `json:"resource"`
	Action    string `json:"action"`
	Effect    string `json:"effect"`
	Condition string `json:"condition,omitempty"`
}

// CheckResult is Cauthy's answer to a check. Anything but a plain yes is a no.
type CheckResult struct {
	Allowed bool       `json:"allowed"`
	Reason  string     `json:"reason"`
	Rule    *CheckRule `json:"rule,omitempty"`
}

func esc(s string) string { return url.PathEscape(s) }

func (c *Client) inviteHeaders() http.Header {
	if !strings.HasPrefix(c.o.AcceptInviteURL, "https://") && !strings.HasPrefix(c.o.AcceptInviteURL, "http://") {
		return http.Header{}
	}
	return http.Header{"X-Cauthy-Client-Id": {c.o.ClientID}, "X-Cauthy-Link-To": {c.o.AcceptInviteURL}}
}

// ListOrganizations lists the system's organizations and their total.
func (c *Client) ListOrganizations(ctx context.Context, q Query) ([]Organization, int, error) {
	v := url.Values{}
	if q.Q != "" {
		v.Set("q", q.Q)
	}
	if q.Status != "" {
		v.Set("status", q.Status)
	}
	if q.Limit > 0 {
		v.Set("limit", strconv.Itoa(q.Limit))
	}
	if q.Offset > 0 {
		v.Set("offset", strconv.Itoa(q.Offset))
	}
	path := "/v1/organizations"
	if len(v) > 0 {
		path += "?" + v.Encode()
	}
	raw, err := c.send(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, 0, err
	}
	var page struct {
		Data  []Organization `json:"data"`
		Total int            `json:"total_count"`
	}
	if err := json.Unmarshal(raw, &page); err != nil {
		return nil, 0, &APIError{Status: 502, Code: "unavailable", Message: "Cauthy's answer is not JSON"}
	}
	return page.Data, page.Total, nil
}

// CreateOrganization makes an organization of the system.
func (c *Client) CreateOrganization(ctx context.Context, name, kind, externalID string, metadata map[string]any) (*Organization, error) {
	var o Organization
	err := c.Request(ctx, http.MethodPost, "/v1/organizations", map[string]any{"name": name, "kind": kind, "external_id": externalID, "metadata": metadata}, &o)
	return &o, err
}

// GetOrganization reads one organization.
func (c *Client) GetOrganization(ctx context.Context, id string) (*Organization, error) {
	var o Organization
	err := c.Request(ctx, http.MethodGet, "/v1/organizations/"+esc(id), nil, &o)
	return &o, err
}

// changed tells Options.Changed that err is nil.
func (c *Client) changed(err error) error {
	if err == nil && c.o.Changed != nil {
		c.o.Changed()
	}
	return err
}

// UpdateOrganization changes an organization.
func (c *Client) UpdateOrganization(ctx context.Context, id string, p OrganizationPatch) (*Organization, error) {
	var o Organization
	err := c.changed(c.Request(ctx, http.MethodPatch, "/v1/organizations/"+esc(id), p, &o))
	return &o, err
}

// RemoveOrganization removes the organization and every membership of it.
func (c *Client) RemoveOrganization(ctx context.Context, id string) error {
	return c.changed(c.Request(ctx, http.MethodDelete, "/v1/organizations/"+esc(id), nil, nil))
}

// ListMembers lists an organization's people.
func (c *Client) ListMembers(ctx context.Context, organizationID string) ([]Member, error) {
	var out []Member
	err := c.Request(ctx, http.MethodGet, "/v1/organizations/"+esc(organizationID)+"/members", nil, &out)
	return out, err
}

// AddMember adds a person to an organization.
func (c *Client) AddMember(ctx context.Context, organizationID string, m NewMember) (*Member, error) {
	body := map[string]any{"role": m.Role, "client_id": c.o.ClientID, "only_new": !m.AllowExisting}
	for k, v := range map[string]string{"user_id": m.UserID, "email": m.Email, "name": m.Name, "locale": m.Locale} {
		if v != "" {
			body[k] = v
		}
	}
	var out Member
	err := c.changed(c.Request(ctx, http.MethodPost, "/v1/organizations/"+esc(organizationID)+"/members", body, &out, c.inviteHeaders()))
	return &out, err
}

// SetMemberRole changes a member's role.
func (c *Client) SetMemberRole(ctx context.Context, organizationID, userID, role string) (*Member, error) {
	var out Member
	err := c.changed(c.Request(ctx, http.MethodPut, "/v1/organizations/"+esc(organizationID)+"/members/"+esc(userID), map[string]any{"role": role}, &out))
	return &out, err
}

// RemoveMember takes a person out of an organization.
func (c *Client) RemoveMember(ctx context.Context, organizationID, userID string) error {
	return c.changed(c.Request(ctx, http.MethodDelete, "/v1/organizations/"+esc(organizationID)+"/members/"+esc(userID), nil, nil))
}

// Invite invites a person who has no account yet; it answers the account's id.
func (c *Client) Invite(ctx context.Context, email, name, locale string) (string, error) {
	body := map[string]any{"email": email, "client_id": c.o.ClientID}
	if name != "" {
		body["name"] = name
	}
	if locale != "" {
		body["locale"] = locale
	}
	var u struct {
		ID string `json:"id"`
	}
	err := c.Request(ctx, http.MethodPost, "/v1/users", body, &u, c.inviteHeaders())
	return u.ID, err
}

// Check asks whether a member of one of the system's organizations may do an
// action on a resource, conditions weighed.
func (c *Client) Check(ctx context.Context, q CheckQuestion) (CheckResult, error) {
	system := q.System
	if system == "" {
		system = c.o.System
	}
	if system == "" && c.o.SystemOf != nil {
		system = c.o.SystemOf()
	}
	if system == "" {
		return CheckResult{}, cfgerr.New("name the system to check in (CheckQuestion.System, or CAUTHY_SYSTEM)")
	}
	body := map[string]any{"organization_id": q.OrganizationID, "user_id": q.UserID, "resource": q.Resource, "action": q.Action}
	if q.ResourceID != "" {
		body["resource_id"] = q.ResourceID
	}
	if q.OwnerID != "" {
		body["owner_id"] = q.OwnerID
	}
	if q.Attributes != nil {
		body["attributes"] = q.Attributes
	}
	var r CheckResult
	err := c.Request(ctx, http.MethodPost, "/v1/systems/"+esc(system)+"/check", body, &r)
	return r, err
}

// PactStatus is how the system stands against its contract, as Cauthy
// checks it now (GET /v1/pact/status). Moments are UTC.
type PactStatus struct {
	System       string           `json:"system"`
	TenantID     string           `json:"tenant_id"`
	CheckedAt    string           `json:"checked_at"`
	ReconciledAt *string          `json:"reconciled_at"`
	InStep       bool             `json:"in_step"`
	Outside      []map[string]any `json:"outside"`
	Missing      []map[string]any `json:"missing"`
	Contract     map[string]any   `json:"contract"`
	Held         map[string]any   `json:"held"`
}

// PactStatus asks Cauthy how system stands against its contract.
func (c *Client) PactStatus(ctx context.Context, system string) (*PactStatus, error) {
	var s PactStatus
	err := c.Request(ctx, http.MethodGet, "/v1/pact/status?system="+url.QueryEscape(system), nil, &s)
	return &s, err
}

// PublicJWKS is the public half of the key the application proves itself
// with, to serve at the address Cauthy reads it from. Empty with a secret.
func (c *Client) PublicJWKS(ctx context.Context) (keys.JWKS, error) {
	if c.o.Keys != nil {
		return c.o.Keys.Published(ctx)
	}
	if c.o.Key == nil {
		return keys.JWKS{Keys: []map[string]any{}}, nil
	}
	_, kid, key, err := c.self(ctx)
	if err != nil {
		return keys.JWKS{}, err
	}
	jwk := map[string]any{"kty": "RSA", "kid": kid, "alg": "RS256", "use": "sig"}
	for k, v := range jose.PublicJWK(&key.PublicKey) {
		jwk[k] = v
	}
	return keys.JWKS{Keys: []map[string]any{jwk}}, nil
}
