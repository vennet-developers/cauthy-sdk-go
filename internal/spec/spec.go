// Package spec reads what the SDK is tested against from cauthy-sdk-spec,
// vendored in testdata/ by scripts/sync-spec.sh at the commit in
// testdata/SPEC_COMMIT: the token vectors and the route table.
package spec

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

// Config is the verifier configuration a case runs with.
type Config struct {
	Issuer         string   `json:"issuer"`
	Issuers        []string `json:"issuers,omitempty"`
	Audience       string   `json:"audience"`
	Tenant         string   `json:"tenant"`
	AllowAnonymous bool     `json:"allow_anonymous,omitempty"`
}

// Case is one token and the verdict every verifier must reach.
type Case struct {
	Name        string `json:"name"`
	Rule        string `json:"rule"`
	Description string `json:"description"`
	Token       string `json:"token"`
	Now         int64  `json:"now"`
	Config      Config `json:"config"`
	Expect      string `json:"expect"`
	Reason      string `json:"reason,omitempty"`
}

// File is vectors/tokens.json.
type File struct {
	Version       int    `json:"version"`
	LeewaySeconds int    `json:"leeway_seconds"`
	MaxTokenBytes int    `json:"max_token_bytes"`
	Cases         []Case `json:"cases"`
}

// Dir is the vendored testdata directory.
func Dir() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "testdata")
}

// Vectors reads tokens.json and jwks.json from Dir.
func Vectors() (*File, []byte, error) {
	raw, err := os.ReadFile(filepath.Join(Dir(), "tokens.json"))
	if err != nil {
		return nil, nil, err
	}
	var f File
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, nil, fmt.Errorf("tokens.json: %w", err)
	}
	jwks, err := os.ReadFile(filepath.Join(Dir(), "jwks.json"))
	if err != nil {
		return nil, nil, err
	}
	return &f, jwks, nil
}

// Route is one route of protocol/routes.yaml.
type Route struct {
	ID, Method, Path string
	Needs            []string
	Deprecated       bool
}

var routeLine = regexp.MustCompile(`^  - \{ id: ([^,]+), method: ([A-Z]+), path: "?([^",]+)"?, group: [^,]+, level: [^,]+, needs: \[([^\]]*)\]`)

// Routes reads the route table. Each route is one entry starting on its own
// line (auth-bff.md, "The route table"), so a line reader is enough.
func Routes() ([]Route, error) {
	raw, err := os.ReadFile(filepath.Join(Dir(), "routes.yaml"))
	if err != nil {
		return nil, err
	}
	var out []Route
	for _, line := range strings.Split(string(raw), "\n") {
		m := routeLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		r := Route{ID: m[1], Method: m[2], Path: m[3], Deprecated: strings.Contains(line, "deprecated: true")}
		for _, n := range strings.Split(m[4], ",") {
			if n = strings.TrimSpace(n); n != "" {
				r.Needs = append(r.Needs, n)
			}
		}
		out = append(out, r)
	}
	return out, nil
}
