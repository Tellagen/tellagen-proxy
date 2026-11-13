// Package grafana makes the few read-only calls the hello and the doctor need.
// Diagnosis queries go through the executor instead.
package grafana

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	maxBodyBytes   = 8 << 20
	requestTimeout = 15 * time.Second
)

// Client reads from one Grafana. It is safe for concurrent use.
type Client struct {
	base  *url.URL
	http  *http.Client
	token func() (string, error)
	orgID int64
}

// Config configures a Client.
type Config struct {
	BaseURL   *url.URL
	Transport http.RoundTripper
	// Token returns the service account token. It is called for every request.
	Token func() (string, error)
	// OrgID selects a Grafana org when it is above zero.
	OrgID int64
}

// New returns a Client.
func New(config Config) *Client {
	return &Client{
		base:  config.BaseURL,
		http:  &http.Client{Transport: config.Transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		token: config.Token,
		orgID: config.OrgID,
	}
}

// StatusError is an HTTP answer that was not 2xx.
type StatusError struct {
	Status int
	Path   string
}

// Error implements error.
func (e *StatusError) Error() string {
	return fmt.Sprintf("Grafana answered %d for %s", e.Status, e.Path)
}

func (c *Client) get(ctx context.Context, path string, query url.Values, authenticated bool, into any) (time.Duration, error) {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	target := c.base.JoinPath(path)
	target.RawQuery = query.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return 0, err
	}
	request.Header.Set("Accept", "application/json")
	if authenticated {
		token, err := c.token()
		if err != nil {
			return 0, fmt.Errorf("read the Grafana token: %w", err)
		}
		request.Header.Set("Authorization", "Bearer "+token)
		if c.orgID > 0 {
			request.Header.Set("X-Grafana-Org-Id", strconv.FormatInt(c.orgID, 10))
		}
	}
	started := time.Now()
	response, err := c.http.Do(request)
	if err != nil {
		return 0, err
	}
	defer func() { _ = response.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(response.Body, maxBodyBytes))
	elapsed := time.Since(started)
	if err != nil {
		return elapsed, err
	}
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return elapsed, &StatusError{Status: response.StatusCode, Path: path}
	}
	if into == nil {
		return elapsed, nil
	}
	if err := json.Unmarshal(data, into); err != nil {
		return elapsed, fmt.Errorf("the answer of %s is not JSON: %w", path, err)
	}
	return elapsed, nil
}

// Health is the answer of Grafana's health endpoint.
type Health struct {
	Version string
	Latency time.Duration
}

// Health asks whether Grafana is up. The endpoint needs no login, so a bad token
// does not hide an outage.
func (c *Client) Health(ctx context.Context) (Health, error) {
	var body struct {
		Version string `json:"version"`
	}
	elapsed, err := c.get(ctx, "/api/health", nil, false, &body)
	return Health{Version: body.Version, Latency: elapsed}, err
}

// Datasource is one datasource that Grafana lists. Its address is not read.
type Datasource struct {
	UID     string `json:"uid"`
	Name    string `json:"name"`
	Type    string `json:"type"`
	Default bool   `json:"isDefault"`
}

// Datasources lists the datasources the token can see.
func (c *Client) Datasources(ctx context.Context) ([]Datasource, error) {
	var list []Datasource
	_, err := c.get(ctx, "/api/datasources", nil, true, &list)
	return list, err
}

// Identity says who the token is in Grafana.
type Identity struct {
	Login   string
	OrgID   int64
	OrgName string
	// Role is Viewer, Editor, Admin or None. It is empty when Grafana did not say.
	Role string
}

// Identity reads the service account behind the token. A 401 from the first call
// is the "token rejected" case.
func (c *Client) Identity(ctx context.Context) (Identity, error) {
	var user struct {
		Login string `json:"login"`
	}
	if _, err := c.get(ctx, "/api/user", nil, true, &user); err != nil {
		return Identity{}, err
	}
	identity := Identity{Login: user.Login}
	var org struct {
		ID   int64  `json:"id"`
		Name string `json:"name"`
	}
	if _, err := c.get(ctx, "/api/org", nil, true, &org); err != nil {
		return identity, err
	}
	identity.OrgID, identity.OrgName = org.ID, org.Name
	var orgs []struct {
		OrgID int64  `json:"orgId"`
		Role  string `json:"role"`
	}
	// Some Grafana versions do not list the orgs of a service account. The role is
	// then unknown, and that is not a failure.
	if _, err := c.get(ctx, "/api/user/orgs", nil, true, &orgs); err == nil {
		for _, entry := range orgs {
			if entry.OrgID == org.ID {
				identity.Role = entry.Role
			}
		}
	}
	return identity, nil
}

// Smoke runs the cheapest possible query against one datasource and reports how
// long it took. It supports Prometheus and Loki and returns the query it ran.
func (c *Client) Smoke(ctx context.Context, datasource Datasource) (query string, latency time.Duration, err error) {
	base := "/api/datasources/proxy/uid/" + url.PathEscape(datasource.UID)
	switch datasource.Type {
	case "prometheus":
		latency, err = c.get(ctx, base+"/api/v1/query", url.Values{"query": {"vector(1)"}}, true, nil)
		return "vector(1)", latency, err
	case "loki":
		latency, err = c.get(ctx, base+"/loki/api/v1/labels", nil, true, nil)
		return "labels", latency, err
	}
	return "", 0, errors.New("only Prometheus and Loki are checked")
}

// Describe names the Grafana address without credentials, for messages.
func (c *Client) Describe() string {
	return strings.TrimRight(c.base.Scheme+"://"+c.base.Host+c.base.Path, "/")
}
