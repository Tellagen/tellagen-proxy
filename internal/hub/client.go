// Package hub is the client of the Tellagen machine routes under /api/proxy/v1.
// It keeps a short-lived session in memory and renews it when needed.
package hub

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tellagen/tellagen-proxy/protocol"
)

const (
	// maxResponseBytes bounds any reply. A poll reply holds a few commands.
	maxResponseBytes = 4 << 20
	// requestTimeout bounds every call except a poll.
	requestTimeout = 30 * time.Second
	// pollMargin is added to a poll's wait: the server may answer a little late.
	pollMargin = 15 * time.Second
	// sessionMargin renews a session this long before it ends.
	sessionMargin = time.Minute
)

// TokenSource is the proxy token. Reload is called after a 401.
type TokenSource interface {
	Value() (string, error)
	Reload() (string, error)
}

// Client talks to Tellagen. It is safe for concurrent use.
type Client struct {
	base      *url.URL
	http      *http.Client
	token     TokenSource
	userAgent string
	now       func() time.Time

	exchangeMu sync.Mutex // one session exchange at a time

	mu         sync.Mutex
	session    string
	expires    time.Time
	generation uint64
	skew       time.Duration
}

// Config configures a Client.
type Config struct {
	BaseURL   *url.URL
	Transport http.RoundTripper
	Token     TokenSource
	Version   string
	Now       func() time.Time
}

// New returns a Client.
func New(config Config) *Client {
	now := config.Now
	if now == nil {
		now = time.Now
	}
	return &Client{
		base:      config.BaseURL,
		http:      &http.Client{Transport: config.Transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		token:     config.Token,
		userAgent: "tellagen-proxy/" + config.Version,
		now:       now,
	}
}

// Generation counts the sessions this client has started. A change means the
// server may not know the proxy's hello for the new session.
func (c *Client) Generation() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.generation
}

// Skew is the latest difference between Tellagen's clock and this machine's:
// positive when Tellagen is ahead.
func (c *Client) Skew() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.skew
}

// Exchange trades the proxy token for a session token and keeps the session. The
// proxy token is the only credential that this call sends.
func (c *Client) Exchange(ctx context.Context) (protocol.SessionReply, error) {
	var reply protocol.SessionReply
	token, err := c.token.Value()
	if err != nil {
		return reply, &TokenError{Err: err}
	}
	err = c.send(ctx, "/api/proxy/v1/session", token, struct{}{}, &reply, requestTimeout)
	var apiErr *APIError
	if errors.As(err, &apiErr) && apiErr.Status == http.StatusUnauthorized {
		// A rotated token file may already hold the new token.
		fresh, reloadErr := c.token.Reload()
		if reloadErr == nil && fresh != token {
			err = c.send(ctx, "/api/proxy/v1/session", fresh, struct{}{}, &reply, requestTimeout)
		}
	}
	if err != nil {
		c.forget()
		return reply, err
	}
	if !strings.HasPrefix(reply.SessionToken, protocol.SessionTokenPrefix) {
		return reply, &DecodeError{Err: errors.New("the session reply holds no session token")}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.session, c.expires = reply.SessionToken, reply.ExpiresAt
	c.generation++
	if !reply.ServerTime.IsZero() {
		c.skew = reply.ServerTime.Sub(c.now())
	}
	return reply, nil
}

// Hello sends the hello of this proxy.
func (c *Client) Hello(ctx context.Context, hello protocol.Hello) (protocol.HelloReply, error) {
	var reply protocol.HelloReply
	err := c.call(ctx, "/api/proxy/v1/hello", hello, &reply, requestTimeout)
	return reply, err
}

// Poll asks for work and doubles as the heartbeat. It holds for up to the
// request's WaitMS.
func (c *Client) Poll(ctx context.Context, request protocol.PollRequest) (protocol.PollReply, error) {
	var reply protocol.PollReply
	timeout := time.Duration(request.WaitMS)*time.Millisecond + pollMargin
	err := c.call(ctx, "/api/proxy/v1/poll", request, &reply, timeout)
	return reply, err
}

// PostResult sends the result of one command. A 409 or 410 means Tellagen no
// longer wants it, and is an *APIError with that status.
func (c *Client) PostResult(ctx context.Context, commandID string, result protocol.CommandResult) error {
	path := "/api/proxy/v1/commands/" + url.PathEscape(commandID) + "/result"
	var reply protocol.AcceptedReply
	return c.call(ctx, path, result, &reply, requestTimeout)
}

// call sends an authenticated request, renewing a missing or ending session first
// and once more after a 401 that says the session ended.
func (c *Client) call(ctx context.Context, path string, body, reply any, timeout time.Duration) error {
	for attempt := 0; ; attempt++ {
		session, err := c.sessionToken(ctx)
		if err != nil {
			return err
		}
		err = c.send(ctx, path, session, body, reply, timeout)
		var apiErr *APIError
		if !errors.As(err, &apiErr) || apiErr.Status != http.StatusUnauthorized {
			return err
		}
		c.forget()
		if apiErr.Reply.Code != protocol.ErrorSessionInvalid || attempt > 0 {
			_, _ = c.token.Reload()
			return err
		}
	}
}

func (c *Client) sessionToken(ctx context.Context) (string, error) {
	if session, ok := c.liveSession(); ok {
		return session, nil
	}
	c.exchangeMu.Lock()
	defer c.exchangeMu.Unlock()
	if session, ok := c.liveSession(); ok {
		return session, nil
	}
	reply, err := c.Exchange(ctx)
	if err != nil {
		return "", err
	}
	return reply.SessionToken, nil
}

func (c *Client) liveSession() (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.session, c.session != "" && c.now().Add(sessionMargin).Before(c.expires)
}

func (c *Client) forget() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.session, c.expires = "", time.Time{}
}

func (c *Client) send(ctx context.Context, path, bearer string, body, reply any, timeout time.Duration) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("encode the request: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base.JoinPath(path).String(), bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("build the request: %w", err)
	}
	request.Header.Set("Authorization", "Bearer "+bearer)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", c.userAgent)
	response, err := c.http.Do(request)
	if err != nil {
		return &TransportError{Err: err}
	}
	defer func() { _ = response.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil {
		return &TransportError{Err: err}
	}
	if len(data) > maxResponseBytes {
		return &DecodeError{Err: errors.New("the reply is too large")}
	}
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return newAPIError(response, data)
	}
	if err := json.Unmarshal(data, reply); err != nil {
		return &DecodeError{Err: err}
	}
	return nil
}

func newAPIError(response *http.Response, data []byte) *APIError {
	apiErr := &APIError{Status: response.StatusCode}
	if err := json.Unmarshal(data, &apiErr.Reply); err != nil {
		apiErr.Reply = protocol.ErrorReply{}
	}
	if seconds, err := strconv.Atoi(strings.TrimSpace(response.Header.Get("Retry-After"))); err == nil && seconds >= 0 {
		apiErr.RetryAfter = time.Duration(seconds) * time.Second
	}
	if date, err := time.Parse(http.TimeFormat, response.Header.Get("Date")); err == nil {
		apiErr.ServerDate = date
	}
	return apiErr
}
