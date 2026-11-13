package hub

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tellagen/tellagen-proxy/protocol"
)

const proxyToken = "tlg_proxy_01JD8K2A-0000.secretsecretsecret"

type staticToken struct {
	mu      sync.Mutex
	value   string
	reload  string
	reloads int
}

func (s *staticToken) Value() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.value, nil
}

func (s *staticToken) Reload() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reloads++
	if s.reload != "" {
		s.value = s.reload
	}
	return s.value, nil
}

// fakeTellagen is a Tellagen that records what it saw.
type fakeTellagen struct {
	t        *testing.T
	server   *httptest.Server
	mu       sync.Mutex
	exchange int
	expires  time.Time
	serverAt time.Time
	handle   func(w http.ResponseWriter, r *http.Request) bool
	seen     []string
}

func newFake(t *testing.T) *fakeTellagen {
	f := &fakeTellagen{t: t, expires: time.Now().Add(15 * time.Minute), serverAt: time.Now()}
	f.server = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeTellagen) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.seen = append(f.seen, r.Method+" "+r.URL.EscapedPath()+" "+r.Header.Get("Authorization"))
	handle := f.handle
	f.mu.Unlock()
	if handle != nil && handle(w, r) {
		return
	}
	if r.URL.Path == "/api/proxy/v1/session" {
		f.mu.Lock()
		f.exchange++
		n := f.exchange
		reply := protocol.SessionReply{SessionToken: protocol.SessionTokenPrefix + "s" + string(rune('0'+n)), ExpiresAt: f.expires, ServerTime: f.serverAt}
		f.mu.Unlock()
		writeJSON(w, http.StatusOK, reply)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"accepted": true, "messages": []any{}, "status": "active"})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func (f *fakeTellagen) client(token TokenSource, now func() time.Time) *Client {
	base, err := url.Parse(f.server.URL)
	if err != nil {
		f.t.Fatal(err)
	}
	return New(Config{BaseURL: base, Transport: http.DefaultTransport, Token: token, Version: "1.2.3", Now: now})
}

func TestExchangeSendsOnlyTheProxyTokenAndKeepsTheSession(t *testing.T) {
	fake := newFake(t)
	fake.serverAt = time.Now().Add(90 * time.Second)
	client := fake.client(&staticToken{value: proxyToken}, nil)

	reply, err := client.Exchange(t.Context())
	if err != nil {
		t.Fatalf("Exchange() error = %v", err)
	}
	if !strings.HasPrefix(reply.SessionToken, protocol.SessionTokenPrefix) {
		t.Errorf("session token = %q", reply.SessionToken)
	}
	if client.Generation() != 1 {
		t.Errorf("Generation() = %d, want 1", client.Generation())
	}
	if skew := client.Skew(); skew < 80*time.Second || skew > 100*time.Second {
		t.Errorf("Skew() = %s, want about 90s", skew)
	}
	if _, err := client.Poll(t.Context(), protocol.PollRequest{InstanceID: "a", Mode: protocol.PollModeLong}); err != nil {
		t.Fatalf("Poll() error = %v", err)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if got := fake.seen[0]; got != "POST /api/proxy/v1/session Bearer "+proxyToken {
		t.Errorf("exchange request = %q", got)
	}
	if got := fake.seen[1]; got != "POST /api/proxy/v1/poll Bearer "+protocol.SessionTokenPrefix+"s1" {
		t.Errorf("poll request = %q, want the session token and not the proxy token", got)
	}
}

func TestSessionIsRenewedBeforeItEnds(t *testing.T) {
	fake := newFake(t)
	now := time.Now()
	fake.expires = now.Add(15 * time.Minute)
	client := fake.client(&staticToken{value: proxyToken}, func() time.Time { return now })
	call := func() {
		t.Helper()
		if _, err := client.Poll(t.Context(), protocol.PollRequest{InstanceID: "a", Mode: protocol.PollModeLong}); err != nil {
			t.Fatalf("Poll() error = %v", err)
		}
	}
	call()
	call()
	if client.Generation() != 1 {
		t.Fatalf("Generation() = %d after two polls, want 1", client.Generation())
	}
	now = now.Add(14*time.Minute + 30*time.Second)
	fake.mu.Lock()
	fake.expires = now.Add(15 * time.Minute)
	fake.mu.Unlock()
	call()
	if client.Generation() != 2 {
		t.Errorf("Generation() = %d, want a new session within a minute of the end", client.Generation())
	}
}

func TestEndedSessionIsExchangedAgainAndTheCallRepeats(t *testing.T) {
	fake := newFake(t)
	var polls atomic.Int32
	fake.handle = func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path != "/api/proxy/v1/poll" || polls.Add(1) != 1 {
			return false
		}
		writeJSON(w, http.StatusUnauthorized, protocol.ErrorReply{Code: protocol.ErrorSessionInvalid, Message: "ended"})
		return true
	}
	client := fake.client(&staticToken{value: proxyToken}, nil)
	if _, err := client.Poll(t.Context(), protocol.PollRequest{InstanceID: "a", Mode: protocol.PollModeLong}); err != nil {
		t.Fatalf("Poll() error = %v", err)
	}
	if client.Generation() != 2 {
		t.Errorf("Generation() = %d, want 2 (a new session)", client.Generation())
	}
}

func TestRevokedTokenIsReportedAndTheTokenFileIsReadAgain(t *testing.T) {
	fake := newFake(t)
	revokedAt := time.Date(2026, 11, 4, 10, 20, 0, 0, time.UTC)
	fake.handle = func(w http.ResponseWriter, r *http.Request) bool {
		writeJSON(w, http.StatusUnauthorized, protocol.ErrorReply{Code: protocol.ErrorRevoked, Message: "revoked", RevokedAt: &revokedAt})
		return true
	}
	token := &staticToken{value: proxyToken}
	client := fake.client(token, nil)
	_, err := client.Exchange(t.Context())
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Reply.RevokedAt == nil || !apiErr.Reply.RevokedAt.Equal(revokedAt) {
		t.Fatalf("Exchange() error = %v, want the time", err)
	}
	if Classify(t.Context(), err) != KindAuth {
		t.Errorf("Classify() = %v, want KindAuth", Classify(t.Context(), err))
	}
	if token.reloads == 0 {
		t.Error("a 401 must read the token file again")
	}
}

func TestRotatedTokenFileRecoversTheExchangeInOneCall(t *testing.T) {
	fake := newFake(t)
	fake.handle = func(w http.ResponseWriter, r *http.Request) bool {
		if strings.HasSuffix(r.Header.Get("Authorization"), "old") {
			writeJSON(w, http.StatusUnauthorized, protocol.ErrorReply{Code: protocol.ErrorTokenInvalid})
			return true
		}
		return false
	}
	client := fake.client(&staticToken{value: "tlg_proxy_a.old", reload: "tlg_proxy_a.new"}, nil)
	if _, err := client.Exchange(t.Context()); err != nil {
		t.Fatalf("Exchange() error = %v, want the new token from the file to work", err)
	}
}

func TestUnreadableTokenIsAnAuthProblem(t *testing.T) {
	client := New(Config{BaseURL: &url.URL{Scheme: "https", Host: "connect.example.com"}, Token: failingToken{}, Version: "1"})
	_, err := client.Exchange(t.Context())
	if Classify(t.Context(), err) != KindAuth {
		t.Errorf("Classify(%v) = %v, want KindAuth", err, Classify(t.Context(), err))
	}
}

type failingToken struct{}

func (failingToken) Value() (string, error) {
	return "", errors.New("the secret file is missing or empty")
}
func (failingToken) Reload() (string, error) {
	return "", errors.New("the secret file is missing or empty")
}

func TestOneExchangeForConcurrentCalls(t *testing.T) {
	fake := newFake(t)
	client := fake.client(&staticToken{value: proxyToken}, nil)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = client.Poll(t.Context(), protocol.PollRequest{InstanceID: "a", Mode: protocol.PollModeLong})
		}()
	}
	wg.Wait()
	if client.Generation() != 1 {
		t.Errorf("Generation() = %d, want one exchange for concurrent calls", client.Generation())
	}
}

func TestPostResultEscapesTheCommandID(t *testing.T) {
	fake := newFake(t)
	client := fake.client(&staticToken{value: proxyToken}, nil)
	result := protocol.CommandResult{AttemptToken: "at_1", Status: protocol.StatusCancelled}
	if err := client.PostResult(t.Context(), "cmd/../01", result); err != nil {
		t.Fatalf("PostResult() error = %v", err)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if got := fake.seen[len(fake.seen)-1]; !strings.HasPrefix(got, "POST /api/proxy/v1/commands/cmd%2F..%2F01/result ") {
		t.Errorf("request = %q", got)
	}
}

func TestClassify(t *testing.T) {
	fake := newFake(t)
	status := http.StatusOK
	var body string
	fake.handle = func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path == "/api/proxy/v1/session" {
			return false
		}
		if status == http.StatusTooManyRequests {
			w.Header().Set("Retry-After", "7")
		}
		w.Header().Set("Date", "Fri, 06 Nov 2026 10:00:00 GMT")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
		return true
	}
	client := fake.client(&staticToken{value: proxyToken}, nil)
	cases := []struct {
		name   string
		status int
		body   string
		want   Kind
	}{
		{"unauthorized", 401, `{"code":"proxy_session_invalid"}`, KindAuth},
		{"forbidden", 403, `{"code":"company_disabled"}`, KindAuth},
		{"upgrade", 426, `{"code":"proxy_upgrade_required","min_version":"1.2.0"}`, KindUpgrade},
		{"rate limited", 429, ``, KindRateLimited},
		{"conflict", 409, ``, KindRefused},
		{"gone", 410, ``, KindRefused},
		{"bad request", 400, `{"code":"invalid_message"}`, KindRefused},
		{"not found", 404, ``, KindRefused},
		{"too large", 413, ``, KindRefused},
		{"inspecting proxy 504", 504, `<html>Gateway Timeout</html>`, KindCut},
		{"bad gateway", 502, ``, KindCut},
		{"redirect to a login page", 307, ``, KindCut},
		{"200 with a login page", 200, `<html>log in</html>`, KindCut},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status, body = tc.status, tc.body
			_, err := client.Poll(t.Context(), protocol.PollRequest{InstanceID: "a", Mode: protocol.PollModeLong})
			if err == nil {
				t.Fatal("Poll() error = nil")
			}
			if got := Classify(t.Context(), err); got != tc.want {
				t.Errorf("Classify(%v) = %v, want %v", err, got, tc.want)
			}
		})
	}
}

func TestAPIErrorCarriesRetryAfterAndTheServerDate(t *testing.T) {
	fake := newFake(t)
	fake.handle = func(w http.ResponseWriter, r *http.Request) bool {
		w.Header().Set("Retry-After", "12")
		w.Header().Set("Date", "Fri, 06 Nov 2026 10:00:00 GMT")
		w.WriteHeader(http.StatusTooManyRequests)
		return true
	}
	client := fake.client(&staticToken{value: proxyToken}, nil)
	_, err := client.Exchange(t.Context())
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("error = %v", err)
	}
	if apiErr.RetryAfter != 12*time.Second || !apiErr.ServerDate.Equal(time.Date(2026, 11, 6, 10, 0, 0, 0, time.UTC)) {
		t.Errorf("RetryAfter = %s, ServerDate = %s", apiErr.RetryAfter, apiErr.ServerDate)
	}
}

func TestClassifyTransportFailures(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	closed := New(Config{BaseURL: &url.URL{Scheme: "http", Host: address}, Transport: http.DefaultTransport, Token: &staticToken{value: proxyToken}, Version: "1"})
	_, err = closed.Exchange(t.Context())
	if got := Classify(t.Context(), err); got != KindUnreachable {
		t.Errorf("Classify(refused connection: %v) = %v, want KindUnreachable", err, got)
	}

	cutting := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		conn, _, _ := w.(http.Hijacker).Hijack()
		_ = conn.Close()
	}))
	defer cutting.Close()
	base, _ := url.Parse(cutting.URL)
	cut := New(Config{BaseURL: base, Transport: &http.Transport{DisableKeepAlives: true}, Token: &staticToken{value: proxyToken}, Version: "1"})
	_, err = cut.Exchange(t.Context())
	if got := Classify(t.Context(), err); got != KindCut {
		t.Errorf("Classify(closed connection: %v) = %v, want KindCut", err, got)
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if got := Classify(ctx, errors.New("anything")); got != KindStopped {
		t.Errorf("Classify(cancelled) = %v, want KindStopped", got)
	}
}
