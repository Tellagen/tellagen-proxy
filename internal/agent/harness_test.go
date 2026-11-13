package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/tellagen/tellagen-proxy/internal/settings"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tellagen/tellagen-proxy/internal/grafana"
	"github.com/tellagen/tellagen-proxy/internal/hub"
	"github.com/tellagen/tellagen-proxy/protocol"
)

// syncBuffer is a bytes.Buffer that tests can read while the agent writes.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// fakeBackend is a scripted Tellagen. A poll beyond the script holds until the
// context ends, as a long poll does.
type fakeBackend struct {
	mu         sync.Mutex
	hellos     []protocol.Hello
	polls      []protocol.PollRequest
	results    map[string][]protocol.CommandResult
	postCalls  map[string]int
	generation atomic.Uint64

	helloFn func(n int, hello protocol.Hello) (protocol.HelloReply, error)
	pollFn  func(n int, request protocol.PollRequest) (protocol.PollReply, error, bool)
	postFn  func(id string, call int) error
}

func newBackend() *fakeBackend {
	return &fakeBackend{results: map[string][]protocol.CommandResult{}, postCalls: map[string]int{}}
}

func (b *fakeBackend) Generation() uint64 { return b.generation.Load() }

func (b *fakeBackend) Hello(_ context.Context, hello protocol.Hello) (protocol.HelloReply, error) {
	b.mu.Lock()
	b.hellos = append(b.hellos, hello)
	n := len(b.hellos)
	fn := b.helloFn
	b.mu.Unlock()
	if b.generation.Load() == 0 {
		b.generation.Store(1)
	}
	if fn != nil {
		return fn(n, hello)
	}
	return protocol.HelloReply{ProtocolVersion: "1", Status: protocol.HelloStatusActive, Poll: protocol.PollSettings{WaitMS: 25_000}}, nil
}

func (b *fakeBackend) Poll(ctx context.Context, request protocol.PollRequest) (protocol.PollReply, error) {
	b.mu.Lock()
	b.polls = append(b.polls, request)
	n := len(b.polls)
	fn := b.pollFn
	b.mu.Unlock()
	if fn != nil {
		if reply, err, ok := fn(n, request); ok {
			return reply, err
		}
	}
	<-ctx.Done()
	return protocol.PollReply{}, ctx.Err()
}

func (b *fakeBackend) PostResult(_ context.Context, id string, result protocol.CommandResult) error {
	b.mu.Lock()
	b.postCalls[id]++
	call := b.postCalls[id]
	fn := b.postFn
	b.mu.Unlock()
	if fn != nil {
		if err := fn(id, call); err != nil {
			return err
		}
	}
	b.mu.Lock()
	b.results[id] = append(b.results[id], result)
	b.mu.Unlock()
	return nil
}

func (b *fakeBackend) pollCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.polls)
}

func (b *fakeBackend) helloCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.hellos)
}

func (b *fakeBackend) poll(i int) protocol.PollRequest {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.polls[i]
}

func (b *fakeBackend) resultsOf(id string) []protocol.CommandResult {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]protocol.CommandResult(nil), b.results[id]...)
}

// script returns a pollFn that answers the first polls from steps and then holds.
func script(steps ...pollStepResult) func(int, protocol.PollRequest) (protocol.PollReply, error, bool) {
	return func(n int, _ protocol.PollRequest) (protocol.PollReply, error, bool) {
		if n > len(steps) {
			return protocol.PollReply{}, nil, false
		}
		return steps[n-1].reply, steps[n-1].err, true
	}
}

type pollStepResult struct {
	reply protocol.PollReply
	err   error
}

func cutError() error {
	return &hub.TransportError{Err: io.ErrUnexpectedEOF}
}

func commandMessage(id string, attempt int) protocol.PollMessage {
	args, _ := json.Marshal(protocol.PrometheusQueryRangeArgs{
		DatasourceUID: "prom-prod",
		Expr:          `sum(rate(http_requests_total{service="checkout"}[5m]))`,
		Start:         time.Date(2026, 11, 6, 9, 0, 0, 0, time.UTC),
		End:           time.Date(2026, 11, 6, 10, 0, 0, 0, time.UTC),
		StepS:         30,
	})
	return protocol.PollMessage{Command: &protocol.Command{
		CommandID:         id,
		Attempt:           attempt,
		AttemptToken:      "at_" + id,
		RunID:             "inv_8f1",
		IncidentRef:       "INC-142",
		Initiator:         protocol.Initiator{Kind: protocol.InitiatorUser, ID: "u_311"},
		Capability:        protocol.CapabilityPrometheusQueryRange,
		CapabilityVersion: 1,
		Args:              args,
		DeadlineMS:        20_000,
		LeaseMS:           30_000,
	}}
}

// fakeExecutor runs commands from a function.
type fakeExecutor struct {
	mu       sync.Mutex
	executed []string
	cancels  []string
	updates  []protocol.PolicyUpdate
	inFlight []protocol.InFlight
	cancelCh map[string]chan struct{}

	run   func(ctx context.Context, command protocol.Command) protocol.CommandResult
	slots int
}

func newExecutor() *fakeExecutor {
	return &fakeExecutor{slots: 2, cancelCh: map[string]chan struct{}{}}
}

func (e *fakeExecutor) Execute(ctx context.Context, command protocol.Command) protocol.CommandResult {
	e.mu.Lock()
	e.executed = append(e.executed, command.CommandID)
	run := e.run
	e.mu.Unlock()
	if run != nil {
		return run(ctx, command)
	}
	return protocol.CommandResult{
		Status: protocol.StatusOK,
		Data: &protocol.ResultData{Kind: protocol.DataMatrix, SeriesTotal: 1, Series: []protocol.Series{
			{Labels: map[string]string{"service": "checkout"}, Values: []*float64{ptr(1), ptr(2), nil}},
		}},
		Bytes: 120, Redactions: 2, RedactionsByKind: map[string]int{"bearer": 2}, QueryFingerprint: "sha256:77d0",
	}
}

func ptr(v float64) *float64 { return &v }

func (e *fakeExecutor) Cancel(id string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.cancels = append(e.cancels, id)
	return true
}

func (e *fakeExecutor) ApplyPolicy(update protocol.PolicyUpdate) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.updates = append(e.updates, update)
}

func (e *fakeExecutor) FreeSlots() int { return e.slots }

func (e *fakeExecutor) InFlight() []protocol.InFlight {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]protocol.InFlight(nil), e.inFlight...)
}

func (e *fakeExecutor) Info() protocol.Executor {
	return protocol.Executor{Kind: "grafana-mcp", Version: "v2.2.0", Mode: "in-process"}
}

func (e *fakeExecutor) executedIDs() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.executed...)
}

func (e *fakeExecutor) cancelled() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.cancels...)
}

type fakePolicy struct {
	mu        sync.Mutex
	revision  string
	redaction bool
	report    protocol.PolicyReport
}

func (p *fakePolicy) Revision() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.revision
}

func (p *fakePolicy) RedactionOff() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.redaction
}

func (p *fakePolicy) Capabilities() []protocol.Capability {
	return []protocol.Capability{{Name: protocol.CapabilityPrometheusQueryRange, Version: 1, Limits: protocol.Limits{MaxRangeS: 86_400, MaxPoints: 500}}}
}

func (p *fakePolicy) Report() protocol.PolicyReport {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.report
}

type fakeGrafana struct {
	mu          sync.Mutex
	err         error
	datasources []grafana.Datasource
	checks      int
}

func (g *fakeGrafana) Health(context.Context) (grafana.Health, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.checks++
	if g.err != nil {
		return grafana.Health{}, g.err
	}
	return grafana.Health{Version: "12.2.1"}, nil
}

func (g *fakeGrafana) Datasources(context.Context) ([]grafana.Datasource, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.datasources, nil
}

// clock is a controllable time source.
type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// harness runs an Agent against the fakes.
type harness struct {
	t        *testing.T
	backend  *fakeBackend
	executor *fakeExecutor
	policy   *fakePolicy
	grafana  *fakeGrafana
	audit    *syncBuffer
	clock    *clock
	agent    *Agent
	address  string
	cancel   context.CancelFunc
	done     chan error

	mu     sync.Mutex
	sleeps []time.Duration
	// holdLong, when set, blocks every sleep of 5 s or more until it is closed, so
	// a test can look at the state during a long wait.
	holdLong chan struct{}
}

func newHarness(t *testing.T, mutate func(*Config)) *harness {
	t.Helper()
	h := &harness{
		t:        t,
		backend:  newBackend(),
		executor: newExecutor(),
		policy:   &fakePolicy{revision: "sha256:41ab"},
		grafana: &fakeGrafana{datasources: []grafana.Datasource{
			{UID: "prom-prod", Name: "Prometheus prod", Type: "prometheus", Default: true},
			{UID: "loki-prod", Name: "Loki prod", Type: "loki"},
		}},
		audit: &syncBuffer{},
		clock: &clock{now: time.Date(2026, 11, 6, 10, 0, 0, 0, time.UTC)},
		done:  make(chan error, 1),
	}
	config := Config{
		Version:           "1.0.0",
		InstanceID:        "tellagen-proxy-7c9f-xk2p",
		InstallMethod:     "helm",
		Labels:            protocol.Labels{"env": "production"},
		PublicURL:         "https://grafana.customerdomain.net",
		Backend:           h.backend,
		Executor:          h.executor,
		Policy:            h.policy,
		Grafana:           h.grafana,
		Audit:             h.audit,
		Logger:            slog.New(slog.NewTextHandler(io.Discard, nil)),
		FileWait:          time.Second,
		CommandGrace:      200 * time.Millisecond,
		CancelGrace:       time.Second,
		GrafanaCheckEvery: time.Hour,
		Now:               h.clock.Now,
		Sleep: func(ctx context.Context, d time.Duration) error {
			h.mu.Lock()
			h.sleeps = append(h.sleeps, d)
			hold := h.holdLong
			h.mu.Unlock()
			if hold != nil && d >= 5*time.Second {
				select {
				case <-hold:
				case <-ctx.Done():
				}
			}
			return ctx.Err()
		},
		Jitter: func(d time.Duration) time.Duration { return d },
		LookupIP: func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("203.0.113.9")}, nil
		},
	}
	if mutate != nil {
		mutate(&config)
	}
	h.agent = New(config)
	return h
}

func (h *harness) start() {
	h.t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		h.t.Fatal(err)
	}
	h.address = listener.Addr().String()
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	go func() { h.done <- h.agent.Run(ctx, listener) }()
	h.t.Cleanup(func() {
		cancel()
		select {
		case err := <-h.done:
			_ = err
		case <-time.After(10 * time.Second):
			h.t.Error("the agent did not stop")
		}
	})
}

// stop ends the agent and returns what Run returned.
func (h *harness) stop() error {
	h.t.Helper()
	h.cancel()
	select {
	case err := <-h.done:
		h.done <- err
		return err
	case <-time.After(10 * time.Second):
		h.t.Fatal("the agent did not stop")
		return nil
	}
}

func (h *harness) sleepsSnapshot() []time.Duration {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]time.Duration(nil), h.sleeps...)
}

func waitFor(t *testing.T, what string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func (h *harness) get(path string) (int, string) {
	h.t.Helper()
	response, err := http.Get("http://" + h.address + path)
	if err != nil {
		h.t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	body, _ := io.ReadAll(response.Body)
	return response.StatusCode, string(body)
}

// status reads what /readyz reports.
func (h *harness) status() Status {
	h.t.Helper()
	_, body := h.get("/readyz")
	var status Status
	if err := json.Unmarshal([]byte(body), &status); err != nil {
		h.t.Fatalf("/readyz body %q: %v", body, err)
	}
	return status
}

var errPost = errors.New("connection reset")

func newFileSecret(t *testing.T, path string) *settings.Secret {
	t.Helper()
	env := settings.Environment{
		Getenv: func(name string) string {
			return map[string]string{
				"TELLAGEN_PROXY_TOKEN_FILE":          path,
				"GRAFANA_URL":                        "https://grafana.example.com",
				"GRAFANA_SERVICE_ACCOUNT_TOKEN":      "glsa_x",
				"TELLAGEN_PROXY_TOKEN_UNUSED_MARKER": "",
			}[name]
		},
		ReadFile: os.ReadFile,
		Now:      time.Now,
	}
	s, err := settings.Load(env)
	if err != nil {
		t.Fatal(err)
	}
	return s.Token
}
