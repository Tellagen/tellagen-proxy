// Package agent is the proxy's main loop: hello, poll, run, post the result and
// write one audit line per command. Its only listener is the health endpoint.
package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/tellagen/tellagen-proxy/internal/grafana"
	"github.com/tellagen/tellagen-proxy/internal/hub"
	"github.com/tellagen/tellagen-proxy/internal/settings"
	"github.com/tellagen/tellagen-proxy/protocol"
)

// Backend is Tellagen as the loop sees it; *hub.Client implements it.
type Backend interface {
	Hello(ctx context.Context, hello protocol.Hello) (protocol.HelloReply, error)
	Poll(ctx context.Context, request protocol.PollRequest) (protocol.PollReply, error)
	PostResult(ctx context.Context, commandID string, result protocol.CommandResult) error
	Generation() uint64
}

// Executor runs commands; the executor package implements it.
type Executor interface {
	Execute(ctx context.Context, command protocol.Command) protocol.CommandResult
	Cancel(commandID string) bool
	ApplyPolicy(update protocol.PolicyUpdate)
	FreeSlots() int
	InFlight() []protocol.InFlight
	Info() protocol.Executor
}

// Policy is the policy as it stands now.
type Policy interface {
	Revision() string
	RedactionOff() bool
	Capabilities() []protocol.Capability
	Report() protocol.PolicyReport
}

// GrafanaReader reads the few things that the hello needs from Grafana.
type GrafanaReader interface {
	Health(ctx context.Context) (grafana.Health, error)
	Datasources(ctx context.Context) ([]grafana.Datasource, error)
}

// Config holds what the loop needs. Zero values of the optional fields mean the
// defaults.
type Config struct {
	Version       string
	InstanceID    string
	InstallMethod string
	Labels        protocol.Labels
	// PublicURL is the Grafana address people open. The address the proxy uses is
	// never sent.
	PublicURL string

	Backend  Backend
	Executor Executor
	Policy   Policy
	Grafana  GrafanaReader
	// Doctor runs the short doctor for the hello. Nil sends an empty summary.
	Doctor func(ctx context.Context) protocol.Doctor
	// Secrets are the files to wait for at start.
	Secrets []*settings.Secret

	Audit  io.Writer
	Logger *slog.Logger

	FileWait          time.Duration
	CommandGrace      time.Duration
	CancelGrace       time.Duration
	GrafanaCheckEvery time.Duration

	// LookupIP resolves the public address. Nil means the system resolver.
	LookupIP func(ctx context.Context, host string) ([]netip.Addr, error)

	// Now, Sleep and Jitter exist for tests.
	Now    func() time.Time
	Sleep  func(ctx context.Context, d time.Duration) error
	Jitter func(d time.Duration) time.Duration
}

const (
	// sourceKey names the one Grafana behind a proxy.
	sourceKey = "grafana-main"

	defaultCommandGrace      = 10 * time.Second
	defaultCancelGrace       = 5 * time.Second
	defaultGrafanaCheckEvery = 5 * time.Minute

	// maxBlockedDelay bounds the wait after a credential problem. The proxy keeps
	// reading the token file, so a new token recovers it without a restart.
	maxBlockedDelay  = 5 * time.Minute
	firstBlockedWait = 5 * time.Second
	maxFailureDelay  = 30 * time.Second
	// heldLongEnough is how long a failed poll must have run for the next poll to
	// follow at once: the failure itself paced the loop.
	heldLongEnough = 5 * time.Second

	resultAttempts = 6
	helloTimeout   = 30 * time.Second
	doctorTimeout  = 25 * time.Second
)

// Agent is the proxy's main loop.
type Agent struct {
	cfg     Config
	log     *slog.Logger
	now     func() time.Time
	sleep   func(ctx context.Context, d time.Duration) error
	jitter  func(d time.Duration) time.Duration
	audit   *auditWriter
	plan    *pollPlan
	state   *state
	metrics *metrics

	// Owned by the loop goroutine.
	needHello       bool
	helloGeneration uint64
	failures        int
	blockedCount    int
	helloAsks       int

	runCtx   context.Context
	stopRun  context.CancelFunc
	postCtx  context.Context
	stopPost context.CancelFunc
	wg       sync.WaitGroup

	mu      sync.Mutex
	running map[string]struct{}
	grafana grafanaSnapshot
}

// grafanaSnapshot is the latest Grafana check.
type grafanaSnapshot struct {
	checkedAt   time.Time
	version     string
	health      string
	code        string
	message     string
	datasources []grafana.Datasource
}

// New returns an Agent.
func New(config Config) *Agent {
	a := &Agent{cfg: config, log: config.Logger, now: config.Now, sleep: config.Sleep, jitter: config.Jitter, plan: newPollPlan(), needHello: true, running: map[string]struct{}{}}
	if a.log == nil {
		a.log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if a.now == nil {
		a.now = time.Now
	}
	if a.sleep == nil {
		a.sleep = sleepContext
	}
	if a.jitter == nil {
		a.jitter = defaultJitter
	}
	if a.cfg.FileWait <= 0 {
		a.cfg.FileWait = settings.FileWait
	}
	if a.cfg.CommandGrace <= 0 {
		a.cfg.CommandGrace = defaultCommandGrace
	}
	if a.cfg.CancelGrace <= 0 {
		a.cfg.CancelGrace = defaultCancelGrace
	}
	if a.cfg.GrafanaCheckEvery <= 0 {
		a.cfg.GrafanaCheckEvery = defaultGrafanaCheckEvery
	}
	a.audit = &auditWriter{w: config.Audit}
	a.state = &state{now: a.now, version: config.Version, mode: protocol.PollModeLong}
	a.metrics = newMetrics(config.Version, a.state)
	a.metrics.setMode(protocol.PollModeLong)
	a.runCtx, a.stopRun = context.WithCancel(context.Background())
	a.postCtx, a.stopPost = context.WithCancel(context.Background())
	return a
}

// Run serves the health endpoint on listener and runs the loop until ctx ends,
// then lets running commands finish or cancels them. An error means the proxy
// could not start: a secret file never appeared, or the health endpoint failed.
func (a *Agent) Run(ctx context.Context, listener net.Listener) error {
	loopCtx, stop := context.WithCancel(ctx)
	defer stop()
	healthDone := make(chan error, 1)
	go func() {
		err := serveHealth(loopCtx, listener, healthHandler(a.state, a.metrics))
		if err != nil {
			stop()
		}
		healthDone <- err
	}()

	runErr := a.start(loopCtx)
	if runErr == nil {
		for loopCtx.Err() == nil {
			a.cycle(loopCtx)
		}
		a.drain()
	}
	stop()
	healthErr := <-healthDone
	switch {
	case runErr != nil:
		return runErr
	case healthErr != nil:
		return fmt.Errorf("health endpoint: %w", healthErr)
	}
	return nil
}

func (a *Agent) start(ctx context.Context) error {
	var lastLogged time.Time
	err := settings.WaitForFiles(ctx, a.cfg.FileWait, a.cfg.Secrets, func(missing []string) {
		a.state.setWaiting(missing)
		if lastLogged.IsZero() || a.now().Sub(lastLogged) >= 15*time.Second {
			lastLogged = a.now()
			a.log.Info("waiting for secret files that are not there yet", "files", missing)
		}
	})
	if err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return err
	}
	a.state.setWaiting(nil)
	go a.watchGrafana(ctx)
	return nil
}

// cycle runs one step of the loop: a hello when one is due, then one poll.
func (a *Agent) cycle(ctx context.Context) {
	if a.needHello || a.cfg.Backend.Generation() != a.helloGeneration {
		if !a.hello(ctx) {
			return
		}
	}
	waitMS, mode, gap := a.plan.next(a.now())
	a.state.setMode(mode, a.plan.step != stepLong)
	a.metrics.setMode(mode)

	request := protocol.PollRequest{
		InstanceID:            a.cfg.InstanceID,
		WaitMS:                waitMS,
		Mode:                  mode,
		FreeSlots:             a.cfg.Executor.FreeSlots(),
		AppliedPolicyRevision: a.cfg.Policy.Revision(),
		InFlight:              a.cfg.Executor.InFlight(),
		SourcesHealth:         a.sourcesHealth(),
	}
	started := a.now()
	reply, err := a.cfg.Backend.Poll(ctx, request)
	if err != nil {
		a.failed(ctx, err, a.now().Sub(started), true)
		return
	}
	a.plan.success()
	a.recovered()
	a.dispatch(reply.Messages)
	if gap > 0 {
		_ = a.sleep(ctx, a.jitter(gap))
	}
}

// hello sends the hello and reports whether it worked.
func (a *Agent) hello(ctx context.Context) bool {
	message := a.buildHello(ctx)
	helloCtx, cancel := context.WithTimeout(ctx, helloTimeout)
	defer cancel()
	started := a.now()
	reply, err := a.cfg.Backend.Hello(helloCtx, message)
	if err != nil {
		a.failed(ctx, err, a.now().Sub(started), false)
		return false
	}
	if reply.Status != "" && reply.Status != protocol.HelloStatusActive {
		a.block(ctx, fmt.Sprintf("Tellagen reports this proxy as %q, not active. Check the proxy in Settings.", reply.Status))
		return false
	}
	a.needHello = false
	a.helloGeneration = a.cfg.Backend.Generation()
	a.plan.setBase(reply.Poll.WaitMS)
	if reply.Policy != nil {
		a.cfg.Executor.ApplyPolicy(*reply.Policy)
	}
	a.state.contact()
	a.log.Info("connected to Tellagen", "protocol_version", reply.ProtocolVersion, "wait_ms", a.plan.baseWaitMS)
	return true
}

func (a *Agent) buildHello(ctx context.Context) protocol.Hello {
	capabilities := a.cfg.Policy.Capabilities()
	digest, err := protocol.CapabilitiesDigest(capabilities)
	if err != nil {
		a.log.Error("cannot compute the capabilities digest", "error", err)
	}
	hello := protocol.Hello{
		Schema:             protocol.SchemaHello,
		ProxyVersion:       a.cfg.Version,
		ProtocolVersions:   []string{protocol.ProtocolVersion},
		InstanceID:         a.cfg.InstanceID,
		InstallMethod:      a.cfg.InstallMethod,
		Labels:             a.cfg.Labels,
		Capabilities:       capabilities,
		CapabilitiesDigest: digest,
		PolicyRevision:     a.cfg.Policy.Revision(),
		Policy:             a.cfg.Policy.Report(),
		Executor:           a.cfg.Executor.Info(),
	}
	if a.cfg.Doctor != nil {
		doctorCtx, cancel := context.WithTimeout(ctx, doctorTimeout)
		hello.Doctor = a.cfg.Doctor(doctorCtx)
		cancel()
	}
	hello.Sources = a.sources(ctx, hello.Policy.DatasourceUIDs)
	return hello
}

// dispatch acts on the messages of one poll reply.
func (a *Agent) dispatch(messages []protocol.PollMessage) {
	for _, message := range messages {
		switch {
		case message.Command != nil:
			a.startCommand(*message.Command)
		case message.Cancel != nil:
			stopped := a.cfg.Executor.Cancel(message.Cancel.CommandID)
			a.log.Info("cancel received", "command_id", message.Cancel.CommandID, "reason", message.Cancel.Reason, "was_running", stopped)
		case message.PolicyUpdate != nil:
			a.cfg.Executor.ApplyPolicy(*message.PolicyUpdate)
			// The hello reports which settings the policy file stopped.
			a.needHello = true
			a.log.Info("policy update applied", "revision", message.PolicyUpdate.Revision)
		}
	}
}

// failed decides what a failed call means and waits before the next try.
func (a *Agent) failed(ctx context.Context, err error, elapsed time.Duration, isPoll bool) {
	kind := hub.Classify(ctx, err)
	if kind == hub.KindStopped {
		return
	}
	a.state.setError(describeError(err))
	switch kind {
	case hub.KindAuth, hub.KindUpgrade:
		if a.helloRequired(err) {
			return
		}
		a.metrics.reconnects.WithLabelValues("auth").Inc()
		a.block(ctx, authMessage(err))
	case hub.KindRefused:
		a.metrics.reconnects.WithLabelValues("refused").Inc()
		a.failures++
		a.log.Error("Tellagen refused a request", "error", err, "failures", a.failures)
		_ = a.sleep(ctx, a.jitter(failureDelay(0, a.failures)))
	case hub.KindRateLimited:
		a.metrics.reconnects.WithLabelValues("rate_limited").Inc()
		delay := retryAfter(err)
		a.log.Warn("Tellagen asked the proxy to slow down", "retry_after", delay.String())
		_ = a.sleep(ctx, delay)
	case hub.KindUnreachable:
		a.metrics.reconnects.WithLabelValues("unreachable").Inc()
		a.failures++
		a.log.Warn("cannot reach Tellagen", "error", err, "failures", a.failures)
		_ = a.sleep(ctx, a.jitter(failureDelay(0, a.failures)))
	default:
		a.metrics.reconnects.WithLabelValues("cut").Inc()
		a.failures++
		if isPoll {
			a.plan.cut(a.now())
		}
		a.log.Warn("a request to Tellagen did not complete", "error", err, "held", elapsed.Round(time.Millisecond).String(), "failures", a.failures)
		if delay := failureDelay(elapsed, a.failures); delay > 0 {
			_ = a.sleep(ctx, a.jitter(delay))
		}
	}
}

// maxHelloAsks is how many times in a row Tellagen may ask for a new hello before
// the proxy treats it as a credential problem.
const maxHelloAsks = 3

// helloRequired handles a 401 that says the session has no hello. That follows a
// Tellagen restart or a session that ended, and a new hello fixes it.
func (a *Agent) helloRequired(err error) bool {
	var apiErr *hub.APIError
	if !errors.As(err, &apiErr) || apiErr.Reply.Code != protocol.ErrorSessionInvalid || a.helloAsks >= maxHelloAsks {
		return false
	}
	a.helloAsks++
	a.needHello = true
	a.log.Info("Tellagen asked the proxy to say hello again")
	return true
}

// block records a credential or version problem and waits with a growing delay.
// The loop tries again, because the token file may hold a new token by then.
func (a *Agent) block(ctx context.Context, reason string) {
	a.state.setBlocked(reason)
	a.needHello = true
	delay := min(firstBlockedWait<<min(a.blockedCount, 6), maxBlockedDelay)
	a.blockedCount++
	a.log.Error(reason, "next_try_in", delay.String())
	_ = a.sleep(ctx, a.jitter(delay))
}

// recovered clears the failure counters after a good answer from Tellagen.
func (a *Agent) recovered() {
	if a.failures > 0 || a.blockedCount > 0 {
		a.log.Info("Tellagen answers again")
	}
	a.failures, a.blockedCount, a.helloAsks = 0, 0, 0
	a.state.contact()
}

// failureDelay is the pause after a failed call. A poll that was held for a while
// before it failed paced the loop itself, so the next one follows at once.
func failureDelay(elapsed time.Duration, failures int) time.Duration {
	if elapsed >= heldLongEnough {
		return 0
	}
	return min(time.Second<<min(max(failures-1, 0), 5), maxFailureDelay)
}

func sleepContext(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// defaultJitter spreads a delay by up to 20% either way, so many proxies that
// failed together do not retry together.
func defaultJitter(d time.Duration) time.Duration {
	if d <= 0 {
		return d
	}
	spread := float64(d) * 0.2
	return d + time.Duration((rand.Float64()*2-1)*spread)
}
