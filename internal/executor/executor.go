// Package executor runs typed capabilities against Grafana through the grafana-mcp
// code linked into the binary, with no MCP server, subprocess or listener. Results
// are reduced and redacted before they leave.
package executor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	mcpgrafana "github.com/grafana/mcp-grafana/v2"
	"github.com/grafana/mcp-grafana/v2/tools"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/prometheus/prometheus/model/labels"

	"github.com/tellagen/tellagen-proxy/internal/guard"
	"github.com/tellagen/tellagen-proxy/internal/policy"
	"github.com/tellagen/tellagen-proxy/internal/reduce"
	"github.com/tellagen/tellagen-proxy/protocol"
)

// Config holds what the executor needs from the proxy's settings.
type Config struct {
	// GrafanaURL is the address the proxy uses. It is never sent to Tellagen.
	GrafanaURL string
	// PublicURL is the address people open, used for links. Empty means no links.
	PublicURL string
	// OrgID selects a Grafana org when it is above zero.
	OrgID int64
	// Token returns the Grafana token. It is called for each Grafana call.
	Token func() (string, error)
	// Transport carries the Grafana traffic, with any company CA or proxy already
	// set on it. Nil means a direct connection with the system roots.
	Transport *http.Transport
	// Policy holds the local policy file and the narrowing from Tellagen.
	Policy *policy.Engine
}

// Executor runs commands. It is safe for concurrent use.
type Executor struct {
	config   Config
	base     *url.URL
	next     http.RoundTripper
	policy   *policy.Engine
	slots    chan struct{}
	matchers []*labels.Matcher
	runs     *runCounter
	lookups  *runCounter

	mu      sync.Mutex
	running map[string]*runningCommand
}

type runningCommand struct {
	attempt    int
	datasource string
	startedAt  time.Time
	cancel     context.CancelFunc
}

// New checks the tools against the lock file and returns an Executor. An error
// means the proxy must not start. It makes no network call, so a Grafana that is
// down shows in the hello and in doctor instead of crash-looping the proxy.
func New(config Config) (*Executor, error) {
	lock, err := loadToolsLock()
	if err != nil {
		return nil, err
	}
	if err := verifyTools(allowedTools, lock, grafanaMCPVersion); err != nil {
		return nil, err
	}
	return newExecutor(config)
}

func newExecutor(config Config) (*Executor, error) {
	base, err := url.Parse(strings.TrimRight(config.GrafanaURL, "/"))
	if err != nil || base.Host == "" || (base.Scheme != "http" && base.Scheme != "https") {
		return nil, errors.New("the Grafana address must be an http or https URL")
	}
	if config.Token == nil || config.Policy == nil {
		return nil, errors.New("the executor needs a token source and a policy")
	}
	var matchers []*labels.Matcher
	file := config.Policy.File()
	for _, spec := range file.EnforcedMatchers {
		parsed, err := tools.ParseEnforcedMatchers(spec)
		if err != nil {
			return nil, fmt.Errorf("logs.enforcedMatchers: %w", err)
		}
		matchers = append(matchers, parsed...)
	}
	next := http.RoundTripper(config.Transport)
	if config.Transport == nil {
		direct := http.DefaultTransport.(*http.Transport).Clone()
		direct.Proxy = nil
		next = direct
	}
	return &Executor{
		config:   config,
		base:     base,
		next:     next,
		policy:   config.Policy,
		slots:    make(chan struct{}, file.MaxConcurrent),
		matchers: matchers,
		runs:     newRunCounter(),
		lookups:  newRunCounter(),
		running:  map[string]*runningCommand{},
	}, nil
}

// Info says what runs the capabilities, for the hello.
func (e *Executor) Info() protocol.Executor {
	return protocol.Executor{Kind: "grafana-mcp", Version: grafanaMCPVersion, Mode: "in-process"}
}

// FreeSlots returns how many more commands can run at once, for the poll.
func (e *Executor) FreeSlots() int {
	return cap(e.slots) - len(e.slots)
}

// InFlight lists the running commands, for the poll.
func (e *Executor) InFlight() []protocol.InFlight {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]protocol.InFlight, 0, len(e.running))
	for id, command := range e.running {
		out = append(out, protocol.InFlight{CommandID: id, Attempt: command.attempt, ElapsedMS: int(time.Since(command.startedAt) / time.Millisecond)})
	}
	return out
}

// Cancel stops a running command. It reports whether the command was running.
func (e *Executor) Cancel(commandID string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	command, ok := e.running[commandID]
	if ok {
		command.cancel()
	}
	return ok
}

// ApplyPolicy applies an update from Tellagen. A datasource that was switched off
// stops here, including a query that is running for a diagnosis.
func (e *Executor) ApplyPolicy(update protocol.PolicyUpdate) {
	view := e.policy.Apply(update)
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, command := range e.running {
		if command.datasource != "" && !view.DatasourceAllowed(command.datasource) {
			command.cancel()
		}
	}
}

// Execute runs one command and always returns a result to post back.
func (e *Executor) Execute(ctx context.Context, command protocol.Command) protocol.CommandResult {
	started := time.Now()
	result := e.execute(ctx, command)
	result.AttemptToken = command.AttemptToken
	result.DurationMS = int(time.Since(started) / time.Millisecond)
	return result
}

func (e *Executor) execute(ctx context.Context, command protocol.Command) protocol.CommandResult {
	view := e.policy.Current()
	p, limits, refused := e.admit(view, command)
	if refused != nil {
		return *refused
	}

	timeout := time.Duration(limits.TimeoutMS) * time.Millisecond
	if command.DeadlineMS > 0 {
		timeout = min(timeout, time.Duration(command.DeadlineMS)*time.Millisecond)
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	p.started = time.Now()
	p.deadline, _ = ctx.Deadline()

	if command.CommandID != "" {
		defer e.track(command, p.datasource, cancel)()
	}

	select {
	case e.slots <- struct{}{}:
		defer func() { <-e.slots }()
	case <-ctx.Done():
		return contextResult(ctx)
	}

	call := func(tool *mcpgrafana.Tool, toolArgs any) (string, *callFailure) {
		return e.callTool(ctx, limits, tool, toolArgs)
	}
	data, skipped, truncated, failure := p.run(call)
	if ctx.Err() != nil && !(p.baseDone && failure == nil && errors.Is(ctx.Err(), context.DeadlineExceeded)) {
		return contextResult(ctx)
	}
	if failure != nil {
		result := failure.result()
		e.policy.Current().Redactor().Result(&result)
		return result
	}
	return e.finish(command, p, limits, data, skipped, truncated)
}

// admit checks a command against the policy and the per-run counters before any
// Grafana call. A non-nil result is the answer to send back.
func (e *Executor) admit(view *policy.View, command protocol.Command) (*plan, protocol.Limits, *protocol.CommandResult) {
	refuse := func(result protocol.CommandResult) (*plan, protocol.Limits, *protocol.CommandResult) {
		return nil, protocol.Limits{}, &result
	}
	capability, known := capabilityVersions[command.Capability]
	if !known || !view.CapabilityAllowed(command.Capability) {
		return refuse(rejectedResult(protocol.CodePolicyCapabilityDisabled, fmt.Sprintf("capability %q is not enabled on this proxy", command.Capability)))
	}
	if command.CapabilityVersion != capability {
		return refuse(rejectedResult(protocol.CodePolicyCapabilityDisabled, fmt.Sprintf("this proxy has version %d of %s, not version %d", capability, command.Capability, command.CapabilityVersion)))
	}
	args, err := protocol.ParseArgs(command.Capability, command.Args)
	if err != nil {
		return refuse(rejectedResult(protocol.CodeQueryGuardFailed, err.Error()))
	}

	limits := view.Limits(command.Capability, command.Limits)
	p, rejection := e.prepare(view, command.Capability, args, limits)
	if rejection != nil {
		return refuse(rejectionResult(rejection))
	}
	if p.datasource != "" && !view.DatasourceAllowed(p.datasource) {
		return refuse(rejectedResult(protocol.CodePolicyDatasourceNotAllowed, fmt.Sprintf("datasource %q is not allowed on this proxy", p.datasource)))
	}
	if protocol.IsDiscoveryCapability(command.Capability) {
		if !e.lookups.admit(command.RunID, command.CommandID, view.MaxListCommandsPerRun()) {
			return refuse(rejectedResult(protocol.CodeQueryGuardFailed, fmt.Sprintf("this run has used its %d list and search calls. Query what it already found", view.MaxListCommandsPerRun())))
		}
	} else if !e.runs.admit(command.RunID, command.CommandID, view.MaxCommandsPerRun()) {
		return refuse(rejectedResult(protocol.CodeQueryGuardFailed, fmt.Sprintf("this run has used its %d queries. Conclude with what the run already has", view.MaxCommandsPerRun())))
	}
	return p, limits, nil
}

// finish turns what a plan read into the result that leaves the proxy: redacted,
// cut to the limits and fitted to the byte budget.
func (e *Executor) finish(command protocol.Command, p *plan, limits protocol.Limits, data *protocol.ResultData, skipped []string, truncated bool) protocol.CommandResult {
	// The policy may have changed during the call, so the datasource and the rules
	// that apply are those of now.
	view := e.policy.Current()
	if p.datasource != "" && !view.DatasourceAllowed(p.datasource) {
		return protocol.CommandResult{Status: protocol.StatusCancelled}
	}
	logLinesOff := min(view.LogLines(), limits.MaxLines) <= 0
	if p.logQuery != nil && logLinesOff {
		if rejection := p.logQuery.RefuseLogText(); rejection != nil {
			return rejectionResult(rejection)
		}
		data.Lines = nil
	}
	result := protocol.CommandResult{
		Status:           protocol.StatusOK,
		Data:             data,
		Skipped:          skipped,
		QueryFingerprint: p.fingerprint(command.Capability),
		ExecutedVia:      "grafana-mcp:" + p.tool + "@" + grafanaMCPVersion,
		DeepLink:         p.deepLink(e.config.PublicURL, e.config.OrgID),
	}
	if len(skipped) > 0 {
		result.Status = protocol.StatusPartial
	}
	view.Redactor().Result(&result)
	reduce.NormalizePatterns(result.Data)
	cut := reduce.CutLines(result.Data, limits.MaxLineChars)
	if p.logQuery != nil {
		maxLabelChars := limits.MaxLineChars
		if logLinesOff {
			maxLabelChars = reduce.MaxLabelCharsWithoutLogLines
		}
		cut = reduce.CutLabels(result.Data, maxLabelChars) || cut
	}
	size, dropped, err := reduce.Fit(result.Data, limits.MaxResultBytes)
	if err != nil {
		return errorResult(protocol.CodeSourceUnavailable, "the result could not be encoded", false)
	}
	result.Bytes = size
	result.Truncated = truncated || cut || dropped
	return result
}

// track records a running command and returns the func that forgets it. A second
// attempt of a command replaces the first, which is stale.
func (e *Executor) track(command protocol.Command, datasource string, cancel context.CancelFunc) func() {
	entry := &runningCommand{attempt: command.Attempt, datasource: datasource, startedAt: time.Now(), cancel: cancel}
	e.mu.Lock()
	defer e.mu.Unlock()
	if previous, ok := e.running[command.CommandID]; ok {
		previous.cancel()
	}
	e.running[command.CommandID] = entry
	return func() {
		e.mu.Lock()
		defer e.mu.Unlock()
		if e.running[command.CommandID] == entry {
			delete(e.running, command.CommandID)
		}
	}
}

// callFailure is one tool call that did not give a usable answer.
type callFailure struct {
	status    string
	code      string
	message   string
	retryable bool
	hint      *protocol.Limits
}

func (f *callFailure) result() protocol.CommandResult {
	return protocol.CommandResult{
		Status: f.status,
		Error:  &protocol.ResultError{Code: f.code, Message: f.message, Retryable: f.retryable, Hint: f.hint},
	}
}

func rejectedResult(code, message string) protocol.CommandResult {
	return protocol.CommandResult{Status: protocol.StatusRejected, Error: &protocol.ResultError{Code: code, Message: message}}
}

func rejectionResult(rejection *guard.Rejection) protocol.CommandResult {
	return protocol.CommandResult{Status: protocol.StatusRejected, Error: &protocol.ResultError{Code: rejection.Code, Message: rejection.Message, Hint: rejection.Hint}}
}

func errorResult(code, message string, retryable bool) protocol.CommandResult {
	return protocol.CommandResult{Status: protocol.StatusError, Error: &protocol.ResultError{Code: code, Message: message, Retryable: retryable}}
}

func contextResult(ctx context.Context) protocol.CommandResult {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return errorResult(protocol.CodeTimeout, "the query did not finish in time. Narrow its range or series", true)
	}
	return protocol.CommandResult{Status: protocol.StatusCancelled}
}

func (e *Executor) newTransport() *readOnlyTransport {
	return &readOnlyTransport{next: e.next, scheme: e.base.Scheme, host: e.base.Host, queryPath: e.base.Path + "/api/ds/query"}
}

// clientMu guards building a Grafana client: the generated OpenAPI client writes a
// package-level variable each time it builds one.
var clientMu sync.Mutex

// callTool runs one grafana-mcp handler with its own context, token and limits. It
// builds no server and opens no port.
func (e *Executor) callTool(ctx context.Context, limits protocol.Limits, tool *mcpgrafana.Tool, args any) (string, *callFailure) {
	token, err := e.config.Token()
	if err != nil {
		return "", &callFailure{status: protocol.StatusError, code: protocol.CodeAuthFailed, message: "the proxy could not read its Grafana token", retryable: true}
	}
	encoded, err := json.Marshal(args)
	if err != nil {
		return "", &callFailure{status: protocol.StatusError, code: protocol.CodeSourceUnavailable, message: "the query could not be encoded"}
	}

	transport := e.newTransport()
	config := mcpgrafana.GrafanaConfig{
		URL:                            e.base.String(),
		APIKey:                         token,
		OrgID:                          e.config.OrgID,
		Timeout:                        time.Duration(limits.TimeoutMS) * time.Millisecond,
		Logger:                         slog.New(slog.NewTextHandler(io.Discard, nil)),
		BaseTransport:                  transport,
		MaxLokiLogLimit:                max(limits.MaxLines, 1),
		LokiEnforcedMatchers:           e.matchers,
		LokiGuardrailMode:              mcpgrafana.LokiGuardrailEnforce,
		LokiGuardrailMaxRange:          time.Duration(limits.MaxRangeS) * time.Second,
		LokiGuardrailMaxBytes:          e.policy.File().MaxScanBytes,
		LokiGuardrailOnEstimateFailure: mcpgrafana.LokiGuardrailFailureBlock,
		PrometheusGuardrailMode:        mcpgrafana.PrometheusGuardrailEnforce,
		PrometheusGuardrailMaxRange:    time.Duration(limits.MaxRangeS) * time.Second,
		PrometheusGuardrailMaxPoints:   int64(limits.MaxPoints),
	}
	toolContext := mcpgrafana.WithGrafanaConfig(ctx, config)
	clientMu.Lock()
	client := mcpgrafana.NewGrafanaClient(toolContext, config.URL, token, nil)
	clientMu.Unlock()
	// With these two set the library never fetches its settings over its own
	// default transport, which would skip the read-only transport above.
	client.PublicURL = config.URL
	client.Version = "unknown"
	toolContext = mcpgrafana.WithGrafanaClient(toolContext, client)

	text, isError, err := callHandler(toolContext, tool, encoded)
	seen := transport.outcome()
	if err != nil || isError {
		detail := text
		if err != nil {
			detail = err.Error()
		}
		return "", e.classify(seen, detail)
	}
	return text, nil
}

// callHandler calls the handler directly. The CLI's recovery middleware is not here,
// so a panic in a handler becomes a failure of this one command.
func callHandler(ctx context.Context, tool *mcpgrafana.Tool, args json.RawMessage) (text string, isError bool, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			text, isError, err = "", false, fmt.Errorf("tool %s stopped: %v", tool.Tool.Name, recovered)
		}
	}()
	result, err := tool.Handler(ctx, &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Name: tool.Tool.Name, Arguments: args}})
	if err != nil {
		return "", false, err
	}
	for _, content := range result.Content {
		if block, ok := content.(*mcp.TextContent); ok {
			return block.Text, result.IsError, nil
		}
	}
	return "", result.IsError, nil
}

const upstreamGuardPhrase = "query blocked by the"

// classify names a failure from what was seen on the wire. Upstream's words reach
// Tellagen only for a guard refusal or a 4xx, where the caller needs them to fix
// its query, and never with the Grafana address in them.
func (e *Executor) classify(seen outcome, detail string) *callFailure {
	switch {
	case seen.refused:
		return &callFailure{status: protocol.StatusRejected, code: protocol.CodeQueryGuardFailed, message: "the proxy only reads from its own Grafana, and this request was refused"}
	case seen.tooLarge:
		return &callFailure{status: protocol.StatusRejected, code: protocol.CodeQueryGuardFailed, message: "the source returned too much data. Narrow the selector or the time range"}
	case strings.Contains(detail, upstreamGuardPhrase):
		return &callFailure{status: protocol.StatusRejected, code: protocol.CodeQueryGuardFailed, message: e.hideAddress(detail)}
	case seen.lastStatus == http.StatusUnauthorized || seen.lastStatus == http.StatusForbidden:
		return &callFailure{status: protocol.StatusError, code: protocol.CodeAuthFailed, message: "Grafana refused the proxy's token"}
	case seen.lastStatus >= 400 && seen.lastStatus < 500:
		return &callFailure{status: protocol.StatusError, code: protocol.CodeUpstream4xx, message: e.hideAddress(detail)}
	}
	return &callFailure{status: protocol.StatusError, code: protocol.CodeSourceUnavailable, message: "Grafana or the datasource did not answer", retryable: true}
}

func (e *Executor) hideAddress(text string) string {
	const maxMessageChars = 500
	text = strings.ReplaceAll(text, e.base.String(), "grafana")
	text = strings.ReplaceAll(text, e.base.Host, "grafana")
	if runes := []rune(text); len(runes) > maxMessageChars {
		text = string(runes[:maxMessageChars])
	}
	return text
}

// runCounter counts the distinct commands of each run. A second attempt of one
// command does not count again.
type runCounter struct {
	mu   sync.Mutex
	runs map[string]*runEntry
}

type runEntry struct {
	commands map[string]bool
	lastSeen time.Time
}

// runRetention is how long the proxy remembers a run after its last command.
const runRetention = 24 * time.Hour

func newRunCounter() *runCounter {
	return &runCounter{runs: map[string]*runEntry{}}
}

// admit reports whether a command of a run may go ahead. A command with no run, such
// as a test query from Settings, is not counted.
func (c *runCounter) admit(runID, commandID string, limit int) bool {
	if runID == "" {
		return true
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	for id, entry := range c.runs {
		if now.Sub(entry.lastSeen) > runRetention {
			delete(c.runs, id)
		}
	}
	entry, ok := c.runs[runID]
	if !ok {
		entry = &runEntry{commands: map[string]bool{}}
		c.runs[runID] = entry
	}
	entry.lastSeen = now
	if entry.commands[commandID] {
		return true
	}
	if len(entry.commands) >= limit {
		return false
	}
	entry.commands[commandID] = true
	return true
}
