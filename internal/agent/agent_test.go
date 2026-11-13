package agent

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tellagen/tellagen-proxy/internal/grafana"
	"github.com/tellagen/tellagen-proxy/internal/hub"
	"github.com/tellagen/tellagen-proxy/internal/settings"
	"github.com/tellagen/tellagen-proxy/protocol"
)

func TestHelloComesBeforeTheFirstPollAndTellsTheStory(t *testing.T) {
	h := newHarness(t, func(c *Config) {
		c.Doctor = func(context.Context) protocol.Doctor {
			return protocol.Doctor{TLS: protocol.DoctorOK, Grafana: protocol.DoctorOK, Warnings: []string{"viewer_all_datasources"}}
		}
	})
	h.policy.report = protocol.PolicyReport{MaxCommandsPerRun: 40, RedactionAllowOff: true}
	h.start()
	waitFor(t, "the first poll", func() bool { return h.backend.pollCount() >= 1 })

	hello := h.backend.hellos[0]
	if err := hello.Validate(); err != nil {
		t.Fatalf("the hello is not valid: %v", err)
	}
	if hello.ProxyVersion != "1.0.0" || hello.InstanceID != "tellagen-proxy-7c9f-xk2p" || hello.InstallMethod != "helm" || hello.Labels["env"] != "production" {
		t.Errorf("hello identity = %+v", hello)
	}
	if hello.PolicyRevision != "sha256:41ab" || hello.Policy.MaxCommandsPerRun != 40 || hello.Executor.Kind != "grafana-mcp" {
		t.Errorf("hello policy or executor = %+v", hello)
	}
	if len(hello.Capabilities) != 1 || !strings.HasPrefix(hello.CapabilitiesDigest, "sha256:") {
		t.Errorf("hello capabilities = %+v digest %q", hello.Capabilities, hello.CapabilitiesDigest)
	}
	if hello.Doctor.TLS != protocol.DoctorOK || len(hello.Doctor.Warnings) != 1 {
		t.Errorf("hello doctor = %+v", hello.Doctor)
	}
	if len(hello.Sources) != 1 {
		t.Fatalf("hello sources = %+v", hello.Sources)
	}
	source := hello.Sources[0]
	if source.Key != "grafana-main" || source.PublicURL != "https://grafana.customerdomain.net" || source.GrafanaVersion != "12.2.1" || source.Health != protocol.HealthOK || len(source.Datasources) != 2 {
		t.Errorf("hello source = %+v", source)
	}
	encoded, _ := json.Marshal(hello)
	if strings.Contains(string(encoded), "10.0.") {
		t.Errorf("the hello holds an internal address: %s", encoded)
	}

	first := h.backend.poll(0)
	if first.InstanceID != "tellagen-proxy-7c9f-xk2p" || first.WaitMS != 25_000 || first.Mode != protocol.PollModeLong || first.FreeSlots != 2 || first.AppliedPolicyRevision != "sha256:41ab" {
		t.Errorf("first poll = %+v", first)
	}
	if err := first.Validate(); err != nil {
		t.Errorf("the poll is not valid: %v", err)
	}
	if len(first.SourcesHealth) != 1 || first.SourcesHealth[0].Health != protocol.HealthOK || first.SourcesHealth[0].CheckedAt == nil {
		t.Errorf("sources_health = %+v", first.SourcesHealth)
	}
}

func TestHelloListsOnlyDatasourcesThePolicyAllows(t *testing.T) {
	h := newHarness(t, nil)
	h.policy.report = protocol.PolicyReport{DatasourceUIDs: []string{"prom-prod"}}
	h.start()
	waitFor(t, "the first poll", func() bool { return h.backend.pollCount() >= 1 })
	datasources := h.backend.hellos[0].Sources[0].Datasources
	if len(datasources) != 1 || datasources[0].UID != "prom-prod" {
		t.Errorf("datasources = %+v, want only prom-prod", datasources)
	}
}

func TestGrafanaDownAtStartIsReportedNotFatal(t *testing.T) {
	h := newHarness(t, nil)
	h.grafana.err = &net.OpError{Op: "dial", Err: errors.New("connect: connection refused to 10.0.0.5:3000")}
	h.start()
	waitFor(t, "the first poll", func() bool { return h.backend.pollCount() >= 1 })
	source := h.backend.hellos[0].Sources[0]
	if source.Health != protocol.HealthUnavailable || len(source.Datasources) != 0 {
		t.Errorf("source = %+v, want unavailable with no datasources", source)
	}
	health := h.backend.poll(0).SourcesHealth[0]
	if health.Code != protocol.CodeSourceUnavailable || strings.Contains(health.Message, "10.0.0.5") {
		t.Errorf("source health = %+v, want a code and no address", health)
	}
}

func TestGrafanaTokenRejectedIsAuthFailed(t *testing.T) {
	h := newHarness(t, nil)
	h.grafana.err = &grafana.StatusError{Status: 401, Path: "/api/datasources"}
	h.start()
	waitFor(t, "the first poll", func() bool { return h.backend.pollCount() >= 1 })
	health := h.backend.poll(0).SourcesHealth[0]
	if health.Code != protocol.CodeAuthFailed || health.Message != "Grafana rejected the token (401)" {
		t.Errorf("source health = %+v", health)
	}
}

func TestACommandIsRunPostedAndAudited(t *testing.T) {
	h := newHarness(t, nil)
	h.policy.redaction = false
	h.backend.pollFn = script(pollStepResult{reply: protocol.PollReply{Messages: []protocol.PollMessage{commandMessage("cmd_01", 1)}}})
	h.start()
	waitFor(t, "the result", func() bool { return len(h.backend.resultsOf("cmd_01")) == 1 })

	result := h.backend.resultsOf("cmd_01")[0]
	if result.AttemptToken != "at_cmd_01" || result.Status != protocol.StatusOK {
		t.Errorf("result = %+v", result)
	}
	waitFor(t, "the audit line", func() bool { return strings.Contains(h.audit.String(), "\n") })
	var line AuditLine
	if err := json.Unmarshal([]byte(strings.TrimSpace(h.audit.String())), &line); err != nil {
		t.Fatalf("audit line is not JSON: %v: %q", err, h.audit.String())
	}
	if line.Event != "command" || line.CommandID != "cmd_01" || line.RunID != "inv_8f1" || line.IncidentRef != "INC-142" || line.Initiator.ID != "u_311" {
		t.Errorf("audit identity = %+v", line)
	}
	if line.Kind != protocol.CapabilityPrometheusQueryRange || line.DatasourceUID != "prom-prod" || !strings.Contains(line.Query, "http_requests_total") || line.StepSeconds != 30 || line.RangeFrom == nil || line.RangeTo == nil {
		t.Errorf("audit query = %+v", line)
	}
	if line.Outcome != protocol.StatusOK || line.Series != 1 || line.Points != 3 || line.Bytes != 120 || line.RedactionCount != 2 || line.Redactions["bearer"] != 2 || line.RedactionOff || line.PolicyRevision != "sha256:41ab" || line.QueryFingerprint != "sha256:77d0" {
		t.Errorf("audit outcome = %+v", line)
	}
	for _, secret := range []string{"at_cmd_01", "tlg_proxy_", "tlg_psess_"} {
		if strings.Contains(h.audit.String(), secret) {
			t.Errorf("the audit line holds %q", secret)
		}
	}
	_, metrics := h.get("/metrics")
	if !strings.Contains(metrics, `tellagen_proxy_jobs_total{status="ok"} 1`) {
		t.Errorf("metrics lack the command count:\n%s", metrics)
	}
}

func TestARejectedCommandIsAuditedWithItsCode(t *testing.T) {
	h := newHarness(t, nil)
	h.executor.run = func(context.Context, protocol.Command) protocol.CommandResult {
		return protocol.CommandResult{Status: protocol.StatusRejected, Error: &protocol.ResultError{Code: protocol.CodePolicyRangeExceeded, Message: "range 48h exceeds 24h"}}
	}
	h.backend.pollFn = script(pollStepResult{reply: protocol.PollReply{Messages: []protocol.PollMessage{commandMessage("cmd_02", 1)}}})
	h.start()
	waitFor(t, "the result", func() bool { return len(h.backend.resultsOf("cmd_02")) == 1 })
	waitFor(t, "the audit line", func() bool { return strings.Contains(h.audit.String(), "\n") })
	var line AuditLine
	if err := json.Unmarshal([]byte(strings.TrimSpace(h.audit.String())), &line); err != nil {
		t.Fatal(err)
	}
	if line.Outcome != protocol.StatusRejected || line.OutcomeCode != protocol.CodePolicyRangeExceeded || line.OutcomeMessage != "range 48h exceeds 24h" {
		t.Errorf("audit = %+v", line)
	}
}

func TestACommandThatPanicsBecomesAnErrorResult(t *testing.T) {
	h := newHarness(t, nil)
	h.executor.run = func(context.Context, protocol.Command) protocol.CommandResult { panic("boom") }
	h.backend.pollFn = script(pollStepResult{reply: protocol.PollReply{Messages: []protocol.PollMessage{commandMessage("cmd_03", 1)}}})
	h.start()
	waitFor(t, "the result", func() bool { return len(h.backend.resultsOf("cmd_03")) == 1 })
	result := h.backend.resultsOf("cmd_03")[0]
	if result.Status != protocol.StatusError || result.Error == nil || result.Error.Code != protocol.CodeSourceUnavailable || !result.Error.Retryable {
		t.Errorf("result = %+v", result)
	}
	if err := result.Validate(); err != nil {
		t.Errorf("the error result is not valid: %v", err)
	}
}

func TestACommandAlreadyRunningIsNotStartedTwice(t *testing.T) {
	h := newHarness(t, nil)
	release := make(chan struct{})
	h.executor.run = func(ctx context.Context, command protocol.Command) protocol.CommandResult {
		select {
		case <-release:
		case <-ctx.Done():
		}
		return protocol.CommandResult{Status: protocol.StatusCancelled}
	}
	same := pollStepResult{reply: protocol.PollReply{Messages: []protocol.PollMessage{commandMessage("cmd_04", 1)}}}
	newAttempt := pollStepResult{reply: protocol.PollReply{Messages: []protocol.PollMessage{commandMessage("cmd_04", 2)}}}
	h.backend.pollFn = script(same, same, newAttempt)
	h.start()
	waitFor(t, "three polls", func() bool { return h.backend.pollCount() >= 4 })
	waitFor(t, "both attempts", func() bool { return len(h.executor.executedIDs()) == 2 })
	close(release)
	waitFor(t, "both results", func() bool { return len(h.backend.resultsOf("cmd_04")) == 2 })
	if got := len(h.executor.executedIDs()); got != 2 {
		t.Errorf("the executor ran %d times, want 2 (attempt 1 once, attempt 2 once)", got)
	}
}

func TestCancelAndPolicyUpdateMessages(t *testing.T) {
	h := newHarness(t, nil)
	update := &protocol.PolicyUpdate{Revision: "srv-8", Narrow: protocol.PolicyNarrow{DatasourceUIDs: []string{"prom-prod"}}}
	h.backend.pollFn = script(pollStepResult{reply: protocol.PollReply{Messages: []protocol.PollMessage{
		{Cancel: &protocol.Cancel{CommandID: "cmd_09", Reason: protocol.CancelReasonRunCancelled}},
		{PolicyUpdate: update},
	}}})
	h.start()
	waitFor(t, "the second hello", func() bool { return h.backend.helloCount() >= 2 })
	if got := h.executor.cancelled(); len(got) != 1 || got[0] != "cmd_09" {
		t.Errorf("cancelled = %v", got)
	}
	h.executor.mu.Lock()
	updates := h.executor.updates
	h.executor.mu.Unlock()
	if len(updates) != 1 || updates[0].Revision != "srv-8" {
		t.Errorf("policy updates = %+v", updates)
	}
}

func TestPolicyFromHelloReplyIsApplied(t *testing.T) {
	h := newHarness(t, nil)
	h.backend.helloFn = func(int, protocol.Hello) (protocol.HelloReply, error) {
		return protocol.HelloReply{Status: protocol.HelloStatusActive, Poll: protocol.PollSettings{WaitMS: 20_000}, Policy: &protocol.PolicyUpdate{Revision: "srv-3"}}, nil
	}
	h.start()
	waitFor(t, "the first poll", func() bool { return h.backend.pollCount() >= 1 })
	if got := h.backend.poll(0).WaitMS; got != 20_000 {
		t.Errorf("wait_ms = %d, want the 20000 that Tellagen asked for", got)
	}
	h.executor.mu.Lock()
	defer h.executor.mu.Unlock()
	if len(h.executor.updates) != 1 || h.executor.updates[0].Revision != "srv-3" {
		t.Errorf("policy updates = %+v", h.executor.updates)
	}
}

func TestANewSessionSendsAnotherHello(t *testing.T) {
	h := newHarness(t, nil)
	h.backend.pollFn = func(n int, _ protocol.PollRequest) (protocol.PollReply, error, bool) {
		if n == 2 {
			h.backend.generation.Add(1)
			return protocol.PollReply{}, nil, true
		}
		if n == 1 {
			return protocol.PollReply{}, nil, true
		}
		return protocol.PollReply{}, nil, false
	}
	h.start()
	waitFor(t, "the second hello", func() bool { return h.backend.helloCount() >= 2 })
}

func TestTwoCutsHalveTheWaitAndTwoMoreSwitchToShortPolls(t *testing.T) {
	h := newHarness(t, nil)
	cut := pollStepResult{err: cutError()}
	ok := pollStepResult{}
	h.backend.pollFn = script(cut, cut, cut, cut, ok, ok)
	h.start()
	waitFor(t, "seven polls", func() bool { return h.backend.pollCount() >= 7 })

	want := []struct {
		wait int
		mode string
	}{
		{25_000, protocol.PollModeLong}, {25_000, protocol.PollModeLong},
		{10_000, protocol.PollModeLong}, {10_000, protocol.PollModeLong},
		{0, protocol.PollModeShort}, {0, protocol.PollModeShort}, {0, protocol.PollModeShort},
	}
	for i, w := range want {
		got := h.backend.poll(i)
		if got.WaitMS != w.wait || got.Mode != w.mode {
			t.Errorf("poll %d = wait %d mode %s, want wait %d mode %s", i, got.WaitMS, got.Mode, w.wait, w.mode)
		}
	}
	status := h.status()
	if status.Mode != protocol.PollModeShort || !status.Degraded {
		t.Errorf("status = %+v", status)
	}
	_, metrics := h.get("/metrics")
	if !strings.Contains(metrics, `tellagen_proxy_transport{mode="short_poll"} 1`) || !strings.Contains(metrics, `tellagen_proxy_reconnects_total{reason="cut"} 4`) {
		t.Errorf("metrics:\n%s", metrics)
	}
	sawGap := false
	for _, d := range h.sleepsSnapshot() {
		if d == 2*time.Second {
			sawGap = true
		}
	}
	if !sawGap {
		t.Errorf("sleeps = %v, want a 2 s gap between short polls", h.sleepsSnapshot())
	}
}

func TestRefusedConnectionsAreNotCuts(t *testing.T) {
	h := newHarness(t, nil)
	refused := pollStepResult{err: &hub.TransportError{Err: &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")}}}
	h.backend.pollFn = script(refused, refused, refused, refused, refused)
	h.start()
	waitFor(t, "six polls", func() bool { return h.backend.pollCount() >= 6 })
	if got := h.backend.poll(5); got.WaitMS != 25_000 || got.Mode != protocol.PollModeLong {
		t.Errorf("poll after five refused connections = %+v, want the full wait", got)
	}
}

func TestFailedCallsBackOffUnlessThePollWasHeld(t *testing.T) {
	h := newHarness(t, nil)
	h.backend.pollFn = func(n int, _ protocol.PollRequest) (protocol.PollReply, error, bool) {
		switch {
		case n <= 3:
			return protocol.PollReply{}, &hub.APIError{Status: http.StatusBadGateway}, true
		case n == 4:
			h.clock.Advance(20 * time.Second) // held for 20 s, then cut
			return protocol.PollReply{}, &hub.APIError{Status: http.StatusGatewayTimeout}, true
		}
		return protocol.PollReply{}, nil, false
	}
	h.start()
	waitFor(t, "five polls", func() bool { return h.backend.pollCount() >= 5 })
	sleeps := h.sleepsSnapshot()
	want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second}
	if len(sleeps) < 3 {
		t.Fatalf("sleeps = %v", sleeps)
	}
	for i, d := range want {
		if sleeps[i] != d {
			t.Errorf("sleep %d = %s, want %s (quick failures back off)", i, sleeps[i], d)
		}
	}
	for _, d := range sleeps[3:] {
		if d == 8*time.Second {
			t.Errorf("sleeps = %v: a poll held for 20 s must be followed at once", sleeps)
		}
	}
}

func TestBackoffIsCapped(t *testing.T) {
	cases := map[int]time.Duration{1: time.Second, 2: 2 * time.Second, 3: 4 * time.Second, 6: 30 * time.Second, 12: 30 * time.Second}
	for failures, want := range cases {
		if got := failureDelay(0, failures); got != want {
			t.Errorf("failureDelay(0, %d) = %s, want %s", failures, got, want)
		}
	}
	if got := failureDelay(5*time.Second, 9); got != 0 {
		t.Errorf("failureDelay(held 5 s) = %s, want 0", got)
	}
}

func TestRateLimitedWaitsAsToldAndDoesNotDegrade(t *testing.T) {
	h := newHarness(t, nil)
	limited := pollStepResult{err: &hub.APIError{Status: http.StatusTooManyRequests, RetryAfter: 7 * time.Second}}
	h.backend.pollFn = script(limited, limited, limited)
	h.start()
	waitFor(t, "four polls", func() bool { return h.backend.pollCount() >= 4 })
	if got := h.backend.poll(3); got.WaitMS != 25_000 {
		t.Errorf("wait after three 429s = %d, want the full wait", got.WaitMS)
	}
	sleeps := h.sleepsSnapshot()
	if len(sleeps) < 3 || sleeps[0] != 7*time.Second {
		t.Errorf("sleeps = %v, want the 7 s from Retry-After", sleeps)
	}
}

func TestRetryAfterIsBounded(t *testing.T) {
	if got := retryAfter(&hub.APIError{Status: 429}); got != 5*time.Second {
		t.Errorf("retryAfter(no header) = %s", got)
	}
	if got := retryAfter(&hub.APIError{Status: 429, RetryAfter: time.Hour}); got != 5*time.Minute {
		t.Errorf("retryAfter(1h) = %s", got)
	}
}

func TestARevokedProxyStopsReadyAndRecoversWithoutARestart(t *testing.T) {
	h := newHarness(t, nil)
	revokedAt := time.Date(2026, 11, 4, 10, 20, 0, 0, time.UTC)
	revoked := &hub.APIError{Status: http.StatusUnauthorized, Reply: protocol.ErrorReply{Code: protocol.ErrorRevoked, RevokedAt: &revokedAt}}
	h.backend.pollFn = script(pollStepResult{}, pollStepResult{err: revoked}, pollStepResult{err: revoked}, pollStepResult{})
	h.holdLong = make(chan struct{})
	h.start()
	waitFor(t, "a blocked status", func() bool { return h.status().Blocked != "" })
	status := h.status()
	for _, want := range []string{"revoked on 2026-11-04 10:20 UTC", "TELLAGEN_PROXY_TOKEN_FILE"} {
		if !strings.Contains(status.Blocked, want) {
			t.Errorf("blocked = %q, want it to say %q", status.Blocked, want)
		}
	}
	if code, _ := h.get("/readyz"); code != http.StatusServiceUnavailable {
		t.Errorf("/readyz = %d while revoked, want 503", code)
	}
	if code, _ := h.get("/healthz"); code != http.StatusOK {
		t.Errorf("/healthz = %d while revoked, want 200", code)
	}
	close(h.holdLong)
	waitFor(t, "a good poll", func() bool { return h.backend.pollCount() >= 5 })
	waitFor(t, "ready again", func() bool { return h.status().Blocked == "" && h.status().Ready })

	var growing []time.Duration
	for _, d := range h.sleepsSnapshot() {
		if d >= 5*time.Second {
			growing = append(growing, d)
		}
	}
	if len(growing) < 2 || growing[0] != 5*time.Second || growing[1] != 10*time.Second {
		t.Errorf("blocked delays = %v, want 5s then 10s", growing)
	}
}

func TestBlockedDelayGrowsToFiveMinutes(t *testing.T) {
	h := newHarness(t, nil)
	revoked := &hub.APIError{Status: http.StatusUnauthorized, Reply: protocol.ErrorReply{Code: protocol.ErrorTokenInvalid}}
	steps := make([]pollStepResult, 12)
	for i := range steps {
		steps[i] = pollStepResult{err: revoked}
	}
	h.backend.pollFn = script(steps...)
	h.start()
	waitFor(t, "twelve polls", func() bool { return h.backend.pollCount() >= 12 })
	longest := time.Duration(0)
	for _, d := range h.sleepsSnapshot() {
		longest = max(longest, d)
	}
	if longest != 5*time.Minute {
		t.Errorf("longest delay = %s, want it capped at 5m", longest)
	}
}

func TestACloudDiagnosisFlagThatIsOffMakesTheProxyBackOff(t *testing.T) {
	h := newHarness(t, nil)
	off := &hub.APIError{Status: http.StatusForbidden, Reply: protocol.ErrorReply{Code: protocol.ErrorCloudDiagnosisDisabled}}
	h.backend.pollFn = func(int, protocol.PollRequest) (protocol.PollReply, error, bool) {
		return protocol.PollReply{}, off, true
	}
	h.start()
	waitFor(t, "eight refused polls", func() bool { return h.backend.pollCount() >= 8 })
	// The status is empty for a moment after each new hello, until the next
	// refused poll sets it again. So wait for it; one read can land in that gap.
	waitFor(t, "the blocked status", func() bool {
		return strings.Contains(h.status().Blocked, "Cloud diagnosis is switched off for this workspace")
	})
	var delays []time.Duration
	for _, d := range h.sleepsSnapshot() {
		if d >= 5*time.Second {
			delays = append(delays, d)
		}
	}
	if len(delays) < 7 || delays[0] != 5*time.Second || delays[1] != 10*time.Second || delays[6] != 5*time.Minute {
		t.Errorf("delays = %v, want 5s, 10s and so on up to 5m, not a fixed short interval", delays)
	}
}

func TestATooOldVersionIsExplained(t *testing.T) {
	h := newHarness(t, nil)
	h.backend.helloFn = func(int, protocol.Hello) (protocol.HelloReply, error) {
		return protocol.HelloReply{}, &hub.APIError{Status: http.StatusUpgradeRequired, Reply: protocol.ErrorReply{Code: protocol.ErrorUpgradeRequired, MinVersion: "1.2.0"}}
	}
	h.start()
	waitFor(t, "a blocked status", func() bool { return h.status().Blocked != "" })
	if blocked := h.status().Blocked; !strings.Contains(blocked, "1.2.0 or later") || !strings.Contains(blocked, "Upgrade the image") {
		t.Errorf("blocked = %q", blocked)
	}
	if h.backend.pollCount() != 0 {
		t.Error("the proxy polled although its hello was refused")
	}
}

func TestAnInactiveProxyIsBlocked(t *testing.T) {
	h := newHarness(t, nil)
	h.backend.helloFn = func(int, protocol.Hello) (protocol.HelloReply, error) {
		return protocol.HelloReply{Status: "paused"}, nil
	}
	h.start()
	waitFor(t, "a blocked status", func() bool { return h.status().Blocked != "" })
	if !strings.Contains(h.status().Blocked, `"paused"`) {
		t.Errorf("blocked = %q", h.status().Blocked)
	}
}

func TestAResultIsSentAgainAfterATransportError(t *testing.T) {
	h := newHarness(t, nil)
	h.backend.postFn = func(id string, call int) error {
		if call < 3 {
			return &hub.TransportError{Err: errPost}
		}
		return nil
	}
	h.backend.pollFn = script(pollStepResult{reply: protocol.PollReply{Messages: []protocol.PollMessage{commandMessage("cmd_05", 1)}}})
	h.start()
	waitFor(t, "the result", func() bool { return len(h.backend.resultsOf("cmd_05")) == 1 })
	h.backend.mu.Lock()
	calls := h.backend.postCalls["cmd_05"]
	h.backend.mu.Unlock()
	if calls != 3 {
		t.Errorf("post calls = %d, want 3", calls)
	}
}

func TestAResultThatTellagenRefusesIsNotSentAgain(t *testing.T) {
	for _, status := range []int{http.StatusConflict, http.StatusGone} {
		h := newHarness(t, nil)
		h.backend.postFn = func(string, int) error { return &hub.APIError{Status: status} }
		h.backend.pollFn = script(pollStepResult{reply: protocol.PollReply{Messages: []protocol.PollMessage{commandMessage("cmd_06", 1)}}})
		h.start()
		waitFor(t, "the post", func() bool {
			h.backend.mu.Lock()
			defer h.backend.mu.Unlock()
			return h.backend.postCalls["cmd_06"] >= 1
		})
		if err := h.stop(); err != nil {
			t.Fatal(err)
		}
		h.backend.mu.Lock()
		calls := h.backend.postCalls["cmd_06"]
		h.backend.mu.Unlock()
		if calls != 1 {
			t.Errorf("status %d: post calls = %d, want 1", status, calls)
		}
	}
}

func TestResultPostingGivesUpAfterSixTries(t *testing.T) {
	h := newHarness(t, nil)
	h.backend.postFn = func(string, int) error { return &hub.TransportError{Err: errPost} }
	h.backend.pollFn = script(pollStepResult{reply: protocol.PollReply{Messages: []protocol.PollMessage{commandMessage("cmd_07", 1)}}})
	h.start()
	waitFor(t, "six posts", func() bool {
		h.backend.mu.Lock()
		defer h.backend.mu.Unlock()
		return h.backend.postCalls["cmd_07"] >= resultAttempts
	})
	if err := h.stop(); err != nil {
		t.Fatal(err)
	}
	h.backend.mu.Lock()
	defer h.backend.mu.Unlock()
	if h.backend.postCalls["cmd_07"] != resultAttempts {
		t.Errorf("post calls = %d, want %d", h.backend.postCalls["cmd_07"], resultAttempts)
	}
}

func TestShutdownLetsAShortCommandFinish(t *testing.T) {
	h := newHarness(t, nil)
	started := make(chan struct{})
	release := make(chan struct{})
	h.executor.run = func(ctx context.Context, command protocol.Command) protocol.CommandResult {
		close(started)
		<-release
		return protocol.CommandResult{Status: protocol.StatusOK, Data: &protocol.ResultData{Kind: protocol.DataNames}}
	}
	h.backend.pollFn = script(pollStepResult{reply: protocol.PollReply{Messages: []protocol.PollMessage{commandMessage("cmd_10", 1)}}})
	h.agent.cfg.CommandGrace = 5 * time.Second
	h.start()
	<-started
	h.cancel()
	time.AfterFunc(20*time.Millisecond, func() { close(release) })
	if err := h.stop(); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	results := h.backend.resultsOf("cmd_10")
	if len(results) != 1 || results[0].Status != protocol.StatusOK {
		t.Errorf("results = %+v, want the finished result", results)
	}
	if len(h.executor.cancelled()) != 0 {
		t.Errorf("cancelled = %v, a command that finished in time must not be cancelled", h.executor.cancelled())
	}
}

func TestShutdownCancelsALongCommandAndSendsItsCancelledResult(t *testing.T) {
	h := newHarness(t, nil)
	started := make(chan struct{})
	h.executor.run = func(ctx context.Context, command protocol.Command) protocol.CommandResult {
		close(started)
		<-ctx.Done()
		return protocol.CommandResult{Status: protocol.StatusCancelled}
	}
	h.executor.inFlight = []protocol.InFlight{{CommandID: "cmd_11", Attempt: 1}}
	h.backend.pollFn = script(pollStepResult{reply: protocol.PollReply{Messages: []protocol.PollMessage{commandMessage("cmd_11", 1)}}})
	h.start()
	<-started
	h.cancel()
	if err := h.stop(); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got := h.executor.cancelled(); len(got) != 1 || got[0] != "cmd_11" {
		t.Errorf("cancelled = %v", got)
	}
	results := h.backend.resultsOf("cmd_11")
	if len(results) != 1 || results[0].Status != protocol.StatusCancelled {
		t.Errorf("results = %+v, want one cancelled result", results)
	}
}

func TestSecretFilesAreWaitedForBeforeThePollingStarts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	secret := newFileSecret(t, path)
	h := newHarness(t, func(c *Config) {
		c.Secrets = []*settings.Secret{secret}
		c.FileWait = 10 * time.Second
	})
	h.start()
	waitFor(t, "a waiting status", func() bool { return len(h.status().WaitingFor) == 1 })
	if code, body := h.get("/readyz"); code != http.StatusServiceUnavailable || !strings.Contains(body, path) {
		t.Errorf("/readyz = %d %s, want 503 naming the file", code, body)
	}
	if h.backend.pollCount() != 0 || h.backend.helloCount() != 0 {
		t.Error("the proxy talked to Tellagen before its secret existed")
	}
	if err := os.WriteFile(path, []byte("tlg_proxy_a.b\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the first poll", func() bool { return h.backend.pollCount() >= 1 })
}

func TestMissingSecretFileEndsTheRunWithAnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "never")
	h := newHarness(t, func(c *Config) {
		c.Secrets = []*settings.Secret{newFileSecret(t, path)}
		c.FileWait = 30 * time.Millisecond
	})
	h.start()
	select {
	case err := <-h.done:
		h.done <- err
		if err == nil || !strings.Contains(err.Error(), path) {
			t.Errorf("Run() error = %v, want it to name %s", err, path)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run() did not return")
	}
}

func TestHealthEndpoints(t *testing.T) {
	h := newHarness(t, nil)
	h.start()
	if code, body := h.get("/healthz"); code != http.StatusOK || strings.TrimSpace(body) != "ok" {
		t.Errorf("/healthz = %d %q", code, body)
	}
	waitFor(t, "ready", func() bool { return h.status().Ready })
	code, body := h.get("/readyz")
	if code != http.StatusOK {
		t.Fatalf("/readyz = %d %s", code, body)
	}
	var status Status
	if err := json.Unmarshal([]byte(body), &status); err != nil {
		t.Fatal(err)
	}
	if !status.Ready || status.Mode != protocol.PollModeLong || status.Version != "1.0.0" || status.Degraded {
		t.Errorf("/readyz body = %+v", status)
	}
	_, metrics := h.get("/metrics")
	for _, want := range []string{"tellagen_proxy_connected 1", `tellagen_proxy_transport{mode="long_poll"} 1`, `tellagen_proxy_build_info{version="1.0.0"} 1`} {
		if !strings.Contains(metrics, want) {
			t.Errorf("/metrics lacks %q", want)
		}
	}
	if code, _ := h.get("/debug/pprof/"); code != http.StatusNotFound {
		t.Errorf("an unknown path answered %d, want 404", code)
	}
	if response, err := http.Post("http://"+h.address+"/healthz", "text/plain", nil); err == nil {
		defer func() { _ = response.Body.Close() }()
		if response.StatusCode == http.StatusOK {
			t.Error("POST /healthz must not be served")
		}
	}
}

func TestReadyGoesStaleAfterSixtySecondsWithoutAnAnswer(t *testing.T) {
	h := newHarness(t, nil)
	h.start()
	waitFor(t, "ready", func() bool { return h.status().Ready })
	h.clock.Advance(61 * time.Second)
	status := h.status()
	if status.Ready || status.LastContactAgeS < 60 {
		t.Errorf("status = %+v, want not ready after 61 s of silence", status)
	}
	if code, _ := h.get("/healthz"); code != http.StatusOK {
		t.Errorf("/healthz = %d, it must not depend on Tellagen", code)
	}
}

func TestRunReturnsAnErrorWhenTheHealthPortFails(t *testing.T) {
	h := newHarness(t, nil)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_ = listener.Close()
	err = h.agent.Run(t.Context(), listener)
	if err == nil || !strings.Contains(err.Error(), "health endpoint") {
		t.Errorf("Run() error = %v, want a health endpoint error", err)
	}
}

func TestPollsStopWhenTheContextEnds(t *testing.T) {
	h := newHarness(t, nil)
	var polls atomic.Int32
	h.backend.pollFn = func(int, protocol.PollRequest) (protocol.PollReply, error, bool) {
		polls.Add(1)
		return protocol.PollReply{}, nil, false
	}
	h.start()
	waitFor(t, "a held poll", func() bool { return polls.Load() == 1 })
	if err := h.stop(); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if polls.Load() != 1 {
		t.Errorf("polls = %d, want the held poll closed and no new one", polls.Load())
	}
}

func TestTellagenAskingForAHelloGetsOneAtOnce(t *testing.T) {
	h := newHarness(t, nil)
	askAgain := &hub.APIError{Status: http.StatusUnauthorized, Reply: protocol.ErrorReply{Code: protocol.ErrorSessionInvalid}}
	h.backend.pollFn = script(pollStepResult{err: askAgain})
	h.start()
	waitFor(t, "the second hello", func() bool { return h.backend.helloCount() >= 2 })
	waitFor(t, "a poll after it", func() bool { return h.backend.pollCount() >= 2 })
	if blocked := h.status().Blocked; blocked != "" {
		t.Errorf("blocked = %q, a request for a hello is not a credential problem", blocked)
	}
	for _, d := range h.sleepsSnapshot() {
		if d >= 5*time.Second {
			t.Errorf("sleeps = %v, the hello must follow at once", h.sleepsSnapshot())
		}
	}
}

func TestEndlessHelloRequestsBecomeAProblem(t *testing.T) {
	h := newHarness(t, nil)
	askAgain := pollStepResult{err: &hub.APIError{Status: http.StatusUnauthorized, Reply: protocol.ErrorReply{Code: protocol.ErrorSessionInvalid, Message: "say hello"}}}
	h.backend.pollFn = script(askAgain, askAgain, askAgain, askAgain)
	h.holdLong = make(chan struct{})
	h.start()
	waitFor(t, "a blocked status", func() bool { return h.status().Blocked != "" })
	if h.backend.helloCount() != maxHelloAsks+1 {
		t.Errorf("hellos = %d, want %d before the proxy gives up", h.backend.helloCount(), maxHelloAsks+1)
	}
	close(h.holdLong)
}

func TestRefusedRequestsDoNotDegradeThePolls(t *testing.T) {
	h := newHarness(t, nil)
	notFound := pollStepResult{err: &hub.APIError{Status: http.StatusNotFound}}
	h.backend.pollFn = script(notFound, notFound, notFound, notFound, notFound)
	h.start()
	waitFor(t, "six polls", func() bool { return h.backend.pollCount() >= 6 })
	if got := h.backend.poll(5); got.WaitMS != 25_000 || got.Mode != protocol.PollModeLong {
		t.Errorf("poll = %+v, want the full wait", got)
	}
}

func TestAResultThatTellagenDoesNotKnowIsNotSentAgain(t *testing.T) {
	h := newHarness(t, nil)
	h.backend.postFn = func(string, int) error { return &hub.APIError{Status: http.StatusNotFound} }
	h.backend.pollFn = script(pollStepResult{reply: protocol.PollReply{Messages: []protocol.PollMessage{commandMessage("cmd_08", 1)}}})
	h.start()
	waitFor(t, "the post", func() bool {
		h.backend.mu.Lock()
		defer h.backend.mu.Unlock()
		return h.backend.postCalls["cmd_08"] >= 1
	})
	if err := h.stop(); err != nil {
		t.Fatal(err)
	}
	h.backend.mu.Lock()
	defer h.backend.mu.Unlock()
	if h.backend.postCalls["cmd_08"] != 1 {
		t.Errorf("post calls = %d, want 1", h.backend.postCalls["cmd_08"])
	}
}

func TestPublicURLNetworkSaysPrivateOnlyWhenEveryAnswerIsPrivate(t *testing.T) {
	broken := errors.New("no such host")
	tests := []struct {
		name      string
		publicURL string
		addresses []string
		err       error
		want      string
	}{
		{"a public answer", "https://grafana.customerdomain.net", []string{"203.0.113.9"}, nil, ""},
		{"a private answer", "https://grafana.customerdomain.net", []string{"10.2.0.8"}, nil, protocol.NetworkPrivate},
		{"a private IPv6 answer", "https://grafana.customerdomain.net", []string{"fd00::1"}, nil, protocol.NetworkPrivate},
		{"an IPv4-mapped private answer", "https://grafana.customerdomain.net", []string{"::ffff:192.168.1.4"}, nil, protocol.NetworkPrivate},
		{"a VPN overlay answer", "https://grafana.customerdomain.net", []string{"100.72.0.4"}, nil, protocol.NetworkPrivate},
		{"one public answer among private ones", "https://grafana.customerdomain.net", []string{"10.2.0.8", "203.0.113.9"}, nil, ""},
		{"a failed lookup", "https://grafana.customerdomain.net", nil, broken, ""},
		{"no answer", "https://grafana.customerdomain.net", nil, nil, ""},
		{"no public address", "", []string{"10.2.0.8"}, nil, ""},
		{"an address that cannot be read", "://broken", []string{"10.2.0.8"}, nil, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			agent := &Agent{cfg: Config{PublicURL: tt.publicURL, LookupIP: func(_ context.Context, host string) ([]netip.Addr, error) {
				if host != "grafana.customerdomain.net" {
					t.Errorf("looked up %q", host)
				}
				var addresses []netip.Addr
				for _, address := range tt.addresses {
					addresses = append(addresses, netip.MustParseAddr(address))
				}
				return addresses, tt.err
			}}}
			if got := agent.publicURLNetwork(context.Background()); got != tt.want {
				t.Fatalf("network = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestHelloCarriesTheNetworkOfThePublicAddress(t *testing.T) {
	h := newHarness(t, func(c *Config) {
		c.LookupIP = func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("10.2.0.8")}, nil
		}
	})
	h.start()
	waitFor(t, "the first poll", func() bool { return h.backend.pollCount() >= 1 })
	h.backend.mu.Lock()
	hello := h.backend.hellos[0]
	h.backend.mu.Unlock()
	if len(hello.Sources) != 1 || hello.Sources[0].PublicURLNetwork != protocol.NetworkPrivate {
		t.Fatalf("sources = %+v", hello.Sources)
	}
}
