package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tellagen/tellagen-proxy/internal/policy"
	"github.com/tellagen/tellagen-proxy/internal/settings"
	"github.com/tellagen/tellagen-proxy/protocol"
)

const testToken = "tlg_proxy_01JD8K2A-0000.secretsecretsecret"

func environment(values map[string]string) settings.Environment {
	return settings.Environment{
		Getenv:   func(name string) string { return values[name] },
		Hostname: func() (string, error) { return "tellagen-proxy-test", nil },
		ReadFile: os.ReadFile,
		Now:      time.Now,
	}
}

func TestVersionHelpAndUnknownCommands(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"version"}, environment(nil), &out, &errOut); code != exitOK || !strings.HasPrefix(out.String(), "tellagen-proxy ") {
		t.Errorf("version = %d %q", code, out.String())
	}
	out.Reset()
	if code := run([]string{"--help"}, environment(nil), &out, &errOut); code != exitOK || !strings.Contains(out.String(), "usage: tellagen-proxy") {
		t.Errorf("help = %d %q", code, out.String())
	}
	out.Reset()
	if code := run([]string{"launch"}, environment(nil), &out, &errOut); code != exitUsage || !strings.Contains(errOut.String(), `unknown command "launch"`) {
		t.Errorf("unknown = %d %q", code, errOut.String())
	}
	errOut.Reset()
	if code := run([]string{"doctor", "--verbose"}, environment(nil), &out, &errOut); code != exitUsage || !strings.Contains(errOut.String(), `unknown option "--verbose"`) {
		t.Errorf("doctor option = %d %q", code, errOut.String())
	}
}

func TestStartingWithBadSettingsListsEveryProblemAndPointsToDoctor(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run(nil, environment(map[string]string{"TELLAGEN_PROXY_TOKEN": testToken, "TELLAGEN_PROXY_TOKEN_FILE": "/run/secrets/token"}), &out, &errOut)
	if code != exitFailed {
		t.Errorf("exit code = %d", code)
	}
	text := errOut.String()
	for _, want := range []string{"TELLAGEN_PROXY_TOKEN and TELLAGEN_PROXY_TOKEN_FILE are both set", "GRAFANA_URL is required", "tellagen-proxy doctor"} {
		if !strings.Contains(text, want) {
			t.Errorf("stderr lacks %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, testToken) {
		t.Error("stderr holds the token")
	}
	if out.Len() != 0 {
		t.Errorf("stdout must hold only audit lines, got %q", out.String())
	}
}

func TestDoctorExitCodeAndFormats(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{"doctor"}, environment(map[string]string{}), &out, &errOut)
	if code != exitFailed || !strings.HasPrefix(out.String(), "tellagen-proxy doctor (") || !strings.Contains(out.String(), "[fail] config") {
		t.Errorf("doctor = %d\n%s", code, out.String())
	}
	out.Reset()
	code = run([]string{"doctor", "--json"}, environment(map[string]string{}), &out, &errOut)
	var report struct {
		Results []struct {
			Check, Status string
		}
	}
	if code != exitFailed || json.Unmarshal(out.Bytes(), &report) != nil || len(report.Results) == 0 || report.Results[0].Status != "fail" {
		t.Errorf("doctor --json = %d\n%s", code, out.String())
	}
}

func TestStatusURL(t *testing.T) {
	cases := map[string]string{
		":8080":          "http://127.0.0.1:8080/readyz",
		"0.0.0.0:9000":   "http://127.0.0.1:9000/readyz",
		"[::]:9000":      "http://127.0.0.1:9000/readyz",
		"10.1.2.3:8080":  "http://10.1.2.3:8080/readyz",
		"not an address": "",
	}
	for addr, want := range cases {
		if got := statusURL(addr); got != want {
			t.Errorf("statusURL(%q) = %q, want %q", addr, got, want)
		}
	}
}

func TestPolicyViewReadsTheEngineAsItStandsNow(t *testing.T) {
	file, err := policy.Load("", nil)
	if err != nil {
		t.Fatal(err)
	}
	engine := policy.NewEngine(file)
	view := policyView{engine}
	before := view.Revision()
	engine.Apply(protocol.PolicyUpdate{Revision: "srv-1", Narrow: protocol.PolicyNarrow{DatasourceUIDs: []string{"prom-prod"}}})
	if view.Revision() == before {
		t.Error("the revision did not follow the policy update")
	}
	if len(view.Capabilities()) == 0 || view.RedactionOff() {
		t.Errorf("capabilities %d redaction off %v", len(view.Capabilities()), view.RedactionOff())
	}
	if view.Report().RedactionAllowOff != file.RedactionAllowOff {
		t.Errorf("Report() = %+v", view.Report())
	}
}

// fakeTellagen is the machine side of Tellagen, enough to run one command.
type fakeTellagen struct {
	t       *testing.T
	server  *httptest.Server
	mu      sync.Mutex
	hello   *protocol.Hello
	polls   int
	result  *protocol.CommandResult
	auth    []string
	command protocol.Command
}

func newFakeTellagen(t *testing.T, command protocol.Command) *fakeTellagen {
	f := &fakeTellagen{t: t, command: command}
	f.server = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeTellagen) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.auth = append(f.auth, r.URL.Path+" "+r.Header.Get("Authorization"))
	f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.URL.Path == "/api/proxy/v1/session":
		_ = json.NewEncoder(w).Encode(protocol.SessionReply{SessionToken: protocol.SessionTokenPrefix + "abc", ExpiresAt: time.Now().Add(15 * time.Minute), ServerTime: time.Now()})
	case r.URL.Path == "/api/proxy/v1/hello":
		var hello protocol.Hello
		_ = json.NewDecoder(r.Body).Decode(&hello)
		f.mu.Lock()
		f.hello = &hello
		f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(protocol.HelloReply{
			ProtocolVersion: "1", Status: protocol.HelloStatusActive, Poll: protocol.PollSettings{WaitMS: 100}, ServerTime: time.Now(),
			Policy: &protocol.PolicyUpdate{Revision: "srv-1", Narrow: protocol.PolicyNarrow{DatasourceUIDs: []string{"prom-prod"}}, Data: protocol.PolicyData{Metrics: protocol.MetricsPoints, Redaction: protocol.RedactionOn}},
		})
	case r.URL.Path == "/api/proxy/v1/poll":
		var request protocol.PollRequest
		_ = json.NewDecoder(r.Body).Decode(&request)
		f.mu.Lock()
		f.polls++
		first := f.polls == 1
		f.mu.Unlock()
		if first {
			_ = json.NewEncoder(w).Encode(protocol.PollReply{Messages: []protocol.PollMessage{{Command: &f.command}}})
			return
		}
		select {
		case <-r.Context().Done():
		case <-time.After(time.Duration(request.WaitMS) * time.Millisecond):
		}
		_ = json.NewEncoder(w).Encode(protocol.PollReply{Messages: []protocol.PollMessage{}})
	case strings.HasSuffix(r.URL.Path, "/result"):
		var result protocol.CommandResult
		_ = json.NewDecoder(r.Body).Decode(&result)
		f.mu.Lock()
		f.result = &result
		f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(protocol.AcceptedReply{Accepted: true})
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (f *fakeTellagen) snapshot() (*protocol.Hello, *protocol.CommandResult) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.hello, f.result
}

func fakeGrafana(t *testing.T) *httptest.Server {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/health":
			_, _ = fmt.Fprint(w, `{"version":"12.2.1"}`)
		case "/api/user":
			_, _ = fmt.Fprint(w, `{"login":"sa-tellagen"}`)
		case "/api/org":
			_, _ = fmt.Fprint(w, `{"id":1,"name":"Main Org."}`)
		case "/api/user/orgs":
			_, _ = fmt.Fprint(w, `[{"orgId":1,"role":"Viewer"}]`)
		case "/api/datasources":
			_, _ = fmt.Fprint(w, `[{"id":1,"uid":"prom-prod","name":"Prometheus prod","type":"prometheus","isDefault":true},{"id":2,"uid":"loki-prod","name":"Loki prod","type":"loki"}]`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

// The proxy, as built by main, says hello to a Tellagen and runs a command from its
// poll through the real executor.
func TestTheProxyConnectsSaysHelloAndRunsACommand(t *testing.T) {
	command := protocol.Command{
		CommandID: "cmd_01", Attempt: 1, AttemptToken: "at_1", RunID: "inv_1",
		Initiator:  protocol.Initiator{Kind: protocol.InitiatorSystem},
		Capability: protocol.CapabilityGrafanaListDatasources, CapabilityVersion: 1,
		Args: json.RawMessage(`{}`), DeadlineMS: 20_000, LeaseMS: 30_000,
	}
	tellagen := newFakeTellagen(t, command)
	grafana := fakeGrafana(t)
	env := environment(map[string]string{
		"TELLAGEN_URL":                  tellagen.server.URL,
		"TELLAGEN_PROXY_TOKEN":          testToken,
		"GRAFANA_URL":                   grafana.URL,
		"GRAFANA_SERVICE_ACCOUNT_TOKEN": "glsa_secret",
		"TELLAGEN_HEALTH_ADDR":          "127.0.0.1:0",
		"TELLAGEN_INSTALL_METHOD":       "test",
	})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var out, errOut syncBuffer
	address := make(chan string, 1)
	done := make(chan int, 1)
	go func() { done <- runProxy(ctx, env, &out, &errOut, func(addr string) { address <- addr }) }()

	var health string
	select {
	case health = <-address:
	case code := <-done:
		t.Fatalf("the proxy exited with %d: %s", code, errOut.String())
	case <-time.After(20 * time.Second):
		t.Fatal("the proxy did not start")
	}
	deadline := time.Now().Add(20 * time.Second)
	for {
		if _, result := tellagen.snapshot(); result != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no result arrived. log:\n%s", errOut.String())
		}
		time.Sleep(5 * time.Millisecond)
	}

	hello, result := tellagen.snapshot()
	if err := hello.Validate(); err != nil {
		t.Errorf("hello: %v", err)
	}
	if hello.InstallMethod != "test" || hello.Executor.Kind != "grafana-mcp" || len(hello.Capabilities) == 0 || len(hello.Sources) != 1 || len(hello.Sources[0].Datasources) != 2 || hello.Sources[0].Health != protocol.HealthOK {
		t.Errorf("hello = %+v", hello)
	}
	if hello.Doctor.Grafana != protocol.DoctorOK {
		t.Errorf("the hello's doctor summary = %+v, want Grafana ok", hello.Doctor)
	}
	if err := result.Validate(); err != nil {
		t.Errorf("result: %v", err)
	}
	if result.AttemptToken != "at_1" || result.Status != protocol.StatusOK || result.Data == nil || len(result.Data.Datasources) != 1 || result.Data.Datasources[0].UID != "prom-prod" {
		t.Errorf("result = %+v: the policy from the hello reply allows only prom-prod", result)
	}

	tellagen.mu.Lock()
	for _, line := range tellagen.auth {
		if strings.HasPrefix(line, "/api/proxy/v1/session ") != strings.HasSuffix(line, testToken) {
			t.Errorf("only the session exchange may carry the proxy token: %q", line)
		}
	}
	tellagen.mu.Unlock()

	response, err := http.Get("http://" + health + "/readyz")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Errorf("/readyz = %d", response.StatusCode)
	}

	var line map[string]any
	waitForLine(t, &out)
	if err := json.Unmarshal([]byte(strings.SplitN(out.String(), "\n", 2)[0]), &line); err != nil {
		t.Fatalf("audit line: %v: %q", err, out.String())
	}
	if line["command_id"] != "cmd_01" || line["kind"] != protocol.CapabilityGrafanaListDatasources || line["outcome"] != "ok" {
		t.Errorf("audit line = %v", line)
	}
	for _, secret := range []string{testToken, "glsa_secret", "at_1"} {
		if strings.Contains(out.String(), secret) || strings.Contains(errOut.String(), secret) {
			t.Errorf("a secret %q reached stdout or stderr", secret)
		}
	}

	cancel()
	select {
	case code := <-done:
		if code != exitOK {
			t.Errorf("exit code = %d\n%s", code, errOut.String())
		}
	case <-time.After(20 * time.Second):
		t.Fatal("the proxy did not stop")
	}
}

func waitForLine(t *testing.T, buffer *syncBuffer) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(buffer.String(), "\n") {
		if time.Now().After(deadline) {
			t.Fatal("no audit line was written")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

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
