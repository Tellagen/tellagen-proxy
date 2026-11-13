package doctor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/tellagen/tellagen-proxy/internal/policy"
	"github.com/tellagen/tellagen-proxy/internal/settings"
	"github.com/tellagen/tellagen-proxy/protocol"
)

// maxSkew is the clock difference at which doctor complains. Certificate checks
// fail on a clock that is far off.
const maxSkew = 2 * time.Minute

const stepTimeout = 10 * time.Second

// Net is the machine as the doctor sees it. Tests replace it.
type Net struct {
	LookupHost  func(ctx context.Context, host string) ([]string, error)
	DialContext func(ctx context.Context, network, address string) (net.Conn, error)
	Now         func() time.Time
	InContainer func() bool
}

// RealNet is the real machine.
func RealNet() Net {
	dialer := &net.Dialer{Timeout: stepTimeout}
	return Net{
		LookupHost:  net.DefaultResolver.LookupHost,
		DialContext: dialer.DialContext,
		Now:         time.Now,
		InContainer: inContainer,
	}
}

// Options configures a run.
type Options struct {
	// Settings is nil when the settings did not load. LoadErr then says why.
	Settings *settings.Settings
	LoadErr  error
	Version  string
	// Short skips the checks that take time or add little at start: the datasource
	// queries and the question to a running proxy.
	Short bool
	// StatusURL is the /readyz address of a running proxy on this machine. Empty
	// means do not ask.
	StatusURL string
	Net       Net
}

// Run runs every check and returns the report. It never stops at the first failure:
// a check that depends on a failed one is marked skip.
func Run(ctx context.Context, options Options) *Report {
	if options.Net.LookupHost == nil {
		options.Net = RealNet()
	}
	run := &runner{Options: options, report: &Report{Version: options.Version}}
	run.config()
	if options.Settings == nil {
		return run.report
	}
	run.tellagen(ctx)
	run.grafana(ctx)
	if !options.Short {
		run.running(ctx)
	}
	return run.report
}

type runner struct {
	Options
	report *Report
	policy *policy.File
}

// fail adds a failed check. The public text for the code is what goes to
// Tellagen in the hello, and it names no address, path or host of this network.
func (r *runner) fail(check, code, message string, more ...string) {
	r.failPublic(check, code, publicText[code], message, more...)
}

func (r *runner) failPublic(check, code, public, message string, more ...string) {
	r.report.add(check, Fail, code, message, more...)
	r.report.Results[len(r.report.Results)-1].public = public
}

// config checks the settings, the secret files and the policy file.
func (r *runner) config() {
	if r.Settings == nil {
		var problems settings.Problems
		if errors.As(r.LoadErr, &problems) {
			for _, problem := range problems {
				r.fail("config", "config_invalid", problem, "Fix: correct the setting and run doctor again")
			}
			return
		}
		r.fail("config", "config_invalid", errorText(r.LoadErr), "Fix: correct the setting and run doctor again")
		return
	}
	s := r.Settings
	tokenOK := r.secret("Tellagen token", s.Token)
	r.secret("Grafana token", s.GrafanaToken)
	if tokenOK {
		value, _ := s.Token.Value()
		if id, _, ok := protocol.ParseToken(value); ok {
			hint := protocol.TokenHint(value)
			if hint == "" {
				hint = protocol.TokenPrefix + id
			}
			r.report.add("config", OK, "", fmt.Sprintf("token from %s (%s)", s.Token.Source(), hint))
		} else {
			r.fail("config", "token_shape", fmt.Sprintf("the value of %s is not a Tellagen proxy token", s.Token.Source()),
				"Fix: copy the whole token from Settings. It starts with "+protocol.TokenPrefix)
		}
	}
	if s.PolicyFile != "" {
		file, err := policy.Load(s.PolicyFile, s.AllowedDatasourceUIDs)
		if err != nil {
			r.fail("config", "policy_invalid", errorText(err), "Fix: correct the policy file. The proxy refuses to start with it")
		} else {
			r.policy = file
			r.report.add("config", OK, "", "policy file "+s.PolicyFile+" read")
		}
	}
}

// secret reports a secret whose file cannot be read, with who owns the file and
// which mode it has. It returns true when the secret has a value.
func (r *runner) secret(label string, secret *settings.Secret) bool {
	_, err := secret.Reload()
	if err == nil {
		return true
	}
	if !secret.FromFile() {
		r.fail("config", "secret_missing", label+" is not set", "Fix: set "+secret.Name()+" or "+secret.Name()+"_FILE")
		return false
	}
	state := settings.Inspect(secret.Path())
	switch {
	case !state.Exists || errors.Is(err, settings.ErrSecretMissing):
		r.fail("config", "secret_file_missing", fmt.Sprintf("%s (%s) is missing or empty", secret.Path(), secret.Source()),
			"Fix: check the mount, or the sidecar that writes this file")
	default:
		r.fail("config", "secret_file_unreadable", fmt.Sprintf("%s cannot be read by user %d (owner %d, mode %04o)", secret.Path(), state.ProcessUID, state.OwnerUID, uint32(state.Mode)),
			"Fix: run chmod 0644 on the file, or make user "+fmt.Sprint(state.ProcessUID)+" its owner.",
			"Docker Compose ignores uid and mode for file secrets")
	}
	return false
}

// running asks a proxy that runs on this machine how its polls go. A cut stream
// shows here, because only the running proxy holds polls.
func (r *runner) running(ctx context.Context) {
	if r.StatusURL == "" {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, r.StatusURL, nil)
	if err != nil {
		return
	}
	response, err := (&http.Client{Transport: &http.Transport{Proxy: nil}}).Do(request)
	if err != nil {
		r.report.add("poll", Skip, "", "no running proxy answers on "+hostOf(request.URL.Host)+" (normal before install)")
		return
	}
	defer func() { _ = response.Body.Close() }()
	var status struct {
		Ready    bool   `json:"ready"`
		Version  string `json:"version"`
		Mode     string `json:"mode"`
		Degraded bool   `json:"degraded"`
		Blocked  string `json:"blocked"`
	}
	// Another service may listen on the port. Only a proxy names its version.
	if json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&status) != nil || status.Version == "" {
		r.report.add("poll", Skip, "", "no running proxy answers on "+hostOf(request.URL.Host)+" (normal before install)")
		return
	}
	switch {
	case status.Blocked != "":
		r.fail("poll", "proxy_blocked", "the running proxy is stopped: "+status.Blocked, "Fix: do what the message says. The proxy tries again by itself")
	case status.Degraded:
		r.report.add("poll", Warn, "stream_cut", "held requests to Tellagen are being cut after a short time. The proxy switched to shorter polls",
			"A device on the path (often a proxy) ends long requests. Ask for requests of 30 seconds to be allowed for "+r.Settings.TellagenURL.Hostname())
	case !status.Ready:
		r.report.add("poll", Warn, "not_ready", "the running proxy is not connected to Tellagen yet", "Look at its log for the reason")
	default:
		r.report.add("poll", OK, "", "the running proxy polls normally ("+status.Mode+")")
	}
}

// errorText returns an error without the long Go prefixes that say nothing to a
// person.
func errorText(err error) string {
	if err == nil {
		return "unknown error"
	}
	text := err.Error()
	var op *net.OpError
	if errors.As(err, &op) && op.Err != nil {
		text = op.Err.Error()
	}
	var dns *net.DNSError
	if errors.As(err, &dns) {
		text = dns.Err
		if dns.IsNotFound {
			text = "no such host"
		}
	}
	if errors.Is(err, context.DeadlineExceeded) {
		text = "timed out"
	}
	return text
}

func inContainer() bool {
	if os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
		return true
	}
	for _, path := range []string{"/.dockerenv", "/run/.containerenv"} {
		if _, err := os.Stat(path); err == nil {
			return true
		}
	}
	return false
}
