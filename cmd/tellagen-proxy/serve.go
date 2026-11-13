package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os/signal"
	"syscall"

	"github.com/tellagen/tellagen-proxy/internal/agent"
	"github.com/tellagen/tellagen-proxy/internal/doctor"
	"github.com/tellagen/tellagen-proxy/internal/executor"
	"github.com/tellagen/tellagen-proxy/internal/grafana"
	"github.com/tellagen/tellagen-proxy/internal/hub"
	"github.com/tellagen/tellagen-proxy/internal/policy"
	"github.com/tellagen/tellagen-proxy/internal/settings"
	"github.com/tellagen/tellagen-proxy/protocol"
)

// serve runs the proxy until it gets SIGINT or SIGTERM.
func serve(env settings.Environment, stdout, stderr io.Writer) int {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return runProxy(ctx, env, stdout, stderr, nil)
}

// runProxy runs the proxy until ctx ends. started, when set, is called with the
// address of the health endpoint once it listens.
func runProxy(ctx context.Context, env settings.Environment, stdout, stderr io.Writer, started func(healthAddr string)) int {
	logger := slog.New(slog.NewJSONHandler(stderr, nil))
	s, err := settings.Load(env)
	if err != nil {
		var problems settings.Problems
		if errors.As(err, &problems) {
			_, _ = fmt.Fprintln(stderr, err)
		} else {
			logger.Error("cannot load the settings", "error", err)
		}
		_, _ = fmt.Fprintln(stderr, "Run tellagen-proxy doctor for a check with the fix for each problem.")
		return exitFailed
	}
	proxy, err := build(s, logger, stdout)
	if err != nil {
		logger.Error("cannot start", "error", err)
		return exitFailed
	}
	listener, err := net.Listen("tcp", s.HealthAddr)
	if err != nil {
		logger.Error("cannot open the health port", "addr", s.HealthAddr, "error", err)
		return exitFailed
	}
	logger.Info("tellagen-proxy starting", "version", version, "instance", s.InstanceID, "health", listener.Addr().String())
	if started != nil {
		started(listener.Addr().String())
	}
	if err := proxy.Run(ctx, listener); err != nil {
		logger.Error("tellagen-proxy stopped", "error", err)
		return exitFailed
	}
	logger.Info("tellagen-proxy stopped")
	return exitOK
}

// build wires the agent from the settings.
func build(s *settings.Settings, logger *slog.Logger, audit io.Writer) (*agent.Agent, error) {
	tellagenTransport, err := s.TellagenTransport()
	if err != nil {
		return nil, err
	}
	grafanaTransport, err := s.GrafanaTransport()
	if err != nil {
		return nil, err
	}
	file, err := policy.Load(s.PolicyFile, s.AllowedDatasourceUIDs)
	if err != nil {
		return nil, err
	}
	engine := policy.NewEngine(file)
	runner, err := executor.New(executor.Config{
		GrafanaURL: s.GrafanaURL.String(),
		PublicURL:  s.GrafanaPublicURL,
		OrgID:      s.GrafanaOrgID,
		Token:      s.GrafanaToken.Value,
		Transport:  grafanaTransport,
		Policy:     engine,
	})
	if err != nil {
		return nil, err
	}
	client := hub.New(hub.Config{BaseURL: s.TellagenURL, Transport: tellagenTransport, Token: s.Token, Version: version})
	reader := grafana.New(grafana.Config{BaseURL: s.GrafanaURL, Transport: grafanaTransport, Token: s.GrafanaToken.Value, OrgID: s.GrafanaOrgID})

	return agent.New(agent.Config{
		Version:       version,
		InstanceID:    s.InstanceID,
		InstallMethod: s.InstallMethod,
		Labels:        s.Labels,
		PublicURL:     s.GrafanaPublicURL,
		Backend:       client,
		Executor:      runner,
		Policy:        policyView{engine},
		Grafana:       reader,
		Doctor: func(ctx context.Context) protocol.Doctor {
			return doctor.Run(ctx, doctor.Options{Settings: s, Version: version, Short: true}).Summary()
		},
		Secrets: s.Secrets(),
		Audit:   audit,
		Logger:  logger,
	}), nil
}

// policyView adapts the policy engine to the agent. Every call reads the current
// policy.
type policyView struct{ engine *policy.Engine }

func (p policyView) Revision() string { return p.engine.Current().Revision() }

func (p policyView) RedactionOff() bool { return p.engine.Current().RedactionOff() }

func (p policyView) Capabilities() []protocol.Capability {
	return p.engine.Current().Capabilities()
}

func (p policyView) Report() protocol.PolicyReport { return p.engine.Current().Report() }

// statusURL is the /readyz address of the proxy on this machine.
func statusURL(healthAddr string) string {
	host, port, err := net.SplitHostPort(healthAddr)
	if err != nil {
		return ""
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	return "http://" + net.JoinHostPort(host, port) + "/readyz"
}

func runDoctor(args []string, env settings.Environment, stdout, stderr io.Writer) int {
	asJSON := false
	for _, arg := range args {
		if arg != "--json" {
			_, _ = fmt.Fprintf(stderr, "unknown option %q\n%s", arg, usageString)
			return exitUsage
		}
		asJSON = true
	}
	s, loadErr := settings.Load(env)
	options := doctor.Options{Settings: s, LoadErr: loadErr, Version: version}
	if s != nil {
		options.StatusURL = statusURL(s.HealthAddr)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	report := doctor.Run(ctx, options)
	if asJSON {
		if err := report.WriteJSON(stdout); err != nil {
			_, _ = fmt.Fprintln(stderr, "cannot write the report:", err)
			return exitFailed
		}
	} else {
		report.Write(stdout)
	}
	if report.Failed() {
		return exitFailed
	}
	return exitOK
}
