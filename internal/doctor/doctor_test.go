package doctor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/tellagen/tellagen-proxy/internal/settings"
	"github.com/tellagen/tellagen-proxy/protocol"
)

func TestAllGoodOnAnOpenNetwork(t *testing.T) {
	lab := newLab(t)
	lab.serveTellagen(lab.pki)
	lab.serveGrafana()
	report := lab.run(nil)
	if report.Failed() {
		t.Fatalf("the run failed:\n%s", report.text())
	}
	text := report.text()
	for _, want := range []string{
		"tellagen-proxy doctor (1.0.0)\n",
		"[ok]   config   token from TELLAGEN_PROXY_TOKEN (tlg_proxy_01JD8K2A…cret)\n",
		"[ok]   dns      connect.tellagen.com -> 203.0.113.10\n",
		"[ok]   proxy    Tellagen direct, Grafana direct\n",
		"[ok]   tls      connect.tellagen.com presented a certificate that this machine trusts\n",
		"[ok]   auth     Tellagen accepted the token\n",
		"[ok]   grafana  http://grafana.customerdomain.net:3000 v12.2.1, org 1, role Viewer\n",
		"[warn] grafana  Viewer can query all 14 datasources in this org.\n         Consider GRAFANA_ALLOWED_DATASOURCE_UIDS\n",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("report lacks %q:\n%s", want, text)
		}
	}
	if !strings.Contains(text, "[ok]   grafana  prom-prod: vector(1) ") || !strings.Contains(text, ", loki-prod: labels ") {
		t.Errorf("report lacks the datasource queries:\n%s", text)
	}
	summary := report.Summary()
	if summary.TLS != protocol.DoctorOK || summary.Grafana != protocol.DoctorOK || summary.GrafanaRole != "Viewer" || len(summary.Warnings) != 1 || summary.Warnings[0] != "viewer_all_datasources" || len(summary.Failures) != 0 {
		t.Errorf("Summary() = %+v", summary)
	}
}

// The example on the research page: a TLS-inspecting proxy.
func TestInspectingProxyMatchesTheResearchPageExample(t *testing.T) {
	lab := newLab(t)
	zscaler := newPKI(t, "Zscaler Root CA")
	lab.serveTellagen(zscaler)
	lab.serveProxy(http.StatusOK)
	lab.serveGrafana()
	report := lab.run(map[string]string{
		"HTTPS_PROXY":                        "http://proxy.corp.example:3128",
		"TELLAGEN_CA_FILE":                   "",
		"TELLAGEN_PROXY_TOKEN":               "",
		"TELLAGEN_PROXY_TOKEN_FILE":          writeToken(t),
		"GRAFANA_ALLOWED_DATASOURCE_UIDS":    "prom-prod,loki-prod",
		"GRAFANA_SERVICE_ACCOUNT_TOKEN":      "",
		"GRAFANA_SERVICE_ACCOUNT_TOKEN_FILE": writeToken(t),
	})
	want := strings.Join([]string{
		"tellagen-proxy doctor (1.0.0)",
		"[ok]   config   token from TELLAGEN_PROXY_TOKEN_FILE (tlg_proxy_01JD8K2A…cret)",
		"[ok]   dns      connect.tellagen.com -> 203.0.113.10",
		"[ok]   proxy    Tellagen via http://proxy.corp.example:3128, Grafana direct",
		`[fail] tls      connect.tellagen.com presented "Zscaler Root CA" (TLS inspection)`,
		"         Fix: set TELLAGEN_CA_FILE to your inspection CA,",
		"         or ask for a bypass for connect.tellagen.com",
		"[skip] auth     needs tls",
	}, "\n")
	text := report.text()
	if !strings.HasPrefix(text, want+"\n") {
		t.Errorf("report does not match the example.\nwant prefix:\n%s\ngot:\n%s", want, text)
	}
	if !strings.Contains(text, "[ok]   grafana  http://grafana.customerdomain.net:3000 v12.2.1, org 1, role Viewer\n") ||
		!strings.Contains(text, "[ok]   grafana  prom-prod: vector(1) ") {
		t.Errorf("the Grafana lines are missing:\n%s", text)
	}
	if strings.Contains(text, "Viewer can query all") {
		t.Errorf("an allowlist is set, so the Viewer warning must not appear:\n%s", text)
	}
	if !report.Failed() {
		t.Error("a failed check must fail the run")
	}
	summary := report.Summary()
	if summary.TLS != protocol.DoctorFail || len(summary.Failures) != 1 || summary.Failures[0].Code != "tls_unknown_ca" {
		t.Fatalf("Summary() = %+v", summary)
	}
	if got := summary.Failures[0].Message; got != `TLS error: the certificate is signed by an unknown authority, "Zscaler Root CA".` {
		t.Errorf("failure message = %q", got)
	}
}

func writeToken(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte(labToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestTrustingTheInspectionCAMakesTLSPass(t *testing.T) {
	lab := newLab(t)
	zscaler := newPKI(t, "Zscaler Root CA")
	lab.serveTellagen(zscaler)
	lab.serveProxy(http.StatusOK)
	lab.serveGrafana()
	lab.pki = zscaler // the CA file now holds the inspection CA
	report := lab.run(map[string]string{"HTTPS_PROXY": "http://proxy.corp.example:3128"})
	if report.Failed() {
		t.Fatalf("the run failed:\n%s", report.text())
	}
}

func TestDNSFailure(t *testing.T) {
	lab := newLab(t)
	lab.serveGrafana()
	lab.lookupAs = func(host string) ([]string, error) {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	report := lab.run(nil)
	dns := report.result(t, "dns")
	if dns.Status != Fail || dns.Message != "cannot resolve connect.tellagen.com: no such host" || !strings.HasPrefix(dns.More[0], "Fix: check the DNS settings") {
		t.Errorf("dns result = %+v", dns)
	}
	if got := report.status("tcp"); got != Skip {
		t.Errorf("tcp = %s, want skip when DNS failed", got)
	}
	if got := report.status("auth"); got != Skip {
		t.Errorf("auth = %s, want skip", got)
	}
}

func TestDNSFailureBehindAProxyIsOnlyAWarning(t *testing.T) {
	lab := newLab(t)
	lab.serveTellagen(lab.pki)
	lab.serveProxy(http.StatusOK)
	lab.lookupAs = func(host string) ([]string, error) { return nil, errors.New("no such host") }
	report := lab.run(map[string]string{"HTTPS_PROXY": "http://proxy.corp.example:3128"})
	if got := report.result(t, "dns_via_proxy").Status; got != Warn {
		t.Errorf("dns = %s, want warn", got)
	}
	if report.status("auth") != OK {
		t.Errorf("the proxy resolves the name, so auth should pass:\n%s", report.text())
	}
}

func TestTCPBlocked(t *testing.T) {
	lab := newLab(t)
	lab.lookupAs = func(string) ([]string, error) { return []string{"203.0.113.10"}, nil }
	probe := lab.net()
	probe.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		return nil, &net.OpError{Op: "dial", Net: network, Err: context.DeadlineExceeded}
	}
	report := lab.run(nil, func(o *Options) { o.Net = probe })
	tcp := report.result(t, "tcp_blocked")
	if tcp.Message != "cannot open a TCP connection to connect.tellagen.com:443: timed out" || tcp.More[0] != "Fix: allow outbound TCP 443 to connect.tellagen.com, or set HTTPS_PROXY to your proxy" {
		t.Errorf("tcp result = %+v", tcp)
	}
	if report.status("tls") != Skip || report.status("auth") != Skip {
		t.Errorf("tls and auth must be skipped:\n%s", report.text())
	}
}

func TestProxyRefusals(t *testing.T) {
	cases := []struct {
		status  int
		code    string
		message string
		fix     string
	}{
		{http.StatusProxyAuthRequired, "proxy_407", "the proxy http://proxy.corp.example:3128 wants a login (407)", "Fix: put the credentials in HTTPS_PROXY, as http://user:password@host:port"},
		{http.StatusForbidden, "proxy_403", "the proxy http://proxy.corp.example:3128 blocks connect.tellagen.com (403)", "Fix: ask the proxy admin to allow connect.tellagen.com on port 443"},
		{http.StatusBadGateway, "proxy_error", "the proxy http://proxy.corp.example:3128 answered CONNECT with 502", "Fix: ask the proxy admin to allow connect.tellagen.com on port 443"},
	}
	for _, tc := range cases {
		t.Run(tc.code, func(t *testing.T) {
			lab := newLab(t)
			lab.serveProxy(tc.status)
			report := lab.run(map[string]string{"HTTPS_PROXY": "http://user:hunter2@proxy.corp.example:3128"})
			result := report.result(t, tc.code)
			if result.Check != "proxy" || result.Message != tc.message || result.More[0] != tc.fix {
				t.Errorf("result = %+v", result)
			}
			if strings.Contains(report.text(), "hunter2") {
				t.Errorf("the report prints the proxy password:\n%s", report.text())
			}
			lab.mu.Lock()
			defer lab.mu.Unlock()
			if len(lab.connect) != 1 || !strings.HasPrefix(lab.connect[0], "CONNECT connect.tellagen.com:443 auth=Basic ") {
				t.Errorf("the proxy saw %v, want one CONNECT with the credentials", lab.connect)
			}
		})
	}
}

func TestProxyUnreachable(t *testing.T) {
	lab := newLab(t)
	report := lab.run(map[string]string{"HTTPS_PROXY": "http://proxy.corp.example:3128"})
	result := report.result(t, "proxy_unreachable")
	if result.Check != "proxy" || !strings.HasPrefix(result.Message, "cannot connect to the proxy http://proxy.corp.example:3128:") || result.More[0] != "Fix: check HTTPS_PROXY, and that this host may reach the proxy" {
		t.Errorf("result = %+v", result)
	}
}

func TestProxySchemesThatAreNotProbed(t *testing.T) {
	lab := newLab(t)
	report := lab.run(map[string]string{"HTTPS_PROXY": "socks5://proxy.corp.example:1080"})
	if got := report.status("proxy"); got != Skip {
		t.Errorf("proxy = %s, want skip", got)
	}
}

func TestExpiredAndMismatchedCertificates(t *testing.T) {
	lab := newLab(t)
	lab.pki = newPKI(t, "Expired Test CA")
	// A leaf that is no longer valid.
	expired := lab.pki.leaf("connect.tellagen.com", time.Now().Add(-time.Minute))
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	server.TLS = serverTLS(expired)
	server.StartTLS()
	t.Cleanup(server.Close)
	lab.routes[tellagenHost+":443"] = server.Listener.Addr().String()
	report := lab.run(nil)
	if got := report.result(t, "tls_time").Status; got != Fail {
		t.Errorf("tls_time = %s", got)
	}

	other := newLab(t)
	wrong := other.pki.leaf("someone-else.example", time.Now().Add(time.Hour))
	server = httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	server.TLS = serverTLS(wrong)
	server.StartTLS()
	t.Cleanup(server.Close)
	other.routes[tellagenHost+":443"] = server.Listener.Addr().String()
	report = other.run(nil)
	if got := report.result(t, "tls_hostname").Status; got != Fail {
		t.Errorf("tls_hostname = %s", got)
	}
}

func TestClockSkew(t *testing.T) {
	lab := newLab(t)
	lab.serveTellagen(lab.pki)
	lab.serveGrafana()
	lab.tellagen = func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, protocol.SessionReply{SessionToken: protocol.SessionTokenPrefix + "s1", ExpiresAt: time.Now().Add(time.Hour), ServerTime: time.Now().Add(7 * time.Minute)})
	}
	report := lab.run(nil)
	skew := report.result(t, "clock_skew")
	if skew.Check != "clock" || skew.Status != Fail || !strings.HasPrefix(skew.Message, "this machine's clock differs from Tellagen's by 7m") || !strings.Contains(skew.More[0], "NTP") {
		t.Errorf("skew result = %+v", skew)
	}
}

func TestSessionRefusals(t *testing.T) {
	revokedAt := time.Date(2026, 11, 4, 10, 20, 0, 0, time.UTC)
	cases := map[string]struct {
		status  int
		reply   any
		code    string
		check   string
		message string
		fix     string
	}{
		"revoked": {http.StatusUnauthorized, protocol.ErrorReply{Code: protocol.ErrorRevoked, RevokedAt: &revokedAt},
			"token_revoked", "auth", "this proxy token was revoked on 2026-11-04 10:20 UTC", "Fix: create a new proxy token in Settings and put it in TELLAGEN_PROXY_TOKEN"},
		"revoked without a time": {http.StatusUnauthorized, protocol.ErrorReply{Code: protocol.ErrorRevoked},
			"token_revoked", "auth", "this proxy token was revoked", "Fix: create a new proxy token in Settings and put it in TELLAGEN_PROXY_TOKEN"},
		"invalid": {http.StatusUnauthorized, protocol.ErrorReply{Code: protocol.ErrorTokenInvalid},
			"token_invalid", "auth", "Tellagen does not accept this token (401)", "Fix: copy the token again from Settings. A rotated-out token fails this way"},
		"too old": {http.StatusUpgradeRequired, protocol.ErrorReply{Code: protocol.ErrorUpgradeRequired, MinVersion: "1.2.0"},
			"version_too_old", "version", "this proxy 1.0.0 is too old. Tellagen needs 1.2.0 or later", "Fix: run a newer image. The install commands in Settings pin the right version"},
		"suspended": {http.StatusForbidden, protocol.ErrorReply{Code: protocol.ErrorCompanyDisabled},
			"company_disabled", "auth", "Tellagen refused the proxy (403): the workspace is suspended", "Fix: ask a workspace admin"},
		"cloud diagnosis off": {http.StatusForbidden, protocol.ErrorReply{Code: protocol.ErrorCloudDiagnosisDisabled},
			"cloud_diagnosis_disabled", "auth", "Tellagen refused the proxy (403): Cloud diagnosis is switched off for this workspace", "Fix: ask a workspace admin to turn it on. The proxy keeps trying and starts again when it is on"},
		"something else answers": {http.StatusBadGateway, nil,
			"auth_unexpected", "auth", "the token exchange got an answer that is not Tellagen's (502)", "Fix: a device on the path may be answering for Tellagen, such as a proxy login page. Ask for a bypass"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			lab := newLab(t)
			lab.serveTellagen(lab.pki)
			lab.tellagen = func(w http.ResponseWriter, r *http.Request) {
				if tc.reply == nil {
					w.WriteHeader(tc.status)
					return
				}
				writeJSON(w, tc.status, tc.reply)
			}
			report := lab.run(nil)
			result := report.result(t, tc.code)
			if result.Check != tc.check || result.Status != Fail || result.Message != tc.message || result.More[0] != tc.fix {
				t.Errorf("result = %+v", result)
			}
			if strings.Contains(report.text(), "secretsecret") {
				t.Errorf("the report prints the token secret:\n%s", report.text())
			}
		})
	}
}

func TestAnExchangeThatNeverCompletes(t *testing.T) {
	lab := newLab(t)
	lab.serveTellagen(lab.pki)
	lab.tellagen = func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html>Please log in</html>"))
	}
	report := lab.run(nil)
	result := report.result(t, "auth_unreachable")
	if result.Status != Fail || !strings.HasPrefix(result.Message, "the token exchange did not complete:") {
		t.Errorf("result = %+v", result)
	}
}

func TestRunningProxyReportsACutStream(t *testing.T) {
	cases := map[string]struct {
		body   string
		status Status
		code   string
	}{
		"cut":     {`{"ready":true,"version":"1.0.0","mode":"short_poll","degraded":true}`, Warn, "stream_cut"},
		"blocked": {`{"ready":false,"version":"1.0.0","blocked":"This proxy was revoked."}`, Fail, "proxy_blocked"},
		"waiting": {`{"ready":false,"version":"1.0.0"}`, Warn, "not_ready"},
		"fine":    {`{"ready":true,"version":"1.0.0","mode":"long_poll"}`, OK, ""},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			lab := newLab(t)
			lab.serveTellagen(lab.pki)
			lab.serveGrafana()
			status := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = fmt.Fprint(w, tc.body) }))
			defer status.Close()
			report := lab.run(nil, func(o *Options) { o.StatusURL = status.URL + "/readyz" })
			var result Result
			for _, candidate := range report.Results {
				if candidate.Check == "poll" {
					result = candidate
				}
			}
			if result.Status != tc.status || result.Code != tc.code {
				t.Errorf("poll result = %+v, want %s %s", result, tc.status, tc.code)
			}
			if tc.code == "stream_cut" && !strings.Contains(result.Message, "cut") {
				t.Errorf("message = %q", result.Message)
			}
			if tc.status == Warn && report.Failed() {
				t.Error("a warning must not fail the run")
			}
		})
	}
}

func TestAnotherServiceOnThePortIsNotAProxy(t *testing.T) {
	lab := newLab(t)
	lab.serveTellagen(lab.pki)
	lab.serveGrafana()
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = fmt.Fprint(w, `{"status":"UP"}`) }))
	defer other.Close()
	report := lab.run(nil, func(o *Options) { o.StatusURL = other.URL + "/readyz" })
	if got := report.status("poll"); got != Skip {
		t.Errorf("poll = %s, want skip:\n%s", got, report.text())
	}
}

func TestNoRunningProxyIsNotAProblem(t *testing.T) {
	lab := newLab(t)
	lab.serveTellagen(lab.pki)
	lab.serveGrafana()
	report := lab.run(nil, func(o *Options) { o.StatusURL = "http://127.0.0.1:1/readyz" })
	if report.Failed() || report.status("poll") != Skip {
		t.Errorf("report:\n%s", report.text())
	}
}

func TestShortRunSkipsTheQueriesAndTheQuestionToARunningProxy(t *testing.T) {
	lab := newLab(t)
	lab.serveTellagen(lab.pki)
	lab.serveGrafana()
	report := lab.run(nil, func(o *Options) { o.Short = true; o.StatusURL = "http://127.0.0.1:1/readyz" })
	text := report.text()
	if strings.Contains(text, "vector(1)") || strings.Contains(text, "poll ") {
		t.Errorf("a short run must skip the queries and the status check:\n%s", text)
	}
	if report.Failed() {
		t.Errorf("report:\n%s", text)
	}
}

func TestGrafanaFailures(t *testing.T) {
	cases := map[string]struct {
		extra   map[string]string
		handler func(w http.ResponseWriter, r *http.Request)
		code    string
		message string
		fix     string
		public  string
	}{
		"token rejected": {nil, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/api/health" {
				_, _ = fmt.Fprint(w, `{"version":"12.2.1"}`)
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
		}, "grafana_unauthorized", "Grafana rejected the token (401) (grafana.customerdomain.net:3000)",
			"Fix: create a new service account token in Grafana (an expired token fails this way)", "Grafana rejected the token (401)."},
		"login page": {nil, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusBadGateway) },
			"grafana_http_error", "Grafana answered 502 (grafana.customerdomain.net:3000)",
			"Fix: check that GRAFANA_URL points at Grafana and not at a login page or another service", "Grafana answered 502."},
		"wrong org": {map[string]string{"GRAFANA_ORG_ID": "2"}, nil, "grafana_wrong_org",
			"the token belongs to org 1 (Main Org.), but GRAFANA_ORG_ID is 2", "Fix: create the service account in org 2, or change GRAFANA_ORG_ID",
			"The Grafana token belongs to another org than GRAFANA_ORG_ID."},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			lab := newLab(t)
			lab.serveTellagen(lab.pki)
			if tc.handler != nil {
				lab.grafana = tc.handler
			}
			lab.serveGrafana()
			report := lab.run(tc.extra)
			result := report.result(t, tc.code)
			if result.Check != "grafana" || result.Status != Fail || result.Message != tc.message || result.More[0] != tc.fix {
				t.Errorf("result = %+v", result)
			}
			summary := report.Summary()
			if summary.Grafana != protocol.DoctorFail {
				t.Errorf("summary.Grafana = %s", summary.Grafana)
			}
			if got := summary.Failures[len(summary.Failures)-1].Message; got != tc.public {
				t.Errorf("public message = %q, want %q", got, tc.public)
			}
			for _, failure := range summary.Failures {
				if strings.Contains(failure.Message, "grafana.customerdomain.net") {
					t.Errorf("the hello would tell Tellagen the Grafana address: %q", failure.Message)
				}
			}
		})
	}
}

func TestGrafanaUnreachable(t *testing.T) {
	lab := newLab(t)
	lab.serveTellagen(lab.pki)
	report := lab.run(nil)
	result := report.result(t, "grafana_unreachable")
	if result.Status != Fail || result.Check != "grafana" {
		t.Errorf("result = %+v", result)
	}
}

func TestGrafanaRefusingTheConnection(t *testing.T) {
	lab := newLab(t)
	lab.serveTellagen(lab.pki)
	probe := lab.net()
	probe.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if address == grafanaHost {
			return nil, &net.OpError{Op: "dial", Net: network, Err: syscall.ECONNREFUSED}
		}
		return lab.net().DialContext(ctx, network, address)
	}
	report := lab.run(nil, func(o *Options) { o.Net = probe })
	result := report.result(t, "grafana_refused")
	if result.More[0] != "Fix: check the host and port in GRAFANA_URL. Grafana must listen where the proxy can reach it" {
		t.Errorf("result = %+v", result)
	}
}

func TestLocalhostInsideAContainer(t *testing.T) {
	lab := newLab(t)
	lab.serveTellagen(lab.pki)
	probe := lab.net()
	probe.InContainer = func() bool { return true }
	probe.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if strings.HasPrefix(address, "localhost:") {
			return nil, &net.OpError{Op: "dial", Net: network, Err: syscall.ECONNREFUSED}
		}
		return lab.net().DialContext(ctx, network, address)
	}
	report := lab.run(map[string]string{"GRAFANA_URL": "http://localhost:3000"}, func(o *Options) { o.Net = probe })
	result := report.result(t, "grafana_localhost")
	if result.Status != Fail || result.Message != "GRAFANA_URL points to localhost, which inside a container is the container itself" ||
		!strings.Contains(result.More[0], "host.docker.internal") || !strings.Contains(result.More[1], "grafana.monitoring.svc") {
		t.Errorf("result = %+v", result)
	}
	// Outside a container the same refusal is an ordinary one.
	probe.InContainer = func() bool { return false }
	report = lab.run(map[string]string{"GRAFANA_URL": "http://localhost:3000"}, func(o *Options) { o.Net = probe })
	report.result(t, "grafana_refused")
}

func TestGrafanaRoles(t *testing.T) {
	for _, role := range []string{"Editor", "Admin"} {
		t.Run(role, func(t *testing.T) {
			lab := newLab(t)
			lab.serveTellagen(lab.pki)
			lab.grafana = func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/user/orgs" {
					_, _ = fmt.Fprintf(w, `[{"orgId":1,"role":%q}]`, role)
					return
				}
				lab.defaultGrafana(w, r)
			}
			lab.serveGrafana()
			report := lab.run(nil)
			warn := report.result(t, "role_too_broad")
			if warn.Status != Warn || !strings.Contains(warn.Message, role) {
				t.Errorf("warn = %+v", warn)
			}
			if report.Failed() {
				t.Errorf("a broad role is a warning:\n%s", report.text())
			}
		})
	}
	t.Run("None gets no warning", func(t *testing.T) {
		lab := newLab(t)
		lab.serveTellagen(lab.pki)
		lab.grafana = func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/api/user/orgs" {
				_, _ = fmt.Fprint(w, `[{"orgId":1,"role":"None"}]`)
				return
			}
			lab.defaultGrafana(w, r)
		}
		lab.serveGrafana()
		report := lab.run(nil)
		for _, result := range report.Results {
			if result.Status == Warn {
				t.Errorf("unexpected warning %+v", result)
			}
		}
	})
}

func TestViewerWarningIsSilentWithAnAllowlistInEnvOrPolicyFile(t *testing.T) {
	lab := newLab(t)
	lab.serveTellagen(lab.pki)
	lab.serveGrafana()
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policyPath, []byte("datasourceUIDs: [prom-prod]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	report := lab.run(map[string]string{"TELLAGEN_POLICY_FILE": policyPath})
	for _, result := range report.Results {
		if result.Code == "viewer_all_datasources" {
			t.Errorf("a policy file allowlist must silence the warning:\n%s", report.text())
		}
	}
	if !strings.Contains(report.text(), "policy file "+policyPath+" read") {
		t.Errorf("the policy file is not reported:\n%s", report.text())
	}
	// Only the allowed datasource is queried.
	if strings.Contains(report.text(), "loki-prod") {
		t.Errorf("a datasource outside the policy was queried:\n%s", report.text())
	}
}

func TestDatasourceQueryFailureIsAWarning(t *testing.T) {
	lab := newLab(t)
	lab.serveTellagen(lab.pki)
	lab.grafana = func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/datasources/proxy/") {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		lab.defaultGrafana(w, r)
	}
	lab.serveGrafana()
	report := lab.run(map[string]string{"GRAFANA_ALLOWED_DATASOURCE_UIDS": "prom-prod"})
	warn := report.result(t, "datasource_query_failed")
	if warn.Status != Warn || !strings.Contains(warn.Message, "prom-prod") {
		t.Errorf("warn = %+v", warn)
	}
	if report.Failed() {
		t.Errorf("report:\n%s", report.text())
	}
}

func TestUnreadableSecretFile(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root can read any file")
	}
	lab := newLab(t)
	path := writeToken(t)
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatal(err)
	}
	report := lab.run(map[string]string{"TELLAGEN_PROXY_TOKEN": "", "TELLAGEN_PROXY_TOKEN_FILE": path})
	result := report.result(t, "secret_file_unreadable")
	want := fmt.Sprintf("%s cannot be read by user %d (owner %d, mode 0000)", path, os.Getuid(), os.Getuid())
	if result.Check != "config" || result.Status != Fail || result.Message != want {
		t.Errorf("result = %+v, want message %q", result, want)
	}
	if !strings.HasPrefix(result.More[0], "Fix: run chmod 0644 on the file") || !strings.Contains(result.More[1], "Docker Compose ignores uid and mode") {
		t.Errorf("result = %+v", result)
	}
}

func TestMissingSecretFile(t *testing.T) {
	lab := newLab(t)
	path := filepath.Join(t.TempDir(), "absent")
	report := lab.run(map[string]string{"GRAFANA_SERVICE_ACCOUNT_TOKEN": "", "GRAFANA_SERVICE_ACCOUNT_TOKEN_FILE": path})
	result := report.result(t, "secret_file_missing")
	if result.Message != path+" (GRAFANA_SERVICE_ACCOUNT_TOKEN_FILE) is missing or empty" {
		t.Errorf("result = %+v", result)
	}
}

func TestSettingsThatDoNotLoad(t *testing.T) {
	lab := newLab(t)
	report := lab.run(map[string]string{"TELLAGEN_PROXY_TOKEN_FILE": "/run/secrets/token", "GRAFANA_URL": ""})
	if len(report.Results) != 2 {
		t.Fatalf("results = %+v, want one config line per problem and nothing else", report.Results)
	}
	for _, result := range report.Results {
		if result.Check != "config" || result.Status != Fail || result.Code != "config_invalid" {
			t.Errorf("result = %+v", result)
		}
	}
	if !strings.Contains(report.text(), "TELLAGEN_PROXY_TOKEN and TELLAGEN_PROXY_TOKEN_FILE are both set") {
		t.Errorf("report:\n%s", report.text())
	}
}

func TestInvalidTokenShapeInAFile(t *testing.T) {
	lab := newLab(t)
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("not a token"), 0o600); err != nil {
		t.Fatal(err)
	}
	report := lab.run(map[string]string{"TELLAGEN_PROXY_TOKEN": "", "TELLAGEN_PROXY_TOKEN_FILE": path})
	if got := report.result(t, "token_shape"); got.Status != Fail {
		t.Errorf("result = %+v", got)
	}
}

func TestInvalidPolicyFile(t *testing.T) {
	lab := newLab(t)
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte("query: {maxTimeout: soon}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	report := lab.run(map[string]string{"TELLAGEN_POLICY_FILE": path})
	result := report.result(t, "policy_invalid")
	if result.Status != Fail || result.More[0] != "Fix: correct the policy file. The proxy refuses to start with it" {
		t.Errorf("result = %+v", result)
	}
}

func TestCAFilesThatAreNotPEM(t *testing.T) {
	lab := newLab(t)
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, []byte("nope"), 0o600); err != nil {
		t.Fatal(err)
	}
	report := lab.run(map[string]string{"GRAFANA_CA_FILE": path, "TELLAGEN_CA_FILE": path})
	if report.status("tls") != Fail && report.status("auth") != Fail {
		t.Logf("report:\n%s", report.text())
	}
	grafana := report.result(t, "ca_file")
	if grafana.Status != Fail {
		t.Errorf("result = %+v", grafana)
	}
}

func TestSummaryNeverCarriesAddressesPathsOrNames(t *testing.T) {
	lab := newLab(t)
	zscaler := newPKI(t, "Zscaler Root CA")
	lab.serveTellagen(zscaler)
	lab.serveProxy(http.StatusOK)
	report := lab.run(map[string]string{"HTTPS_PROXY": "http://proxy.corp.example:3128", "TELLAGEN_CA_FILE": ""})
	encoded, err := json.Marshal(report.Summary())
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"proxy.corp.example", "grafana.customerdomain.net", "/tmp", labToken} {
		if strings.Contains(string(encoded), secret) {
			t.Errorf("the summary holds %q: %s", secret, encoded)
		}
	}
}

func TestWriteJSONIsRedacted(t *testing.T) {
	lab := newLab(t)
	lab.serveTellagen(lab.pki)
	lab.serveGrafana()
	report := lab.run(map[string]string{"HTTPS_PROXY": ""})
	var out strings.Builder
	if err := report.WriteJSON(&out); err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Version string   `json:"version"`
		Results []Result `json:"results"`
	}
	if err := json.Unmarshal([]byte(out.String()), &decoded); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	if decoded.Version != "1.0.0" || len(decoded.Results) == 0 {
		t.Errorf("decoded = %+v", decoded)
	}
	for _, secret := range []string{"secretsecret", "glsa_secret"} {
		if strings.Contains(out.String(), secret) {
			t.Errorf("the JSON report holds %q", secret)
		}
	}
	if strings.Contains(out.String(), `"public"`) {
		t.Error("the hello sentence must not leak into the JSON report")
	}
}

func TestSettingsProblemsKeepTheirOrderInTheReport(t *testing.T) {
	var problems settings.Problems = []string{"first", "second"}
	report := Run(t.Context(), Options{LoadErr: problems, Version: "1.0.0"})
	if len(report.Results) != 2 || report.Results[0].Message != "first" || report.Results[1].Message != "second" {
		t.Errorf("results = %+v", report.Results)
	}
	other := Run(t.Context(), Options{LoadErr: errors.New("boom"), Version: "1.0.0"})
	if len(other.Results) != 1 || other.Results[0].Message != "boom" {
		t.Errorf("results = %+v", other.Results)
	}
}
