package settings

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func serverCA(t *testing.T, server *httptest.Server) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ca.pem")
	block := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if err := os.WriteFile(path, block, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func settingsFor(t *testing.T, extra map[string]string) *Settings {
	t.Helper()
	values := validEnv()
	for key, value := range extra {
		values[key] = value
	}
	s, err := Load(envOf(values))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	return s
}

func get(t *testing.T, transport http.RoundTripper, target string) (*http.Response, error) {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, target, nil)
	if err != nil {
		t.Fatal(err)
	}
	return (&http.Client{Transport: transport}).Do(request)
}

func TestTellagenTransportTrustsTheCompanyCAInAdditionToSystemRoots(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") }))
	defer server.Close()

	without, err := settingsFor(t, nil).TellagenTransport()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := get(t, without, server.URL); err == nil {
		t.Fatal("a server with an unknown CA must fail without TELLAGEN_CA_FILE")
	}

	with, err := settingsFor(t, map[string]string{"TELLAGEN_CA_FILE": serverCA(t, server)}).TellagenTransport()
	if err != nil {
		t.Fatal(err)
	}
	response, err := get(t, with, server.URL)
	if err != nil {
		t.Fatalf("get() with TELLAGEN_CA_FILE error = %v", err)
	}
	_ = response.Body.Close()

	// Without a CA file the pool is the system pool. With one, the pool also trusts
	// the CA, which the system pool does not.
	roots, err := Roots(serverCA(t, server))
	if err != nil {
		t.Fatal(err)
	}
	system, err := Roots("")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := server.Certificate().Verify(x509.VerifyOptions{Roots: roots}); err != nil {
		t.Errorf("the pool with the CA does not trust it: %v", err)
	}
	if roots.Equal(system) {
		t.Error("adding a CA file must add a root")
	}
}

func TestRootsRejectsAFileWithoutCertificates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Roots(path); err == nil || !strings.Contains(err.Error(), "no PEM certificate") {
		t.Errorf("Roots() error = %v", err)
	}
	if _, err := Roots(path + ".absent"); err == nil {
		t.Error("Roots(missing file) must fail")
	}
	s := settingsFor(t, map[string]string{"TELLAGEN_CA_FILE": path})
	if _, err := s.TellagenTransport(); err == nil || !strings.Contains(err.Error(), "TELLAGEN_CA_FILE") {
		t.Errorf("TellagenTransport() error = %v, want it to name TELLAGEN_CA_FILE", err)
	}
	s = settingsFor(t, map[string]string{"GRAFANA_CA_FILE": path})
	if _, err := s.GrafanaTransport(); err == nil || !strings.Contains(err.Error(), "GRAFANA_CA_FILE") {
		t.Errorf("GrafanaTransport() error = %v, want it to name GRAFANA_CA_FILE", err)
	}
}

func TestTellagenTransportSpeaksHTTP11Only(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, r.Proto) }))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	transport, err := settingsFor(t, map[string]string{"TELLAGEN_CA_FILE": serverCA(t, server)}).TellagenTransport()
	if err != nil {
		t.Fatal(err)
	}
	response, err := get(t, transport, server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	body, _ := io.ReadAll(response.Body)
	if response.ProtoMajor != 1 || string(body) != "HTTP/1.1" {
		t.Errorf("protocol = %d, server saw %q, want HTTP/1.1", response.ProtoMajor, body)
	}
	if got := transport.TLSClientConfig.NextProtos; len(got) != 1 || got[0] != "http/1.1" {
		t.Errorf("NextProtos = %v", got)
	}
	if transport.TLSClientConfig.MinVersion < tls.VersionTLS12 {
		t.Error("TLS below 1.2 must be refused")
	}
}

func proxyFor(t *testing.T, proxy func(*url.URL) (*url.URL, error), target string) string {
	t.Helper()
	parsed, err := url.Parse(target)
	if err != nil {
		t.Fatal(err)
	}
	got, err := proxy(parsed)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		return ""
	}
	return got.Host
}

func TestTellagenTrafficFollowsHTTPSProxyAndNoProxy(t *testing.T) {
	s := settingsFor(t, map[string]string{"HTTPS_PROXY": "http://proxy.corp.example:3128", "NO_PROXY": ".corp.example,10.0.0.0/8"})
	proxy := s.ProxyFunc()
	for target, want := range map[string]string{
		"https://connect.tellagen.com":  "proxy.corp.example:3128",
		"https://intranet.corp.example": "",
		"https://10.1.2.3":              "",
		"https://localhost:8080":        "",
	} {
		if got := proxyFor(t, proxy, target); got != want {
			t.Errorf("proxy for %s = %q, want %q", target, got, want)
		}
	}
}

func TestGrafanaTrafficGoesDirectUnlessGrafanaHTTPSProxyIsSet(t *testing.T) {
	s := settingsFor(t, map[string]string{"HTTPS_PROXY": "http://proxy.corp.example:3128"})
	if got := proxyFor(t, s.GrafanaProxyFunc(), "https://grafana.customerdomain.net"); got != "" {
		t.Errorf("Grafana went through %q although only HTTPS_PROXY is set", got)
	}
	if got := proxyFor(t, s.ProxyFunc(), "https://grafana.customerdomain.net"); got == "" {
		t.Error("control: HTTPS_PROXY must apply to Tellagen traffic")
	}
	s = settingsFor(t, map[string]string{"HTTPS_PROXY": "http://proxy.corp.example:3128", "GRAFANA_HTTPS_PROXY": "http://graf.corp.example:3128", "NO_PROXY": ".internal"})
	if got := proxyFor(t, s.GrafanaProxyFunc(), "https://grafana.customerdomain.net"); got != "graf.corp.example:3128" {
		t.Errorf("Grafana proxy = %q, want graf.corp.example:3128", got)
	}
	if got := proxyFor(t, s.GrafanaProxyFunc(), "https://grafana.internal"); got != "" {
		t.Errorf("NO_PROXY must apply to Grafana too, got %q", got)
	}
}

func TestIsUnknownAuthorityNamesTheIssuer(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	transport, err := settingsFor(t, nil).TellagenTransport()
	if err != nil {
		t.Fatal(err)
	}
	_, err = get(t, transport, server.URL)
	issuer, ok := IsUnknownAuthority(err)
	if !ok || issuer == "" {
		t.Fatalf("IsUnknownAuthority(%v) = %q, %v", err, issuer, ok)
	}
	if _, ok := IsUnknownAuthority(io.EOF); ok {
		t.Error("IsUnknownAuthority(EOF) must be false")
	}
}
