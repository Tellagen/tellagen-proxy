package grafana

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"syscall"
	"testing"
)

type fakeGrafana struct {
	server  *httptest.Server
	role    string
	orgID   int64
	status  map[string]int
	headers []http.Header
}

func newFakeGrafana(t *testing.T) *fakeGrafana {
	f := &fakeGrafana{role: "Viewer", orgID: 1, status: map[string]int{}}
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.headers = append(f.headers, r.Header.Clone())
		if status := f.status[r.URL.Path]; status != 0 {
			w.WriteHeader(status)
			return
		}
		switch r.URL.Path {
		case "/api/health":
			_, _ = fmt.Fprint(w, `{"database":"ok","version":"12.2.1"}`)
		case "/api/datasources":
			_, _ = fmt.Fprint(w, `[{"uid":"prom-prod","name":"Prometheus prod","type":"prometheus","isDefault":true,"url":"http://10.0.0.5:9090"},{"uid":"loki-prod","name":"Loki prod","type":"loki"}]`)
		case "/api/user":
			_, _ = fmt.Fprint(w, `{"login":"sa-tellagen-proxy"}`)
		case "/api/org":
			_, _ = fmt.Fprintf(w, `{"id":%d,"name":"Main Org."}`, f.orgID)
		case "/api/user/orgs":
			_, _ = fmt.Fprintf(w, `[{"orgId":99,"role":"Admin"},{"orgId":%d,"role":%q}]`, f.orgID, f.role)
		case "/api/datasources/proxy/uid/prom-prod/api/v1/query":
			if r.URL.Query().Get("query") != "vector(1)" {
				w.WriteHeader(http.StatusBadRequest)
			}
			_, _ = fmt.Fprint(w, `{"status":"success"}`)
		case "/api/datasources/proxy/uid/loki-prod/loki/api/v1/labels":
			_, _ = fmt.Fprint(w, `{"status":"success"}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeGrafana) client(t *testing.T, orgID int64) *Client {
	base, err := url.Parse(f.server.URL)
	if err != nil {
		t.Fatal(err)
	}
	return New(Config{BaseURL: base, Transport: http.DefaultTransport, Token: func() (string, error) { return "glsa_secret", nil }, OrgID: orgID})
}

func TestHealthNeedsNoLogin(t *testing.T) {
	f := newFakeGrafana(t)
	health, err := f.client(t, 0).Health(t.Context())
	if err != nil || health.Version != "12.2.1" {
		t.Fatalf("Health() = %+v, %v", health, err)
	}
	if got := f.headers[0].Get("Authorization"); got != "" {
		t.Errorf("health sent Authorization %q, want none", got)
	}
}

func TestDatasourcesSendTheTokenAndOrgAndSkipTheAddress(t *testing.T) {
	f := newFakeGrafana(t)
	list, err := f.client(t, 4).Datasources(t.Context())
	if err != nil || len(list) != 2 {
		t.Fatalf("Datasources() = %v, %v", list, err)
	}
	if list[0].UID != "prom-prod" || !list[0].Default || list[1].Type != "loki" {
		t.Errorf("Datasources() = %+v", list)
	}
	if got := f.headers[0].Get("Authorization"); got != "Bearer glsa_secret" {
		t.Errorf("Authorization = %q", got)
	}
	if got := f.headers[0].Get("X-Grafana-Org-Id"); got != "4" {
		t.Errorf("X-Grafana-Org-Id = %q", got)
	}
}

func TestIdentityFindsTheRoleOfTheCurrentOrg(t *testing.T) {
	f := newFakeGrafana(t)
	f.role, f.orgID = "Editor", 7
	identity, err := f.client(t, 0).Identity(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if identity.Role != "Editor" || identity.OrgID != 7 || identity.OrgName != "Main Org." || identity.Login != "sa-tellagen-proxy" {
		t.Errorf("Identity() = %+v", identity)
	}
}

func TestIdentityWithoutOrgListHasNoRoleAndNoError(t *testing.T) {
	f := newFakeGrafana(t)
	f.status["/api/user/orgs"] = http.StatusForbidden
	identity, err := f.client(t, 0).Identity(t.Context())
	if err != nil || identity.Role != "" {
		t.Errorf("Identity() = %+v, %v, want an unknown role and no error", identity, err)
	}
}

func TestIdentityRejectedToken(t *testing.T) {
	f := newFakeGrafana(t)
	f.status["/api/user"] = http.StatusUnauthorized
	_, err := f.client(t, 0).Identity(t.Context())
	failure := Explain(err)
	if failure.Code != CodeUnauthorized || !failure.Auth || failure.Message != "Grafana rejected the token (401)" {
		t.Errorf("Explain(%v) = %+v", err, failure)
	}
}

func TestSmokeQueriesPrometheusAndLoki(t *testing.T) {
	f := newFakeGrafana(t)
	client := f.client(t, 0)
	query, latency, err := client.Smoke(t.Context(), Datasource{UID: "prom-prod", Type: "prometheus"})
	if err != nil || query != "vector(1)" || latency < 0 {
		t.Errorf("Smoke(prometheus) = %q, %s, %v", query, latency, err)
	}
	query, _, err = client.Smoke(t.Context(), Datasource{UID: "loki-prod", Type: "loki"})
	if err != nil || query != "labels" {
		t.Errorf("Smoke(loki) = %q, %v", query, err)
	}
	if _, _, err := client.Smoke(t.Context(), Datasource{UID: "x", Type: "mysql"}); err == nil {
		t.Error("Smoke(mysql) must refuse")
	}
}

func TestRedirectsAreNotFollowed(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { t.Error("the redirect was followed") }))
	defer target.Close()
	redirecting := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer redirecting.Close()
	base, _ := url.Parse(redirecting.URL)
	client := New(Config{BaseURL: base, Transport: http.DefaultTransport, Token: func() (string, error) { return "t", nil }})
	_, err := client.Datasources(t.Context())
	var status *StatusError
	if !errors.As(err, &status) || status.Status != http.StatusFound {
		t.Errorf("Datasources() error = %v, want a 302 status error", err)
	}
}

func TestTokenReadFailureIsReported(t *testing.T) {
	f := newFakeGrafana(t)
	base, _ := url.Parse(f.server.URL)
	client := New(Config{BaseURL: base, Transport: http.DefaultTransport, Token: func() (string, error) { return "", errors.New("file gone") }})
	if _, err := client.Datasources(t.Context()); err == nil || !strings.Contains(err.Error(), "read the Grafana token") {
		t.Errorf("Datasources() error = %v", err)
	}
}

func TestExplain(t *testing.T) {
	unknownCA := x509.UnknownAuthorityError{Cert: &x509.Certificate{}}
	cases := []struct {
		name     string
		err      error
		wantCode string
		wantAuth bool
	}{
		{"401", &StatusError{Status: 401}, CodeUnauthorized, true},
		{"403", &StatusError{Status: 403}, CodeForbidden, true},
		{"502", &StatusError{Status: 502}, CodeHTTP, false},
		{"dns", &net.DNSError{Err: "no such host", Name: "grafana.internal", IsNotFound: true}, CodeDNS, false},
		{"refused", &net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}, CodeRefused, false},
		{"deadline", context.DeadlineExceeded, CodeTimeout, false},
		{"hostname", x509.HostnameError{Host: "a"}, CodeCertificate, false},
		{"expired", x509.CertificateInvalidError{Reason: x509.Expired}, CodeCertificate, false},
		{"other", errors.New("boom"), CodeUnreachable, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			failure := Explain(tc.err)
			if failure.Code != tc.wantCode || failure.Auth != tc.wantAuth {
				t.Errorf("Explain() = %+v, want code %s auth %v", failure, tc.wantCode, tc.wantAuth)
			}
			for _, secret := range []string{"grafana.internal", "10.0.0.5"} {
				if strings.Contains(failure.Message, secret) {
					t.Errorf("message %q names an address", failure.Message)
				}
			}
		})
	}
	if got := Explain(unknownCA); got.Code != CodeUnknownCA {
		// An empty certificate has no issuer name, but the code still tells the cause.
		t.Errorf("Explain(unknown authority) = %+v", got)
	}
}

func TestDescribeHidesNothingButCredentials(t *testing.T) {
	base, _ := url.Parse("https://grafana.example.com/grafana/")
	client := New(Config{BaseURL: base, Token: func() (string, error) { return "", nil }})
	if got := client.Describe(); got != "https://grafana.example.com/grafana" {
		t.Errorf("Describe() = %q", got)
	}
}
