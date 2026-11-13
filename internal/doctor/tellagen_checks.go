package doctor

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/tellagen/tellagen-proxy/internal/hub"
	"github.com/tellagen/tellagen-proxy/internal/settings"
	"github.com/tellagen/tellagen-proxy/protocol"
)

// tellagen checks the path to Tellagen: DNS, the proxy or the direct connection,
// TLS, the token and the clock.
func (r *runner) tellagen(ctx context.Context) {
	s := r.Settings
	target := s.TellagenURL
	host := target.Hostname()
	port := target.Port()
	if port == "" {
		port = "443"
		if target.Scheme == "http" {
			port = "80"
		}
	}
	address := net.JoinHostPort(host, port)

	proxyURL, _ := s.ProxyFunc()(&url.URL{Scheme: target.Scheme, Host: target.Host})
	resolved := r.dns(ctx, host, proxyURL != nil)
	routing := "Grafana direct"
	if s.GrafanaProxy != "" {
		routing = "Grafana via " + settings.RedactProxy(s.GrafanaProxy)
	}
	var conn net.Conn
	var reached bool
	if proxyURL == nil {
		r.report.add("proxy", OK, "", "Tellagen direct, "+routing)
		if resolved {
			conn, reached = r.direct(ctx, address)
		} else {
			r.report.add("tcp", Skip, "", "needs dns")
		}
	} else {
		conn, reached = r.viaProxy(ctx, proxyURL, address, routing)
	}
	if conn != nil {
		defer func() { _ = conn.Close() }()
	}
	tlsOK := false
	switch {
	case !reached:
		r.report.add("tls", Skip, "", "needs a connection")
	case target.Scheme != "https":
		r.report.add("tls", Skip, "", "Tellagen is addressed without TLS here")
		tlsOK = true
	default:
		tlsOK = r.tls(ctx, conn, host)
	}
	if !tlsOK {
		r.report.add("auth", Skip, "", "needs tls")
		return
	}
	r.auth(ctx)
}

// dns resolves the Tellagen host and reports whether it worked.
func (r *runner) dns(ctx context.Context, host string, viaProxy bool) bool {
	ctx, cancel := context.WithTimeout(ctx, stepTimeout)
	defer cancel()
	addresses, err := r.Net.LookupHost(ctx, host)
	switch {
	case err == nil && len(addresses) > 0:
		r.report.add("dns", OK, "", fmt.Sprintf("%s -> %s", host, strings.Join(addresses[:min(len(addresses), 3)], ", ")))
		return true
	case viaProxy:
		r.report.add("dns", Warn, "dns_via_proxy", fmt.Sprintf("this machine cannot resolve %s", host),
			"The proxy resolves it for Tellagen traffic, so this may be fine")
		return true
	default:
		r.fail("dns", "dns", fmt.Sprintf("cannot resolve %s: %s", host, errorText(err)),
			"Fix: check the DNS settings of this host or container, or set HTTPS_PROXY if a proxy must resolve names")
	}
	return false
}

// direct opens a TCP connection to Tellagen.
func (r *runner) direct(ctx context.Context, address string) (net.Conn, bool) {
	ctx, cancel := context.WithTimeout(ctx, stepTimeout)
	defer cancel()
	conn, err := r.Net.DialContext(ctx, "tcp", address)
	if err != nil {
		r.fail("tcp", "tcp_blocked", fmt.Sprintf("cannot open a TCP connection to %s: %s", address, errorText(err)),
			"Fix: allow outbound TCP "+portOf(address)+" to "+hostOf(address)+", or set HTTPS_PROXY to your proxy")
		return nil, false
	}
	r.report.add("tcp", OK, "", "connected to "+address)
	return conn, true
}

// viaProxy opens a tunnel through an HTTP proxy with CONNECT and reports what the
// proxy said.
func (r *runner) viaProxy(ctx context.Context, proxyURL *url.URL, address, routing string) (net.Conn, bool) {
	name := settings.RedactProxy(proxyURL.String())
	if proxyURL.Scheme != "http" {
		r.report.add("proxy", Skip, "", fmt.Sprintf("Tellagen via %s, which doctor does not probe", name))
		return nil, false
	}
	ctx, cancel := context.WithTimeout(ctx, stepTimeout)
	defer cancel()
	conn, err := r.Net.DialContext(ctx, "tcp", proxyURL.Host)
	if err != nil {
		r.fail("proxy", "proxy_unreachable", fmt.Sprintf("cannot connect to the proxy %s: %s", name, errorText(err)),
			"Fix: check HTTPS_PROXY, and that this host may reach the proxy")
		return nil, false
	}
	status, err := connect(ctx, conn, address, proxyURL.User)
	switch {
	case err != nil:
		_ = conn.Close()
		r.fail("proxy", "proxy_unreachable", fmt.Sprintf("the proxy %s did not complete a CONNECT: %s", name, errorText(err)),
			"Fix: check HTTPS_PROXY. The address must be a forward proxy that allows CONNECT")
	case status == http.StatusOK:
		r.report.add("proxy", OK, "", fmt.Sprintf("Tellagen via %s, %s", name, routing))
		return conn, true
	case status == http.StatusProxyAuthRequired:
		_ = conn.Close()
		r.fail("proxy", "proxy_407", fmt.Sprintf("the proxy %s wants a login (407)", name),
			"Fix: put the credentials in HTTPS_PROXY, as http://user:password@host:port")
	case status == http.StatusForbidden:
		_ = conn.Close()
		r.fail("proxy", "proxy_403", fmt.Sprintf("the proxy %s blocks %s (403)", name, hostOf(address)),
			"Fix: ask the proxy admin to allow "+hostOf(address)+" on port 443")
	default:
		_ = conn.Close()
		r.fail("proxy", "proxy_error", fmt.Sprintf("the proxy %s answered CONNECT with %d", name, status),
			"Fix: ask the proxy admin to allow "+hostOf(address)+" on port 443")
	}
	return nil, false
}

// tls does a TLS handshake and verifies the chain itself, so that a failure can
// name the issuer this machine does not trust.
func (r *runner) tls(ctx context.Context, conn net.Conn, host string) bool {
	roots, err := settings.Roots(r.Settings.TellagenCA)
	if err != nil {
		r.fail("tls", "ca_file", errorText(err), "Fix: point TELLAGEN_CA_FILE at a PEM file with your CA certificates")
		return false
	}
	var chain []*x509.Certificate
	config := &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true, // the chain is verified below, to keep it when verification fails
		MinVersion:         tls.VersionTLS12,
		NextProtos:         []string{"http/1.1"},
		VerifyConnection: func(state tls.ConnectionState) error {
			chain = state.PeerCertificates
			return nil
		},
	}
	ctx, cancel := context.WithTimeout(ctx, stepTimeout)
	defer cancel()
	secure := tls.Client(conn, config)
	if err := secure.HandshakeContext(ctx); err != nil {
		r.fail("tls", "tls_handshake", fmt.Sprintf("the TLS handshake with %s failed: %s", host, errorText(err)),
			"Fix: check that a device on the path does not block TLS to "+host)
		return false
	}
	if len(chain) == 0 {
		r.fail("tls", "tls_handshake", host+" presented no certificate", "Fix: check the path to "+host)
		return false
	}
	intermediates := x509.NewCertPool()
	for _, cert := range chain[1:] {
		intermediates.AddCert(cert)
	}
	_, err = chain[0].Verify(x509.VerifyOptions{DNSName: host, Roots: roots, Intermediates: intermediates, CurrentTime: r.Net.Now()})
	if err == nil {
		r.report.add("tls", OK, "", fmt.Sprintf("%s presented a certificate that this machine trusts", host))
		return true
	}
	var invalid x509.CertificateInvalidError
	var hostname x509.HostnameError
	switch {
	case errors.As(err, &invalid) && invalid.Reason == x509.Expired:
		r.fail("tls", "tls_time", fmt.Sprintf("the certificate of %s is not valid at the time of this machine", host),
			"Fix: check the clock of this machine (NTP)")
	case errors.As(err, &hostname):
		r.fail("tls", "tls_hostname", fmt.Sprintf("the certificate presented for %s is for another name", host),
			"Fix: a device on the path may be answering for "+host+". Ask for a bypass")
	default:
		// Go reports an untrusted chain as UnknownAuthorityError, the macOS and
		// Windows verifiers use other errors, so anything left is treated as one.
		issuer := topIssuer(chain)
		r.failPublic("tls", "tls_unknown_ca", fmt.Sprintf("TLS error: the certificate is signed by an unknown authority, %q.", issuer),
			fmt.Sprintf("%s presented %q (TLS inspection)", host, issuer),
			"Fix: set TELLAGEN_CA_FILE to your inspection CA,",
			"or ask for a bypass for "+host)
	}
	return false
}

// auth trades the token for a session and reads Tellagen's clock from the answer.
func (r *runner) auth(ctx context.Context) {
	s := r.Settings
	transport, err := s.TellagenTransport()
	if err != nil {
		r.fail("auth", "ca_file", errorText(err), "Fix: point TELLAGEN_CA_FILE at a PEM file with your CA certificates")
		return
	}
	defer transport.CloseIdleConnections()
	transport.DialContext = r.Net.DialContext
	client := hub.New(hub.Config{BaseURL: s.TellagenURL, Transport: transport, Token: s.Token, Version: r.Version, Now: r.Net.Now})
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	_, err = client.Exchange(ctx)
	skew := client.Skew()
	var apiErr *hub.APIError
	if errors.As(err, &apiErr) && !apiErr.ServerDate.IsZero() {
		skew = apiErr.ServerDate.Sub(r.Net.Now())
	}
	switch {
	case err == nil:
		r.report.add("auth", OK, "", "Tellagen accepted the token")
	case errors.As(err, &apiErr):
		r.authRefused(apiErr)
	default:
		r.fail("auth", "auth_unreachable", "the token exchange did not complete: "+errorText(err),
			"Fix: check the path to Tellagen. A device may cut or rewrite the request")
	}
	if skew > maxSkew || skew < -maxSkew {
		r.fail("clock", "clock_skew", fmt.Sprintf("this machine's clock differs from Tellagen's by %s", skew.Abs().Round(time.Second)),
			"Fix: sync the clock with NTP. Certificates and tokens depend on it")
	}
}

func (r *runner) authRefused(apiErr *hub.APIError) {
	reply := apiErr.Reply
	switch {
	case reply.Code == protocol.ErrorRevoked:
		when := ""
		if reply.RevokedAt != nil {
			when = " on " + reply.RevokedAt.UTC().Format("2006-01-02 15:04 UTC")
		}
		r.fail("auth", "token_revoked", "this proxy token was revoked"+when,
			"Fix: create a new proxy token in Settings and put it in "+r.Settings.Token.Source())
	case apiErr.Status == http.StatusUpgradeRequired || reply.Code == protocol.ErrorUpgradeRequired:
		message := fmt.Sprintf("this proxy %s is too old for Tellagen", r.Version)
		if reply.MinVersion != "" {
			message = fmt.Sprintf("this proxy %s is too old. Tellagen needs %s or later", r.Version, reply.MinVersion)
		}
		r.fail("version", "version_too_old", message, "Fix: run a newer image. The install commands in Settings pin the right version")
		r.report.add("auth", Skip, "", "needs a newer version")
	case apiErr.Status == http.StatusUnauthorized:
		r.fail("auth", "token_invalid", "Tellagen does not accept this token (401)",
			"Fix: copy the token again from Settings. A rotated-out token fails this way")
	case reply.Code == protocol.ErrorCloudDiagnosisDisabled:
		r.fail("auth", "cloud_diagnosis_disabled", "Tellagen refused the proxy (403): Cloud diagnosis is switched off for this workspace",
			"Fix: ask a workspace admin to turn it on. The proxy keeps trying and starts again when it is on")
	case apiErr.Status == http.StatusForbidden:
		r.fail("auth", "company_disabled", "Tellagen refused the proxy (403): the workspace is suspended",
			"Fix: ask a workspace admin")
	case apiErr.Status == http.StatusTooManyRequests:
		r.report.add("auth", Warn, "rate_limited", "Tellagen asked this proxy to slow down (429)", "Try again in a minute")
	default:
		r.fail("auth", "auth_unexpected", fmt.Sprintf("the token exchange got an answer that is not Tellagen's (%d)", apiErr.Status),
			"Fix: a device on the path may be answering for Tellagen, such as a proxy login page. Ask for a bypass")
	}
}

// topIssuer names the issuer of the last certificate that was presented: for an
// inspecting proxy, the root that signed its certificates.
func topIssuer(chain []*x509.Certificate) string {
	top := chain[len(chain)-1]
	if top.Issuer.CommonName != "" {
		return top.Issuer.CommonName
	}
	if len(top.Issuer.Organization) > 0 {
		return top.Issuer.Organization[0]
	}
	return top.Issuer.String()
}

func portOf(address string) string {
	if _, port, err := net.SplitHostPort(address); err == nil {
		return port
	}
	return "443"
}

func hostOf(address string) string {
	if host, _, err := net.SplitHostPort(address); err == nil {
		return host
	}
	return address
}
