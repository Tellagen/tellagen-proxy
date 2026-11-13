package settings

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"golang.org/x/net/http/httpproxy"
)

const (
	dialTimeout          = 10 * time.Second
	tlsHandshakeTimeout  = 10 * time.Second
	idleConnTimeout      = 50 * time.Second
	grafanaHeaderTimeout = 60 * time.Second
)

// Roots returns the system roots plus the PEM bundle in caFile. The bundle adds to
// the system roots: Go's SSL_CERT_FILE replaces them, and a company that passes
// only its own CA that way would lose the public ones.
func Roots(caFile string) (*x509.CertPool, error) {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if caFile == "" {
		return pool, nil
	}
	data, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read the CA file %s: %w", caFile, err)
	}
	if !pool.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("the CA file %s holds no PEM certificate", caFile)
	}
	return pool, nil
}

// ProxyFunc returns the proxy decision for Tellagen traffic: HTTPS_PROXY,
// HTTP_PROXY and NO_PROXY, as Go's http.ProxyFromEnvironment reads them, but from
// the values loaded here. A request to localhost never goes through a proxy.
func (s *Settings) ProxyFunc() func(*url.URL) (*url.URL, error) {
	return (&httpproxy.Config{HTTPProxy: s.HTTPProxy, HTTPSProxy: s.HTTPSProxy, NoProxy: s.NoProxy}).ProxyFunc()
}

// GrafanaProxyFunc returns the proxy decision for Grafana traffic. Grafana is
// reached directly unless GRAFANA_HTTPS_PROXY is set. NO_PROXY still applies to it.
func (s *Settings) GrafanaProxyFunc() func(*url.URL) (*url.URL, error) {
	if s.GrafanaProxy == "" {
		return func(*url.URL) (*url.URL, error) { return nil, nil }
	}
	return (&httpproxy.Config{HTTPProxy: s.GrafanaProxy, HTTPSProxy: s.GrafanaProxy, NoProxy: s.NoProxy}).ProxyFunc()
}

// TellagenTransport builds the transport for Tellagen. It speaks HTTP/1.1 only,
// follows the proxy settings and trusts TELLAGEN_CA_FILE in addition to the
// system roots.
func (s *Settings) TellagenTransport() (*http.Transport, error) {
	roots, err := Roots(s.TellagenCA)
	if err != nil {
		return nil, fmt.Errorf("TELLAGEN_CA_FILE: %w", err)
	}
	proxy := s.ProxyFunc()
	return &http.Transport{
		Proxy:               func(request *http.Request) (*url.URL, error) { return proxy(request.URL) },
		DialContext:         (&net.Dialer{Timeout: dialTimeout, KeepAlive: 30 * time.Second}).DialContext,
		TLSClientConfig:     &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}},
		TLSNextProto:        map[string]func(string, *tls.Conn) http.RoundTripper{},
		TLSHandshakeTimeout: tlsHandshakeTimeout,
		IdleConnTimeout:     idleConnTimeout,
		MaxIdleConns:        4,
		MaxIdleConnsPerHost: 2,
	}, nil
}

// GrafanaTransport builds the transport for Grafana. It goes direct unless
// GRAFANA_HTTPS_PROXY is set, and trusts GRAFANA_CA_FILE in addition to the
// system roots.
func (s *Settings) GrafanaTransport() (*http.Transport, error) {
	roots, err := Roots(s.GrafanaCA)
	if err != nil {
		return nil, fmt.Errorf("GRAFANA_CA_FILE: %w", err)
	}
	proxy := s.GrafanaProxyFunc()
	return &http.Transport{
		Proxy:                 func(request *http.Request) (*url.URL, error) { return proxy(request.URL) },
		DialContext:           (&net.Dialer{Timeout: dialTimeout, KeepAlive: 30 * time.Second}).DialContext,
		TLSClientConfig:       &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:   tlsHandshakeTimeout,
		ResponseHeaderTimeout: grafanaHeaderTimeout,
		IdleConnTimeout:       idleConnTimeout,
		MaxIdleConns:          8,
		MaxIdleConnsPerHost:   4,
	}, nil
}

// IsUnknownAuthority reports the issuer name of an untrusted certificate chain,
// for the doctor and the log. It returns false when err is something else.
func IsUnknownAuthority(err error) (issuer string, ok bool) {
	var unknown x509.UnknownAuthorityError
	if !errors.As(err, &unknown) || unknown.Cert == nil {
		return "", false
	}
	name := unknown.Cert.Issuer.CommonName
	if name == "" && len(unknown.Cert.Issuer.Organization) > 0 {
		name = unknown.Cert.Issuer.Organization[0]
	}
	if name == "" {
		name = unknown.Cert.Issuer.String()
	}
	return name, true
}
