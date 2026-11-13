package doctor

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tellagen/tellagen-proxy/internal/settings"
	"github.com/tellagen/tellagen-proxy/protocol"
)

const (
	labToken     = "tlg_proxy_01JD8K2A-0000.secretsecretsecret"
	tellagenHost = "connect.tellagen.com"
	grafanaHost  = "grafana.customerdomain.net:3000"
)

// pki is a certificate authority that signs the certificate of a fake host.
type pki struct {
	t    *testing.T
	key  *ecdsa.PrivateKey
	cert *x509.Certificate
	der  []byte
}

func newPKI(t *testing.T, commonName string) *pki {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &pki{t: t, key: key, cert: cert, der: der}
}

func (p *pki) leaf(host string, notAfter time.Time) tls.Certificate {
	p.t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		p.t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, p.cert, &key.PublicKey, p.key)
	if err != nil {
		p.t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func (p *pki) writeCA(dir string) string {
	path := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p.der}), 0o600); err != nil {
		p.t.Fatal(err)
	}
	return path
}

// lab is a fake network: Tellagen, Grafana and a corporate proxy, reached by the
// names the real ones have.
type lab struct {
	t        *testing.T
	pki      *pki
	routes   map[string]string
	lookupAs func(host string) ([]string, error)

	tellagen func(w http.ResponseWriter, r *http.Request)
	grafana  func(w http.ResponseWriter, r *http.Request)

	mu      sync.Mutex
	connect []string
}

func newLab(t *testing.T) *lab {
	l := &lab{t: t, pki: newPKI(t, "Tellagen Test Root"), routes: map[string]string{}}
	l.lookupAs = func(string) ([]string, error) { return []string{"203.0.113.10"}, nil }
	l.tellagen = func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, protocol.SessionReply{SessionToken: protocol.SessionTokenPrefix + "s1", ExpiresAt: time.Now().Add(15 * time.Minute), ServerTime: time.Now()})
	}
	l.grafana = func(w http.ResponseWriter, r *http.Request) { l.defaultGrafana(w, r) }
	return l
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// serveTellagen starts the fake Tellagen with a certificate from signer.
func (l *lab) serveTellagen(signer *pki) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { l.tellagen(w, r) }))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{signer.leaf("connect.tellagen.com", time.Now().Add(time.Hour))}}
	server.StartTLS()
	l.t.Cleanup(server.Close)
	l.routes[tellagenHost+":443"] = server.Listener.Addr().String()
}

func (l *lab) serveGrafana() {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { l.grafana(w, r) }))
	l.t.Cleanup(server.Close)
	l.routes[grafanaHost] = server.Listener.Addr().String()
}

func (l *lab) defaultGrafana(w http.ResponseWriter, r *http.Request) {
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
		var items []string
		for i := range 12 {
			items = append(items, fmt.Sprintf(`{"uid":"other-%d","name":"Other %d","type":"postgres"}`, i, i))
		}
		items = append(items, `{"uid":"prom-prod","name":"Prometheus prod","type":"prometheus","isDefault":true}`, `{"uid":"loki-prod","name":"Loki prod","type":"loki"}`)
		_, _ = fmt.Fprintf(w, "[%s]", strings.Join(items, ","))
	case "/api/datasources/proxy/uid/prom-prod/api/v1/query":
		_, _ = fmt.Fprint(w, `{"status":"success"}`)
	case "/api/datasources/proxy/uid/loki-prod/loki/api/v1/labels":
		_, _ = fmt.Fprint(w, `{"status":"success"}`)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

// serveProxy starts a forward proxy that answers CONNECT with status. A 200 opens
// a tunnel to the fake host that was asked for.
func (l *lab) serveProxy(status int) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		l.t.Fatal(err)
	}
	l.t.Cleanup(func() { _ = listener.Close() })
	l.routes["proxy.corp.example:3128"] = listener.Addr().String()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go l.handleConnect(conn, status)
		}
	}()
}

func (l *lab) handleConnect(conn net.Conn, status int) {
	defer func() { _ = conn.Close() }()
	reader := bufio.NewReader(conn)
	request, err := http.ReadRequest(reader)
	if err != nil {
		return
	}
	l.mu.Lock()
	l.connect = append(l.connect, request.Method+" "+request.Host+" auth="+request.Header.Get("Proxy-Authorization"))
	l.mu.Unlock()
	if status != http.StatusOK {
		_, _ = fmt.Fprintf(conn, "HTTP/1.1 %d %s\r\nContent-Length: 0\r\n\r\n", status, http.StatusText(status))
		return
	}
	upstream, err := net.Dial("tcp", l.routes[request.Host])
	if err != nil {
		_, _ = fmt.Fprint(conn, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		return
	}
	defer func() { _ = upstream.Close() }()
	_, _ = fmt.Fprint(conn, "HTTP/1.1 200 Connection established\r\n\r\n")
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(upstream, reader); done <- struct{}{} }()
	go func() { _, _ = io.Copy(conn, upstream); done <- struct{}{} }()
	<-done
}

func (l *lab) net() Net {
	return Net{
		LookupHost: func(_ context.Context, host string) ([]string, error) { return l.lookupAs(host) },
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			target, ok := l.routes[address]
			if !ok {
				return nil, &net.OpError{Op: "dial", Net: network, Err: fmt.Errorf("connection refused")}
			}
			return (&net.Dialer{}).DialContext(ctx, network, target)
		},
		Now:         time.Now,
		InContainer: func() bool { return false },
	}
}

// settings loads settings from the environment, with defaults a good install has.
func (l *lab) settings(extra map[string]string) (*settings.Settings, error) {
	values := map[string]string{
		"TELLAGEN_PROXY_TOKEN":          labToken,
		"GRAFANA_URL":                   "http://" + grafanaHost,
		"GRAFANA_SERVICE_ACCOUNT_TOKEN": "glsa_secret",
		"TELLAGEN_CA_FILE":              l.pki.writeCA(l.t.TempDir()),
	}
	for key, value := range extra {
		if value == "" {
			delete(values, key)
			continue
		}
		values[key] = value
	}
	return settings.Load(settings.Environment{
		Getenv:   func(name string) string { return values[name] },
		Hostname: func() (string, error) { return "tellagen-proxy-test", nil },
		ReadFile: os.ReadFile,
		Now:      time.Now,
	})
}

func (l *lab) run(extra map[string]string, mutate ...func(*Options)) *Report {
	l.t.Helper()
	s, err := l.settings(extra)
	options := Options{Settings: s, LoadErr: err, Version: "1.0.0", Net: l.net()}
	for _, m := range mutate {
		m(&options)
	}
	return Run(l.t.Context(), options)
}

func (r *Report) result(t *testing.T, code string) Result {
	t.Helper()
	for _, result := range r.Results {
		if result.Code == code {
			return result
		}
	}
	var got []string
	for _, result := range r.Results {
		got = append(got, fmt.Sprintf("%s/%s/%s", result.Check, result.Status, result.Code))
	}
	t.Fatalf("no result with code %q in %v", code, got)
	return Result{}
}

func (r *Report) text() string {
	var b strings.Builder
	r.Write(&b)
	return b.String()
}

// serverTLS wraps one certificate in a server TLS config.
func serverTLS(cert tls.Certificate) *tls.Config {
	return &tls.Config{Certificates: []tls.Certificate{cert}}
}
