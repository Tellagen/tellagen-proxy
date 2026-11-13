// Package settings reads the proxy configuration from the environment and files
// and builds the HTTP transports. A secret X also reads from X_FILE, not both.
package settings

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/tellagen/tellagen-proxy/protocol"
)

// DefaultTellagenURL is the address of Tellagen.
const DefaultTellagenURL = "https://connect.tellagen.com"

// DefaultHealthAddr is the one port the proxy opens.
const DefaultHealthAddr = ":8080"

// Settings holds everything the proxy needs to start. Secrets are not read here:
// a Secret reads its own file when it is asked for its value.
type Settings struct {
	TellagenURL *url.URL
	Token       *Secret

	GrafanaURL            *url.URL
	GrafanaToken          *Secret
	GrafanaPublicURL      string
	GrafanaOrgID          int64
	AllowedDatasourceUIDs []string

	PolicyFile    string
	TellagenCA    string
	GrafanaCA     string
	HTTPProxy     string
	HTTPSProxy    string
	NoProxy       string
	GrafanaProxy  string
	HealthAddr    string
	InstanceID    string
	InstallMethod string
	Labels        protocol.Labels
}

// Problems is the error of Load: every problem with the settings, one per line, so
// that a person fixes them in one go.
type Problems []string

// Error implements error.
func (p Problems) Error() string {
	return "the settings are not valid:\n  " + strings.Join(p, "\n  ")
}

// Secrets lists the secrets that can be files, for WaitForFiles.
func (s *Settings) Secrets() []*Secret {
	return []*Secret{s.Token, s.GrafanaToken}
}

// Environment gives Load what it needs from the machine. Tests replace it.
type Environment struct {
	Getenv   func(string) string
	Hostname func() (string, error)
	ReadFile func(string) ([]byte, error)
	Now      func() time.Time
}

// OSEnvironment is the real machine.
func OSEnvironment() Environment {
	return Environment{Getenv: os.Getenv, Hostname: os.Hostname, ReadFile: os.ReadFile, Now: time.Now}
}

const (
	maxLabelValue    = 128
	maxLabels        = 16
	maxInstallMethod = 32
)

var (
	labelKeyPattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$`)
	localTestHostEnds = []string{".localhost", ".test"}
)

// Load reads the settings. It reports every problem it finds, not only the first.
func Load(env Environment) (*Settings, error) {
	if env.Getenv == nil {
		env.Getenv = os.Getenv
	}
	if env.ReadFile == nil {
		env.ReadFile = os.ReadFile
	}
	if env.Now == nil {
		env.Now = time.Now
	}
	l := loader{env: env}
	s := &Settings{HealthAddr: DefaultHealthAddr}

	s.TellagenURL = l.tellagenURL()
	s.Token = l.secret("TELLAGEN_PROXY_TOKEN", true)
	l.checkToken(s.Token)
	s.GrafanaURL = l.grafanaURL()
	s.GrafanaToken = l.secret("GRAFANA_SERVICE_ACCOUNT_TOKEN", true)
	s.GrafanaPublicURL = l.publicURL()
	s.GrafanaOrgID = l.orgID()
	s.AllowedDatasourceUIDs = l.uids()
	s.PolicyFile = l.value("TELLAGEN_POLICY_FILE")
	s.TellagenCA = l.value("TELLAGEN_CA_FILE")
	s.GrafanaCA = l.value("GRAFANA_CA_FILE")
	s.HTTPSProxy = l.proxyURL("HTTPS_PROXY", "https_proxy")
	s.HTTPProxy = l.proxyURL("HTTP_PROXY", "http_proxy")
	s.NoProxy = l.first("NO_PROXY", "no_proxy")
	s.GrafanaProxy = l.proxyURL("GRAFANA_HTTPS_PROXY")
	if addr := l.value("TELLAGEN_HEALTH_ADDR"); addr != "" {
		s.HealthAddr = addr
	}
	s.InstallMethod = l.value("TELLAGEN_INSTALL_METHOD")
	if len(s.InstallMethod) > maxInstallMethod {
		l.problem("TELLAGEN_INSTALL_METHOD is longer than %d characters", maxInstallMethod)
	}
	s.Labels = l.labels()
	s.InstanceID = l.instanceID()

	if len(l.problems) > 0 {
		return nil, l.problems
	}
	return s, nil
}

type loader struct {
	env      Environment
	problems Problems
}

func (l *loader) problem(format string, args ...any) {
	l.problems = append(l.problems, fmt.Sprintf(format, args...))
}

func (l *loader) value(name string) string {
	return strings.TrimSpace(l.env.Getenv(name))
}

func (l *loader) first(names ...string) string {
	for _, name := range names {
		if value := l.value(name); value != "" {
			return value
		}
	}
	return ""
}

// secret reads X and X_FILE. A variable that is set but empty counts as unset,
// because Compose and Helm templates often pass empty values.
func (l *loader) secret(name string, required bool) *Secret {
	inline, path := l.value(name), l.value(name+"_FILE")
	secret := &Secret{name: name, inline: inline, path: path, now: l.env.Now, read: l.env.ReadFile}
	switch {
	case inline != "" && path != "":
		l.problem("%s and %s_FILE are both set. Set only one, so that a rotated secret cannot be hidden by a stale one", name, name)
	case inline == "" && path == "" && required:
		l.problem("%s or %s_FILE is required", name, name)
	}
	return secret
}

// checkToken adds a problem when an inline proxy token does not have a proxy
// token's shape. A token in a file is checked when the file is read.
func (l *loader) checkToken(token *Secret) {
	if token.inline == "" {
		return
	}
	if _, _, ok := protocol.ParseToken(token.inline); !ok {
		l.problem("%s does not look like a Tellagen proxy token. It starts with %s. Copy it whole from Settings, without quotes", token.name, protocol.TokenPrefix)
	}
}

func (l *loader) tellagenURL() *url.URL {
	raw := l.value("TELLAGEN_URL")
	if raw == "" {
		raw = DefaultTellagenURL
	}
	parsed, err := url.Parse(strings.TrimRight(raw, "/"))
	switch {
	case err != nil || parsed.Host == "":
		l.problem("TELLAGEN_URL is not a URL")
	case parsed.User != nil:
		l.problem("TELLAGEN_URL must not hold a user name or password")
	case parsed.Scheme == "https":
	case parsed.Scheme == "http" && localHost(parsed.Hostname()):
	default:
		l.problem("TELLAGEN_URL must start with https://. Plain http is allowed only for localhost")
	}
	return parsed
}

func (l *loader) grafanaURL() *url.URL {
	raw := l.value("GRAFANA_URL")
	if raw == "" {
		l.problem("GRAFANA_URL is required")
		return nil
	}
	parsed, err := url.Parse(strings.TrimRight(raw, "/"))
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		l.problem("GRAFANA_URL must be an http or https URL")
		return nil
	}
	if parsed.User != nil {
		l.problem("GRAFANA_URL must not hold a user name or password. Use GRAFANA_SERVICE_ACCOUNT_TOKEN")
		return nil
	}
	return parsed
}

func (l *loader) publicURL() string {
	raw := l.value("GRAFANA_PUBLIC_URL")
	if raw == "" {
		return ""
	}
	parsed, err := url.Parse(strings.TrimRight(raw, "/"))
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.User != nil {
		l.problem("GRAFANA_PUBLIC_URL must be an http or https URL without a user name or password")
		return ""
	}
	return parsed.String()
}

func (l *loader) orgID() int64 {
	raw := l.value("GRAFANA_ORG_ID")
	if raw == "" {
		return 0
	}
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || id <= 0 {
		l.problem("GRAFANA_ORG_ID must be a number above zero")
		return 0
	}
	return id
}

func (l *loader) uids() []string {
	raw := l.value("GRAFANA_ALLOWED_DATASOURCE_UIDS")
	if raw == "" {
		return nil
	}
	uids := []string{}
	for _, uid := range strings.Split(raw, ",") {
		if uid = strings.TrimSpace(uid); uid != "" {
			uids = append(uids, uid)
		}
	}
	return uids
}

func (l *loader) proxyURL(names ...string) string {
	raw := l.first(names...)
	if raw == "" {
		return ""
	}
	if _, err := ParseProxy(raw); err != nil {
		l.problem("%s is not a proxy address. Use a form such as http://proxy.example:3128", names[0])
		return ""
	}
	return raw
}

func (l *loader) labels() protocol.Labels {
	raw := l.value("TELLAGEN_LABELS")
	if raw == "" {
		return nil
	}
	labels := protocol.Labels{}
	for _, pair := range strings.Split(raw, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		key, value, found := strings.Cut(pair, "=")
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		if !found || !labelKeyPattern.MatchString(key) || value == "" || len(value) > maxLabelValue {
			l.problem("TELLAGEN_LABELS must look like env=production,cluster=prod-eu-1. %q does not", pair)
			return nil
		}
		labels[key] = value
	}
	if len(labels) > maxLabels {
		l.problem("TELLAGEN_LABELS holds more than %d labels", maxLabels)
		return nil
	}
	if len(labels) == 0 {
		return nil
	}
	return labels
}

// instanceID is the name of this replica: the configured ID, else the host name,
// else a random suffix when the host name is empty or "localhost".
func (l *loader) instanceID() string {
	if id := l.value("TELLAGEN_INSTANCE_ID"); id != "" {
		return id
	}
	host := ""
	if l.env.Hostname != nil {
		host, _ = l.env.Hostname()
	}
	host = strings.TrimSpace(host)
	if host != "" && host != "localhost" {
		return "tellagen-proxy-" + host
	}
	var random [4]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "tellagen-proxy"
	}
	return "tellagen-proxy-" + hex.EncodeToString(random[:])
}

// ParseProxy parses an HTTPS_PROXY value the way Go's own proxy support does: a
// bare host:port means http.
func ParseProxy(raw string) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		parsed, err = url.Parse("http://" + raw)
	}
	if err != nil || parsed.Host == "" {
		return nil, errors.New("not a proxy address")
	}
	switch parsed.Scheme {
	case "http", "https", "socks5", "socks5h":
		return parsed, nil
	}
	return nil, errors.New("unsupported proxy scheme")
}

// RedactProxy returns a proxy address that is safe to print: no user name and no
// password.
func RedactProxy(raw string) string {
	parsed, err := ParseProxy(raw)
	if err != nil {
		return "(unreadable)"
	}
	return parsed.Scheme + "://" + parsed.Host
}

func localHost(host string) bool {
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	for _, end := range localTestHostEnds {
		if strings.HasSuffix(host, end) {
			return true
		}
	}
	return false
}
