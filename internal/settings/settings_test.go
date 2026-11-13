package settings

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tellagen/tellagen-proxy/protocol"
)

const testToken = "tlg_proxy_01JD8K2A-0000.secretsecretsecret"

func envOf(values map[string]string) Environment {
	return Environment{
		Getenv:   func(name string) string { return values[name] },
		Hostname: func() (string, error) { return "tellagen-proxy-7c9f-xk2p", nil },
		ReadFile: os.ReadFile,
		Now:      time.Now,
	}
}

func validEnv() map[string]string {
	return map[string]string{
		"TELLAGEN_PROXY_TOKEN":          testToken,
		"GRAFANA_URL":                   "https://grafana.customerdomain.net/",
		"GRAFANA_SERVICE_ACCOUNT_TOKEN": "glsa_secret",
	}
}

func problemsOf(t *testing.T, values map[string]string) Problems {
	t.Helper()
	_, err := Load(envOf(values))
	var problems Problems
	if !errors.As(err, &problems) {
		t.Fatalf("Load() error = %v, want Problems", err)
	}
	return problems
}

func TestLoadDefaults(t *testing.T) {
	s, err := Load(envOf(validEnv()))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got := s.TellagenURL.String(); got != DefaultTellagenURL {
		t.Errorf("TellagenURL = %q, want %q", got, DefaultTellagenURL)
	}
	if s.HealthAddr != DefaultHealthAddr {
		t.Errorf("HealthAddr = %q, want %q", s.HealthAddr, DefaultHealthAddr)
	}
	if got := s.GrafanaURL.String(); got != "https://grafana.customerdomain.net" {
		t.Errorf("GrafanaURL = %q, want the trailing slash trimmed", got)
	}
	if s.InstanceID != "tellagen-proxy-tellagen-proxy-7c9f-xk2p" {
		t.Errorf("InstanceID = %q", s.InstanceID)
	}
	if s.AllowedDatasourceUIDs != nil {
		t.Errorf("AllowedDatasourceUIDs = %v, want nil when unset", s.AllowedDatasourceUIDs)
	}
}

func TestLoadAllSettings(t *testing.T) {
	values := validEnv()
	values["GRAFANA_PUBLIC_URL"] = "https://grafana.example.com/"
	values["GRAFANA_ORG_ID"] = "4"
	values["GRAFANA_ALLOWED_DATASOURCE_UIDS"] = " prom-prod, loki-prod ,,"
	values["TELLAGEN_POLICY_FILE"] = "/etc/policy.yaml"
	values["TELLAGEN_CA_FILE"] = "/certs/a.pem"
	values["GRAFANA_CA_FILE"] = "/certs/b.pem"
	values["https_proxy"] = "proxy.corp.example:3128"
	values["NO_PROXY"] = ".corp.example"
	values["GRAFANA_HTTPS_PROXY"] = "http://graf-proxy:3128"
	values["TELLAGEN_LABELS"] = "env=production, cluster=prod-eu-1"
	values["TELLAGEN_INSTALL_METHOD"] = "helm"
	values["TELLAGEN_INSTANCE_ID"] = "replica-a"
	values["TELLAGEN_HEALTH_ADDR"] = "127.0.0.1:9000"
	values["TELLAGEN_URL"] = "https://connect.example.com/"
	s, err := Load(envOf(values))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if s.GrafanaPublicURL != "https://grafana.example.com" || s.GrafanaOrgID != 4 {
		t.Errorf("public URL %q org %d", s.GrafanaPublicURL, s.GrafanaOrgID)
	}
	if got := strings.Join(s.AllowedDatasourceUIDs, "|"); got != "prom-prod|loki-prod" {
		t.Errorf("AllowedDatasourceUIDs = %q", got)
	}
	if s.HTTPSProxy != "proxy.corp.example:3128" || s.NoProxy != ".corp.example" || s.GrafanaProxy != "http://graf-proxy:3128" {
		t.Errorf("proxy settings = %q %q %q", s.HTTPSProxy, s.NoProxy, s.GrafanaProxy)
	}
	want := protocol.Labels{"env": "production", "cluster": "prod-eu-1"}
	if len(s.Labels) != 2 || s.Labels["env"] != want["env"] || s.Labels["cluster"] != want["cluster"] {
		t.Errorf("Labels = %v", s.Labels)
	}
	if s.InstanceID != "replica-a" || s.InstallMethod != "helm" || s.HealthAddr != "127.0.0.1:9000" || s.TellagenURL.Host != "connect.example.com" {
		t.Errorf("settings = %+v", s)
	}
}

func TestLoadRefusesInlineAndFileTogether(t *testing.T) {
	values := validEnv()
	values["TELLAGEN_PROXY_TOKEN_FILE"] = "/run/secrets/token"
	values["GRAFANA_SERVICE_ACCOUNT_TOKEN_FILE"] = "/run/secrets/grafana"
	problems := problemsOf(t, values)
	if len(problems) != 2 {
		t.Fatalf("problems = %v, want one for each pair", problems)
	}
	for _, want := range []string{"TELLAGEN_PROXY_TOKEN and TELLAGEN_PROXY_TOKEN_FILE are both set", "GRAFANA_SERVICE_ACCOUNT_TOKEN and GRAFANA_SERVICE_ACCOUNT_TOKEN_FILE are both set"} {
		if !strings.Contains(problems.Error(), want) {
			t.Errorf("error %q does not name %q", problems, want)
		}
	}
	if strings.Contains(problems.Error(), testToken) || strings.Contains(problems.Error(), "glsa_secret") {
		t.Errorf("the error prints a secret: %q", problems)
	}
}

func TestLoadReportsEveryMissingSetting(t *testing.T) {
	problems := problemsOf(t, map[string]string{})
	text := problems.Error()
	for _, want := range []string{"TELLAGEN_PROXY_TOKEN or TELLAGEN_PROXY_TOKEN_FILE is required", "GRAFANA_URL is required", "GRAFANA_SERVICE_ACCOUNT_TOKEN or GRAFANA_SERVICE_ACCOUNT_TOKEN_FILE is required"} {
		if !strings.Contains(text, want) {
			t.Errorf("error does not say %q: %s", want, text)
		}
	}
}

func TestLoadTreatsEmptyValuesAsUnset(t *testing.T) {
	values := validEnv()
	values["TELLAGEN_PROXY_TOKEN_FILE"] = "   "
	values["GRAFANA_ORG_ID"] = ""
	s, err := Load(envOf(values))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if s.Token.FromFile() {
		t.Error("an empty TELLAGEN_PROXY_TOKEN_FILE must not select the file")
	}
}

func TestLoadRejectsBadValues(t *testing.T) {
	cases := map[string]struct {
		name, value, want string
	}{
		"token shape":      {"TELLAGEN_PROXY_TOKEN", "'" + testToken + "'", "does not look like a Tellagen proxy token"},
		"plain http":       {"TELLAGEN_URL", "http://connect.example.com", "must start with https://"},
		"url credentials":  {"TELLAGEN_URL", "https://user:pw@connect.example.com", "must not hold a user name"},
		"grafana scheme":   {"GRAFANA_URL", "grafana.example.com:3000", "http or https"},
		"grafana password": {"GRAFANA_URL", "https://admin:pw@grafana.example.com", "must not hold a user name"},
		"public url":       {"GRAFANA_PUBLIC_URL", "ftp://grafana", "GRAFANA_PUBLIC_URL"},
		"org":              {"GRAFANA_ORG_ID", "-1", "GRAFANA_ORG_ID must be a number above zero"},
		"proxy":            {"HTTPS_PROXY", "ftp://proxy", "HTTPS_PROXY is not a proxy address"},
		"label":            {"TELLAGEN_LABELS", "env", "TELLAGEN_LABELS must look like"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			values := validEnv()
			values[tc.name] = tc.value
			text := problemsOf(t, values).Error()
			if !strings.Contains(text, tc.want) {
				t.Errorf("error %q does not contain %q", text, tc.want)
			}
			if strings.Contains(text, "pw@") || strings.Contains(text, testToken) {
				t.Errorf("the error prints a secret: %q", text)
			}
		})
	}
}

func TestLoadAllowsPlainHTTPOnlyForLocalHosts(t *testing.T) {
	for _, host := range []string{"http://localhost:8080", "http://127.0.0.1:8080", "http://api.acme.tellagen.test", "http://app.localhost"} {
		values := validEnv()
		values["TELLAGEN_URL"] = host
		if _, err := Load(envOf(values)); err != nil {
			t.Errorf("TELLAGEN_URL=%s error = %v", host, err)
		}
	}
}

func TestLoadInstanceIDWithoutHostname(t *testing.T) {
	env := envOf(validEnv())
	env.Hostname = func() (string, error) { return "localhost", nil }
	s, err := Load(env)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !strings.HasPrefix(s.InstanceID, "tellagen-proxy-") || s.InstanceID == "tellagen-proxy-localhost" {
		t.Errorf("InstanceID = %q, want a random suffix", s.InstanceID)
	}
}

func TestRedactProxy(t *testing.T) {
	cases := map[string]string{
		"http://user:secret@proxy.corp.example:3128/": "http://proxy.corp.example:3128",
		"proxy.corp.example:3128":                     "http://proxy.corp.example:3128",
		"::bad::":                                     "(unreadable)",
	}
	for raw, want := range cases {
		if got := RedactProxy(raw); got != want {
			t.Errorf("RedactProxy(%q) = %q, want %q", raw, got, want)
		}
	}
}

func writeFile(t *testing.T, dir, name, content string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestSecretFileIsTrimmedAndReadAgainEvery60Seconds(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "token", "  "+testToken+"\n\n", 0o600)
	now := time.Date(2026, 11, 6, 10, 0, 0, 0, time.UTC)
	values := validEnv()
	delete(values, "TELLAGEN_PROXY_TOKEN")
	values["TELLAGEN_PROXY_TOKEN_FILE"] = path
	env := envOf(values)
	env.Now = func() time.Time { return now }
	s, err := Load(env)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got, err := s.Token.Value(); err != nil || got != testToken {
		t.Fatalf("Value() = %q, %v, want the trimmed token", got, err)
	}
	if s.Token.Source() != "TELLAGEN_PROXY_TOKEN_FILE" {
		t.Errorf("Source() = %q", s.Token.Source())
	}

	writeFile(t, dir, "token", "tlg_proxy_other.rotated", 0o600)
	now = now.Add(RefreshInterval - time.Second)
	if got, _ := s.Token.Value(); got != testToken {
		t.Errorf("Value() before 60 s = %q, want the cached token", got)
	}
	now = now.Add(2 * time.Second)
	if got, _ := s.Token.Value(); got != "tlg_proxy_other.rotated" {
		t.Errorf("Value() after 60 s = %q, want the rotated token", got)
	}
}

func TestSecretReloadReadsAtOnce(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "token", "first", 0o600)
	secret := &Secret{name: "X", path: path, now: time.Now, read: os.ReadFile}
	if got, _ := secret.Value(); got != "first" {
		t.Fatalf("Value() = %q", got)
	}
	writeFile(t, dir, "token", "second", 0o600)
	if got, err := secret.Reload(); err != nil || got != "second" {
		t.Errorf("Reload() = %q, %v, want the new value at once", got, err)
	}
}

func TestSecretKeepsLastValueWhenFileDisappears(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "token", "first", 0o600)
	now := time.Now()
	secret := &Secret{name: "X", path: path, now: func() time.Time { return now }, read: os.ReadFile}
	if _, err := secret.Value(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * RefreshInterval)
	got, err := secret.Value()
	if err != nil || got != "first" {
		t.Errorf("Value() = %q, %v, want the last good value while the sidecar rewrites the file", got, err)
	}
	if !errors.Is(secret.Err(), ErrSecretMissing) {
		t.Errorf("Err() = %v, want ErrSecretMissing", secret.Err())
	}
}

func TestSecretMissingAndEmptyFiles(t *testing.T) {
	dir := t.TempDir()
	for name, path := range map[string]string{
		"missing": filepath.Join(dir, "absent"),
		"empty":   writeFile(t, dir, "empty", " \n", 0o600),
	} {
		secret := &Secret{name: "TELLAGEN_PROXY_TOKEN", path: path, now: time.Now, read: os.ReadFile}
		_, err := secret.Value()
		if !errors.Is(err, ErrSecretMissing) {
			t.Errorf("%s: Value() error = %v, want ErrSecretMissing", name, err)
		}
		if err != nil && !strings.Contains(err.Error(), "TELLAGEN_PROXY_TOKEN_FILE") {
			t.Errorf("%s: error %q does not name the setting", name, err)
		}
	}
}

func TestWaitForFilesWaitsForASidecar(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "token")
	secret := &Secret{name: "X", path: path, now: time.Now, read: os.ReadFile}
	calls := 0
	onWaiting := func(missing []string) {
		calls++
		if len(missing) != 1 || missing[0] != path {
			t.Errorf("missing = %v", missing)
		}
		if calls == 2 {
			writeFile(t, dir, "token", "value", 0o600)
		}
	}
	err := waitForFiles(t.Context(), time.Minute, time.Millisecond, []*Secret{secret}, onWaiting)
	if err != nil {
		t.Fatalf("waitForFiles() error = %v", err)
	}
	if calls != 2 {
		t.Errorf("onWaiting calls = %d, want 2", calls)
	}
	if got, _ := secret.Value(); got != "value" {
		t.Errorf("Value() = %q", got)
	}
}

func TestWaitForFilesGivesUpAndNamesTheFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "never")
	secret := &Secret{name: "X", path: path, now: time.Now, read: os.ReadFile}
	err := waitForFiles(t.Context(), 20*time.Millisecond, time.Millisecond, []*Secret{secret}, nil)
	if err == nil || !strings.Contains(err.Error(), path) || !strings.Contains(err.Error(), "waited") {
		t.Errorf("waitForFiles() error = %v, want it to name %s", err, path)
	}
}

func TestWaitForFilesStopsAtOnceOnAPermissionError(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root can read any file")
	}
	path := writeFile(t, t.TempDir(), "token", "value", 0o000)
	secret := &Secret{name: "X", path: path, now: time.Now, read: os.ReadFile}
	waited := false
	err := waitForFiles(t.Context(), time.Minute, time.Millisecond, []*Secret{secret}, func([]string) { waited = true })
	if err == nil || errors.Is(err, ErrSecretMissing) {
		t.Fatalf("waitForFiles() error = %v, want a permission error", err)
	}
	if waited {
		t.Error("a permission error must not be waited out")
	}
}

func TestWaitForFilesIgnoresInlineSecrets(t *testing.T) {
	secret := &Secret{name: "X", inline: "value", now: time.Now, read: os.ReadFile}
	if err := waitForFiles(t.Context(), time.Millisecond, time.Millisecond, []*Secret{secret}, nil); err != nil {
		t.Errorf("waitForFiles() error = %v", err)
	}
}

func TestInspectReportsModeAndUser(t *testing.T) {
	path := writeFile(t, t.TempDir(), "token", "x", 0o600)
	state := Inspect(path)
	if !state.Exists || state.Mode != 0o600 || state.ProcessUID != os.Getuid() || state.OwnerUID != os.Getuid() {
		t.Errorf("Inspect() = %+v", state)
	}
	if missing := Inspect(path + ".absent"); missing.Exists || missing.Err == nil {
		t.Errorf("Inspect(missing) = %+v", missing)
	}
}
