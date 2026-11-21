package protocol

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"
)

// fixtureDigests pins the golden files per protocol version. A change to any file
// changes the digest, and the change needs a new ProtocolVersion: an old proxy
// keeps speaking the old messages for at least 6 months.
var fixtureDigests = map[string]string{
	"1": "f3a4eb867bcd7f290a52aea370f88433f6bc6e8badcb4d1ff76b116dab60f028",
}

// addedFixtureDigests pins files that were added to a version after its release, as the
// capability that came with them. The digest in fixtureDigests covers the released files only
// and never changes, so a proxy of the release keeps speaking what it shipped. A new file may
// join a version as a new entry here; an entry is never edited or removed.
var addedFixtureDigests = map[string]struct {
	files  []string
	digest string
}{
	"1/alert_rule_details": {
		files:  []string{"testdata/args/grafana.alert_rule_versions.json", "testdata/messages/result_ok_alert_rule_versions.json", "testdata/messages/result_ok_alert_rules_detail.json"},
		digest: "38a78727285519a6e823d2002ef5a6c355ba2bf6dce4cc0e39c2c846a686c795",
	},
}

// messageFixtures maps each golden file to the message it holds.
var messageFixtures = map[string]func() any{
	"session_reply.json":                 func() any { return &SessionReply{} },
	"hello.json":                         func() any { return &Hello{} },
	"hello_reply.json":                   func() any { return &HelloReply{} },
	"poll_request.json":                  func() any { return &PollRequest{} },
	"poll_reply.json":                    func() any { return &PollReply{} },
	"poll_reply_empty.json":              func() any { return &PollReply{} },
	"result_ok_matrix.json":              func() any { return &CommandResult{} },
	"result_ok_vector.json":              func() any { return &CommandResult{} },
	"result_ok_logs.json":                func() any { return &CommandResult{} },
	"result_ok_patterns.json":            func() any { return &CommandResult{} },
	"result_ok_names.json":               func() any { return &CommandResult{} },
	"result_ok_datasources.json":         func() any { return &CommandResult{} },
	"result_ok_dashboards.json":          func() any { return &CommandResult{} },
	"result_ok_panel_queries.json":       func() any { return &CommandResult{} },
	"result_ok_alert_rules.json":         func() any { return &CommandResult{} },
	"result_ok_alert_rules_detail.json":  func() any { return &CommandResult{} },
	"result_ok_alert_rule_versions.json": func() any { return &CommandResult{} },
	"result_partial.json":                func() any { return &CommandResult{} },
	"result_rejected.json":               func() any { return &CommandResult{} },
	"result_error.json":                  func() any { return &CommandResult{} },
	"result_cancelled.json":              func() any { return &CommandResult{} },
	"result_accepted.json":               func() any { return &AcceptedReply{} },
	"error_upgrade_required.json":        func() any { return &ErrorReply{} },
	"error_revoked.json":                 func() any { return &ErrorReply{} },
}

func readFixture(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", path))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return raw
}

func canonicalJSON(t *testing.T, raw []byte) string {
	t.Helper()
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatalf("parse JSON: %v\n%s", err, raw)
	}
	out, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("encode JSON: %v", err)
	}
	return string(out)
}

func TestGoldenMessagesRoundTrip(t *testing.T) {
	files, err := filepath.Glob("testdata/messages/*.json")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(files) != len(messageFixtures) {
		t.Errorf("found %d message fixtures, want %d: every golden file needs an entry", len(files), len(messageFixtures))
	}
	for name, newMessage := range messageFixtures {
		t.Run(name, func(t *testing.T) {
			raw := readFixture(t, filepath.Join("messages", name))
			message := newMessage()
			if err := json.Unmarshal(raw, message); err != nil {
				t.Fatalf("decode: %v", err)
			}
			encoded, err := json.Marshal(message)
			if err != nil {
				t.Fatalf("encode: %v", err)
			}
			if got, want := canonicalJSON(t, encoded), canonicalJSON(t, raw); got != want {
				t.Fatalf("round trip changed the message\n got %s\nwant %s", got, want)
			}
		})
	}
}

func TestGoldenFixturesCannotChangeWithoutAVersionBump(t *testing.T) {
	var files []string
	err := filepath.WalkDir("testdata", func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !entry.IsDir() {
			files = append(files, filepath.ToSlash(path))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk fixtures: %v", err)
	}
	sort.Strings(files)
	fileDigest := func(names []string) string {
		digest := sha256.New()
		for _, path := range names {
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			digest.Write([]byte(path + "\n"))
			digest.Write(raw)
		}
		return hex.EncodeToString(digest.Sum(nil))
	}
	added := map[string]bool{}
	for key, entry := range addedFixtureDigests {
		if !strings.HasPrefix(key, ProtocolVersion+"/") {
			continue
		}
		for _, path := range entry.files {
			added[path] = true
		}
		if got := fileDigest(entry.files); got != entry.digest {
			t.Fatalf("the files added as %s changed: digest %s, pinned %s. An added file is pinned once; never edit it", key, got, entry.digest)
		}
	}
	var released []string
	for _, path := range files {
		if !added[path] {
			released = append(released, path)
		}
	}
	want, ok := fixtureDigests[ProtocolVersion]
	if !ok {
		t.Fatalf("no fixture digest for protocol version %s", ProtocolVersion)
	}
	if got := fileDigest(released); got != want {
		t.Fatalf("the golden files changed: digest %s, pinned %s. A changed message needs a new ProtocolVersion and SchemaHello, with a new digest entry; never edit the digest of a released version", got, want)
	}
}

// Every JSON field of every message must appear in a golden file, so adding a
// field changes a fixture, and that changes the digest above.
func TestEveryFieldAppearsInAGoldenFile(t *testing.T) {
	seen := map[string]bool{}
	var collect func(value any)
	collect = func(value any) {
		switch typed := value.(type) {
		case map[string]any:
			for key, child := range typed {
				seen[key] = true
				collect(child)
			}
		case []any:
			for _, child := range typed {
				collect(child)
			}
		}
	}
	for name := range messageFixtures {
		var value any
		if err := json.Unmarshal(readFixture(t, filepath.Join("messages", name)), &value); err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		collect(value)
	}
	types := []any{
		SessionReply{}, Hello{}, HelloReply{}, PollRequest{}, PollReply{}, Command{}, Cancel{}, PolicyUpdate{},
		CommandResult{}, AcceptedReply{}, ErrorReply{},
	}
	visited := map[reflect.Type]bool{}
	var missing []string
	var walk func(typ reflect.Type)
	walk = func(typ reflect.Type) {
		switch typ.Kind() {
		case reflect.Pointer, reflect.Slice, reflect.Map:
			walk(typ.Elem())
			return
		case reflect.Struct:
		default:
			return
		}
		if visited[typ] || typ == reflect.TypeFor[time.Time]() {
			return
		}
		visited[typ] = true
		for field := range typ.Fields() {
			name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
			if name != "" && name != "-" && !seen[name] {
				missing = append(missing, typ.Name()+"."+name)
			}
			walk(field.Type)
		}
	}
	for _, value := range types {
		walk(reflect.TypeOf(value))
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Fatalf("fields with no golden file: %v", missing)
	}
}

func TestPollMessageUnion(t *testing.T) {
	if _, err := json.Marshal(PollMessage{}); err == nil {
		t.Fatal("an empty message must not encode")
	}
	var unknown PollMessage
	if err := json.Unmarshal([]byte(`{"type":"future_message","x":1}`), &unknown); err != nil {
		t.Fatalf("a message of an unknown type must decode: %v", err)
	}
	if unknown.Command != nil || unknown.Cancel != nil || unknown.PolicyUpdate != nil {
		t.Fatalf("an unknown message must set no field: %+v", unknown)
	}
	if err := json.Unmarshal([]byte(`{"type":`), &unknown); err == nil {
		t.Fatal("broken JSON must fail")
	}
	encoded, err := json.Marshal(PollMessage{Cancel: &Cancel{CommandID: "cmd_1", Reason: CancelReasonDeadline}})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if got, want := canonicalJSON(t, encoded), `{"command_id":"cmd_1","reason":"deadline","type":"cancel"}`; got != want {
		t.Fatalf("encoded = %s, want %s", got, want)
	}
}

// An empty datasource list means that no datasource is allowed, and it must stay
// an empty list on the wire.
func TestEmptyDatasourceListSurvivesTheWire(t *testing.T) {
	var update PolicyUpdate
	if err := json.Unmarshal([]byte(`{"revision":"srv-1","narrow":{"datasource_uids":[]},"data":{"metrics":"points","log_lines":0,"redaction":"on"}}`), &update); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if update.Narrow.DatasourceUIDs == nil {
		t.Fatal("an empty list decoded as absent")
	}
	encoded, err := json.Marshal(update)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if !bytes.Contains(encoded, []byte(`"datasource_uids":[]`)) {
		t.Fatalf("encoded = %s", encoded)
	}
}

func TestCapabilityCatalog(t *testing.T) {
	want := []string{
		"grafana.alert_rule_versions", "grafana.get_dashboard_panel_queries", "grafana.list_alert_rules", "grafana.list_datasources", "grafana.search_dashboards",
		"loki.list_label_values", "loki.query_patterns", "loki.query_range",
		"prometheus.list_label_values", "prometheus.list_metric_names", "prometheus.query_instant", "prometheus.query_range",
	}
	var got []string
	for _, capability := range Capabilities() {
		got = append(got, capability.Name)
		if capability.Version != 1 {
			t.Errorf("%s version = %d, want 1", capability.Name, capability.Version)
		}
		if capability.Limits.TimeoutMS != 60_000 || capability.Limits.MaxResultBytes != 64*1024 {
			t.Errorf("%s limits = %+v", capability.Name, capability.Limits)
		}
		if !IsKnownCapability(capability.Name) {
			t.Errorf("%s is not known", capability.Name)
		}
		family := CapabilityFamily(capability.Name)
		if family != FamilyPrometheus && family != FamilyLoki && family != FamilyGrafana {
			t.Errorf("%s family = %q", capability.Name, family)
		}
	}
	if !slices.Equal(got, want) {
		t.Fatalf("capabilities = %v, want %v", got, want)
	}
	if IsKnownCapability("grafana.api_request") {
		t.Fatal("a generic Grafana API tool must not be a capability")
	}
}

func TestCapabilityCeilingsCoverThePolicyMaximums(t *testing.T) {
	limits := map[string]Limits{}
	for _, capability := range Capabilities() {
		limits[capability.Name] = capability.Limits
	}
	if got := limits[CapabilityPrometheusQueryRange]; got.MaxRangeS != 7*24*60*60 || got.MaxPoints != 500 {
		t.Errorf("prometheus.query_range = %+v", got)
	}
	if got := limits[CapabilityLokiQueryRange]; got.MaxRangeS != 24*60*60 || got.MaxLines != 50 || got.MaxLineChars != 500 {
		t.Errorf("loki.query_range = %+v", got)
	}
	if got := limits[CapabilityLokiQueryPatterns]; got.MaxPatterns != 5 {
		t.Errorf("loki.query_patterns = %+v", got)
	}
}

func TestGoldenArgsParseStrictlyAndSummarize(t *testing.T) {
	summaries := map[string]ArgsSummary{
		CapabilityPrometheusQueryRange:      {DatasourceUID: "prom-prod", Query: `sum(rate(http_requests_total{service="checkout-api"}[5m]))`, StepS: 30},
		CapabilityPrometheusQueryInstant:    {DatasourceUID: "prom-prod", Query: `up{job="checkout-api"}`},
		CapabilityPrometheusListMetricNames: {DatasourceUID: "prom-prod", Query: "http_request_duration.*"},
		CapabilityPrometheusListLabelValues: {DatasourceUID: "prom-prod", Query: "service http_requests_total"},
		CapabilityLokiQueryRange:            {DatasourceUID: "loki-prod", Query: `sum(count_over_time({app="checkout-api"} |= "connection pool exhausted" [1m]))`, StepS: 60},
		CapabilityLokiQueryPatterns:         {DatasourceUID: "loki-prod", Query: `{app="checkout-api", level="error"}`},
		CapabilityLokiListLabelValues:       {DatasourceUID: "loki-prod", Query: "app"},
		CapabilityGrafanaListDatasources:    {Query: "prometheus"},
		CapabilityGrafanaSearchDashboards:   {Query: "checkout"},
		CapabilityGrafanaGetPanelQueries:    {Query: "checkout"},
		CapabilityGrafanaListAlertRules:     {Query: "checkout"},
		CapabilityGrafanaAlertRuleVersions:  {Query: "rule-5xx"},
	}
	for _, capability := range Capabilities() {
		t.Run(capability.Name, func(t *testing.T) {
			raw := readFixture(t, filepath.Join("args", capability.Name+".json"))
			args, err := ParseArgs(capability.Name, raw)
			if err != nil {
				t.Fatalf("ParseArgs: %v", err)
			}
			encoded, err := json.Marshal(args)
			if err != nil {
				t.Fatalf("encode: %v", err)
			}
			if got, want := canonicalJSON(t, encoded), canonicalJSON(t, raw); got != want {
				t.Fatalf("round trip changed the args\n got %s\nwant %s", got, want)
			}
			summary := args.Summary()
			want := summaries[capability.Name]
			if summary.DatasourceUID != want.DatasourceUID || summary.Query != want.Query || summary.StepS != want.StepS {
				t.Fatalf("summary = %+v, want %+v", summary, want)
			}

			var fields map[string]any
			if err := json.Unmarshal(raw, &fields); err != nil {
				t.Fatalf("parse: %v", err)
			}
			fields["fetch_url"] = "https://example.test"
			withExtra, err := json.Marshal(fields)
			if err != nil {
				t.Fatalf("encode: %v", err)
			}
			if _, err := ParseArgs(capability.Name, withExtra); err == nil {
				t.Fatal("an unknown argument must be refused")
			}
		})
	}
	if _, err := ParseArgs("grafana.api_request", []byte(`{}`)); err == nil {
		t.Fatal("an unknown capability must be refused")
	}
}

func TestLimitsNarrowOnlyLowers(t *testing.T) {
	binary := Limits{MaxRangeS: 604800, MaxSeries: 50, TimeoutMS: 60000}
	tests := []struct {
		name  string
		other Limits
		want  Limits
	}{
		{"a lower value applies", Limits{MaxRangeS: 86400, MaxSeries: 10}, Limits{MaxRangeS: 86400, MaxSeries: 10, TimeoutMS: 60000}},
		{"a higher value is ignored", Limits{MaxRangeS: 9_999_999, TimeoutMS: 120000}, binary},
		{"an unset value keeps the limit", Limits{}, binary},
		{"a negative value keeps the limit", Limits{TimeoutMS: -1}, binary},
		{"a value the base does not set is taken", Limits{MaxLines: 3}, Limits{MaxRangeS: 604800, MaxSeries: 50, TimeoutMS: 60000, MaxLines: 3}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := binary.Narrow(tt.other); got != tt.want {
				t.Fatalf("Narrow = %+v, want %+v", got, tt.want)
			}
			if got := tt.other.Narrow(binary); got != tt.want && tt.other.TimeoutMS >= 0 {
				t.Fatalf("Narrow in the other order = %+v, want %+v", got, tt.want)
			}
		})
	}
	if got := (Limits{TimeoutMS: -1}).Narrow(Limits{}); got != (Limits{}) {
		t.Fatalf("a negative value must never survive: %+v", got)
	}
}

func TestCapabilitiesDigestIgnoresOrderAndSeesChanges(t *testing.T) {
	caps := Capabilities()
	first, err := CapabilitiesDigest(caps)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	if !strings.HasPrefix(first, "sha256:") || len(first) != len("sha256:")+64 {
		t.Fatalf("digest = %q", first)
	}
	reversed := slices.Clone(caps)
	slices.Reverse(reversed)
	second, err := CapabilitiesDigest(reversed)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	if first != second {
		t.Fatal("the digest must not depend on the order")
	}
	changed := slices.Clone(caps)
	changed[0].Limits.TimeoutMS = 1
	third, err := CapabilitiesDigest(changed)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	if first == third {
		t.Fatal("a changed limit must change the digest")
	}
}

func TestNegotiateVersion(t *testing.T) {
	if got, ok := NegotiateVersion([]string{"9", ProtocolVersion}); !ok || got != ProtocolVersion {
		t.Fatalf("NegotiateVersion = %q, %v", got, ok)
	}
	if _, ok := NegotiateVersion([]string{"0"}); ok {
		t.Fatal("an unknown version must not negotiate")
	}
	if _, ok := NegotiateVersion(nil); ok {
		t.Fatal("no version must not negotiate")
	}
}

func TestHelloValidate(t *testing.T) {
	good := func() Hello {
		var hello Hello
		if err := json.Unmarshal(readFixture(t, "messages/hello.json"), &hello); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return hello
	}
	if err := good().Validate(); err != nil {
		t.Fatalf("the golden hello must pass: %v", err)
	}
	newer := good()
	newer.Capabilities[0].Name = "tempo.search_traces"
	if err := newer.Validate(); err != nil {
		t.Fatalf("a capability this build does not know must not refuse the hello: %v", err)
	}
	for name, change := range map[string]func(*Hello){
		"schema":     func(h *Hello) { h.Schema = "tellagen.proxy.hello/v0" },
		"version":    func(h *Hello) { h.ProxyVersion = " " },
		"protocols":  func(h *Hello) { h.ProtocolVersions = nil },
		"instance":   func(h *Hello) { h.InstanceID = "" },
		"capability": func(h *Hello) { h.Capabilities[0].Name = " " },
	} {
		t.Run(name, func(t *testing.T) {
			hello := good()
			change(&hello)
			if err := hello.Validate(); err == nil {
				t.Fatal("Validate must fail")
			}
		})
	}
}

func TestPollRequestValidate(t *testing.T) {
	var poll PollRequest
	if err := json.Unmarshal(readFixture(t, "messages/poll_request.json"), &poll); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if err := poll.Validate(); err != nil {
		t.Fatalf("the golden poll must pass: %v", err)
	}
	for name, change := range map[string]func(*PollRequest){
		"instance": func(p *PollRequest) { p.InstanceID = "" },
		"mode":     func(p *PollRequest) { p.Mode = "websocket" },
		"wait":     func(p *PollRequest) { p.WaitMS = -1 },
		"slots":    func(p *PollRequest) { p.FreeSlots = -1 },
	} {
		t.Run(name, func(t *testing.T) {
			changed := poll
			change(&changed)
			if err := changed.Validate(); err == nil {
				t.Fatal("Validate must fail")
			}
		})
	}
}

func TestCommandResultValidate(t *testing.T) {
	for name := range messageFixtures {
		if !strings.HasPrefix(name, "result_") || name == "result_accepted.json" {
			continue
		}
		var result CommandResult
		if err := json.Unmarshal(readFixture(t, filepath.Join("messages", name)), &result); err != nil {
			t.Fatalf("decode %s: %v", name, err)
		}
		if err := result.Validate(); err != nil {
			t.Errorf("%s must pass: %v", name, err)
		}
	}
	data := &ResultData{Kind: DataMatrix}
	failure := &ResultError{Code: CodeTimeout, Message: "timed out"}
	tests := []struct {
		name   string
		result CommandResult
	}{
		{"no token", CommandResult{Status: StatusOK, Data: data}},
		{"unknown status", CommandResult{AttemptToken: "at", Status: "done"}},
		{"ok without data", CommandResult{AttemptToken: "at", Status: StatusOK}},
		{"ok with an error", CommandResult{AttemptToken: "at", Status: StatusOK, Data: data, Error: failure}},
		{"partial without data", CommandResult{AttemptToken: "at", Status: StatusPartial}},
		{"rejected without an error", CommandResult{AttemptToken: "at", Status: StatusRejected}},
		{"error without an error", CommandResult{AttemptToken: "at", Status: StatusError}},
		{"unknown code", CommandResult{AttemptToken: "at", Status: StatusError, Error: &ResultError{Code: "nope"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.result.Validate(); err == nil {
				t.Fatal("Validate must fail")
			}
		})
	}
}

func TestEveryErrorCodeOfTheContractIsKnown(t *testing.T) {
	for _, code := range []string{
		"policy_range_exceeded", "policy_datasource_not_allowed", "policy_capability_disabled", "query_guard_failed",
		"source_unavailable", "auth_failed", "timeout", "upstream_4xx",
	} {
		result := CommandResult{AttemptToken: "at", Status: StatusRejected, Error: &ResultError{Code: code}}
		if err := result.Validate(); err != nil {
			t.Errorf("%s: %v", code, err)
		}
	}
}

func TestProxyTokenShape(t *testing.T) {
	token := FormatToken("0194f3a2-7c9f-7000-8000-1234567890ab", "c2VjcmV0LXNlY3JldA")
	proxyID, secret, ok := ParseToken(token)
	if !ok || proxyID != "0194f3a2-7c9f-7000-8000-1234567890ab" || secret != "c2VjcmV0LXNlY3JldA" {
		t.Fatalf("ParseToken = %q, %q, %v", proxyID, secret, ok)
	}
	if got, want := TokenHint(token), "tlg_proxy_0194f3a2…JldA"; got != want {
		t.Fatalf("TokenHint = %q, want %q", got, want)
	}
	for _, bad := range []string{
		"", "tllg_abc", "tlg_proxy_", "tlg_proxy_id", "tlg_proxy_.secret", "tlg_proxy_id.", SessionTokenPrefix + "abc.def",
	} {
		if _, _, ok := ParseToken(bad); ok {
			t.Errorf("ParseToken(%q) must fail", bad)
		}
		if hint := TokenHint(bad); hint != "" {
			t.Errorf("TokenHint(%q) = %q, want empty", bad, hint)
		}
	}
	if hint := TokenHint(TokenPrefix + "id.abc"); hint != "" {
		t.Errorf("a secret too short for a hint gave %q", hint)
	}
}

// The package stays standard-library only, because other modules import it.
func TestPackageImportsOnlyTheStandardLibrary(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil || len(files) == 0 {
		t.Fatalf("no source files: %v", err)
	}
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), name, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imported := range file.Imports {
			path := strings.Trim(imported.Path.Value, `"`)
			if first, _, _ := strings.Cut(path, "/"); strings.Contains(first, ".") {
				t.Errorf("%s imports %s", name, path)
			}
		}
	}
}
