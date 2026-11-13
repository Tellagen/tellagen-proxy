package policy

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/tellagen/tellagen-proxy/protocol"
)

func mustParse(t *testing.T, text string) *File {
	t.Helper()
	file, err := parseFile([]byte(text))
	if err != nil {
		t.Fatalf("parseFile() error = %v", err)
	}
	return file
}

func TestDefaultsWithNoFile(t *testing.T) {
	file, err := Load("", nil)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	view := NewEngine(file).Current()
	if view.DatasourceAllowed("prom-prod") {
		t.Error("a datasource is allowed before the first policy_update")
	}
	if view.LogLines() != 0 || view.RedactionOff() || view.MaxCommandsPerRun() != 40 {
		t.Errorf("view = lines %d, off %v, per run %d", view.LogLines(), view.RedactionOff(), view.MaxCommandsPerRun())
	}
	if !view.CapabilityAllowed(protocol.CapabilityLokiQueryRange) {
		t.Error("a capability is off with no policy file")
	}
	if view.CapabilityAllowed("grafana.api_request") {
		t.Error("an unknown capability is allowed")
	}
	if file.RedactionAllowOff || file.MaxConcurrent != 2 {
		t.Errorf("file = allowOff %v, concurrent %d", file.RedactionAllowOff, file.MaxConcurrent)
	}

	got := view.Limits(protocol.CapabilityPrometheusQueryRange, protocol.Limits{})
	want := protocol.Limits{MaxRangeS: 86400, MaxPoints: 500, MaxSeries: 20, TimeoutMS: 20000, MaxResultBytes: 65536, MaxItems: 200}
	if got != want {
		t.Errorf("Limits() = %+v, want %+v", got, want)
	}
	logs := view.Limits(protocol.CapabilityLokiQueryRange, protocol.Limits{})
	if logs.MaxRangeS != 21600 || logs.MaxLines != 20 || logs.MaxLineChars != 500 {
		t.Errorf("loki Limits() = %+v", logs)
	}
}

func TestLoadRefusesWhatItCannotUnderstand(t *testing.T) {
	tests := []struct {
		name string
		text string
		want string
	}{
		{"unknown key", "logs:\n  maxLine: 3\n", "maxLine"},
		{"unknown top-level key", "datasources: [a]\n", "datasources"},
		{"not yaml", "a: [", "yaml"},
		{"unknown capability", "capabilities: [grafana.api_request]\n", "unknown capability"},
		{"bad duration", "query:\n  maxTimeout: soon\n", "not a duration"},
		{"zero timeout", "query:\n  maxTimeout: 0s\n", "query.maxTimeout must be"},
		{"negative lines", "logs:\n  maxLines: -1\n", "logs.maxLines must be above zero"},
		{"zero list limit", "query:\n  maxListPerRun: 0\n", "query.maxListPerRun must be above zero"},
		{"zero range", "metrics:\n  maxRange: 0s\n", "metrics.maxRange must be"},
		{"zero scan bytes", "logs:\n  maxScanBytes: 0\n", "logs.maxScanBytes must be"},
		{"bad regex rule", "redaction:\n  extraRules:\n    - {kind: pattern, regex: '('}\n", "does not compile"},
		{"unknown rule kind", "redaction:\n  extraRules:\n    - {kind: other, key: a}\n", "unknown rule kind"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseFile([]byte(tt.text))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("parseFile() error = %v, want it to hold %q", err, tt.want)
			}
		})
	}
	if _, err := Load(filepath.Join(t.TempDir(), "missing.yaml"), nil); err == nil {
		t.Error("Load() of a missing file passed")
	}
}

func TestFileValuesStayUnderTheBinaryCeilings(t *testing.T) {
	file := mustParse(t, `
query: {maxTimeout: 10m, maxResultBytes: 99999999, maxPerRun: 5000, maxConcurrent: 50}
metrics: {maxRange: 800h, maxPoints: 9000, maxSeries: 900}
logs: {maxLines: 900, maxLineChars: 9000, maxRange: 800h, maxPatterns: 900}
`)
	view := NewEngine(file).Current()
	metrics := view.Limits(protocol.CapabilityPrometheusQueryRange, protocol.Limits{TimeoutMS: 999999})
	if metrics.MaxRangeS != 7*86400 || metrics.MaxPoints != 500 || metrics.MaxSeries != 50 || metrics.TimeoutMS != 60000 || metrics.MaxResultBytes != 65536 {
		t.Errorf("Limits() = %+v", metrics)
	}
	logs := view.Limits(protocol.CapabilityLokiQueryRange, protocol.Limits{})
	if logs.MaxLines != 50 || logs.MaxLineChars != 500 || logs.MaxRangeS != 86400 {
		t.Errorf("loki Limits() = %+v", logs)
	}
	if file.MaxPerRun != 200 || file.MaxConcurrent != 2 {
		t.Errorf("file = per run %d, concurrent %d", file.MaxPerRun, file.MaxConcurrent)
	}
}

func TestListLimitCanOnlyBeLoweredFromTheProtocolValue(t *testing.T) {
	tests := []struct {
		name string
		text string
		want int
	}{
		{"no file value", "", protocol.DiscoveryCommandsPerRun},
		{"lowered", "query: {maxListPerRun: 12}\n", 12},
		{"raised above the protocol value", "query: {maxListPerRun: 500}\n", protocol.DiscoveryCommandsPerRun},
		{"the data query limit does not move it", "query: {maxPerRun: 20}\n", protocol.DiscoveryCommandsPerRun},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			view := NewEngine(mustParse(t, tt.text)).Current()
			if got := view.MaxListCommandsPerRun(); got != tt.want {
				t.Errorf("MaxListCommandsPerRun() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestTheSmallestLimitApplies(t *testing.T) {
	file := mustParse(t, "metrics: {maxSeries: 15, maxRange: 12h}\nquery: {maxTimeout: 30s}\n")
	engine := NewEngine(file)
	view := engine.Apply(protocol.PolicyUpdate{Narrow: protocol.PolicyNarrow{
		Limits: map[string]protocol.Limits{protocol.FamilyPrometheus: {MaxSeries: 10, MaxPoints: 300}},
	}})
	got := view.Limits(protocol.CapabilityPrometheusQueryRange, protocol.Limits{MaxSeries: 12, MaxPoints: 100, TimeoutMS: 25000, MaxRangeS: 999999})
	want := protocol.Limits{MaxRangeS: 43200, MaxPoints: 100, MaxSeries: 10, TimeoutMS: 25000, MaxResultBytes: 65536, MaxItems: 200}
	if got != want {
		t.Errorf("Limits() = %+v, want %+v", got, want)
	}
	if capped := view.Report().Capped; len(capped) != 0 {
		t.Errorf("Capped = %+v, want none", capped)
	}
}

func TestTimeoutDefaultsTo20SecondsAndStaysUnderTheFile(t *testing.T) {
	file := mustParse(t, "query: {maxTimeout: 30s}\n")
	engine := NewEngine(file)
	capability := protocol.CapabilityPrometheusQueryRange
	if got := engine.Current().Limits(capability, protocol.Limits{}).TimeoutMS; got != 20000 {
		t.Errorf("default timeout = %d", got)
	}
	if got := engine.Current().Limits(capability, protocol.Limits{TimeoutMS: 45000}).TimeoutMS; got != 30000 {
		t.Errorf("command timeout above the file = %d", got)
	}
	view := engine.Apply(protocol.PolicyUpdate{Narrow: protocol.PolicyNarrow{Limits: map[string]protocol.Limits{protocol.FamilyPrometheus: {TimeoutMS: 25000}}}})
	if got := view.Limits(capability, protocol.Limits{}).TimeoutMS; got != 25000 {
		t.Errorf("admin timeout = %d", got)
	}
}

func TestWideningUpdateIsIgnoredAndReported(t *testing.T) {
	file := mustParse(t, `
datasourceUIDs: [prom-prod, loki-prod]
query: {maxPerRun: 30}
metrics: {maxRange: 12h}
logs: {maxLines: 5}
redaction: {allowOff: false}
`)
	engine := NewEngine(file)
	view := engine.Apply(protocol.PolicyUpdate{
		Revision: "srv-8",
		Narrow: protocol.PolicyNarrow{
			DatasourceUIDs:    []string{"prom-prod", "prom-secret"},
			Limits:            map[string]protocol.Limits{protocol.FamilyPrometheus: {MaxRangeS: 86400}, "sql": {MaxItems: 1}},
			MaxCommandsPerRun: 100,
		},
		Data: protocol.PolicyData{LogLines: 20, Redaction: protocol.RedactionOff},
	})

	if !view.DatasourceAllowed("prom-prod") || view.DatasourceAllowed("prom-secret") || view.DatasourceAllowed("loki-prod") {
		t.Errorf("allowed = %v", view.allowed)
	}
	if got := view.Limits(protocol.CapabilityPrometheusQueryRange, protocol.Limits{}).MaxRangeS; got != 43200 {
		t.Errorf("MaxRangeS = %d", got)
	}
	if view.MaxCommandsPerRun() != 30 || view.LogLines() != 5 || view.RedactionOff() {
		t.Errorf("per run %d, lines %d, off %v", view.MaxCommandsPerRun(), view.LogLines(), view.RedactionOff())
	}
	if view.Revision() != "srv-8" {
		t.Errorf("Revision() = %q", view.Revision())
	}

	settings := map[string]protocol.CappedSetting{}
	for _, capped := range view.Report().Capped {
		settings[capped.Setting] = capped
	}
	for _, want := range []struct{ setting, requested, applied string }{
		{"datasource_uids", "prom-secret", "not allowed"},
		{"limits.prometheus.max_range_s", "86400", "43200"},
		{"limits.sql", "set", "ignored"},
		{"max_commands_per_run", "100", "30"},
		{"log_lines", "20", "5"},
		{"redaction", "off", "on"},
	} {
		got, ok := settings[want.setting]
		if !ok {
			t.Errorf("no capped setting %q in %+v", want.setting, settings)
			continue
		}
		if got.Requested != want.requested || got.Applied != want.applied || got.Reason == "" {
			t.Errorf("capped %q = %+v", want.setting, got)
		}
	}
}

func TestNarrowingWithNoFileListAllowsTellagensList(t *testing.T) {
	engine := NewEngine(mustParse(t, ""))
	view := engine.Apply(protocol.PolicyUpdate{Narrow: protocol.PolicyNarrow{DatasourceUIDs: []string{"prom-prod"}}})
	if !view.DatasourceAllowed("prom-prod") || view.DatasourceAllowed("other") {
		t.Errorf("allowed = %v", view.allowed)
	}
}

func TestDatasourceSwitchedOffStopsAtTheNextUpdate(t *testing.T) {
	engine := NewEngine(mustParse(t, ""))
	engine.Apply(protocol.PolicyUpdate{Narrow: protocol.PolicyNarrow{DatasourceUIDs: []string{"a", "b"}}})
	view := engine.Apply(protocol.PolicyUpdate{Narrow: protocol.PolicyNarrow{DatasourceUIDs: []string{"b"}}})
	if view.DatasourceAllowed("a") || !view.DatasourceAllowed("b") {
		t.Errorf("allowed = %v", view.allowed)
	}
	if engine.Current() != view {
		t.Error("Current() is not the applied view")
	}
	if none := engine.Apply(protocol.PolicyUpdate{}); none.DatasourceAllowed("b") {
		t.Error("an update with no list left a datasource allowed")
	}
}

func TestCappedSettingsClearWhenTheUpdateFits(t *testing.T) {
	engine := NewEngine(mustParse(t, "logs: {maxLines: 5}\n"))
	if capped := engine.Apply(protocol.PolicyUpdate{Data: protocol.PolicyData{LogLines: 9}}).Report().Capped; len(capped) != 1 {
		t.Fatalf("Capped = %+v", capped)
	}
	if capped := engine.Apply(protocol.PolicyUpdate{Data: protocol.PolicyData{LogLines: 3}}).Report().Capped; len(capped) != 0 {
		t.Fatalf("Capped = %+v, want none", capped)
	}
}

func TestRedactionSettings(t *testing.T) {
	const line = "customer=Jaan from mari@example.ee"
	tests := []struct {
		name  string
		file  string
		data  protocol.PolicyData
		off   bool
		wants []string
		gone  []string
	}{
		{
			name: "on by default for an unknown value",
			data: protocol.PolicyData{Redaction: "maybe"},
			gone: []string{"mari@example.ee"}, wants: []string{"customer=Jaan"},
		},
		{
			name: "off when the file allows it",
			file: "redaction: {allowOff: true}\n",
			data: protocol.PolicyData{Redaction: protocol.RedactionOff},
			off:  true, wants: []string{line},
		},
		{
			name: "on when the file says nothing about it",
			data: protocol.PolicyData{Redaction: protocol.RedactionOff},
			gone: []string{"mari@example.ee"},
		},
		{
			name: "on when the file forbids off",
			file: "redaction: {allowOff: false}\n",
			data: protocol.PolicyData{Redaction: protocol.RedactionOff},
			gone: []string{"mari@example.ee"},
		},
		{
			name: "extra rules from Tellagen apply",
			data: protocol.PolicyData{Redaction: protocol.RedactionOn, ExtraRules: []protocol.RedactionRule{{Kind: protocol.RedactionRuleKey, Key: "customer"}}},
			gone: []string{"Jaan", "mari@example.ee"},
		},
		{
			name: "the file's rules stay on with redaction off",
			file: "redaction:\n  allowOff: true\n  extraRules:\n    - {kind: key, key: customer}\n",
			data: protocol.PolicyData{Redaction: protocol.RedactionOff},
			off:  true, gone: []string{"Jaan"}, wants: []string{"mari@example.ee"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			view := NewEngine(mustParse(t, tt.file)).Apply(protocol.PolicyUpdate{Data: tt.data})
			if view.RedactionOff() != tt.off {
				t.Errorf("RedactionOff() = %v", view.RedactionOff())
			}
			got := view.Redactor().Text(line, map[string]int{})
			for _, want := range tt.wants {
				if !strings.Contains(got, want) {
					t.Errorf("Text() = %q, want it to hold %q", got, want)
				}
			}
			for _, gone := range tt.gone {
				if strings.Contains(got, gone) {
					t.Errorf("Text() = %q, still holds %q", got, gone)
				}
			}
		})
	}
}

func TestBadRuleFromTellagenIsReportedAndTheOthersApply(t *testing.T) {
	view := NewEngine(mustParse(t, "")).Apply(protocol.PolicyUpdate{Data: protocol.PolicyData{ExtraRules: []protocol.RedactionRule{
		{Kind: protocol.RedactionRulePattern, Regex: "("},
		{Kind: protocol.RedactionRuleKey, Key: "customer"},
	}}})
	capped := view.Report().Capped
	if len(capped) != 1 || capped[0].Setting != "extra_rules" || capped[0].Requested != "(" {
		t.Fatalf("Capped = %+v", capped)
	}
	if got := view.Redactor().Text("customer=Jaan", map[string]int{}); strings.Contains(got, "Jaan") {
		t.Errorf("Text() = %q", got)
	}
}

func TestCapabilitiesAndReportForHello(t *testing.T) {
	file := mustParse(t, `
datasourceUIDs: [prom-prod]
capabilities: [prometheus.query_range, loki.query_range]
query: {maxPerRun: 30, maxTimeout: 30s}
metrics: {maxSeries: 10}
redaction: {allowOff: false}
`)
	view := NewEngine(file).Current()
	caps := view.Capabilities()
	if len(caps) != 2 || caps[0].Name != protocol.CapabilityLokiQueryRange || caps[1].Name != protocol.CapabilityPrometheusQueryRange {
		t.Fatalf("Capabilities() = %+v", caps)
	}
	if got := caps[1].Limits; got != (protocol.Limits{MaxRangeS: 86400, MaxPoints: 500, MaxSeries: 10, TimeoutMS: 30000, MaxResultBytes: 65536}) {
		t.Errorf("limits = %+v", got)
	}
	if view.CapabilityAllowed(protocol.CapabilityGrafanaListAlertRules) {
		t.Error("a capability outside the file is allowed")
	}
	want := protocol.PolicyReport{DatasourceUIDs: []string{"prom-prod"}, MaxCommandsPerRun: 30, RedactionAllowOff: false}
	got := view.Report()
	got.Capped = nil
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Report() = %+v, want %+v", got, want)
	}
}

func TestLoadIntersectsTheEnvironmentAllowlist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte("datasourceUIDs: [a, b]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := Load(path, []string{"b", "c"})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !reflect.DeepEqual(file.DatasourceUIDs, []string{"b"}) {
		t.Errorf("DatasourceUIDs = %v", file.DatasourceUIDs)
	}
	noFile, err := Load("", []string{"x"})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !reflect.DeepEqual(noFile.DatasourceUIDs, []string{"x"}) {
		t.Errorf("DatasourceUIDs = %v", noFile.DatasourceUIDs)
	}
	other, err := Load(path, nil)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if other.Revision() == noFile.Revision() || !strings.HasPrefix(other.Revision(), "sha256:") {
		t.Errorf("Revision() = %q and %q", other.Revision(), noFile.Revision())
	}
}

func TestEmptyFileListAllowsNothing(t *testing.T) {
	view := NewEngine(mustParse(t, "datasourceUIDs: []\n")).Apply(protocol.PolicyUpdate{Narrow: protocol.PolicyNarrow{DatasourceUIDs: []string{"a"}}})
	if view.DatasourceAllowed("a") {
		t.Error("an empty file list allowed a datasource")
	}
	if len(view.Report().Capped) != 1 {
		t.Errorf("Capped = %+v", view.Report().Capped)
	}
}

func TestApplyAndCurrentRace(t *testing.T) {
	engine := NewEngine(mustParse(t, ""))
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for range 200 {
				engine.Apply(protocol.PolicyUpdate{Narrow: protocol.PolicyNarrow{DatasourceUIDs: []string{"a"}}, Data: protocol.PolicyData{LogLines: 3}})
			}
		}()
		go func() {
			defer wg.Done()
			for range 200 {
				view := engine.Current()
				_ = view.Limits(protocol.CapabilityLokiQueryRange, protocol.Limits{})
				_ = view.DatasourceAllowed("a")
				_ = view.Report()
			}
		}()
	}
	wg.Wait()
}
