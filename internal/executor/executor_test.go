package executor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	mcpgrafana "github.com/grafana/mcp-grafana/v2"
	"github.com/grafana/mcp-grafana/v2/tools"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/tellagen/tellagen-proxy/internal/policy"
	"github.com/tellagen/tellagen-proxy/internal/reduce"
	"github.com/tellagen/tellagen-proxy/protocol"
	"github.com/tellagen/tellagen-proxy/redact"
)

func writeFile(path, text string) error {
	return os.WriteFile(path, []byte(text), 0o600)
}

func assertValid(t *testing.T, result protocol.CommandResult) {
	t.Helper()
	if err := result.Validate(); err != nil {
		t.Fatalf("result does not validate: %v (%+v)", err, result)
	}
}

func assertRejected(t *testing.T, result protocol.CommandResult, code string) {
	t.Helper()
	assertValid(t, result)
	if result.Status != protocol.StatusRejected || result.Error == nil || result.Error.Code != code {
		t.Fatalf("result = %+v (error %+v), want rejected with %s", result, result.Error, code)
	}
}

func TestEveryCapabilityRunsThroughTheStub(t *testing.T) {
	expr := `hikaricp_connections_active{service="checkout"}`
	tests := []struct {
		capability string
		args       any
		check      func(t *testing.T, data *protocol.ResultData)
	}{
		{protocol.CapabilityPrometheusQueryRange, promRange(expr), func(t *testing.T, data *protocol.ResultData) {
			if data.Kind != protocol.DataMatrix || len(data.Series) != 1 || data.Series[0].Stats.Max != 100 || data.Series[0].StepS != 30 {
				t.Errorf("data = %+v", data)
			}
		}},
		{protocol.CapabilityPrometheusQueryInstant, protocol.PrometheusQueryInstantArgs{DatasourceUID: "prom-prod", Expr: expr, At: stubT0}, func(t *testing.T, data *protocol.ResultData) {
			if data.Kind != protocol.DataVector || len(data.Samples) != 1 || data.Samples[0].Value != 7 {
				t.Fatalf("data = %+v", data)
			}
			if data.Samples[0].Labels["instance"] != "[redacted:ip]:9090" {
				t.Errorf("labels = %v", data.Samples[0].Labels)
			}
		}},
		{protocol.CapabilityPrometheusListMetricNames, protocol.PrometheusListMetricNamesArgs{DatasourceUID: "prom-prod", Match: "check"}, func(t *testing.T, data *protocol.ResultData) {
			if data.Kind != protocol.DataNames || !reflect.DeepEqual(data.Names, []string{"checkout", "[redacted:email]", "payments"}) {
				t.Errorf("data = %+v", data)
			}
		}},
		{protocol.CapabilityPrometheusListLabelValues, protocol.PrometheusListLabelValuesArgs{DatasourceUID: "prom-prod", Label: "service", Match: `{job="api"}`}, func(t *testing.T, data *protocol.ResultData) {
			if data.Kind != protocol.DataNames || len(data.Names) != 3 || data.Names[1] != "[redacted:email]" {
				t.Errorf("data = %+v", data)
			}
		}},
		{protocol.CapabilityLokiQueryRange, lokiRange(`{job="api"} |= "error"`), func(t *testing.T, data *protocol.ResultData) {
			if data.Kind != protocol.DataLogs || data.LinesTotal != 42 || len(data.Lines) != 1 || data.Lines[0].Text != "pool exhausted" {
				t.Errorf("data = %+v", data)
			}
			if data.Lines[0].Labels["pod"] != "checkout-1" || data.Lines[0].Labels["password"] != "[redacted:field]" {
				t.Errorf("labels = %v", data.Lines[0].Labels)
			}
			if data.Lines[0].At.IsZero() {
				t.Errorf("line time is zero: %+v", data.Lines[0])
			}
		}},
		{protocol.CapabilityLokiQueryRange, protocol.LokiQueryRangeArgs{DatasourceUID: "loki-prod", Expr: `sum by (pod) (count_over_time({job="api"} |= "pool" [1m]))`, Start: stubT0, End: stubT0.Add(time.Hour), StepS: 60}, func(t *testing.T, data *protocol.ResultData) {
			if data.Kind != protocol.DataMatrix || len(data.Series) != 1 || data.Series[0].Stats.Max != 1912 {
				t.Errorf("data = %+v", data)
			}
		}},
		{protocol.CapabilityLokiQueryPatterns, protocol.LokiQueryPatternsArgs{DatasourceUID: "loki-prod", Expr: `{job="api"}`, Start: stubT0, End: stubT0.Add(time.Hour)}, func(t *testing.T, data *protocol.ResultData) {
			if data.Kind != protocol.DataPatterns || len(data.Patterns) != 2 {
				t.Fatalf("data = %+v", data)
			}
			if data.Patterns[0].Pattern != "pool exhausted after <_> ms" || data.Patterns[0].Count != 12 {
				t.Errorf("first pattern = %+v", data.Patterns[0])
			}
			if data.Patterns[1].Pattern != "login <_> from [redacted:ip]" {
				t.Errorf("second pattern = %+v", data.Patterns[1])
			}
		}},
		{protocol.CapabilityLokiListLabelValues, protocol.LokiListLabelValuesArgs{DatasourceUID: "loki-prod", Label: "pod"}, func(t *testing.T, data *protocol.ResultData) {
			if data.Kind != protocol.DataNames || len(data.Names) != 3 {
				t.Errorf("data = %+v", data)
			}
		}},
		{protocol.CapabilityGrafanaListDatasources, protocol.GrafanaListDatasourcesArgs{}, func(t *testing.T, data *protocol.ResultData) {
			if data.Kind != protocol.DataDatasources || len(data.Datasources) != 2 || data.Datasources[0].UID != "prom-prod" || !data.Datasources[0].Default {
				t.Errorf("data = %+v", data)
			}
		}},
		{protocol.CapabilityGrafanaSearchDashboards, protocol.GrafanaSearchDashboardsArgs{Query: "check"}, func(t *testing.T, data *protocol.ResultData) {
			if data.Kind != protocol.DataDashboards || len(data.Dashboards) != 2 || data.Dashboards[0].Folder != "Prod" || data.Dashboards[1].Title != "Owner [redacted:email]" {
				t.Errorf("data = %+v", data)
			}
		}},
		{protocol.CapabilityGrafanaGetPanelQueries, protocol.GrafanaGetPanelQueriesArgs{DashboardUID: "d1"}, func(t *testing.T, data *protocol.ResultData) {
			if data.Kind != protocol.DataPanelQueries || len(data.PanelQueries) != 2 {
				t.Fatalf("data = %+v", data)
			}
			for _, query := range data.PanelQueries {
				if query.DatasourceUID == "prom-secret" {
					t.Errorf("a panel on a datasource outside the policy came through: %+v", query)
				}
			}
		}},
		{protocol.CapabilityGrafanaListAlertRules, protocol.GrafanaListAlertRulesArgs{}, func(t *testing.T, data *protocol.ResultData) {
			if data.Kind != protocol.DataAlertRules || len(data.AlertRules) != 2 || data.AlertRules[0].Title != "Pool full" {
				t.Errorf("data = %+v", data)
			}
		}},
		{protocol.CapabilityGrafanaAlertRuleVersions, protocol.GrafanaAlertRuleVersionsArgs{UID: "a1"}, func(t *testing.T, data *protocol.ResultData) {
			if data.Kind != protocol.DataAlertRuleVersions || len(data.AlertRuleVersions) != 2 || data.AlertRuleVersions[0].Version != 3 {
				t.Errorf("data = %+v", data)
			}
		}},
	}
	covered := map[string]bool{}
	for _, tt := range tests {
		covered[tt.capability] = true
		t.Run(tt.capability, func(t *testing.T) {
			f := newFixture(t, allowAllPolicy, defaultUpdate())
			counted := &countingTransport{next: f.executor.next}
			f.executor.next = counted
			result := f.executor.Execute(context.Background(), command(t, tt.capability, tt.args))
			assertValid(t, result)
			if result.Status != protocol.StatusOK {
				t.Fatalf("result = %+v, error %+v, requests %+v", result, result.Error, f.stub.recorded())
			}
			tt.check(t, result.Data)
			if seen := f.stub.requestCount(); seen == 0 || counted.count.Load() != int64(seen) {
				t.Errorf("Grafana saw %d requests, and %d went through the read-only transport", seen, counted.count.Load())
			}
			if result.Bytes == 0 || result.AttemptToken == "" {
				t.Errorf("result = %+v", result)
			}
			if !strings.HasPrefix(result.ExecutedVia, "grafana-mcp:") || !strings.HasSuffix(result.ExecutedVia, "@"+grafanaMCPVersion) {
				t.Errorf("ExecutedVia = %q", result.ExecutedVia)
			}
			for _, request := range f.stub.recorded() {
				if request.Method != http.MethodGet && request.Path != "/api/ds/query" {
					t.Errorf("a write reached Grafana: %+v", request)
				}
				if request.Token != "glsa_test" {
					t.Errorf("request without the token: %+v", request)
				}
			}
		})
	}
	for _, capability := range protocol.Capabilities() {
		if !covered[capability.Name] {
			t.Errorf("capability %s has no test", capability.Name)
		}
	}
}

type countingTransport struct {
	next  http.RoundTripper
	count atomic.Int64
}

func (c *countingTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	c.count.Add(1)
	return c.next.RoundTrip(request)
}

func TestCapabilityToolMapIsCompleteAndInsideTheAllowlist(t *testing.T) {
	used := map[string]bool{}
	for _, capability := range protocol.Capabilities() {
		tool, ok := capabilityTools[capability.Name]
		if !ok {
			t.Errorf("capability %s maps to no tool", capability.Name)
			continue
		}
		if allowedTools[tool.Tool.Name] != tool {
			t.Errorf("capability %s runs %s, which is not on the allowlist", capability.Name, tool.Tool.Name)
		}
		used[tool.Tool.Name] = true
	}
	for name := range allowedTools {
		if !used[name] {
			t.Errorf("tool %s is on the allowlist, and no capability runs it", name)
		}
	}
	for name := range allowedTools {
		for _, banned := range []string{"grafana_api", "api_request", "sql", "update_", "create_", "delete_", "write"} {
			if strings.Contains(name, banned) {
				t.Errorf("tool %s must not be on the allowlist", name)
			}
		}
	}
}

func TestToolLockMatchesThisBuild(t *testing.T) {
	lock, err := loadToolsLock()
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyTools(allowedTools, lock, grafanaMCPVersion); err != nil {
		if os.Getenv("UPDATE_TOOL_LOCK") == "" {
			t.Fatalf("%v\nAfter reviewing a version bump, run with UPDATE_TOOL_LOCK=1", err)
		}
		fresh := toolsLock{Version: grafanaMCPVersion, Tools: map[string]string{}}
		for name, tool := range allowedTools {
			digest, err := schemaDigest(tool)
			if err != nil {
				t.Fatal(err)
			}
			fresh.Tools[name] = digest
		}
		encoded, err := json.MarshalIndent(fresh, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile("tools.lock.json", append(encoded, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Fatal("tools.lock.json was rewritten. Run the test again")
	}
}

func TestChangedToolListStopsTheProxyAtStart(t *testing.T) {
	lock, err := loadToolsLock()
	if err != nil {
		t.Fatal(err)
	}
	clone := func() map[string]*mcpgrafana.Tool {
		out := map[string]*mcpgrafana.Tool{}
		for name, tool := range allowedTools {
			out[name] = tool
		}
		return out
	}
	changedSchema := tools.QueryPrometheus
	changedTool := *changedSchema.Tool
	changedTool.InputSchema = map[string]any{"type": "object", "properties": map[string]any{"url": map[string]any{"type": "string"}}}
	changedSchema.Tool = &changedTool

	writable := tools.QueryPrometheus
	writableTool := *writable.Tool
	writableTool.Annotations = &mcp.ToolAnnotations{ReadOnlyHint: false}
	writable.Tool = &writableTool

	renamed := tools.QueryPrometheus
	renamedTool := *renamed.Tool
	renamedTool.Name = "query_anything"
	renamed.Tool = &renamedTool

	tests := []struct {
		name    string
		tools   func() map[string]*mcpgrafana.Tool
		lock    toolsLock
		version string
		want    string
	}{
		{"new tool", func() map[string]*mcpgrafana.Tool {
			out := clone()
			out["update_dashboard"] = &tools.UpdateDashboard
			return out
		}, lock, grafanaMCPVersion, "update_dashboard is registered but not in the lock file"},
		{"missing tool", func() map[string]*mcpgrafana.Tool {
			out := clone()
			delete(out, "query_prometheus")
			return out
		}, lock, grafanaMCPVersion, "query_prometheus is in the lock file but not registered"},
		{"changed schema", func() map[string]*mcpgrafana.Tool {
			out := clone()
			out["query_prometheus"] = &changedSchema
			return out
		}, lock, grafanaMCPVersion, "query_prometheus has a changed input schema"},
		{"no longer read-only", func() map[string]*mcpgrafana.Tool {
			out := clone()
			out["query_prometheus"] = &writable
			return out
		}, lock, grafanaMCPVersion, "query_prometheus is not marked as read-only"},
		{"renamed", func() map[string]*mcpgrafana.Tool {
			out := clone()
			out["query_prometheus"] = &renamed
			return out
		}, lock, grafanaMCPVersion, "now calls itself query_anything"},
		{"other version", clone, lock, "v9.9.9", "the lock file is for grafana-mcp v2.2.0"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := verifyTools(tt.tools(), tt.lock, tt.version)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("verifyTools() = %v, want it to hold %q", err, tt.want)
			}
		})
	}
}

func TestDatasourceOutsideTheListIsRejected(t *testing.T) {
	f := newFixture(t, allowAllPolicy, defaultUpdate())
	args := promRange(`up`)
	args.DatasourceUID = "prom-secret"
	result := f.executor.Execute(context.Background(), command(t, protocol.CapabilityPrometheusQueryRange, args))
	assertRejected(t, result, protocol.CodePolicyDatasourceNotAllowed)
	if f.stub.requestCount() != 0 {
		t.Errorf("a refused command reached Grafana: %+v", f.stub.recorded())
	}
	args.DatasourceUID = ""
	result = f.executor.Execute(context.Background(), command(t, protocol.CapabilityPrometheusQueryRange, args))
	assertRejected(t, result, protocol.CodePolicyDatasourceNotAllowed)
}

func TestNothingIsAllowedBeforeTheFirstPolicyUpdate(t *testing.T) {
	f := newFixture(t, "", protocol.PolicyUpdate{})
	result := f.executor.Execute(context.Background(), command(t, protocol.CapabilityPrometheusQueryRange, promRange(`up`)))
	assertRejected(t, result, protocol.CodePolicyDatasourceNotAllowed)
}

func TestWideningUpdateIsIgnoredAtExecution(t *testing.T) {
	update := defaultUpdate()
	update.Narrow.DatasourceUIDs = append(update.Narrow.DatasourceUIDs, "prom-secret")
	update.Narrow.Limits = map[string]protocol.Limits{protocol.FamilyPrometheus: {MaxRangeS: 7 * 24 * 3600}}
	update.Data.LogLines = 500
	f := newFixture(t, allowAllPolicy+"metrics: {maxRange: 2h}\nlogs: {maxLines: 2}\n", update)

	args := promRange(`up`)
	args.DatasourceUID = "prom-secret"
	assertRejected(t, f.executor.Execute(context.Background(), command(t, protocol.CapabilityPrometheusQueryRange, args)), protocol.CodePolicyDatasourceNotAllowed)

	wide := promRange(`up`)
	wide.End = stubT0.Add(3 * time.Hour)
	result := f.executor.Execute(context.Background(), command(t, protocol.CapabilityPrometheusQueryRange, wide))
	assertRejected(t, result, protocol.CodePolicyRangeExceeded)
	if result.Error.Hint == nil || result.Error.Hint.MaxRangeS != 7200 {
		t.Errorf("Hint = %+v", result.Error.Hint)
	}

	capped := map[string]string{}
	for _, setting := range f.executor.policy.Current().Report().Capped {
		capped[setting.Setting] = setting.Applied
	}
	want := map[string]string{"datasource_uids": "not allowed", "limits.prometheus.max_range_s": "7200", "log_lines": "2"}
	if !reflect.DeepEqual(capped, want) {
		t.Errorf("capped = %v, want %v", capped, want)
	}
}

func TestCapabilityOutsideThePolicyIsRejected(t *testing.T) {
	f := newFixture(t, "capabilities: [prometheus.query_range]\n", defaultUpdate())
	tests := []struct {
		name    string
		command protocol.Command
	}{
		{"not in the file", command(t, protocol.CapabilityLokiQueryRange, lokiRange(`{a="b"}`))},
		{"unknown", func() protocol.Command {
			c := command(t, "grafana.api_request", map[string]string{"path": "/api/admin"})
			return c
		}()},
		{"other version", func() protocol.Command {
			c := command(t, protocol.CapabilityPrometheusQueryRange, promRange(`up`))
			c.CapabilityVersion = 2
			return c
		}()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertRejected(t, f.executor.Execute(context.Background(), tt.command), protocol.CodePolicyCapabilityDisabled)
			if f.stub.requestCount() != 0 {
				t.Errorf("a refused command reached Grafana: %+v", f.stub.recorded())
			}
		})
	}
}

func TestCommandArgumentsAreStrict(t *testing.T) {
	f := newFixture(t, allowAllPolicy, defaultUpdate())
	c := command(t, protocol.CapabilityPrometheusQueryRange, map[string]any{"datasource_uid": "prom-prod", "expr": "up", "url": "http://evil.example"})
	assertRejected(t, f.executor.Execute(context.Background(), c), protocol.CodeQueryGuardFailed)
	if f.stub.requestCount() != 0 {
		t.Errorf("a refused command reached Grafana: %+v", f.stub.recorded())
	}
}

func TestQueryGuardsStopACommandBeforeGrafana(t *testing.T) {
	longRange := promRange(`up`)
	longRange.End = stubT0.Add(48 * time.Hour)
	longRange.StepS = 3600
	lookback := promRange(`rate(up[30d])`)
	points := promRange(`up`)
	points.StepS = 1
	noStep := promRange(`up`)
	noStep.StepS = 0
	logRange := lokiRange(`{job="api"}`)
	logRange.End = stubT0.Add(7 * time.Hour)
	metricNoStep := lokiRange(`rate({job="api"}[1m])`)
	logStep := lokiRange(`{job="api"}`)
	logStep.StepS = 60
	tests := []struct {
		name       string
		capability string
		args       any
		code       string
		hint       *protocol.Limits
	}{
		{"catch-all metric name", protocol.CapabilityPrometheusQueryRange, promRange(`{__name__=~".+"}`), protocol.CodeQueryGuardFailed, nil},
		{"unparseable PromQL", protocol.CapabilityPrometheusQueryRange, promRange(`sum(`), protocol.CodeQueryGuardFailed, nil},
		{"instant catch-all", protocol.CapabilityPrometheusQueryInstant, protocol.PrometheusQueryInstantArgs{DatasourceUID: "prom-prod", Expr: `{a=~".*"}`, At: stubT0}, protocol.CodeQueryGuardFailed, nil},
		{"instant lookback", protocol.CapabilityPrometheusQueryInstant, protocol.PrometheusQueryInstantArgs{DatasourceUID: "prom-prod", Expr: `rate(up[30d])`, At: stubT0}, protocol.CodePolicyRangeExceeded, &protocol.Limits{MaxRangeS: 86400}},
		{"instant no time", protocol.CapabilityPrometheusQueryInstant, protocol.PrometheusQueryInstantArgs{DatasourceUID: "prom-prod", Expr: `up`}, protocol.CodeQueryGuardFailed, nil},
		{"range too long", protocol.CapabilityPrometheusQueryRange, longRange, protocol.CodePolicyRangeExceeded, &protocol.Limits{MaxRangeS: 86400}},
		{"range vector too long", protocol.CapabilityPrometheusQueryRange, lookback, protocol.CodePolicyRangeExceeded, &protocol.Limits{MaxRangeS: 86400}},
		{"too many points", protocol.CapabilityPrometheusQueryRange, points, protocol.CodeQueryGuardFailed, &protocol.Limits{MaxPoints: 500}},
		{"no step", protocol.CapabilityPrometheusQueryRange, noStep, protocol.CodeQueryGuardFailed, nil},
		{"label name with a path", protocol.CapabilityPrometheusListLabelValues, protocol.PrometheusListLabelValuesArgs{DatasourceUID: "prom-prod", Label: "../../admin"}, protocol.CodeQueryGuardFailed, nil},
		{"broad label match", protocol.CapabilityPrometheusListLabelValues, protocol.PrometheusListLabelValuesArgs{DatasourceUID: "prom-prod", Label: "job", Match: `{a=~".+"}`}, protocol.CodeQueryGuardFailed, nil},
		{"bad metric regex", protocol.CapabilityPrometheusListMetricNames, protocol.PrometheusListMetricNamesArgs{DatasourceUID: "prom-prod", Match: "("}, protocol.CodeQueryGuardFailed, nil},
		{"Loki regex only", protocol.CapabilityLokiQueryRange, lokiRange(`{job=~".+"}`), protocol.CodeQueryGuardFailed, nil},
		{"Loki stage", protocol.CapabilityLokiQueryRange, lokiRange(`{job="api"} | line_format "x"`), protocol.CodeQueryGuardFailed, nil},
		{"Loki range", protocol.CapabilityLokiQueryRange, logRange, protocol.CodePolicyRangeExceeded, &protocol.Limits{MaxRangeS: 21600}},
		{"Loki metric with no step", protocol.CapabilityLokiQueryRange, metricNoStep, protocol.CodeQueryGuardFailed, nil},
		{"Loki log query with a step", protocol.CapabilityLokiQueryRange, logStep, protocol.CodeQueryGuardFailed, nil},
		{"Loki patterns with a pipeline", protocol.CapabilityLokiQueryPatterns, protocol.LokiQueryPatternsArgs{DatasourceUID: "loki-prod", Expr: `{a="b"} |= "c"`, Start: stubT0, End: stubT0.Add(time.Hour)}, protocol.CodeQueryGuardFailed, nil},
		{"Loki patterns too long", protocol.CapabilityLokiQueryPatterns, protocol.LokiQueryPatternsArgs{DatasourceUID: "loki-prod", Expr: `{a="b"}`, Start: stubT0, End: stubT0.Add(7 * time.Hour)}, protocol.CodePolicyRangeExceeded, &protocol.Limits{MaxRangeS: 21600}},
		{"Loki label with a path", protocol.CapabilityLokiListLabelValues, protocol.LokiListLabelValuesArgs{DatasourceUID: "loki-prod", Label: "a/b"}, protocol.CodeQueryGuardFailed, nil},
		{"dashboard uid with a path", protocol.CapabilityGrafanaGetPanelQueries, protocol.GrafanaGetPanelQueriesArgs{DashboardUID: "../admin"}, protocol.CodeQueryGuardFailed, nil},
		{"long search", protocol.CapabilityGrafanaSearchDashboards, protocol.GrafanaSearchDashboardsArgs{Query: strings.Repeat("a", 300)}, protocol.CodeQueryGuardFailed, nil},
		{"long alert search", protocol.CapabilityGrafanaListAlertRules, protocol.GrafanaListAlertRulesArgs{Query: strings.Repeat("a", 300)}, protocol.CodeQueryGuardFailed, nil},
		{"bad datasource type", protocol.CapabilityGrafanaListDatasources, protocol.GrafanaListDatasourcesArgs{Type: "a/b"}, protocol.CodeQueryGuardFailed, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t, allowAllPolicy, defaultUpdate())
			result := f.executor.Execute(context.Background(), command(t, tt.capability, tt.args))
			assertRejected(t, result, tt.code)
			if result.Error.Message == "" {
				t.Error("the rejection has no message")
			}
			if tt.hint != nil && (result.Error.Hint == nil || *result.Error.Hint != *tt.hint) {
				t.Errorf("Hint = %+v, want %+v", result.Error.Hint, tt.hint)
			}
			if f.stub.requestCount() != 0 {
				t.Errorf("a refused command reached Grafana: %+v", f.stub.recorded())
			}
		})
	}
}

func TestCommandLimitsCanOnlyLower(t *testing.T) {
	f := newFixture(t, allowAllPolicy, defaultUpdate())
	c := command(t, protocol.CapabilityPrometheusQueryRange, promRange(`up`))
	c.Limits = protocol.Limits{MaxRangeS: 60}
	result := f.executor.Execute(context.Background(), c)
	assertRejected(t, result, protocol.CodePolicyRangeExceeded)
	if result.Error.Hint.MaxRangeS != 60 {
		t.Errorf("Hint = %+v", result.Error.Hint)
	}

	wide := promRange(`up`)
	wide.End = stubT0.Add(48 * time.Hour)
	wide.StepS = 3600
	c = command(t, protocol.CapabilityPrometheusQueryRange, wide)
	c.Limits = protocol.Limits{MaxRangeS: 10 * 24 * 3600}
	assertRejected(t, f.executor.Execute(context.Background(), c), protocol.CodePolicyRangeExceeded)
}

func TestSeriesPointsAndBytesAreBounded(t *testing.T) {
	f := newFixture(t, allowAllPolicy, defaultUpdate())
	f.stub.override = func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path != "/api/ds/query" {
			return false
		}
		var frames []string
		for i := range 60 {
			frames = append(frames, `{"schema":{"fields":[{"name":"Time","type":"time","typeInfo":{"frame":"time.Time"}},{"name":"Value","type":"number","typeInfo":{"frame":"float64"},"labels":{"pod":"`+strings.Repeat("p", 2000)+string(rune('A'+i%26))+`"}}]},"data":{"values":[[1762261200000,1762261260000],[`+jsonNumber(i)+`,1]]}}`)
		}
		_, _ = w.Write([]byte(`{"results":{"A":{"status":200,"frames":[` + strings.Join(frames, ",") + `]}}}`))
		return true
	}
	c := command(t, protocol.CapabilityPrometheusQueryRange, promRange(`up`))
	c.Limits = protocol.Limits{MaxSeries: 5}
	result := f.executor.Execute(context.Background(), c)
	assertValid(t, result)
	if !result.Truncated || len(result.Data.Series) != 5 || result.Data.SeriesTotal != 60 {
		t.Fatalf("truncated %v, series %d of %d", result.Truncated, len(result.Data.Series), result.Data.SeriesTotal)
	}

	c = command(t, protocol.CapabilityPrometheusQueryRange, promRange(`up`))
	c.Limits = protocol.Limits{MaxResultBytes: 6000}
	result = f.executor.Execute(context.Background(), c)
	assertValid(t, result)
	if !result.Truncated || result.Bytes > 6000 || len(result.Data.Series) == 0 {
		t.Fatalf("truncated %v, bytes %d, series %d", result.Truncated, result.Bytes, len(result.Data.Series))
	}
	encoded, err := json.Marshal(result.Data)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) != result.Bytes {
		t.Errorf("Bytes = %d, data is %d bytes", result.Bytes, len(encoded))
	}
}

func jsonNumber(i int) string {
	encoded, _ := json.Marshal(i)
	return string(encoded)
}

func TestItemAndPatternLimitsTruncate(t *testing.T) {
	f := newFixture(t, allowAllPolicy, defaultUpdate())
	c := command(t, protocol.CapabilityLokiListLabelValues, protocol.LokiListLabelValuesArgs{DatasourceUID: "loki-prod", Label: "pod"})
	c.Limits = protocol.Limits{MaxItems: 2}
	result := f.executor.Execute(context.Background(), c)
	assertValid(t, result)
	if len(result.Data.Names) != 2 || !result.Truncated {
		t.Errorf("names %v, truncated %v", result.Data.Names, result.Truncated)
	}

	c = command(t, protocol.CapabilityLokiQueryPatterns, protocol.LokiQueryPatternsArgs{DatasourceUID: "loki-prod", Expr: `{a="b"}`, Start: stubT0, End: stubT0.Add(time.Hour)})
	c.Limits = protocol.Limits{MaxPatterns: 1}
	result = f.executor.Execute(context.Background(), c)
	assertValid(t, result)
	if len(result.Data.Patterns) != 1 || !result.Truncated {
		t.Errorf("patterns %v, truncated %v", result.Data.Patterns, result.Truncated)
	}

	c = command(t, protocol.CapabilityGrafanaSearchDashboards, protocol.GrafanaSearchDashboardsArgs{})
	c.Limits = protocol.Limits{MaxItems: 1}
	result = f.executor.Execute(context.Background(), c)
	assertValid(t, result)
	if len(result.Data.Dashboards) != 1 || !result.Truncated {
		t.Errorf("dashboards %v, truncated %v", result.Data.Dashboards, result.Truncated)
	}
}

func TestLokiScanBudgetIsEnforced(t *testing.T) {
	tests := []struct {
		name  string
		stats func(w http.ResponseWriter)
	}{
		{"estimate over the budget", func(w http.ResponseWriter) {
			_, _ = w.Write([]byte(`{"streams":9,"chunks":9,"entries":9,"bytes":5000}`))
		}},
		{"estimate unavailable", func(w http.ResponseWriter) { w.WriteHeader(http.StatusBadGateway) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t, allowAllPolicy+"logs: {maxScanBytes: 1000}\n", defaultUpdate())
			f.stub.override = func(w http.ResponseWriter, r *http.Request) bool {
				if strings.HasSuffix(r.URL.Path, "/index/stats") {
					tt.stats(w)
					return true
				}
				return false
			}
			c := command(t, protocol.CapabilityLokiQueryRange, protocol.LokiQueryRangeArgs{DatasourceUID: "loki-prod", Expr: `sum(rate({job="api"}[1m]))`, Start: stubT0, End: stubT0.Add(time.Hour), StepS: 60})
			assertRejected(t, f.executor.Execute(context.Background(), c), protocol.CodeQueryGuardFailed)
			if bodies := f.stub.queryBodies(); len(bodies) != 0 {
				t.Errorf("the query reached Loki: %v", bodies)
			}
		})
	}
}

func TestRunCapCountsCommandsNotAttempts(t *testing.T) {
	f := newFixture(t, allowAllPolicy+"query: {maxPerRun: 2}\n", defaultUpdate())
	run := func(c protocol.Command) protocol.CommandResult {
		c.RunID = "inv_1"
		return f.executor.Execute(context.Background(), c)
	}
	first := command(t, protocol.CapabilityPrometheusQueryRange, promRange(`up`))
	if result := run(first); result.Status != protocol.StatusOK {
		t.Fatalf("first = %+v", result)
	}
	second := command(t, protocol.CapabilityPrometheusQueryRange, promRange(`up`))
	if result := run(second); result.Status != protocol.StatusOK {
		t.Fatalf("second = %+v", result)
	}
	retried := first
	retried.Attempt = 2
	if result := run(retried); result.Status != protocol.StatusOK {
		t.Fatalf("a retry was counted: %+v", result)
	}
	calls := f.stub.requestCount()
	result := run(command(t, protocol.CapabilityPrometheusQueryRange, promRange(`up`)))
	assertRejected(t, result, protocol.CodeQueryGuardFailed)
	if !strings.Contains(result.Error.Message, "2 queries") {
		t.Errorf("Message = %q", result.Error.Message)
	}
	if f.stub.requestCount() != calls {
		t.Error("the refused command reached Grafana")
	}

	other := command(t, protocol.CapabilityPrometheusQueryRange, promRange(`up`))
	other.RunID = "inv_2"
	if result := f.executor.Execute(context.Background(), other); result.Status != protocol.StatusOK {
		t.Errorf("another run was refused: %+v", result)
	}
	noRun := command(t, protocol.CapabilityPrometheusQueryRange, promRange(`up`))
	if result := f.executor.Execute(context.Background(), noRun); result.Status != protocol.StatusOK {
		t.Errorf("a test query was refused: %+v", result)
	}
}

func TestDiscoveryHasItsOwnRunLimit(t *testing.T) {
	f := newFixture(t, allowAllPolicy+"query: {maxPerRun: 1}\n", defaultUpdate())
	run := func(c protocol.Command) protocol.CommandResult {
		c.RunID = "inv_1"
		return f.executor.Execute(context.Background(), c)
	}
	list := func() protocol.Command {
		return command(t, protocol.CapabilityGrafanaListDatasources, map[string]any{})
	}
	if result := run(list()); result.Status != protocol.StatusOK {
		t.Fatalf("a list call = %+v", result)
	}
	if result := run(command(t, protocol.CapabilityPrometheusQueryRange, promRange(`up`))); result.Status != protocol.StatusOK {
		t.Fatalf("a list call used up the run's one query: %+v", result)
	}
	assertRejected(t, run(command(t, protocol.CapabilityPrometheusQueryRange, promRange(`up`))), protocol.CodeQueryGuardFailed)
	for i := 1; i < protocol.DiscoveryCommandsPerRun; i++ {
		if result := run(list()); result.Status != protocol.StatusOK {
			t.Fatalf("list call %d after the queries ran out = %+v", i+1, result)
		}
	}
	calls := f.stub.requestCount()
	result := run(list())
	assertRejected(t, result, protocol.CodeQueryGuardFailed)
	if !strings.Contains(result.Error.Message, "list and search calls") {
		t.Errorf("Message = %q", result.Error.Message)
	}
	if f.stub.requestCount() != calls {
		t.Error("the refused command reached Grafana")
	}
}

func TestPolicyFileCanLowerTheListLimit(t *testing.T) {
	f := newFixture(t, allowAllPolicy+"query: {maxListPerRun: 2}\n", defaultUpdate())
	run := func(c protocol.Command) protocol.CommandResult {
		c.RunID = "inv_1"
		return f.executor.Execute(context.Background(), c)
	}
	list := func() protocol.Command {
		return command(t, protocol.CapabilityGrafanaListDatasources, map[string]any{})
	}
	for i := 1; i <= 2; i++ {
		if result := run(list()); result.Status != protocol.StatusOK {
			t.Fatalf("list call %d = %+v", i, result)
		}
	}
	calls := f.stub.requestCount()
	result := run(list())
	assertRejected(t, result, protocol.CodeQueryGuardFailed)
	if !strings.Contains(result.Error.Message, "2 list and search calls") {
		t.Errorf("Message = %q", result.Error.Message)
	}
	if f.stub.requestCount() != calls {
		t.Error("the refused command reached Grafana")
	}
	if result := run(command(t, protocol.CapabilityPrometheusQueryRange, promRange(`up`))); result.Status != protocol.StatusOK {
		t.Errorf("a data query was refused by the list limit: %+v", result)
	}
}

func TestRunCounterForgetsOldRuns(t *testing.T) {
	counter := newRunCounter()
	if !counter.admit("old", "c1", 1) {
		t.Fatal("first command refused")
	}
	counter.runs["old"].lastSeen = time.Now().Add(-2 * runRetention)
	if !counter.admit("new", "c2", 1) {
		t.Fatal("new run refused")
	}
	if _, ok := counter.runs["old"]; ok {
		t.Error("the old run is still held")
	}
}

func waitFor(t *testing.T, what string, done func() bool) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for !done() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestAtMostTwoQueriesRunAtATime(t *testing.T) {
	f := newFixture(t, allowAllPolicy, defaultUpdate())
	release := make(chan struct{})
	f.stub.hold = release

	if got := f.executor.FreeSlots(); got != 2 {
		t.Fatalf("FreeSlots() = %d", got)
	}
	var wg sync.WaitGroup
	results := make([]protocol.CommandResult, 4)
	for i := range results {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i] = f.executor.Execute(context.Background(), command(t, protocol.CapabilityPrometheusQueryRange, promRange(`up`)))
		}()
	}
	waitFor(t, "two queries at Grafana", func() bool { return len(f.stub.queryBodies()) == 2 })
	if got := f.executor.FreeSlots(); got != 0 {
		t.Errorf("FreeSlots() = %d", got)
	}
	if got := len(f.executor.InFlight()); got != 4 {
		t.Errorf("InFlight() = %d", got)
	}
	time.Sleep(50 * time.Millisecond)
	if got := len(f.stub.queryBodies()); got != 2 {
		t.Errorf("%d queries reached Grafana at once", got)
	}
	close(release)
	wg.Wait()
	for _, result := range results {
		if result.Status != protocol.StatusOK {
			t.Errorf("result = %+v (%+v)", result, result.Error)
		}
	}
	if got := f.executor.FreeSlots(); got != 2 {
		t.Errorf("FreeSlots() after = %d", got)
	}
	if got := len(f.executor.InFlight()); got != 0 {
		t.Errorf("InFlight() after = %d", got)
	}
}

func TestPolicyFileCanLowerConcurrency(t *testing.T) {
	f := newFixture(t, allowAllPolicy+"query: {maxConcurrent: 1}\n", defaultUpdate())
	if got := f.executor.FreeSlots(); got != 1 {
		t.Errorf("FreeSlots() = %d", got)
	}
}

func TestWaitingForASlotEndsAtTheDeadline(t *testing.T) {
	f := newFixture(t, allowAllPolicy+"query: {maxConcurrent: 1}\n", defaultUpdate())
	release := make(chan struct{})
	defer close(release)
	f.stub.hold = release
	go f.executor.Execute(context.Background(), command(t, protocol.CapabilityPrometheusQueryRange, promRange(`up`)))
	waitFor(t, "the first query", func() bool { return len(f.stub.queryBodies()) == 1 })

	c := command(t, protocol.CapabilityPrometheusQueryRange, promRange(`up`))
	c.DeadlineMS = 20
	result := f.executor.Execute(context.Background(), c)
	assertValid(t, result)
	if result.Status != protocol.StatusError || result.Error.Code != protocol.CodeTimeout || !result.Error.Retryable {
		t.Fatalf("result = %+v (%+v)", result, result.Error)
	}
}

func TestSlowQueryTimesOut(t *testing.T) {
	f := newFixture(t, allowAllPolicy, defaultUpdate())
	release := make(chan struct{})
	defer close(release)
	f.stub.hold = release
	c := command(t, protocol.CapabilityPrometheusQueryRange, promRange(`up`))
	c.Limits = protocol.Limits{TimeoutMS: 50}
	result := f.executor.Execute(context.Background(), c)
	assertValid(t, result)
	if result.Status != protocol.StatusError || result.Error.Code != protocol.CodeTimeout {
		t.Fatalf("result = %+v (%+v)", result, result.Error)
	}
}

func TestCancelStopsARunningCommand(t *testing.T) {
	f := newFixture(t, allowAllPolicy, defaultUpdate())
	release := make(chan struct{})
	defer close(release)
	f.stub.hold = release
	c := command(t, protocol.CapabilityPrometheusQueryRange, promRange(`up`))
	done := make(chan protocol.CommandResult, 1)
	go func() { done <- f.executor.Execute(context.Background(), c) }()
	waitFor(t, "the query", func() bool { return len(f.stub.queryBodies()) == 1 })
	if !f.executor.Cancel(c.CommandID) {
		t.Fatal("Cancel() = false")
	}
	result := <-done
	assertValid(t, result)
	if result.Status != protocol.StatusCancelled || result.Data != nil {
		t.Fatalf("result = %+v", result)
	}
	if f.executor.Cancel(c.CommandID) {
		t.Error("Cancel() = true after the command ended")
	}
}

func TestDatasourceSwitchedOffStopsARunningCommand(t *testing.T) {
	f := newFixture(t, allowAllPolicy, defaultUpdate())
	release := make(chan struct{})
	defer close(release)
	f.stub.hold = release
	prom := command(t, protocol.CapabilityPrometheusQueryRange, promRange(`up`))
	done := make(chan protocol.CommandResult, 1)
	go func() { done <- f.executor.Execute(context.Background(), prom) }()
	waitFor(t, "the query", func() bool { return len(f.stub.queryBodies()) == 1 })

	update := defaultUpdate()
	update.Revision = "srv-2"
	update.Narrow.DatasourceUIDs = []string{"loki-prod"}
	f.executor.ApplyPolicy(update)

	result := <-done
	assertValid(t, result)
	if result.Status != protocol.StatusCancelled {
		t.Fatalf("result = %+v (%+v)", result, result.Error)
	}
	assertRejected(t, f.executor.Execute(context.Background(), command(t, protocol.CapabilityPrometheusQueryRange, promRange(`up`))), protocol.CodePolicyDatasourceNotAllowed)
	if got := f.executor.policy.Current().Revision(); got != "srv-2" {
		t.Errorf("Revision() = %q", got)
	}
}

func TestDatasourceSwitchedOffAsAQueryEndsReturnsNoData(t *testing.T) {
	f := newFixture(t, allowAllPolicy, defaultUpdate())
	f.stub.override = func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path == "/api/ds/query" {
			update := defaultUpdate()
			update.Narrow.DatasourceUIDs = nil
			f.executor.policy.Apply(update)
		}
		return false
	}
	result := f.executor.Execute(context.Background(), command(t, protocol.CapabilityPrometheusQueryRange, promRange(`up`)))
	assertValid(t, result)
	if result.Status != protocol.StatusCancelled || result.Data != nil {
		t.Fatalf("result = %+v", result)
	}
}

func TestSecondAttemptReplacesARunningFirst(t *testing.T) {
	f := newFixture(t, allowAllPolicy, defaultUpdate())
	release := make(chan struct{})
	f.stub.hold = release
	c := command(t, protocol.CapabilityPrometheusQueryRange, promRange(`up`))
	done := make(chan protocol.CommandResult, 1)
	go func() { done <- f.executor.Execute(context.Background(), c) }()
	waitFor(t, "the query", func() bool { return len(f.stub.queryBodies()) == 1 })

	retry := c
	retry.Attempt = 2
	second := make(chan protocol.CommandResult, 1)
	go func() { second <- f.executor.Execute(context.Background(), retry) }()
	if result := <-done; result.Status != protocol.StatusCancelled {
		t.Fatalf("first attempt = %+v", result)
	}
	waitFor(t, "the second query", func() bool { return len(f.stub.queryBodies()) == 2 })
	close(release)
	if result := <-second; result.Status != protocol.StatusOK {
		t.Fatalf("second attempt = %+v (%+v)", result, result.Error)
	}
}

func TestUpstreamFailuresAreNamed(t *testing.T) {
	tests := []struct {
		name      string
		status    int
		body      string
		code      string
		retryable bool
		message   string
	}{
		{"unauthorized", 401, `{"message":"invalid API key"}`, protocol.CodeAuthFailed, false, "refused the proxy's token"},
		{"forbidden", 403, `{"message":"permissions"}`, protocol.CodeAuthFailed, false, "refused the proxy's token"},
		{"bad query", 400, `{"results":{"A":{"error":"parse error at char 3","status":400,"frames":[]}}}`, protocol.CodeUpstream4xx, false, "parse error"},
		{"source down", 502, `{"message":"bad gateway"}`, protocol.CodeSourceUnavailable, true, "did not answer"},
		{"server error", 500, `{"message":"boom"}`, protocol.CodeSourceUnavailable, true, "did not answer"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t, allowAllPolicy, defaultUpdate())
			f.stub.override = func(w http.ResponseWriter, r *http.Request) bool {
				if r.URL.Path != "/api/ds/query" {
					return false
				}
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(tt.body))
				return true
			}
			result := f.executor.Execute(context.Background(), command(t, protocol.CapabilityPrometheusQueryRange, promRange(`up`)))
			assertValid(t, result)
			if result.Status != protocol.StatusError || result.Error.Code != tt.code || result.Error.Retryable != tt.retryable {
				t.Fatalf("result = %+v (%+v)", result, result.Error)
			}
			if !strings.Contains(result.Error.Message, tt.message) {
				t.Errorf("Message = %q", result.Error.Message)
			}
			host := strings.TrimPrefix(f.stub.URL, "http://")
			if strings.Contains(result.Error.Message, host) {
				t.Errorf("the message holds the internal address: %q", result.Error.Message)
			}
		})
	}
}

func TestErrorMessageNeverHoldsTheInternalAddress(t *testing.T) {
	f := newFixture(t, allowAllPolicy, defaultUpdate())
	host := strings.TrimPrefix(f.stub.URL, "http://")
	got := f.executor.hideAddress("failed: Post " + f.stub.URL + "/api/ds/query and dial " + host)
	if strings.Contains(got, host) {
		t.Errorf("hideAddress() = %q", got)
	}
	if long := f.executor.hideAddress(strings.Repeat("a", 5000)); len(long) > 500 {
		t.Errorf("len(hideAddress()) = %d", len(long))
	}
}

func TestConnectionFailureIsSourceUnavailable(t *testing.T) {
	f := newFixture(t, allowAllPolicy, defaultUpdate())
	f.stub.Close()
	result := f.executor.Execute(context.Background(), command(t, protocol.CapabilityPrometheusQueryRange, promRange(`up`)))
	assertValid(t, result)
	if result.Status != protocol.StatusError || result.Error.Code != protocol.CodeSourceUnavailable || !result.Error.Retryable {
		t.Fatalf("result = %+v (%+v)", result, result.Error)
	}
	if strings.Contains(result.Error.Message, "127.0.0.1") {
		t.Errorf("Message = %q", result.Error.Message)
	}
}

func TestAnswerInAnotherShapeIsAnError(t *testing.T) {
	f := newFixture(t, allowAllPolicy, defaultUpdate())
	view := f.executor.policy.Current()
	notJSON := func(*mcpgrafana.Tool, any) (string, *callFailure) { return "nope", nil }
	args := []struct {
		capability string
		args       any
	}{
		{protocol.CapabilityPrometheusQueryRange, promRange(`up`)},
		{protocol.CapabilityPrometheusQueryInstant, protocol.PrometheusQueryInstantArgs{DatasourceUID: "prom-prod", Expr: "up", At: stubT0}},
		{protocol.CapabilityPrometheusListMetricNames, protocol.PrometheusListMetricNamesArgs{DatasourceUID: "prom-prod"}},
		{protocol.CapabilityLokiQueryRange, lokiRange(`{a="b"}`)},
		{protocol.CapabilityLokiQueryRange, protocol.LokiQueryRangeArgs{DatasourceUID: "loki-prod", Expr: `rate({a="b"}[1m])`, Start: stubT0, End: stubT0.Add(time.Hour), StepS: 60}},
		{protocol.CapabilityLokiQueryPatterns, protocol.LokiQueryPatternsArgs{DatasourceUID: "loki-prod", Expr: `{a="b"}`, Start: stubT0, End: stubT0.Add(time.Hour)}},
		{protocol.CapabilityGrafanaListDatasources, protocol.GrafanaListDatasourcesArgs{}},
		{protocol.CapabilityGrafanaSearchDashboards, protocol.GrafanaSearchDashboardsArgs{}},
		{protocol.CapabilityGrafanaGetPanelQueries, protocol.GrafanaGetPanelQueriesArgs{DashboardUID: "d"}},
		{protocol.CapabilityGrafanaListAlertRules, protocol.GrafanaListAlertRulesArgs{}},
		{protocol.CapabilityGrafanaAlertRuleVersions, protocol.GrafanaAlertRuleVersionsArgs{UID: "a1"}},
	}
	for _, one := range args {
		encoded, _ := json.Marshal(one.args)
		parsed, err := protocol.ParseArgs(one.capability, encoded)
		if err != nil {
			t.Fatal(err)
		}
		limits := view.Limits(one.capability, protocol.Limits{})
		plan, rejection := f.executor.prepare(view, one.capability, parsed, limits)
		if rejection != nil {
			t.Fatalf("%s: %v", one.capability, rejection)
		}
		_, _, _, failure := plan.run(notJSON)
		if failure == nil || failure.code != protocol.CodeSourceUnavailable {
			t.Errorf("%s: failure = %+v", one.capability, failure)
		}
	}
}

func TestLogLinesAreRedactedCountedAndCut(t *testing.T) {
	f := newFixture(t, allowAllPolicy, defaultUpdate())
	f.stub.logLines = []string{
		"payment failed for mari.kask@example.ee from 203.0.113.42 token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1XzMxMSJ9.c2lnbmF0dXJl",
		strings.Repeat("x", 800) + " mari.kask@example.ee",
		"key AKIAIOSFODNN7EXAMPLE card 4242 4242 4242 4242",
	}
	result := f.executor.Execute(context.Background(), command(t, protocol.CapabilityLokiQueryRange, lokiRange(`{job="api"}`)))
	assertValid(t, result)
	if result.Status != protocol.StatusOK {
		t.Fatalf("result = %+v (%+v)", result, result.Error)
	}
	encoded, _ := json.Marshal(result.Data)
	for _, secret := range []string{"mari.kask", "203.0.113.42", "eyJhbGci", "AKIAIOSF", "4242 4242", "hunter22"} {
		if strings.Contains(string(encoded), secret) {
			t.Errorf("result still holds %q: %s", secret, encoded)
		}
	}
	for _, kind := range []string{redact.KindEmail, redact.KindIP, redact.KindToken, redact.KindKey, redact.KindCard, redact.KindField} {
		if result.RedactionsByKind[kind] == 0 {
			t.Errorf("kind %s not counted: %v", kind, result.RedactionsByKind)
		}
	}
	if result.Redactions != redact.Counts(result.RedactionsByKind).Total() {
		t.Errorf("Redactions = %d, by kind %v", result.Redactions, result.RedactionsByKind)
	}
	if !result.Truncated {
		t.Error("Truncated = false with a line cut")
	}
	for _, line := range result.Data.Lines {
		if len([]rune(line.Text)) > 500 {
			t.Errorf("a line has %d characters", len([]rune(line.Text)))
		}
	}
	// The secret past the cut was redacted before the cut, so it counts.
	if result.RedactionsByKind[redact.KindEmail] != 2 {
		t.Errorf("emails counted = %d", result.RedactionsByKind[redact.KindEmail])
	}
}

func TestLogLinesOffReturnsCountsAndFetchesNoLine(t *testing.T) {
	update := defaultUpdate()
	update.Data.LogLines = 0
	f := newFixture(t, allowAllPolicy, update)
	result := f.executor.Execute(context.Background(), command(t, protocol.CapabilityLokiQueryRange, lokiRange(`{job="api"} |= "pool"`)))
	assertValid(t, result)
	if result.Status != protocol.StatusOK || result.Data.LinesTotal != 42 || len(result.Data.Lines) != 0 {
		t.Fatalf("result = %+v, data %+v, error %+v", result, result.Data, result.Error)
	}
	bodies := f.stub.queryBodies()
	if len(bodies) != 1 || !strings.Contains(bodies[0], "sum(count_over_time(") {
		t.Errorf("queries = %v", bodies)
	}
}

func lokiMetric(expr string) protocol.LokiQueryRangeArgs {
	return protocol.LokiQueryRangeArgs{DatasourceUID: "loki-prod", Expr: expr, Start: stubT0, End: stubT0.Add(time.Hour), StepS: 60}
}

// lokiMetricLabels makes the stub answer a metric query with one series with these
// labels, as Loki does for a field that a parser stage took from a log line.
func lokiMetricLabels(t *testing.T, f *fixture, labels map[string]string) {
	t.Helper()
	encoded, err := json.Marshal(labels)
	if err != nil {
		t.Fatal(err)
	}
	f.stub.override = func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path != "/api/ds/query" {
			return false
		}
		fmt.Fprintf(w, `{"results":{"A":{"status":200,"frames":[{"schema":{"fields":[{"name":"Time","type":"time","typeInfo":{"frame":"time.Time"}},{"name":"Value","type":"number","typeInfo":{"frame":"float64"},"labels":%s}]},"data":{"values":[[%d],[3]]}}]}}}`, encoded, stubT0.UnixMilli())
		return true
	}
}

func TestMetricLogQLCannotReturnLogTextWhileLogLinesAreOff(t *testing.T) {
	for _, expr := range []string{
		`count_over_time({job="api"} | json [5m])`,
		`sum by (msg) (count_over_time({job="api"} | regexp "(?P<msg>.*)" [1h]))`,
		`sum by (msg) (count_over_time({job="api"} | pattern "<msg>" [1h]))`,
		`topk by (status) (5, rate({job="api"} | logfmt [5m]))`,
	} {
		t.Run(expr, func(t *testing.T) {
			off := defaultUpdate()
			off.Data.LogLines = 0
			f := newFixture(t, allowAllPolicy, off)
			result := f.executor.Execute(context.Background(), command(t, protocol.CapabilityLokiQueryRange, lokiMetric(expr)))
			assertRejected(t, result, protocol.CodeQueryGuardFailed)
			if !strings.Contains(result.Error.Message, "log lines are off") {
				t.Errorf("message = %q", result.Error.Message)
			}
			if f.stub.requestCount() != 0 {
				t.Errorf("the query reached Loki: %+v", f.stub.recorded())
			}

			on := newFixture(t, allowAllPolicy, defaultUpdate())
			result = on.executor.Execute(context.Background(), command(t, protocol.CapabilityLokiQueryRange, lokiMetric(expr)))
			if result.Status != protocol.StatusOK {
				t.Errorf("with log lines on: %+v, error %+v", result, result.Error)
			}
		})
	}
}

func TestMetricLogQLThatNamesItsLabelsKeepsWorkingWhileLogLinesAreOff(t *testing.T) {
	update := defaultUpdate()
	update.Data.LogLines = 0
	for _, expr := range []string{
		`sum by (pod) (count_over_time({job="api"} |= "pool" [1m]))`,
		`count_over_time({job="api"} [1m])`,
		`sum by (status) (count_over_time({job="api"} | json [1m]))`,
		`sum(count_over_time({job="api"} | json | status >= 500 [1m]))`,
		`count_over_time({job="api"} | logfmt status [1m])`,
	} {
		f := newFixture(t, allowAllPolicy, update)
		result := f.executor.Execute(context.Background(), command(t, protocol.CapabilityLokiQueryRange, lokiMetric(expr)))
		assertValid(t, result)
		if result.Status != protocol.StatusOK || len(result.Data.Series) != 1 {
			t.Errorf("%s: result = %+v, error %+v", expr, result, result.Error)
		}
	}
}

func TestSeriesLabelsWhileLogLinesAreOffAreCutAfterRedaction(t *testing.T) {
	update := defaultUpdate()
	update.Data.LogLines = 0
	f := newFixture(t, allowAllPolicy, update)
	value := "login of mari@example.ee failed " + strings.Repeat("x", 300)
	lokiMetricLabels(t, f, map[string]string{"msg": value, "PASSWORD": "hunter22", "status": "500"})
	result := f.executor.Execute(context.Background(), command(t, protocol.CapabilityLokiQueryRange, lokiMetric(`sum by (msg, PASSWORD, status) (count_over_time({job="api"} | json [1m]))`)))
	assertValid(t, result)
	if result.Status != protocol.StatusOK {
		t.Fatalf("result = %+v, error %+v", result, result.Error)
	}
	labels := result.Data.Series[0].Labels
	if got := len([]rune(labels["msg"])); got != reduce.MaxLabelCharsWithoutLogLines {
		t.Errorf("msg has %d characters: %q", got, labels["msg"])
	}
	if !strings.HasPrefix(labels["msg"], "login of [redacted:email] failed ") {
		t.Errorf("msg = %q", labels["msg"])
	}
	if labels["PASSWORD"] != "[redacted:field]" || labels["status"] != "500" {
		t.Errorf("labels = %v", labels)
	}
	if !result.Truncated {
		t.Error("Truncated = false after a cut")
	}
}

func TestSeriesLabelsWithLogLinesOnFollowTheLineLimit(t *testing.T) {
	f := newFixture(t, allowAllPolicy, defaultUpdate())
	lokiMetricLabels(t, f, map[string]string{"msg": strings.Repeat("x", 600), "path": strings.Repeat("y", 200)})
	result := f.executor.Execute(context.Background(), command(t, protocol.CapabilityLokiQueryRange, lokiMetric(`count_over_time({job="api"} | json [1m])`)))
	assertValid(t, result)
	labels := result.Data.Series[0].Labels
	if len(labels["msg"]) != 500 || len(labels["path"]) != 200 || !result.Truncated {
		t.Errorf("msg %d, path %d, truncated %v", len(labels["msg"]), len(labels["path"]), result.Truncated)
	}
}

func TestPrometheusLabelsAreNotCutWhileLogLinesAreOff(t *testing.T) {
	update := defaultUpdate()
	update.Data.LogLines = 0
	f := newFixture(t, allowAllPolicy, update)
	lokiMetricLabels(t, f, map[string]string{"path": strings.Repeat("y", 200)})
	result := f.executor.Execute(context.Background(), command(t, protocol.CapabilityPrometheusQueryRange, promRange(`up`)))
	assertValid(t, result)
	if got := result.Data.Series[0].Labels["path"]; len(got) != 200 || result.Truncated {
		t.Errorf("path has %d characters, truncated %v", len(got), result.Truncated)
	}
}

func TestLogLinesSwitchedOffDuringACallStopWhatTheQueryReturned(t *testing.T) {
	off := defaultUpdate()
	off.Revision = "srv-2"
	off.Data.LogLines = 0
	switchOff := func(f *fixture) {
		f.stub.override = func(http.ResponseWriter, *http.Request) bool {
			f.executor.ApplyPolicy(off)
			return false
		}
	}

	f := newFixture(t, allowAllPolicy, defaultUpdate())
	switchOff(f)
	result := f.executor.Execute(context.Background(), command(t, protocol.CapabilityLokiQueryRange, lokiMetric(`count_over_time({job="api"} | json [1m])`)))
	assertRejected(t, result, protocol.CodeQueryGuardFailed)

	f = newFixture(t, allowAllPolicy, defaultUpdate())
	f.stub.logLines = []string{"a line"}
	switchOff(f)
	result = f.executor.Execute(context.Background(), command(t, protocol.CapabilityLokiQueryRange, lokiRange(`{job="api"}`)))
	assertValid(t, result)
	if len(result.Data.Lines) != 0 {
		t.Errorf("lines = %+v", result.Data.Lines)
	}
}

func TestPanelWithNoDatasourceStaysOut(t *testing.T) {
	f := newFixture(t, allowAllPolicy, defaultUpdate())
	f.stub.override = func(w http.ResponseWriter, r *http.Request) bool {
		if !strings.HasPrefix(r.URL.Path, "/api/dashboards/uid/") {
			return false
		}
		fmt.Fprint(w, `{"dashboard":{"uid":"d1","panels":[
			{"id":1,"title":"Default","type":"timeseries","targets":[{"refId":"A","expr":"secret_metric"}]},
			{"id":2,"title":"Pool","type":"timeseries","datasource":{"uid":"prom-prod","type":"prometheus"},"targets":[{"refId":"A","expr":"up"}]}]},"meta":{}}`)
		return true
	}
	result := f.executor.Execute(context.Background(), command(t, protocol.CapabilityGrafanaGetPanelQueries, protocol.GrafanaGetPanelQueriesArgs{DashboardUID: "d1"}))
	assertValid(t, result)
	if result.Status != protocol.StatusOK || len(result.Data.PanelQueries) != 1 || result.Data.PanelQueries[0].Title != "Pool" || !result.Truncated {
		t.Fatalf("result = %+v, data %+v, error %+v", result, result.Data, result.Error)
	}
}

func TestLokiLabelValuesTakeNoQuery(t *testing.T) {
	for _, field := range []string{"expr", "query", "match"} {
		raw := fmt.Sprintf(`{"datasource_uid":"loki-prod","label":"msg",%q:"{job=\"api\"} | json"}`, field)
		if _, err := protocol.ParseArgs(protocol.CapabilityLokiListLabelValues, json.RawMessage(raw)); err == nil {
			t.Errorf("ParseArgs() took %s", field)
		}
	}
}

func TestLogLinesFollowTheSmallestLimit(t *testing.T) {
	update := defaultUpdate()
	update.Data.LogLines = 3
	f := newFixture(t, allowAllPolicy, update)
	f.stub.logLines = []string{"a", "b", "c", "d", "e"}
	result := f.executor.Execute(context.Background(), command(t, protocol.CapabilityLokiQueryRange, lokiRange(`{job="api"}`)))
	assertValid(t, result)
	if len(result.Data.Lines) != 3 || result.Data.LinesTotal != 42 || !result.Truncated {
		t.Fatalf("data = %+v, truncated %v", result.Data, result.Truncated)
	}

	c := command(t, protocol.CapabilityLokiQueryRange, lokiRange(`{job="api"}`))
	c.Limits = protocol.Limits{MaxLines: 1}
	result = f.executor.Execute(context.Background(), c)
	assertValid(t, result)
	if len(result.Data.Lines) != 1 {
		t.Fatalf("lines = %d", len(result.Data.Lines))
	}
}

func TestCountFailureStillReturnsLinesAsPartial(t *testing.T) {
	f := newFixture(t, allowAllPolicy, defaultUpdate())
	calls := 0
	view := f.executor.policy.Current()
	encoded, _ := json.Marshal(lokiRange(`{a="b"}`))
	parsed, _ := protocol.ParseArgs(protocol.CapabilityLokiQueryRange, encoded)
	limits := view.Limits(protocol.CapabilityLokiQueryRange, protocol.Limits{})
	plan, rejection := f.executor.prepare(view, protocol.CapabilityLokiQueryRange, parsed, limits)
	if rejection != nil {
		t.Fatal(rejection)
	}
	failed := &callFailure{status: protocol.StatusError, code: protocol.CodeSourceUnavailable, message: "down"}

	data, skipped, _, failure := plan.run(func(*mcpgrafana.Tool, any) (string, *callFailure) {
		calls++
		if calls == 1 {
			return "", failed
		}
		return `{"data":[{"timestamp":"1762261200000000000","line":"x","labels":{}}]}`, nil
	})
	if failure != nil || len(skipped) != 1 || skipped[0] != "lines_total" || data.LinesTotal != 1 || len(data.Lines) != 1 {
		t.Fatalf("data %+v, skipped %v, failure %+v", data, skipped, failure)
	}

	calls = 0
	data, skipped, _, failure = plan.run(func(*mcpgrafana.Tool, any) (string, *callFailure) {
		calls++
		if calls == 1 {
			return `{"data":[{"value":7,"labels":{}}]}`, nil
		}
		return "", failed
	})
	if failure != nil || len(skipped) != 1 || skipped[0] != "lines" || data.LinesTotal != 7 {
		t.Fatalf("data %+v, skipped %v, failure %+v", data, skipped, failure)
	}

	_, _, _, failure = plan.run(func(*mcpgrafana.Tool, any) (string, *callFailure) { return "", failed })
	if failure != failed {
		t.Fatalf("failure = %+v", failure)
	}
}

func TestRedactionOffReturnsTextAsWritten(t *testing.T) {
	const line = "payment failed for mari.kask@example.ee from 203.0.113.42"
	update := defaultUpdate()
	update.Data.Redaction = protocol.RedactionOff

	f := newFixture(t, allowAllPolicy+"redaction: {allowOff: true}\n", update)
	f.stub.logLines = []string{line}
	result := f.executor.Execute(context.Background(), command(t, protocol.CapabilityLokiQueryRange, lokiRange(`{job="api"}`)))
	assertValid(t, result)
	if result.Data.Lines[0].Text != line || result.Redactions != 0 || result.Data.Lines[0].Labels["password"] != "hunter22" {
		t.Fatalf("data = %+v, redactions %d", result.Data.Lines[0], result.Redactions)
	}

	forbidden := newFixture(t, allowAllPolicy, update)
	forbidden.stub.logLines = []string{line}
	result = forbidden.executor.Execute(context.Background(), command(t, protocol.CapabilityLokiQueryRange, lokiRange(`{job="api"}`)))
	assertValid(t, result)
	if strings.Contains(result.Data.Lines[0].Text, "mari.kask") || result.Redactions == 0 {
		t.Fatalf("data = %+v, redactions %d", result.Data.Lines[0], result.Redactions)
	}
	capped := forbidden.executor.policy.Current().Report().Capped
	if len(capped) != 1 || capped[0].Setting != "redaction" {
		t.Errorf("Capped = %+v", capped)
	}
}

func TestPolicyAddedDuringACallAppliesToItsResult(t *testing.T) {
	f := newFixture(t, allowAllPolicy, defaultUpdate())
	f.stub.logLines = []string{"customer=Jaan"}
	f.stub.override = func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path == "/api/ds/query" {
			update := defaultUpdate()
			update.Data.ExtraRules = []protocol.RedactionRule{{Kind: protocol.RedactionRuleKey, Key: "customer"}}
			f.executor.policy.Apply(update)
		}
		return false
	}
	result := f.executor.Execute(context.Background(), command(t, protocol.CapabilityLokiQueryRange, lokiRange(`{job="api"}`)))
	assertValid(t, result)
	if strings.Contains(result.Data.Lines[0].Text, "Jaan") || result.RedactionsByKind[redact.KindRule] != 1 {
		t.Fatalf("line %q, by kind %v", result.Data.Lines[0].Text, result.RedactionsByKind)
	}
}

func TestLokiEnforcedMatchersReachTheQuery(t *testing.T) {
	f := newFixture(t, allowAllPolicy+"logs:\n  enforcedMatchers: ['namespace=~\"prod|staging\"']\n", defaultUpdate())
	result := f.executor.Execute(context.Background(), command(t, protocol.CapabilityLokiQueryRange, lokiRange(`{job="api"}`)))
	assertValid(t, result)
	if result.Status != protocol.StatusOK {
		t.Fatalf("result = %+v (%+v)", result, result.Error)
	}
	bodies := f.stub.queryBodies()
	if len(bodies) != 2 {
		t.Fatalf("queries = %v", bodies)
	}
	for _, body := range bodies {
		if !strings.Contains(body, "namespace") {
			t.Errorf("query without the enforced matcher: %s", body)
		}
	}
}

func TestBadEnforcedMatcherStopsTheProxyAtStart(t *testing.T) {
	path := t.TempDir() + "/policy.yaml"
	if err := writeFile(path, "logs:\n  enforcedMatchers: ['{{']\n"); err != nil {
		t.Fatal(err)
	}
	file, err := policy.Load(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = New(Config{GrafanaURL: "http://grafana:3000", Token: func() (string, error) { return "", nil }, Policy: policy.NewEngine(file)})
	if err == nil || !strings.Contains(err.Error(), "enforcedMatchers") {
		t.Fatalf("New() error = %v", err)
	}
}

func TestNewRefusesBadConfig(t *testing.T) {
	file, err := policy.Load("", nil)
	if err != nil {
		t.Fatal(err)
	}
	engine := policy.NewEngine(file)
	token := func() (string, error) { return "", nil }
	tests := []Config{
		{GrafanaURL: "", Token: token, Policy: engine},
		{GrafanaURL: "ftp://grafana", Token: token, Policy: engine},
		{GrafanaURL: "grafana:3000", Token: token, Policy: engine},
		{GrafanaURL: "http://grafana", Policy: engine},
		{GrafanaURL: "http://grafana", Token: token},
	}
	for _, config := range tests {
		if _, err := New(config); err == nil {
			t.Errorf("New(%+v) passed", config)
		}
	}
}

func TestTokenIsReadPerCommand(t *testing.T) {
	f := newFixture(t, allowAllPolicy, defaultUpdate())
	current := "glsa_first"
	f.token = func() (string, error) { return current, nil }
	f.executor.Execute(context.Background(), command(t, protocol.CapabilityPrometheusQueryRange, promRange(`up`)))
	current = "glsa_second"
	f.executor.Execute(context.Background(), command(t, protocol.CapabilityPrometheusQueryRange, promRange(`up`)))
	requests := f.stub.recorded()
	if requests[0].Token != "glsa_first" || requests[len(requests)-1].Token != "glsa_second" {
		t.Errorf("tokens = %q ... %q", requests[0].Token, requests[len(requests)-1].Token)
	}
}

func TestTokenFailureIsAuthFailed(t *testing.T) {
	f := newFixture(t, allowAllPolicy, defaultUpdate())
	f.token = func() (string, error) { return "", errors.New("no file") }
	result := f.executor.Execute(context.Background(), command(t, protocol.CapabilityPrometheusQueryRange, promRange(`up`)))
	assertValid(t, result)
	if result.Error == nil || result.Error.Code != protocol.CodeAuthFailed {
		t.Fatalf("result = %+v", result)
	}
	if f.stub.requestCount() != 0 {
		t.Errorf("requests = %+v", f.stub.recorded())
	}
}

func TestPanicInAToolFailsOneCommand(t *testing.T) {
	panicking := tools.QueryPrometheus
	panicking.Handler = func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		panic("boom")
	}
	f := newFixture(t, allowAllPolicy, defaultUpdate())
	text, failure := f.executor.callTool(context.Background(), protocol.Limits{TimeoutMS: 1000}, &panicking, map[string]any{})
	if text != "" || failure == nil || failure.code != protocol.CodeSourceUnavailable {
		t.Fatalf("text %q, failure %+v", text, failure)
	}
}

func TestReadOnlyTransport(t *testing.T) {
	stub := newStubGrafana(t)
	base, err := url.Parse(stub.URL)
	if err != nil {
		t.Fatal(err)
	}
	stub.override = func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path == "/redirect" {
			w.Header().Set("Location", "http://evil.example/")
			w.WriteHeader(http.StatusFound)
			return true
		}
		return false
	}
	tests := []struct {
		name    string
		method  string
		target  string
		allowed bool
	}{
		{"GET", http.MethodGet, stub.URL + "/api/health", true},
		{"query POST", http.MethodPost, stub.URL + "/api/ds/query", true},
		{"dashboard write", http.MethodPost, stub.URL + "/api/dashboards/db", false},
		{"datasource delete", http.MethodDelete, stub.URL + "/api/datasources/1", false},
		{"PUT", http.MethodPut, stub.URL + "/api/ds/query", false},
		{"other host", http.MethodGet, "http://evil.example/api/health", false},
		{"other scheme", http.MethodGet, "https://" + base.Host + "/api/health", false},
		{"redirect", http.MethodGet, stub.URL + "/redirect", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := &readOnlyTransport{next: http.DefaultTransport, scheme: base.Scheme, host: base.Host, queryPath: "/api/ds/query"}
			request, err := http.NewRequest(tt.method, tt.target, strings.NewReader(`{"queries":[{"expr":"x"}]}`))
			if err != nil {
				t.Fatal(err)
			}
			before := stub.requestCount()
			response, err := transport.RoundTrip(request)
			if tt.allowed {
				if err != nil {
					t.Fatalf("RoundTrip() error = %v", err)
				}
				_ = response.Body.Close()
				return
			}
			if err == nil {
				_ = response.Body.Close()
				t.Fatal("RoundTrip() passed")
			}
			if !transport.outcome().refused {
				t.Error("the refusal was not recorded")
			}
			if tt.name != "redirect" && stub.requestCount() != before {
				t.Error("a refused request reached Grafana")
			}
		})
	}
}

func TestGrafanaUnderASubPathKeepsItsQueryPath(t *testing.T) {
	file, err := policy.Load("", nil)
	if err != nil {
		t.Fatal(err)
	}
	executor, err := New(Config{GrafanaURL: "https://example.ee/grafana/", Token: func() (string, error) { return "", nil }, Policy: policy.NewEngine(file)})
	if err != nil {
		t.Fatal(err)
	}
	if got := executor.newTransport().queryPath; got != "/grafana/api/ds/query" {
		t.Errorf("queryPath = %q", got)
	}
}

// The AI and data setting decides what the model reads, in the engine. The proxy
// returns the points in both modes, because Tellagen draws charts from them.
func TestMetricsSummariesModeStillSendsPointsForCharts(t *testing.T) {
	update := defaultUpdate()
	update.Data.Metrics = protocol.MetricsSummaries
	f := newFixture(t, allowAllPolicy, update)
	result := f.executor.Execute(context.Background(), command(t, protocol.CapabilityPrometheusQueryRange, promRange(`up`)))
	assertValid(t, result)
	if result.Status != protocol.StatusOK || len(result.Data.Series[0].Values) != 3 || result.Data.Series[0].Stats == nil {
		t.Fatalf("result = %+v (%+v)", result.Data, result.Error)
	}
}

func TestFailureMessageIsRedactedAndCounted(t *testing.T) {
	f := newFixture(t, allowAllPolicy, defaultUpdate())
	f.stub.override = func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path != "/api/ds/query" {
			return false
		}
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"results":{"A":{"error":"cannot read line of mari@example.ee","status":400,"frames":[]}}}`))
		return true
	}
	result := f.executor.Execute(context.Background(), command(t, protocol.CapabilityPrometheusQueryRange, promRange(`up`)))
	assertValid(t, result)
	if result.Error == nil || strings.Contains(result.Error.Message, "mari@example.ee") || result.Redactions != 1 {
		t.Fatalf("result = %+v (%+v)", result, result.Error)
	}
}

func TestRefusedRequestAndTooLargeBodyAreRejections(t *testing.T) {
	f := newFixture(t, allowAllPolicy, defaultUpdate())
	refused := f.executor.classify(outcome{refused: true}, "ignored")
	if refused.status != protocol.StatusRejected || refused.code != protocol.CodeQueryGuardFailed {
		t.Errorf("refused = %+v", refused)
	}
	large := f.executor.classify(outcome{tooLarge: true, lastStatus: 200}, "ignored")
	if large.status != protocol.StatusRejected || !strings.Contains(large.message, "Narrow") {
		t.Errorf("too large = %+v", large)
	}
	guard := f.executor.classify(outcome{}, "query blocked by the Loki cost guardrail: too many bytes on "+f.stub.URL)
	if guard.status != protocol.StatusRejected || strings.Contains(guard.message, f.stub.URL) {
		t.Errorf("guardrail = %+v", guard)
	}
}

type closeTracker struct {
	*strings.Reader
}

func (closeTracker) Close() error { return nil }

func TestLimitedBodyStopsAtTheLimit(t *testing.T) {
	tooLarge := false
	body := &limitedBody{ReadCloser: closeTracker{strings.NewReader(strings.Repeat("a", 100))}, remaining: 10, onTooLarge: func() { tooLarge = true }}
	buffer := make([]byte, 64)
	var total int
	var err error
	for err == nil {
		var n int
		n, err = body.Read(buffer)
		total += n
	}
	if !errors.Is(err, errUpstreamTooLarge) || !tooLarge || total > 10 {
		t.Fatalf("total %d, err %v, tooLarge %v", total, err, tooLarge)
	}

	fits := &limitedBody{ReadCloser: closeTracker{strings.NewReader("short")}, remaining: 10, onTooLarge: func() { t.Error("too large") }}
	buffer = make([]byte, 64)
	total = 0
	err = nil
	for err == nil {
		var n int
		n, err = fits.Read(buffer)
		total += n
	}
	if err.Error() != "EOF" || total != 5 {
		t.Fatalf("total %d, err %v", total, err)
	}
}

func TestResultHoldsFingerprintAndDeepLink(t *testing.T) {
	f := newFixture(t, allowAllPolicy, defaultUpdate())
	first := f.executor.Execute(context.Background(), command(t, protocol.CapabilityPrometheusQueryRange, promRange(`up{job="a"}`)))
	spaced := promRange(`up{ job = "a" }`)
	spaced.End = stubT0.Add(2 * time.Hour)
	second := f.executor.Execute(context.Background(), command(t, protocol.CapabilityPrometheusQueryRange, spaced))
	other := f.executor.Execute(context.Background(), command(t, protocol.CapabilityPrometheusQueryRange, promRange(`up{job="b"}`)))
	if !strings.HasPrefix(first.QueryFingerprint, "sha256:") || first.QueryFingerprint != second.QueryFingerprint || first.QueryFingerprint == other.QueryFingerprint {
		t.Errorf("fingerprints = %s %s %s", first.QueryFingerprint, second.QueryFingerprint, other.QueryFingerprint)
	}
	if first.DeepLink == nil || first.DeepLink.Kind != protocol.DeepLinkGrafanaExplore {
		t.Fatalf("DeepLink = %+v", first.DeepLink)
	}
	link, err := url.Parse(first.DeepLink.URL)
	if err != nil {
		t.Fatal(err)
	}
	if link.Host != "grafana.example.ee" || link.Path != "/explore" || link.Query().Get("schemaVersion") != "1" {
		t.Errorf("link = %s", first.DeepLink.URL)
	}
	panes := link.Query().Get("panes")
	for _, want := range []string{"prom-prod", `up{job=\"a\"}`, `"from"`, `"to"`} {
		if !strings.Contains(panes, want) {
			t.Errorf("panes %s do not hold %s", panes, want)
		}
	}
	host := strings.TrimPrefix(f.stub.URL, "http://")
	if strings.Contains(first.DeepLink.URL, host) {
		t.Errorf("the link holds the internal address: %s", first.DeepLink.URL)
	}

	if link := (&plan{explore: &exploreLink{}}).deepLink("", 0); link != nil {
		t.Errorf("deepLink with no public address = %+v", link)
	}
	withOrg := (&plan{explore: &exploreLink{datasource: "a"}}).deepLink("https://g.example/", 4)
	if !strings.HasPrefix(withOrg.URL, "https://g.example/explore?") || !strings.Contains(withOrg.URL, "orgId=4") {
		t.Errorf("deepLink = %+v", withOrg)
	}
	if fingerprint := (&plan{}).fingerprint("a"); fingerprint != "" {
		t.Errorf("fingerprint with no query = %q", fingerprint)
	}
}

func TestInfo(t *testing.T) {
	f := newFixture(t, "", protocol.PolicyUpdate{})
	if got := f.executor.Info(); got != (protocol.Executor{Kind: "grafana-mcp", Version: grafanaMCPVersion, Mode: "in-process"}) {
		t.Errorf("Info() = %+v", got)
	}
}

func TestCapabilitiesForHelloHaveADigest(t *testing.T) {
	file, err := policy.Load("", nil)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := protocol.CapabilitiesDigest(policy.NewEngine(file).Current().Capabilities())
	if err != nil || !strings.HasPrefix(digest, "sha256:") {
		t.Fatalf("digest %q, err %v", digest, err)
	}
}
