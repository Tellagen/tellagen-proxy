//go:build integration

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/docker/go-connections/nat"
	"github.com/testcontainers/testcontainers-go"
	tcnetwork "github.com/testcontainers/testcontainers-go/network"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/tellagen/tellagen-proxy/internal/policy"
	"github.com/tellagen/tellagen-proxy/protocol"
)

const (
	contractGrafanaImage    = "grafana/grafana:12.2.1"
	contractPrometheusImage = "prom/prometheus:v3.5.0"
	contractLokiImage       = "grafana/loki:3.5.0"
)

// contractStack is a real Grafana in front of a real Prometheus and Loki. The proxy
// reads it with a Viewer service account token, as the install guide asks.
type contractStack struct {
	grafanaURL string
	lokiURL    string
	token      string
}

func startContainer(ctx context.Context, t *testing.T, request testcontainers.ContainerRequest) testcontainers.Container {
	t.Helper()
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{ContainerRequest: request, Started: true})
	if err != nil {
		t.Fatalf("start %s: %v", request.Image, err)
	}
	t.Cleanup(func() { _ = container.Terminate(context.Background()) })
	return container
}

func endpoint(ctx context.Context, t *testing.T, container testcontainers.Container, port nat.Port) string {
	t.Helper()
	value, err := container.PortEndpoint(ctx, port, "http")
	if err != nil {
		t.Fatalf("endpoint: %v", err)
	}
	return value
}

func adminCall(t *testing.T, method, target string, body any) []byte {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(method, target, bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	request.SetBasicAuth("admin", "admin")
	request.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("%s %s: %v", method, target, err)
	}
	defer func() { _ = response.Body.Close() }()
	answer, _ := io.ReadAll(response.Body)
	if response.StatusCode >= 300 {
		t.Fatalf("%s %s: %d %s", method, target, response.StatusCode, answer)
	}
	return answer
}

func startContractStack(t *testing.T) contractStack {
	t.Helper()
	ctx := context.Background()
	network, err := tcnetwork.New(ctx)
	if err != nil {
		t.Fatalf("network: %v", err)
	}
	t.Cleanup(func() { _ = network.Remove(context.Background()) })

	startContainer(ctx, t, testcontainers.ContainerRequest{
		Image: contractPrometheusImage, ExposedPorts: []string{"9090/tcp"}, Networks: []string{network.Name},
		NetworkAliases: map[string][]string{network.Name: {"prometheus"}},
		Cmd:            []string{"--config.file=/etc/prometheus/prometheus.yml", "--storage.tsdb.path=/prometheus"},
		Files: []testcontainers.ContainerFile{{
			Reader:            strings.NewReader("global:\n  scrape_interval: 1s\nscrape_configs:\n  - job_name: prometheus\n    static_configs:\n      - targets: ['localhost:9090']\n"),
			ContainerFilePath: "/etc/prometheus/prometheus.yml", FileMode: 0o644,
		}},
		WaitingFor: wait.ForHTTP("/-/ready").WithPort("9090/tcp").WithStartupTimeout(2 * time.Minute),
	})
	loki := startContainer(ctx, t, testcontainers.ContainerRequest{
		Image: contractLokiImage, ExposedPorts: []string{"3100/tcp"}, Networks: []string{network.Name},
		NetworkAliases: map[string][]string{network.Name: {"loki"}},
		Cmd:            []string{"-config.file=/etc/loki/local-config.yaml", "-pattern-ingester.enabled=true"},
		WaitingFor:     wait.ForHTTP("/ready").WithPort("3100/tcp").WithStartupTimeout(3 * time.Minute),
	})
	grafana := startContainer(ctx, t, testcontainers.ContainerRequest{
		Image: contractGrafanaImage, ExposedPorts: []string{"3000/tcp"}, Networks: []string{network.Name},
		Env:        map[string]string{"GF_SECURITY_ADMIN_PASSWORD": "admin", "GF_ANALYTICS_REPORTING_ENABLED": "false", "GF_ANALYTICS_CHECK_FOR_UPDATES": "false"},
		WaitingFor: wait.ForHTTP("/api/health").WithPort("3000/tcp").WithStartupTimeout(3 * time.Minute),
	})

	stack := contractStack{grafanaURL: endpoint(ctx, t, grafana, "3000/tcp"), lokiURL: endpoint(ctx, t, loki, "3100/tcp")}
	adminCall(t, http.MethodPost, stack.grafanaURL+"/api/datasources", map[string]any{"uid": "prom-prod", "name": "Prometheus prod", "type": "prometheus", "url": "http://prometheus:9090", "access": "proxy", "isDefault": true})
	adminCall(t, http.MethodPost, stack.grafanaURL+"/api/datasources", map[string]any{"uid": "loki-prod", "name": "Loki prod", "type": "loki", "url": "http://loki:3100", "access": "proxy"})
	adminCall(t, http.MethodPost, stack.grafanaURL+"/api/dashboards/db", map[string]any{"dashboard": map[string]any{
		"uid": "checkout", "title": "Checkout pool",
		"panels": []map[string]any{{
			"id": 1, "title": "Pool", "type": "timeseries",
			"datasource": map[string]string{"uid": "prom-prod", "type": "prometheus"},
			"targets":    []map[string]string{{"refId": "A", "expr": "up"}},
		}},
	}})

	var account struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(adminCall(t, http.MethodPost, stack.grafanaURL+"/api/serviceaccounts", map[string]any{"name": "tellagen-proxy", "role": "Viewer"}), &account); err != nil {
		t.Fatal(err)
	}
	var created struct {
		Key string `json:"key"`
	}
	if err := json.Unmarshal(adminCall(t, http.MethodPost, fmt.Sprintf("%s/api/serviceaccounts/%d/tokens", stack.grafanaURL, account.ID), map[string]any{"name": "proxy"}), &created); err != nil {
		t.Fatal(err)
	}
	stack.token = created.Key
	return stack
}

func pushLogs(t *testing.T, lokiURL string, lines []string) {
	t.Helper()
	values := make([][2]string, 0, len(lines))
	now := time.Now().Add(-time.Minute)
	for i, line := range lines {
		values = append(values, [2]string{fmt.Sprint(now.Add(time.Duration(i) * time.Millisecond).UnixNano()), line})
	}
	encoded, err := json.Marshal(map[string]any{"streams": []map[string]any{{"stream": map[string]string{"job": "checkout", "namespace": "prod"}, "values": values}}})
	if err != nil {
		t.Fatal(err)
	}
	response, err := http.Post(lokiURL+"/loki/api/v1/push", "application/json", bytes.NewReader(encoded))
	if err != nil {
		t.Fatalf("push logs: %v", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode >= 300 {
		answer, _ := io.ReadAll(response.Body)
		t.Fatalf("push logs: %d %s", response.StatusCode, answer)
	}
}

// TestContractWithRealGrafana is the check that stub answers cannot give: every
// capability against a real Grafana, Prometheus and Loki, with a Viewer token and the
// read-only transport in the path.
func TestContractWithRealGrafana(t *testing.T) {
	stack := startContractStack(t)
	lines := make([]string, 0, 30)
	for i := range 30 {
		lines = append(lines, fmt.Sprintf("connection pool exhausted for mari@example.ee after %d ms", 100+i))
	}
	pushLogs(t, stack.lokiURL, lines)

	file, err := policy.Load("", nil)
	if err != nil {
		t.Fatal(err)
	}
	engine := policy.NewEngine(file)
	executor, err := New(Config{
		GrafanaURL: stack.grafanaURL,
		PublicURL:  "https://grafana.example.ee",
		Token:      func() (string, error) { return stack.token, nil },
		Policy:     engine,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	executor.ApplyPolicy(protocol.PolicyUpdate{
		Revision: "srv-1",
		Narrow:   protocol.PolicyNarrow{DatasourceUIDs: []string{"prom-prod", "loki-prod"}},
		Data:     protocol.PolicyData{Metrics: protocol.MetricsPoints, LogLines: 3, Redaction: protocol.RedactionOn},
	})

	ctx := context.Background()
	end := time.Now().UTC()
	start := end.Add(-10 * time.Minute)
	run := func(capability string, args any) protocol.CommandResult {
		t.Helper()
		encoded, err := json.Marshal(args)
		if err != nil {
			t.Fatal(err)
		}
		result := executor.Execute(ctx, protocol.Command{CommandID: "c", Attempt: 1, AttemptToken: "at", Capability: capability, CapabilityVersion: 1, Args: encoded})
		if err := result.Validate(); err != nil {
			t.Fatalf("%s: %v (%+v)", capability, err, result)
		}
		return result
	}
	mustBeOK := func(capability string, result protocol.CommandResult) {
		t.Helper()
		if result.Status != protocol.StatusOK {
			t.Fatalf("%s: status %s, error %+v", capability, result.Status, result.Error)
		}
		t.Logf("%s: %d bytes, %d redactions", capability, result.Bytes, result.Redactions)
	}
	retry := func(what string, attempt func() bool) {
		t.Helper()
		deadline := time.Now().Add(2 * time.Minute)
		for !attempt() {
			if time.Now().After(deadline) {
				t.Fatalf("timed out waiting for %s", what)
			}
			time.Sleep(2 * time.Second)
		}
	}

	retry("Prometheus samples", func() bool {
		result := run(protocol.CapabilityPrometheusQueryInstant, protocol.PrometheusQueryInstantArgs{DatasourceUID: "prom-prod", Expr: `up{job="prometheus"}`, At: time.Now().UTC()})
		return result.Status == protocol.StatusOK && len(result.Data.Samples) == 1
	})

	matrix := run(protocol.CapabilityPrometheusQueryRange, protocol.PrometheusQueryRangeArgs{DatasourceUID: "prom-prod", Expr: `up{job="prometheus"}`, Start: time.Now().UTC().Add(-time.Minute), End: time.Now().UTC(), StepS: 5})
	mustBeOK("query_range", matrix)
	if len(matrix.Data.Series) != 1 || matrix.Data.Series[0].Stats == nil || matrix.Data.Series[0].Stats.Max != 1 || len(matrix.Data.Series[0].Values) == 0 {
		t.Errorf("matrix = %+v", matrix.Data)
	}

	names := run(protocol.CapabilityPrometheusListMetricNames, protocol.PrometheusListMetricNamesArgs{DatasourceUID: "prom-prod", Match: "^up$"})
	mustBeOK("list_metric_names", names)
	if len(names.Data.Names) != 1 || names.Data.Names[0] != "up" {
		t.Errorf("names = %+v", names.Data.Names)
	}
	values := run(protocol.CapabilityPrometheusListLabelValues, protocol.PrometheusListLabelValuesArgs{DatasourceUID: "prom-prod", Label: "job", Match: `{job="prometheus"}`})
	mustBeOK("list_label_values", values)
	if len(values.Data.Names) != 1 || values.Data.Names[0] != "prometheus" {
		t.Errorf("values = %+v", values.Data.Names)
	}

	retry("Loki lines", func() bool {
		result := run(protocol.CapabilityLokiQueryRange, protocol.LokiQueryRangeArgs{DatasourceUID: "loki-prod", Expr: `{job="checkout"} |= "pool"`, Start: start, End: time.Now().UTC()})
		return result.Status == protocol.StatusOK && result.Data.LinesTotal == 30
	})
	logs := run(protocol.CapabilityLokiQueryRange, protocol.LokiQueryRangeArgs{DatasourceUID: "loki-prod", Expr: `{job="checkout"} |= "pool"`, Start: start, End: time.Now().UTC()})
	mustBeOK("loki.query_range logs", logs)
	if len(logs.Data.Lines) != 3 || logs.Data.Lines[0].At.IsZero() || logs.Data.Lines[0].Labels["job"] != "checkout" {
		t.Errorf("lines = %+v", logs.Data.Lines)
	}
	if strings.Contains(logs.Data.Lines[0].Text, "mari@example.ee") || logs.RedactionsByKind["email"] != 3 {
		t.Errorf("line %q, by kind %v", logs.Data.Lines[0].Text, logs.RedactionsByKind)
	}

	counts := run(protocol.CapabilityLokiQueryRange, protocol.LokiQueryRangeArgs{DatasourceUID: "loki-prod", Expr: `sum(count_over_time({job="checkout"}[5m]))`, Start: start, End: time.Now().UTC(), StepS: 60})
	mustBeOK("loki.query_range counts", counts)
	if len(counts.Data.Series) != 1 || counts.Data.Series[0].Stats == nil || counts.Data.Series[0].Stats.Max != 30 {
		t.Errorf("counts = %+v", counts.Data)
	}

	labelValues := run(protocol.CapabilityLokiListLabelValues, protocol.LokiListLabelValuesArgs{DatasourceUID: "loki-prod", Label: "job"})
	mustBeOK("loki.list_label_values", labelValues)
	if len(labelValues.Data.Names) != 1 || labelValues.Data.Names[0] != "checkout" {
		t.Errorf("label values = %+v", labelValues.Data.Names)
	}

	// Loki learns patterns in the background, a little after it takes the lines.
	var patterns protocol.CommandResult
	retry("Loki patterns", func() bool {
		patterns = run(protocol.CapabilityLokiQueryPatterns, protocol.LokiQueryPatternsArgs{DatasourceUID: "loki-prod", Expr: `{job="checkout"}`, Start: start, End: time.Now().UTC()})
		return patterns.Status == protocol.StatusOK && len(patterns.Data.Patterns) > 0
	})
	mustBeOK("loki.query_patterns", patterns)
	if len(patterns.Data.Patterns) != 1 || !strings.Contains(patterns.Data.Patterns[0].Pattern, "[redacted:email] after <_> ms") {
		t.Errorf("patterns = %+v", patterns.Data.Patterns)
	}

	datasources := run(protocol.CapabilityGrafanaListDatasources, protocol.GrafanaListDatasourcesArgs{})
	mustBeOK("list_datasources", datasources)
	if len(datasources.Data.Datasources) != 2 {
		t.Errorf("datasources = %+v", datasources.Data.Datasources)
	}

	dashboards := run(protocol.CapabilityGrafanaSearchDashboards, protocol.GrafanaSearchDashboardsArgs{Query: "Checkout"})
	mustBeOK("search_dashboards", dashboards)
	if len(dashboards.Data.Dashboards) != 1 || dashboards.Data.Dashboards[0].UID != "checkout" {
		t.Errorf("dashboards = %+v", dashboards.Data.Dashboards)
	}

	panels := run(protocol.CapabilityGrafanaGetPanelQueries, protocol.GrafanaGetPanelQueriesArgs{DashboardUID: "checkout"})
	mustBeOK("get_dashboard_panel_queries", panels)
	if len(panels.Data.PanelQueries) != 1 || panels.Data.PanelQueries[0].Expr != "up" || panels.Data.PanelQueries[0].DatasourceUID != "prom-prod" {
		t.Errorf("panel queries = %+v", panels.Data.PanelQueries)
	}

	mustBeOK("list_alert_rules", run(protocol.CapabilityGrafanaListAlertRules, protocol.GrafanaListAlertRulesArgs{}))

	broad := run(protocol.CapabilityPrometheusQueryRange, protocol.PrometheusQueryRangeArgs{DatasourceUID: "prom-prod", Expr: `{__name__=~".+"}`, Start: start, End: end, StepS: 60})
	if broad.Status != protocol.StatusRejected || broad.Error.Code != protocol.CodeQueryGuardFailed {
		t.Errorf("broad query = %+v", broad)
	}
}
