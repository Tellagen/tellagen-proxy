package executor

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tellagen/tellagen-proxy/internal/policy"
	"github.com/tellagen/tellagen-proxy/protocol"
)

var stubT0 = time.Date(2026, 11, 4, 13, 0, 0, 0, time.UTC)

// stubGrafana answers the requests grafana-mcp makes, in Grafana's own shapes. Every
// request is recorded, so a test can show that a refused command made no call.
type stubGrafana struct {
	*httptest.Server
	mu       sync.Mutex
	requests []stubRequest
	// hold, when set, blocks every query until the request's context ends.
	hold chan struct{}
	// override answers a request instead of the routes below.
	override func(w http.ResponseWriter, r *http.Request) bool
	// logLines is what a Loki log query returns.
	logLines []string
}

type stubRequest struct {
	Method string
	Path   string
	Body   string
	Token  string
}

func newStubGrafana(t *testing.T) *stubGrafana {
	t.Helper()
	stub := &stubGrafana{logLines: []string{"pool exhausted"}}
	stub.Server = httptest.NewServer(http.HandlerFunc(stub.serve))
	t.Cleanup(stub.Close)
	return stub
}

func (s *stubGrafana) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	s.mu.Lock()
	s.requests = append(s.requests, stubRequest{r.Method, r.URL.Path, string(body), strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")})
	hold, override := s.hold, s.override
	s.mu.Unlock()

	if override != nil && override(w, r) {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	path := r.URL.Path
	switch {
	case path == "/api/health":
		fmt.Fprint(w, `{"version":"12.2.1","database":"ok"}`)
	case path == "/api/datasources":
		fmt.Fprint(w, `[
			{"id":1,"uid":"prom-prod","name":"Prometheus prod","type":"prometheus","isDefault":true},
			{"id":2,"uid":"loki-prod","name":"Loki prod","type":"loki"},
			{"id":3,"uid":"prom-secret","name":"Prometheus secret","type":"prometheus"}]`)
	case strings.Contains(path, "/api/v1/label/") || strings.Contains(path, "/loki/api/v1/label/"):
		fmt.Fprint(w, `{"status":"success","data":["checkout","mari@example.ee","payments"]}`)
	case strings.HasPrefix(path, "/api/datasources/uid/prom"):
		fmt.Fprintf(w, `{"id":1,"uid":%q,"name":"P","type":"prometheus"}`, strings.TrimPrefix(path, "/api/datasources/uid/"))
	case strings.HasPrefix(path, "/api/datasources/uid/loki"):
		fmt.Fprintf(w, `{"id":2,"uid":%q,"name":"L","type":"loki"}`, strings.TrimPrefix(path, "/api/datasources/uid/"))
	case path == "/api/ds/query":
		if hold != nil {
			select {
			case <-hold:
			case <-r.Context().Done():
				return
			}
		}
		s.serveQuery(w, string(body))
	case strings.HasSuffix(path, "/index/stats"):
		fmt.Fprint(w, `{"streams":1,"chunks":1,"entries":10,"bytes":1000}`)
	case strings.HasSuffix(path, "/patterns"):
		fmt.Fprint(w, `{"status":"success","data":[
			{"pattern":"login <_> from 203.0.113.42","samples":[[1762261200,3]]},
			{"pattern":"pool exhausted after <_> ms","samples":[[1762261200,9],[1762261260,3]]}]}`)
	case path == "/api/search":
		fmt.Fprint(w, `[{"uid":"d1","title":"Checkout","type":"dash-db","folderTitle":"Prod"},{"uid":"d2","title":"Owner mari@example.ee","type":"dash-db"}]`)
	case strings.HasPrefix(path, "/api/dashboards/uid/"):
		fmt.Fprint(w, `{"dashboard":{"uid":"d1","panels":[
			{"id":1,"title":"Pool","type":"timeseries","datasource":{"uid":"prom-prod","type":"prometheus"},"targets":[{"refId":"A","expr":"hikaricp_connections_active"}]},
			{"id":2,"title":"Secret","type":"timeseries","datasource":{"uid":"prom-secret","type":"prometheus"},"targets":[{"refId":"A","expr":"secret_metric"}]},
			{"id":3,"title":"Variable","type":"timeseries","datasource":{"uid":"$ds","type":"prometheus"},"targets":[{"refId":"A","expr":"up"}]}]},"meta":{}}`)
	case strings.HasPrefix(path, "/api/prometheus/grafana/api/v1/rules"):
		fmt.Fprint(w, `{"status":"success","data":{"groups":[{"name":"g","file":"f","folderUid":"f1","rules":[
			{"uid":"a1","name":"Pool full","type":"alerting","state":"firing","health":"ok","duration":300,"labels":{"severity":"page","owner":"mari@example.ee"}},
			{"uid":"a2","name":"Disk fill","type":"alerting","state":"normal","health":"ok"}]}]}}`)
	case path == "/api/ruler/grafana/api/v1/rule/a1/versions":
		// Oldest first on purpose: the proxy sorts them.
		fmt.Fprint(w, `[
			{"for":"5m","grafana_alert":{"uid":"a1","version":2,"updated":"2026-10-12T14:05:00.000Z","condition":"C","data":[
				{"refId":"A","datasourceUid":"prom-prod","model":{"expr":"hikaricp_connections_active"}},
				{"refId":"B","datasourceUid":"__expr__","model":{"type":"reduce","expression":"A","reducer":"last"}},
				{"refId":"C","datasourceUid":"__expr__","model":{"type":"threshold","expression":"B","conditions":[{"evaluator":{"type":"gt","params":[20]}}]}}]}},
			{"for":"5m","grafana_alert":{"uid":"a1","version":3,"updated":"2026-11-03T09:30:00.000Z","condition":"C","data":[
				{"refId":"A","datasourceUid":"prom-prod","model":{"expr":"hikaricp_connections_active"}},
				{"refId":"B","datasourceUid":"__expr__","model":{"type":"reduce","expression":"A","reducer":"last"}},
				{"refId":"C","datasourceUid":"__expr__","model":{"type":"threshold","expression":"B","conditions":[{"evaluator":{"type":"gt","params":[40]}}]}}]}}]`)
	case path == "/api/v1/provisioning/alert-rules/a2":
		// A Grafana without a version endpoint still answers a plain read of the rule.
		fmt.Fprint(w, `{"uid":"a2","title":"Disk fill","folderUID":"f1","ruleGroup":"g","orgID":1,"condition":"B","noDataState":"NoData","execErrState":"Error","for":"10m",
			"data":[
				{"refId":"A","datasourceUid":"prom-prod","model":{"expr":"node_filesystem_used_ratio"}},
				{"refId":"B","datasourceUid":"__expr__","model":{"type":"classic_conditions","conditions":[{"evaluator":{"type":"gt","params":[90]},"query":{"params":["A"]},"reducer":{"type":"avg"}}]}}]}`)
	default:
		http.NotFound(w, r)
	}
}

func (s *stubGrafana) serveQuery(w http.ResponseWriter, body string) {
	var payload struct {
		Queries []struct {
			Expr       string `json:"expr"`
			Instant    bool   `json:"instant"`
			Datasource struct {
				Type string `json:"type"`
			} `json:"datasource"`
			QueryType string `json:"queryType"`
		} `json:"queries"`
	}
	_ = json.Unmarshal([]byte(body), &payload)
	query := payload.Queries[0]
	ms := stubT0.UnixMilli()
	timeField := `{"name":"Time","type":"time","typeInfo":{"frame":"time.Time"}}`
	valueField := func(labels string) string {
		return `{"name":"Value","type":"number","typeInfo":{"frame":"float64"},"labels":` + labels + `}`
	}
	frame := ""
	switch {
	case query.Datasource.Type == "loki" && strings.Contains(query.Expr, "count_over_time") && query.QueryType == "instant":
		frame = fmt.Sprintf(`{"schema":{"fields":[%s,%s]},"data":{"values":[[%d],[42]]}}`, timeField, valueField(`{}`), ms)
	case query.Datasource.Type == "loki" && strings.Contains(query.Expr, "_over_time"):
		frame = fmt.Sprintf(`{"schema":{"fields":[%s,%s]},"data":{"values":[[%d,%d],[1912,3]]}}`, timeField, valueField(`{"pod":"p1"}`), ms, ms+60000)
	case query.Datasource.Type == "loki":
		times, nanos, labels, kinds := []string{}, []string{}, []string{}, []string{}
		lines, _ := json.Marshal(s.logLines)
		for i := range s.logLines {
			at := ms + int64(i)
			times = append(times, fmt.Sprint(at))
			nanos = append(nanos, fmt.Sprintf("%q", fmt.Sprint(at*1000000)))
			labels = append(labels, `{"pod":"checkout-1","password":"hunter22"}`)
			kinds = append(kinds, `{"pod":"I","password":"I"}`)
		}
		frame = fmt.Sprintf(`{"schema":{"meta":{"type":"logs"},"fields":[
			{"name":"labels","type":"other","typeInfo":{"frame":"json.RawMessage"}},
			{"name":"Time","type":"time","typeInfo":{"frame":"time.Time"}},
			{"name":"Line","type":"string","typeInfo":{"frame":"string"}},
			{"name":"tsNs","type":"string","typeInfo":{"frame":"string"}},
			{"name":"labelTypes","type":"other","typeInfo":{"frame":"json.RawMessage"}}]},
			"data":{"values":[[%s],[%s],%s,[%s],[%s]]}}`, strings.Join(labels, ","), strings.Join(times, ","), lines, strings.Join(nanos, ","), strings.Join(kinds, ","))
	case query.Instant:
		frame = fmt.Sprintf(`{"schema":{"fields":[%s,%s]},"data":{"values":[[%d],[7]]}}`, timeField, valueField(`{"service":"checkout","instance":"203.0.113.42:9090"}`), ms)
	default:
		frame = fmt.Sprintf(`{"schema":{"fields":[%s,%s]},"data":{"values":[[%d,%d,%d],[38,100,40]]}}`, timeField, valueField(`{"service":"checkout"}`), ms, ms+30000, ms+60000)
	}
	fmt.Fprintf(w, `{"results":{"A":{"status":200,"frames":[%s]}}}`, frame)
}

func (s *stubGrafana) recorded() []stubRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]stubRequest{}, s.requests...)
}

func (s *stubGrafana) requestCount() int {
	return len(s.recorded())
}

func (s *stubGrafana) queryBodies() []string {
	var bodies []string
	for _, request := range s.recorded() {
		if request.Path == "/api/ds/query" {
			bodies = append(bodies, request.Body)
		}
	}
	return bodies
}

type fixture struct {
	stub     *stubGrafana
	executor *Executor
	token    func() (string, error)
}

const allowAllPolicy = `
datasourceUIDs: [prom-prod, loki-prod]
`

func newFixture(t *testing.T, policyText string, update protocol.PolicyUpdate) *fixture {
	t.Helper()
	stub := newStubGrafana(t)
	path := t.TempDir() + "/policy.yaml"
	if err := writeFile(path, policyText); err != nil {
		t.Fatal(err)
	}
	file, err := policy.Load(path, nil)
	if err != nil {
		t.Fatalf("policy.Load() error = %v", err)
	}
	engine := policy.NewEngine(file)
	engine.Apply(update)
	f := &fixture{stub: stub, token: func() (string, error) { return "glsa_test", nil }}
	executor, err := New(Config{
		GrafanaURL: stub.URL,
		PublicURL:  "https://grafana.example.ee",
		Token:      func() (string, error) { return f.token() },
		Policy:     engine,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	f.executor = executor
	return f
}

func defaultUpdate() protocol.PolicyUpdate {
	return protocol.PolicyUpdate{
		Revision: "srv-1",
		Narrow:   protocol.PolicyNarrow{DatasourceUIDs: []string{"prom-prod", "loki-prod"}},
		Data:     protocol.PolicyData{Metrics: protocol.MetricsPoints, LogLines: 3, Redaction: protocol.RedactionOn},
	}
}

var commandCounter struct {
	sync.Mutex
	n int
}

func command(t *testing.T, capability string, args any) protocol.Command {
	t.Helper()
	encoded, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	commandCounter.Lock()
	commandCounter.n++
	id := fmt.Sprintf("cmd_%d", commandCounter.n)
	commandCounter.Unlock()
	return protocol.Command{
		CommandID:         id,
		Attempt:           1,
		AttemptToken:      "at_" + id,
		Capability:        capability,
		CapabilityVersion: 1,
		Args:              encoded,
	}
}

func promRange(expr string) protocol.PrometheusQueryRangeArgs {
	return protocol.PrometheusQueryRangeArgs{DatasourceUID: "prom-prod", Expr: expr, Start: stubT0, End: stubT0.Add(time.Hour), StepS: 30}
}

func lokiRange(expr string) protocol.LokiQueryRangeArgs {
	return protocol.LokiQueryRangeArgs{DatasourceUID: "loki-prod", Expr: expr, Start: stubT0, End: stubT0.Add(time.Hour)}
}
