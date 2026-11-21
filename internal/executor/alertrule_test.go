package executor

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	mcpgrafana "github.com/grafana/mcp-grafana/v2"

	"github.com/tellagen/tellagen-proxy/protocol"
)

func node(ref, datasource, typ, expression, expr string) alertQueryNode {
	var n alertQueryNode
	n.RefID, n.DatasourceUID = ref, datasource
	n.Model.Type, n.Model.Expression, n.Model.Expr = typ, expression, expr
	return n
}

func withEvaluator(n alertQueryNode, op string, params ...float64) alertQueryNode {
	n.Model.Conditions = append(n.Model.Conditions, struct {
		Evaluator struct {
			Type   string    `json:"type"`
			Params []float64 `json:"params"`
		} `json:"evaluator"`
		Query struct {
			Params []string `json:"params"`
		} `json:"query"`
	}{})
	last := &n.Model.Conditions[len(n.Model.Conditions)-1]
	last.Evaluator.Type, last.Evaluator.Params = op, params
	return n
}

func classicOn(n alertQueryNode, ref string) alertQueryNode {
	n.Model.Conditions[0].Query.Params = []string{ref}
	return n
}

func ptr(v float64) *float64 { return &v }

func TestRuleConditionReadsTheThresholdOnlyWhenItIsSure(t *testing.T) {
	query := node("A", "prom-prod", "", "", "errors_ratio")
	reduce := node("B", "__expr__", "reduce", "A", "")
	threshold := func(op string, params ...float64) alertQueryNode {
		return withEvaluator(node("C", "__expr__", "threshold", "B", ""), op, params...)
	}
	tests := []struct {
		name      string
		condition string
		nodes     []alertQueryNode
		wantExpr  string
		wantDS    string
		want      *protocol.AlertThreshold
	}{
		{"greater than", "C", []alertQueryNode{query, reduce, threshold("gt", 0.05)}, "errors_ratio", "prom-prod", &protocol.AlertThreshold{Op: "gt", Value: 0.05}},
		{"less than", "C", []alertQueryNode{query, reduce, threshold("lt", 10)}, "errors_ratio", "prom-prod", &protocol.AlertThreshold{Op: "lt", Value: 10}},
		{"a threshold range in order", "C", []alertQueryNode{query, reduce, threshold("outside_range", 0.1, 0.8)}, "errors_ratio", "prom-prod", &protocol.AlertThreshold{Op: "outside_range", Value: 0.1, To: ptr(0.8)}},
		{"a threshold range in reverse order is not stated", "C", []alertQueryNode{query, reduce, threshold("within_range", 0.8, 0.1)}, "errors_ratio", "prom-prod", nil},
		{"a classic range in reverse order is sorted", "B", []alertQueryNode{query, classicOn(withEvaluator(node("B", "__expr__", "classic_conditions", "", ""), "within_range", 0.8, 0.1), "A")}, "errors_ratio", "prom-prod", &protocol.AlertThreshold{Op: "within_range", Value: 0.1, To: ptr(0.8)}},
		{"no value has no number", "C", []alertQueryNode{query, reduce, threshold("no_value")}, "errors_ratio", "prom-prod", &protocol.AlertThreshold{Op: "no_value"}},
		{"a classic condition", "B", []alertQueryNode{query, classicOn(withEvaluator(node("B", "__expr__", "classic_conditions", "", ""), "gt", 90), "A")}, "errors_ratio", "prom-prod", &protocol.AlertThreshold{Op: "gt", Value: 90}},
		{"a classic condition with no query is no expression", "B", []alertQueryNode{query, withEvaluator(node("B", "__expr__", "classic_conditions", "", ""), "gt", 90)}, "", "", &protocol.AlertThreshold{Op: "gt", Value: 90}},
		{"two conditions are not guessed", "C", []alertQueryNode{query, reduce, withEvaluator(threshold("gt", 1), "lt", 0)}, "errors_ratio", "prom-prod", nil},
		{"a math formula is no threshold", "C", []alertQueryNode{query, node("C", "__expr__", "math", "$A > 0.5", "")}, "", "", nil},
		{"a threshold the condition does not name is not taken", "B", []alertQueryNode{query, reduce, threshold("gt", 1)}, "errors_ratio", "prom-prod", nil},
		{"no condition and one threshold", "", []alertQueryNode{query, reduce, threshold("gt", 1)}, "errors_ratio", "prom-prod", &protocol.AlertThreshold{Op: "gt", Value: 1}},
		{"no condition and two thresholds", "", []alertQueryNode{query, withEvaluator(node("C", "__expr__", "threshold", "A", ""), "gt", 1), withEvaluator(node("D", "__expr__", "threshold", "A", ""), "lt", 0)}, "", "", nil},
		{"a threshold that lacks its number", "C", []alertQueryNode{query, reduce, threshold("gt")}, "errors_ratio", "prom-prod", nil},
		{"two data queries and no chain", "Z", []alertQueryNode{query, node("D", "prom-prod", "", "", "other")}, "", "", nil},
		{"a threshold straight on the query", "C", []alertQueryNode{query, withEvaluator(node("C", "__expr__", "threshold", "A", ""), "gt", 3)}, "errors_ratio", "prom-prod", &protocol.AlertThreshold{Op: "gt", Value: 3}},
		// The number 5 judges A * 100, not A, so neither it nor the query of A is given.
		{"a math node under a threshold node", "C", []alertQueryNode{
			node("A", "prom-prod", "", "", "errors_total"),
			node("B", "__expr__", "math", "$A * 100", ""),
			withEvaluator(node("C", "__expr__", "threshold", "B", ""), "gt", 5),
		}, "", "", nil},
		{"a math node between a reduce and the query", "C", []alertQueryNode{
			node("A", "prom-prod", "", "", "errors_total"),
			node("M", "__expr__", "math", "$A * 100", ""),
			node("B", "__expr__", "reduce", "M", ""),
			withEvaluator(node("C", "__expr__", "threshold", "B", ""), "gt", 5),
		}, "", "", nil},
		{"a resample under a threshold node", "C", []alertQueryNode{
			query,
			node("B", "__expr__", "resample", "A", ""),
			withEvaluator(node("C", "__expr__", "threshold", "B", ""), "gt", 5),
		}, "", "", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expr, datasource, got := ruleCondition(tt.condition, tt.nodes)
			if expr != tt.wantExpr || datasource != tt.wantDS {
				t.Errorf("expr, datasource = %q, %q, want %q, %q", expr, datasource, tt.wantExpr, tt.wantDS)
			}
			if (got == nil) != (tt.want == nil) {
				t.Fatalf("threshold = %+v, want %+v", got, tt.want)
			}
			if got == nil {
				return
			}
			if got.Op != tt.want.Op || got.Value != tt.want.Value || (got.To == nil) != (tt.want.To == nil) {
				t.Fatalf("threshold = %+v, want %+v", got, tt.want)
			}
			if tt.want.To != nil && *got.To != *tt.want.To {
				t.Errorf("to = %v, want %v", *got.To, *tt.want.To)
			}
		})
	}
}

func TestAListedRuleCarriesItsDetailsFromTheVersionHistory(t *testing.T) {
	f := newFixture(t, allowAllPolicy, defaultUpdate())
	result := f.executor.Execute(context.Background(), command(t, protocol.CapabilityGrafanaListAlertRules, protocol.GrafanaListAlertRulesArgs{}))
	assertValid(t, result)
	rules := result.Data.AlertRules
	if len(rules) != 2 {
		t.Fatalf("rules = %+v", rules)
	}
	rule := rules[0]
	if rule.Threshold == nil || rule.Threshold.Op != "gt" || rule.Threshold.Value != 40 || rule.Threshold.To != nil {
		t.Errorf("threshold = %+v", rule.Threshold)
	}
	if rule.For != "5m" || rule.Version != 3 || !rule.Updated.Equal(time.Date(2026, 11, 3, 9, 30, 0, 0, time.UTC)) {
		t.Errorf("rule = %+v", rule)
	}
	if rule.Expr != "hikaricp_connections_active" || rule.DatasourceUID != "prom-prod" {
		t.Errorf("expr, datasource = %q, %q", rule.Expr, rule.DatasourceUID)
	}
	if rule.Labels["severity"] != "page" {
		t.Errorf("labels = %v", rule.Labels)
	}
	if strings.Contains(fmt.Sprint(rule.Labels), "mari@example.ee") {
		t.Errorf("a label value was not redacted: %v", rule.Labels)
	}
}

// Grafana before version 12 has no version history. The rule still gets the threshold from a
// plain read, and says nothing about its version or its time.
func TestARuleOfAGrafanaWithoutHistoryHasOnlyWhatAPlainReadGives(t *testing.T) {
	f := newFixture(t, allowAllPolicy, defaultUpdate())
	result := f.executor.Execute(context.Background(), command(t, protocol.CapabilityGrafanaListAlertRules, protocol.GrafanaListAlertRulesArgs{}))
	assertValid(t, result)
	rule := result.Data.AlertRules[1]
	if rule.Threshold == nil || rule.Threshold.Op != "gt" || rule.Threshold.Value != 90 {
		t.Errorf("threshold = %+v", rule.Threshold)
	}
	if rule.Expr != "node_filesystem_used_ratio" || rule.DatasourceUID != "prom-prod" {
		t.Errorf("expr, datasource = %q, %q", rule.Expr, rule.DatasourceUID)
	}
	if rule.Version != 0 || !rule.Updated.IsZero() {
		t.Errorf("a field that was not read has a value: %+v", rule)
	}
}

// A rule that none of the extra reads can answer is listed as before.
func TestAListedRuleSurvivesWhenEveryExtraReadFails(t *testing.T) {
	f := newFixture(t, allowAllPolicy, defaultUpdate())
	f.stub.override = func(w http.ResponseWriter, r *http.Request) bool {
		if strings.Contains(r.URL.Path, "/api/ruler/") || strings.Contains(r.URL.Path, "/provisioning/") {
			http.Error(w, `{"message":"forbidden"}`, http.StatusForbidden)
			return true
		}
		return false
	}
	result := f.executor.Execute(context.Background(), command(t, protocol.CapabilityGrafanaListAlertRules, protocol.GrafanaListAlertRulesArgs{}))
	assertValid(t, result)
	if result.Status != protocol.StatusOK || len(result.Data.AlertRules) != 2 {
		t.Fatalf("result = %+v", result)
	}
	for _, rule := range result.Data.AlertRules {
		if rule.Threshold != nil || rule.Version != 0 {
			t.Errorf("rule = %+v", rule)
		}
	}
}

func listOfRules(count int) func(w http.ResponseWriter, r *http.Request) bool {
	var rules []string
	for i := range count {
		rules = append(rules, fmt.Sprintf(`{"uid":"r%d","name":"Rule %d","type":"alerting","state":"normal","health":"ok"}`, i, i))
	}
	return func(w http.ResponseWriter, r *http.Request) bool {
		if strings.HasPrefix(r.URL.Path, "/api/prometheus/grafana/api/v1/rules") {
			fmt.Fprintf(w, `{"status":"success","data":{"groups":[{"name":"g","file":"f","folderUid":"f1","rules":[%s]}]}}`, strings.Join(rules, ","))
			return true
		}
		return false
	}
}

func TestOnlyTheFirstRulesOfALongListAreRead(t *testing.T) {
	f := newFixture(t, allowAllPolicy, defaultUpdate())
	list := listOfRules(8)
	var versionReads atomic.Int64
	f.stub.override = func(w http.ResponseWriter, r *http.Request) bool {
		if strings.HasSuffix(r.URL.Path, "/versions") {
			versionReads.Add(1)
			// A Grafana with a history: an empty list falls back to the plain read.
			fmt.Fprint(w, `[]`)
			return true
		}
		return list(w, r)
	}
	result := f.executor.Execute(context.Background(), command(t, protocol.CapabilityGrafanaListAlertRules, protocol.GrafanaListAlertRulesArgs{}))
	assertValid(t, result)
	if len(result.Data.AlertRules) != 8 || int(versionReads.Load()) != alertRuleDetailLimit {
		t.Fatalf("%d rules, %d version reads, want 8 and %d", len(result.Data.AlertRules), versionReads.Load(), alertRuleDetailLimit)
	}
}

// The first answer that says the version history does not exist ends the version reads of
// the command: the other rules use the plain read only.
func TestAfterTheFirstMissingVersionHistoryTheOtherRulesUseThePlainRead(t *testing.T) {
	f := newFixture(t, allowAllPolicy, defaultUpdate())
	list := listOfRules(4)
	var versionReads, plainReads atomic.Int64
	f.stub.override = func(w http.ResponseWriter, r *http.Request) bool {
		switch {
		case strings.HasSuffix(r.URL.Path, "/versions"):
			versionReads.Add(1)
			http.NotFound(w, r)
			return true
		case strings.HasPrefix(r.URL.Path, "/api/v1/provisioning/alert-rules/"):
			plainReads.Add(1)
			uid := strings.TrimPrefix(r.URL.Path, "/api/v1/provisioning/alert-rules/")
			fmt.Fprintf(w, `{"uid":%q,"title":"R","folderUID":"f1","ruleGroup":"g","orgID":1,"condition":"B","noDataState":"NoData","execErrState":"Error","for":"1m",
				"data":[{"refId":"A","datasourceUid":"prom-prod","model":{"expr":"m"}},
					{"refId":"B","datasourceUid":"__expr__","model":{"type":"classic_conditions","conditions":[{"evaluator":{"type":"gt","params":[1]},"query":{"params":["A"]}}]}}]}`, uid)
			return true
		}
		return list(w, r)
	}
	result := f.executor.Execute(context.Background(), command(t, protocol.CapabilityGrafanaListAlertRules, protocol.GrafanaListAlertRulesArgs{}))
	assertValid(t, result)
	if versionReads.Load() != 1 || plainReads.Load() != 4 {
		t.Fatalf("%d version reads and %d plain reads, want 1 and 4", versionReads.Load(), plainReads.Load())
	}
	for _, rule := range result.Data.AlertRules {
		if rule.Threshold == nil || rule.Expr != "m" {
			t.Errorf("rule = %+v", rule)
		}
	}
}

func TestADetailReaderStopsWhenLessThanHalfOfTheTimeIsLeft(t *testing.T) {
	var calls int
	reader := &detailReader{
		call:     func(*mcpgrafana.Tool, any) (string, *callFailure) { calls++; return "", &callFailure{} },
		started:  time.Now().Add(-8 * time.Second),
		deadline: time.Now().Add(2 * time.Second),
	}
	rules := []protocol.AlertRule{{UID: "a"}, {UID: "b"}}
	skipped := reader.addDetails(rules)
	if calls != 0 || len(skipped) != 1 || !strings.Contains(skipped[0], "ran out of time") {
		t.Fatalf("%d calls, skipped %v", calls, skipped)
	}
	reader.started, reader.deadline = time.Now(), time.Now().Add(time.Minute)
	if skipped := reader.addDetails(rules); calls == 0 || len(skipped) != 0 {
		t.Fatalf("%d calls, skipped %v", calls, skipped)
	}
}

// A deadline that passes during a detail read leaves the listed rules intact, and the result
// says that the details were cut short.
func TestADeadlineDuringTheDetailReadsKeepsTheList(t *testing.T) {
	f := newFixture(t, allowAllPolicy, defaultUpdate())
	f.stub.override = func(w http.ResponseWriter, r *http.Request) bool {
		if strings.HasSuffix(r.URL.Path, "/versions") || strings.Contains(r.URL.Path, "/provisioning/") {
			<-r.Context().Done()
			return true
		}
		return false
	}
	cmd := command(t, protocol.CapabilityGrafanaListAlertRules, protocol.GrafanaListAlertRulesArgs{})
	cmd.DeadlineMS = 1500
	result := f.executor.Execute(context.Background(), cmd)
	assertValid(t, result)
	if result.Status != protocol.StatusPartial || result.Data == nil || len(result.Data.AlertRules) != 2 {
		t.Fatalf("result = %+v", result)
	}
	if len(result.Skipped) == 0 || !strings.Contains(result.Skipped[0], "ran out of time") {
		t.Errorf("skipped = %v", result.Skipped)
	}
	if result.Data.AlertRules[0].Title != "Pool full" {
		t.Errorf("rules = %+v", result.Data.AlertRules)
	}
}

// A deadline that passes before the list is read is still a timeout.
func TestADeadlineBeforeTheListIsStillATimeout(t *testing.T) {
	f := newFixture(t, allowAllPolicy, defaultUpdate())
	f.stub.override = func(w http.ResponseWriter, r *http.Request) bool {
		if strings.HasPrefix(r.URL.Path, "/api/prometheus/") {
			<-r.Context().Done()
			return true
		}
		return false
	}
	cmd := command(t, protocol.CapabilityGrafanaListAlertRules, protocol.GrafanaListAlertRulesArgs{})
	cmd.DeadlineMS = 300
	result := f.executor.Execute(context.Background(), cmd)
	if result.Status == protocol.StatusOK || result.Status == protocol.StatusPartial {
		t.Fatalf("result = %+v", result)
	}
}

func TestADetailReadSkipsAUidThatIsNotOne(t *testing.T) {
	var calls int
	reader := &detailReader{call: func(*mcpgrafana.Tool, any) (string, *callFailure) { calls++; return "", &callFailure{} }}
	reader.addDetails([]protocol.AlertRule{{UID: "../admin"}, {UID: "a b"}, {UID: ""}})
	if calls != 0 {
		t.Fatalf("%d reads for a uid that is not one", calls)
	}
}

func TestAlertRuleVersionsComeNewestFirstWithTheirThresholds(t *testing.T) {
	f := newFixture(t, allowAllPolicy, defaultUpdate())
	result := f.executor.Execute(context.Background(), command(t, protocol.CapabilityGrafanaAlertRuleVersions, protocol.GrafanaAlertRuleVersionsArgs{UID: "a1"}))
	assertValid(t, result)
	versions := result.Data.AlertRuleVersions
	if len(versions) != 2 || versions[0].Version != 3 || versions[1].Version != 2 {
		t.Fatalf("versions = %+v", versions)
	}
	if versions[0].Threshold == nil || versions[0].Threshold.Value != 40 || versions[1].Threshold == nil || versions[1].Threshold.Value != 20 {
		t.Errorf("thresholds = %+v, %+v", versions[0].Threshold, versions[1].Threshold)
	}
	if versions[1].Expr != "hikaricp_connections_active" || !versions[1].Updated.Equal(time.Date(2026, 10, 12, 14, 5, 0, 0, time.UTC)) {
		t.Errorf("version = %+v", versions[1])
	}
}

func TestAlertRuleVersionsSayWhenThereIsNoHistory(t *testing.T) {
	f := newFixture(t, allowAllPolicy, defaultUpdate())
	result := f.executor.Execute(context.Background(), command(t, protocol.CapabilityGrafanaAlertRuleVersions, protocol.GrafanaAlertRuleVersionsArgs{UID: "a2"}))
	assertValid(t, result)
	if result.Status != protocol.StatusError || result.Error == nil || result.Error.Code != protocol.CodeUpstream4xx ||
		!strings.Contains(result.Error.Message, "the rule was not found, or Grafana is older than 12") {
		t.Fatalf("result = %+v", result)
	}
	if result.Data != nil {
		t.Errorf("an unavailable history must not read as an empty one: %+v", result.Data)
	}
}

func TestAlertRuleVersionsRefuseAUidThatIsNotOne(t *testing.T) {
	for _, uid := range []string{"", "../admin", "a b", strings.Repeat("a", 200)} {
		f := newFixture(t, allowAllPolicy, defaultUpdate())
		result := f.executor.Execute(context.Background(), command(t, protocol.CapabilityGrafanaAlertRuleVersions, protocol.GrafanaAlertRuleVersionsArgs{UID: uid}))
		assertRejected(t, result, protocol.CodeQueryGuardFailed)
		if f.stub.requestCount() != 0 {
			t.Errorf("uid %q made %d Grafana calls", uid, f.stub.requestCount())
		}
	}
}

func TestShortDuration(t *testing.T) {
	for in, want := range map[string]string{"5m0s": "5m", "1h0m0s": "1h", "1h30m0s": "1h30m", "30s": "30s", "10m30s": "10m30s", "": ""} {
		if got := shortDuration(in); got != want {
			t.Errorf("shortDuration(%q) = %q, want %q", in, got, want)
		}
	}
}
