package guard

import (
	"strings"
	"testing"
	"time"

	"github.com/tellagen/tellagen-proxy/protocol"
)

func TestCheckPromQL(t *testing.T) {
	tests := []struct {
		name     string
		expr     string
		refused  string
		lookback time.Duration
	}{
		{name: "metric name", expr: `up`},
		{name: "metric name with a regex label", expr: `up{job=~"api.*"}`},
		{name: "exact matcher without a name", expr: `{job="api"}`},
		{name: "exact name matcher", expr: `{__name__="up"}`},
		{name: "narrow name regex with an exact matcher", expr: `{__name__=~"http_.+",job="api"}`},
		{name: "aggregation with a rate", expr: `sum by (le) (rate(http_request_duration_seconds_bucket{service="checkout"}[5m]))`, lookback: 5 * time.Minute},
		{name: "one subquery", expr: `max_over_time(rate(http_requests_total{job="api"}[5m])[1h:1m])`, lookback: time.Hour + 5*time.Minute},
		{name: "offset counts", expr: `up{job="api"} offset 2h`, lookback: 2 * time.Hour},
		{name: "negative offset counts", expr: `up{job="api"} offset -2h`, lookback: 2 * time.Hour},
		{name: "longest of two selectors", expr: `rate(a[5m]) / rate(b[1h])`, lookback: time.Hour},

		{name: "catch-all name regex", expr: `{__name__=~".+"}`, refused: "matches every metric"},
		{name: "catch-all name regex beside an exact matcher", expr: `{__name__=~".*",job="api"}`, refused: "matches every metric"},
		{name: "catch-all in a group", expr: `{__name__=~"(.+)"}`, refused: "matches every metric"},
		{name: "regex matcher alone", expr: `{job=~"api.*"}`, refused: "no metric name and no exact matcher"},
		{name: "negative matcher alone", expr: `{job!="api",env="" ,x=~".+"}`, refused: "no metric name and no exact matcher"},
		{name: "broad selector inside a function", expr: `sum(rate({job=~".+"}[5m]))`, refused: "no metric name and no exact matcher"},
		{name: "two subqueries nested", expr: `max_over_time(max_over_time(rate(a[1m])[5m:1m])[1h:5m])`, refused: "nests 2 subqueries"},
		{name: "no selector", expr: `1 + 1`, refused: "reads no metric"},
		{name: "vector function with no selector", expr: `vector(1)`, refused: "reads no metric"},
		{name: "does not parse", expr: `sum(rate(up[5m]`, refused: "does not parse"},
		{name: "dashboard variable", expr: `rate(up[$__rate_interval])`, refused: "Replace dashboard variables"},
		{name: "empty", expr: "  ", refused: "empty"},
		{name: "too long", expr: `up{job="` + strings.Repeat("a", MaxQueryBytes) + `"}`, refused: "more than the 8192 allowed"},
		{name: "at modifier", expr: `up{job="api"} @ 0`, refused: "@ modifier"},
		{name: "at start", expr: `up{job="api"} @ start()`, refused: "@ modifier"},
		{name: "at on a subquery", expr: `max_over_time(rate(a[1m])[5m:1m] @ 0)`, refused: "@ modifier"},
		{name: "experimental function", expr: `info(up{job="api"})`, refused: "does not parse"},
		{name: "duration expression", expr: `rate(up[1m*5])`, refused: "does not parse"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			query, rejection := CheckPromQL(tt.expr)
			if tt.refused == "" {
				if rejection != nil {
					t.Fatalf("CheckPromQL(%q) refused: %v", tt.expr, rejection)
				}
				if query.Lookback != tt.lookback {
					t.Fatalf("Lookback = %s, want %s", query.Lookback, tt.lookback)
				}
				if query.Normalized == "" {
					t.Fatal("Normalized is empty")
				}
				return
			}
			if rejection == nil {
				t.Fatalf("CheckPromQL(%q) passed, want a refusal holding %q", tt.expr, tt.refused)
			}
			if rejection.Code != protocol.CodeQueryGuardFailed {
				t.Errorf("Code = %s", rejection.Code)
			}
			if !strings.Contains(rejection.Message, tt.refused) {
				t.Errorf("Message = %q, want it to hold %q", rejection.Message, tt.refused)
			}
		})
	}
}

func TestCheckPromSelector(t *testing.T) {
	tests := []struct {
		name    string
		expr    string
		refused bool
	}{
		{name: "exact", expr: `{job="api"}`},
		{name: "metric", expr: `up{job=~"a.*"}`},
		{name: "regex alone", expr: `{job=~".+"}`, refused: true},
		{name: "not a selector", expr: `rate(up[5m])`, refused: true},
		{name: "offset", expr: `up offset 1d`, refused: true},
		{name: "does not parse", expr: `{job=`, refused: true},
		{name: "empty", expr: ``, refused: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if rejection := CheckPromSelector(tt.expr); (rejection != nil) != tt.refused {
				t.Fatalf("CheckPromSelector(%q) = %v, refused %v", tt.expr, rejection, tt.refused)
			}
		})
	}
}

func TestCheckLogQL(t *testing.T) {
	tests := []struct {
		name     string
		expr     string
		refused  string
		metric   bool
		lookback time.Duration
	}{
		{name: "selector", expr: `{job="api"}`},
		{name: "exact and regex", expr: `{job="api", ns=~"prod|staging", pod!="x"}`},
		{name: "line filters", expr: `{job="api"} |= "error" != "debug" |~ "pool.*" !~ "x" |> "<_> failed" !> "y"`},
		{name: "line filter with or", expr: `{job="api"} |= "a" or "b"`},
		{name: "line filter with ip", expr: `{job="api"} |= ip("10.0.0.0/8")`},
		{name: "raw string", expr: "{job=\"api\"} |~ `a\\d+`"},
		{name: "parsers", expr: `{job="api"} | json | logfmt --strict --keep-empty | unpack | decolorize`},
		{name: "json extraction", expr: `{job="api"} | json first="a.b", status`},
		{name: "pattern and regexp", expr: `{job="api"} | pattern "<ip> <_>" | regexp "(?P<x>a)"`},
		{name: "label filters", expr: `{job="api"} | json | level="error" or status>=500 and latency>1s | __error__=""`},
		{name: "label filter group", expr: `{job="api"} | json | (level="error" or level="warn"), status!=200`},
		{name: "label filter with ip", expr: `{job="api"} | logfmt | addr = ip("10.0.0.0/8")`},
		{name: "drop and keep", expr: `{job="api"} | json | drop a, b="c" | keep d`},
		{name: "count", expr: `count_over_time({job="api"} |= "error" [5m])`, metric: true, lookback: 5 * time.Minute},
		{name: "sum by rate", expr: `sum by (pod) (rate({job="api"} |= "error" [1m]))`, metric: true, lookback: time.Minute},
		{name: "grouping after", expr: `sum(rate({job="api"}[1m])) by (pod)`, metric: true, lookback: time.Minute},
		{name: "unwrap", expr: `quantile_over_time(0.99, {job="api"} | json | unwrap duration(latency) | __error__="" [5m]) by (pod)`, metric: true, lookback: 5 * time.Minute},
		{name: "topk", expr: `topk(5, sum by (pod) (count_over_time({job="api"}[1h])))`, metric: true, lookback: time.Hour},
		{name: "offset counts", expr: `rate({job="api"}[5m] offset 1h)`, metric: true, lookback: time.Hour + 5*time.Minute},
		{name: "binary", expr: `sum(rate({a="b"} |= "x" [1m])) / on (pod) group_left sum(rate({a="b"}[2m])) * 100`, metric: true, lookback: 2 * time.Minute},

		{name: "empty selector", expr: `{}`, refused: "exact matcher"},
		{name: "catch-all regex", expr: `{job=~".+"}`, refused: "exact matcher"},
		{name: "narrow regex alone", expr: `{job=~"api-.*"}`, refused: "exact matcher"},
		{name: "negative alone", expr: `{job!="api"}`, refused: "exact matcher"},
		{name: "exact empty value", expr: `{job=""}`, refused: "exact matcher"},
		{name: "broad selector in a function", expr: `rate({job=~".+"}[5m])`, refused: "exact matcher"},
		{name: "line_format", expr: `{job="api"} | line_format "{{.a}}"`, refused: `stage "line_format" is not allowed`},
		{name: "label_format", expr: `{job="api"} | label_format a=b`, refused: `stage "label_format" is not allowed`},
		{name: "unknown stage", expr: `{job="api"} | distinct a`, refused: `stage "distinct" is not allowed`},
		{name: "unknown function", expr: `label_replace(rate({a="b"}[1m]), "a", "b", "c", "d")`, refused: `function "label_replace" is not allowed`},
		{name: "comment", expr: "{job=\"api\"} # hidden", refused: "comments"},
		{name: "not closed", expr: `{job="api`, refused: "not closed"},
		{name: "unbalanced", expr: `sum(rate({a="b"}[1m])`, refused: "ends early"},
		{name: "trailing tokens", expr: `{job="api"} [5m]`, refused: "needs a function"},
		{name: "number only", expr: `1 + 1`, refused: "reads no logs"},
		{name: "empty", expr: ``, refused: "empty"},
		{name: "too long", expr: `{job="` + strings.Repeat("a", MaxQueryBytes) + `"}`, refused: "more than the 8192 allowed"},
		{name: "bad duration", expr: `rate({a="b"}[5parsecs])`, refused: "not a duration"},
		{name: "too deep", expr: strings.Repeat("(", maxLogQLDepth+1) + `rate({a="b"}[1m])` + strings.Repeat(")", maxLogQLDepth+1), refused: "nests too deeply"},
		{name: "bad parser flag", expr: `{job="api"} | json --other`, refused: "--other"},
		{name: "unexpected character", expr: `{job="api"} ; drop`, refused: "unexpected character"},
		{name: "single quotes", expr: `{job='api'}`, refused: "unexpected character"},
		{name: "invalid text", expr: "{job=\"a\xff\"}", refused: "not valid text"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			query, rejection := CheckLogQL(tt.expr)
			if tt.refused == "" {
				if rejection != nil {
					t.Fatalf("CheckLogQL(%q) refused: %v", tt.expr, rejection)
				}
				if query.Metric != tt.metric || query.Lookback != tt.lookback {
					t.Fatalf("query = %+v, want metric %v lookback %s", query, tt.metric, tt.lookback)
				}
				return
			}
			if rejection == nil {
				t.Fatalf("CheckLogQL(%q) passed, want a refusal holding %q", tt.expr, tt.refused)
			}
			if !strings.Contains(rejection.Message, tt.refused) {
				t.Errorf("Message = %q, want it to hold %q", rejection.Message, tt.refused)
			}
		})
	}
}

func TestRefuseLogText(t *testing.T) {
	const reads = `{job="api"}`
	tests := []struct {
		name    string
		expr    string
		refused string
	}{
		{"count of a stream", `count_over_time(` + reads + ` [5m])`, ""},
		{"count with a line filter", `sum by (pod) (rate(` + reads + ` |= "error" [5m]))`, ""},
		{"a log query returns only a count while lines are off", reads + ` | json`, ""},
		{"json with no aggregation", `count_over_time(` + reads + ` | json [5m])`, "json"},
		{"logfmt with no aggregation", `rate(` + reads + ` | logfmt [5m])`, "logfmt"},
		{"unpack with no aggregation", `count_over_time(` + reads + ` | unpack [5m])`, "unpack"},
		{"json under sum by", `sum by (status) (count_over_time(` + reads + ` | json [5m]))`, ""},
		{"json under a trailing by", `sum(count_over_time(` + reads + ` | json [5m])) by (status)`, ""},
		{"json under sum, which keeps no label", `sum(count_over_time(` + reads + ` | json | status >= 500 [5m]))`, ""},
		{"json under count by", `count by (status) (rate(` + reads + ` | json [5m]))`, ""},
		{"json with named fields", `count_over_time(` + reads + ` | json status="status" [5m])`, ""},
		{"logfmt with a named field", `count_over_time(` + reads + ` | logfmt status [5m])`, ""},
		{"named fields, then a parser that takes all", `count_over_time(` + reads + ` | json status="status" | logfmt [5m])`, "logfmt"},
		{"json under sum without keeps every other field", `sum without (pod) (count_over_time(` + reads + ` | json [5m]))`, "json"},
		{"json under topk keeps every field", `topk(5, count_over_time(` + reads + ` | json [5m]))`, "json"},
		{"json under topk by keeps every field", `topk by (status) (5, count_over_time(` + reads + ` | json [5m]))`, "json"},
		{"json under sort keeps every field", `sort(count_over_time(` + reads + ` | json [5m]))`, "json"},
		{"topk over a grouped query", `topk(5, sum by (status) (count_over_time(` + reads + ` | json [5m])))`, ""},
		{"sum over topk", `sum by (status) (topk(5, count_over_time(` + reads + ` | json [5m])))`, ""},
		{"unwrap grouped on the range function", `avg_over_time(` + reads + ` | json | unwrap took [5m]) by (pod)`, ""},
		{"unwrap with no group", `avg_over_time(` + reads + ` | json | unwrap took [5m])`, "json"},
		{"unwrap without keeps every other field", `avg_over_time(` + reads + ` | json | unwrap took [5m]) without (pod)`, "json"},
		{"the second term of a sum is checked too", `sum by (a) (rate(` + reads + ` | json [5m])) / rate(` + reads + ` | json [5m])`, "json"},
		{"the first term of a sum is checked too", `rate(` + reads + ` | json [5m]) / sum by (a) (rate(` + reads + ` | json [5m]))`, "json"},
		{"both terms grouped", `sum by (a) (rate(` + reads + ` | json [5m])) / sum by (a) (rate(` + reads + ` |= "x" [5m]))`, ""},
		{"a parser of one pipeline does not stick to the next", `sum by (a) (rate(` + reads + ` | json [5m])) / rate(` + reads + ` [5m])`, ""},
		{"regexp captures anything", `sum by (msg) (count_over_time(` + reads + ` | regexp "(?P<msg>.*)" [1h]))`, "regexp"},
		{"pattern captures anything", `sum by (msg) (count_over_time(` + reads + ` | pattern "<msg>" [1h]))`, "pattern"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			query, rejection := CheckLogQL(tt.expr)
			if rejection != nil {
				t.Fatalf("CheckLogQL() = %s", rejection.Message)
			}
			got := query.RefuseLogText()
			switch {
			case tt.refused == "" && got != nil:
				t.Fatalf("RefuseLogText() = %s", got.Message)
			case tt.refused != "" && got == nil:
				t.Fatal("RefuseLogText() let it pass")
			case tt.refused != "" && !strings.Contains(got.Message, tt.refused):
				t.Fatalf("RefuseLogText() = %s, want it to name %s", got.Message, tt.refused)
			}
		})
	}
}

func TestCheckLokiSelector(t *testing.T) {
	if rejection := CheckLokiSelector(`{job="api", ns=~"a|b"}`); rejection != nil {
		t.Fatalf("selector refused: %v", rejection)
	}
	for _, expr := range []string{`{job=~".+"}`, `{job="api"} |= "x"`, `rate({a="b"}[1m])`, ``, `{job="api`} {
		if rejection := CheckLokiSelector(expr); rejection == nil {
			t.Errorf("CheckLokiSelector(%q) passed", expr)
		}
	}
}

func TestCheckRange(t *testing.T) {
	start := time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC)
	limits := protocol.Limits{MaxRangeS: 24 * 60 * 60, MaxPoints: 500}
	tests := []struct {
		name     string
		r        Range
		limits   protocol.Limits
		code     string
		hint     *protocol.Limits
		contains string
	}{
		{name: "inside", r: Range{Start: start, End: start.Add(2 * time.Hour), StepS: 30}, limits: limits},
		{name: "exactly at the range and points limit", r: Range{Start: start, End: start.Add(24 * time.Hour), StepS: 174}, limits: limits},
		{name: "no step on a log query", r: Range{Start: start, End: start.Add(time.Hour)}, limits: limits},
		{name: "no limits set", r: Range{Start: start, End: start.Add(1000 * time.Hour), StepS: 1}},
		{
			name: "range over", r: Range{Start: start, End: start.Add(48 * time.Hour), StepS: 3600}, limits: limits,
			code: protocol.CodePolicyRangeExceeded, hint: &protocol.Limits{MaxRangeS: 86400}, contains: "range 48h exceeds 24h",
		},
		{
			name: "range vector pushes it over", r: Range{Start: start, End: start.Add(24 * time.Hour), StepS: 3600, Lookback: time.Hour}, limits: limits,
			code: protocol.CodePolicyRangeExceeded, hint: &protocol.Limits{MaxRangeS: 86400}, contains: "range 25h exceeds 24h",
		},
		{
			name: "too many points", r: Range{Start: start, End: start.Add(24 * time.Hour), StepS: 4}, limits: limits,
			code: protocol.CodeQueryGuardFailed, hint: &protocol.Limits{MaxPoints: 500}, contains: "Raise step_s to at least 173",
		},
		{name: "end before start", r: Range{Start: start, End: start.Add(-time.Hour), StepS: 30}, limits: limits, code: protocol.CodeQueryGuardFailed, contains: "after the start"},
		{name: "no times", r: Range{StepS: 30}, limits: limits, code: protocol.CodeQueryGuardFailed, contains: "start and an end"},
		{name: "negative step", r: Range{Start: start, End: start.Add(time.Hour), StepS: -1}, limits: limits, code: protocol.CodeQueryGuardFailed, contains: "negative"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rejection := CheckRange(tt.r, tt.limits)
			if tt.code == "" {
				if rejection != nil {
					t.Fatalf("CheckRange() = %v", rejection)
				}
				return
			}
			if rejection == nil {
				t.Fatal("CheckRange() passed")
			}
			if rejection.Code != tt.code || !strings.Contains(rejection.Message, tt.contains) {
				t.Errorf("rejection = %+v", rejection)
			}
			if tt.hint != nil && (rejection.Hint == nil || *rejection.Hint != *tt.hint) {
				t.Errorf("Hint = %+v, want %+v", rejection.Hint, tt.hint)
			}
		})
	}
}

func TestCheckLookback(t *testing.T) {
	limits := protocol.Limits{MaxRangeS: 3600}
	if rejection := CheckLookback(time.Hour, limits); rejection != nil {
		t.Fatalf("CheckLookback at the limit = %v", rejection)
	}
	rejection := CheckLookback(2*time.Hour, limits)
	if rejection == nil || rejection.Code != protocol.CodePolicyRangeExceeded || rejection.Hint.MaxRangeS != 3600 {
		t.Fatalf("rejection = %+v", rejection)
	}
}

func TestSaturatingLookbackCannotWrapUnderALimit(t *testing.T) {
	query, rejection := CheckLogQL(`rate({a="b"}[100000000y] offset 100000000y)`)
	if rejection != nil {
		t.Fatalf("CheckLogQL() = %v", rejection)
	}
	if query.Lookback != maxDuration {
		t.Fatalf("Lookback = %s", query.Lookback)
	}
	if rejection := CheckLookback(query.Lookback, protocol.Limits{MaxRangeS: 3600}); rejection == nil {
		t.Fatal("a huge lookback passed")
	}
}

func TestCheckIdentifiersThatBecomeURLPaths(t *testing.T) {
	for _, name := range []string{"job", "__name__", "service.name"} {
		if rejection := CheckLabelName(name); rejection != nil {
			t.Errorf("CheckLabelName(%q) = %v", name, rejection)
		}
	}
	for _, name := range []string{"", "../../api/admin", "a/b", "a b", "9a", strings.Repeat("a", 257)} {
		if rejection := CheckLabelName(name); rejection == nil {
			t.Errorf("CheckLabelName(%q) passed", name)
		}
	}
	for _, uid := range []string{"abc-DEF_1"} {
		if rejection := CheckDashboardUID(uid); rejection != nil {
			t.Errorf("CheckDashboardUID(%q) = %v", uid, rejection)
		}
	}
	for _, uid := range []string{"", "../admin", "a/b", "a?b=c", strings.Repeat("a", 129)} {
		if rejection := CheckDashboardUID(uid); rejection == nil {
			t.Errorf("CheckDashboardUID(%q) passed", uid)
		}
	}
}

func TestCheckTextArguments(t *testing.T) {
	if rejection := CheckNamePattern("http_.*"); rejection != nil {
		t.Errorf("CheckNamePattern() = %v", rejection)
	}
	if rejection := CheckNamePattern("("); rejection == nil {
		t.Error("a bad regex passed")
	}
	if rejection := CheckNamePattern(strings.Repeat("a", MaxQueryBytes+1)); rejection == nil {
		t.Error("a long regex passed")
	}
	if rejection := CheckSearchText("query", "checkout"); rejection != nil {
		t.Errorf("CheckSearchText() = %v", rejection)
	}
	if rejection := CheckSearchText("query", strings.Repeat("a", 257)); rejection == nil {
		t.Error("a long search passed")
	}
}

func FuzzCheckPromQL(f *testing.F) {
	for _, seed := range []string{
		`up`, `{__name__=~".+"}`, `sum by (le) (rate(a_bucket{b="c"}[5m]))`, `max_over_time(rate(a[1m])[5m:1m])`,
		`up offset -1h`, `a + on(b) group_left c`, `(((`, `{a="`, "`", `$__rate_interval`, `1e400`,
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, expr string) {
		query, rejection := CheckPromQL(expr)
		if rejection != nil {
			if rejection.Code == "" || rejection.Message == "" {
				t.Fatalf("empty rejection for %q: %+v", expr, rejection)
			}
			return
		}
		if query.Lookback < 0 {
			t.Fatalf("Lookback = %s for %q", query.Lookback, expr)
		}
		// What passed must still pass after printing, because the printed form
		// is what the fingerprint covers.
		if _, again := CheckPromQL(query.Normalized); again != nil && len(query.Normalized) <= MaxQueryBytes {
			t.Fatalf("CheckPromQL(%q) passed, but its printed form %q was refused: %v", expr, query.Normalized, again)
		}
	})
}

func FuzzCheckLogQL(f *testing.F) {
	for _, seed := range []string{
		`{a="b"}`, `{a=~".+"}`, `{a="b"} |= "c" | json | d="e"`, `sum by (a) (rate({a="b"}[5m] offset 1h))`,
		`topk(5, count_over_time({a="b"}[1h]))`, `{a="b"} | line_format "{{.c}}"`, "{a=`b`}", `(((`, `{`, `"`, `--`, `|`,
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, expr string) {
		query, rejection := CheckLogQL(expr)
		if rejection != nil {
			if rejection.Code == "" || rejection.Message == "" {
				t.Fatalf("empty rejection for %q: %+v", expr, rejection)
			}
			return
		}
		if !strings.Contains(expr, "{") {
			t.Fatalf("CheckLogQL(%q) passed with no selector", expr)
		}
		if query.Lookback < 0 {
			t.Fatalf("Lookback = %s for %q", query.Lookback, expr)
		}
		if query.Metric && query.Lookback == 0 {
			t.Fatalf("metric query %q passed with no range", expr)
		}
		_ = CheckLokiSelector(expr)
	})
}
