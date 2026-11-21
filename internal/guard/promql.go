package guard

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/promql/parser"
)

const (
	maxSubqueryDepth = 1
	metricNameLabel  = "__name__"
)

// promParser has experimental functions and duration expressions off: an
// expression outside plain PromQL does not parse, and so it is refused.
var promParser = parser.NewParser(parser.Options{})

// catchAllProbes are metric names that any selective pattern would leave out. A
// name pattern that matches all of them selects every metric.
var catchAllProbes = []string{"a", "zz9_total", "node_cpu_seconds_total", "http_requests_total", "up"}

// PromQuery is what a checked PromQL expression reads.
type PromQuery struct {
	// Normalized is the parsed expression printed back, for the fingerprint.
	Normalized string
	// Lookback is how far back the expression reads beyond each evaluation step.
	Lookback time.Duration
}

// CheckPromQL parses expr and checks it by its syntax tree. An expression that
// does not parse is refused.
func CheckPromQL(expr string) (PromQuery, *Rejection) {
	if rejection := checkLength("PromQL", expr); rejection != nil {
		return PromQuery{}, rejection
	}
	tree, rejection := parsePromQL(expr)
	if rejection != nil {
		return PromQuery{}, rejection
	}

	query := PromQuery{Normalized: tree.String()}
	selectors := 0
	parser.Inspect(tree, func(node parser.Node, path []parser.Node) error {
		if rejection != nil {
			return nil
		}
		switch n := node.(type) {
		case *parser.SubqueryExpr:
			if depth := subqueryDepth(path) + 1; depth > maxSubqueryDepth {
				rejection = refused("the query nests %d subqueries, and %d is allowed", depth, maxSubqueryDepth)
				return nil
			}
			if n.Timestamp != nil || n.StartOrEnd != 0 {
				rejection = refused("the @ modifier is not allowed. Use the time range of the query instead")
			}
		case *parser.VectorSelector:
			selectors++
			if n.Timestamp != nil || n.StartOrEnd != 0 {
				rejection = refused("the @ modifier is not allowed. Use the time range of the query instead")
				return nil
			}
			if rejection = checkVectorSelector(n.Name, n.LabelMatchers); rejection != nil {
				return nil
			}
			query.Lookback = max(query.Lookback, selectorLookback(n, path))
		}
		return nil
	})
	if rejection != nil {
		return PromQuery{}, rejection
	}
	if selectors == 0 {
		return PromQuery{}, refused("the query reads no metric. Name a metric or use an exact label matcher")
	}
	return query, nil
}

// CheckPromSelector checks a selector such as {job="api"}, as the match argument
// of a list capability.
func CheckPromSelector(selector string) *Rejection {
	if rejection := checkLength("selector", selector); rejection != nil {
		return rejection
	}
	tree, rejection := parsePromQL(selector)
	if rejection != nil {
		return rejection
	}
	vector, ok := tree.(*parser.VectorSelector)
	if !ok {
		return refused("match must be a selector such as {job=\"api\"}")
	}
	if vector.Timestamp != nil || vector.StartOrEnd != 0 || vector.OriginalOffset != 0 {
		return refused("match must be a selector such as {job=\"api\"}")
	}
	return checkVectorSelector(vector.Name, vector.LabelMatchers)
}

// parsePromQL fails closed: a parser panic is a refusal.
func parsePromQL(expr string) (tree parser.Expr, rejection *Rejection) {
	defer func() {
		if recovered := recover(); recovered != nil {
			tree, rejection = nil, refused("the query could not be read")
		}
	}()
	parsed, err := promParser.ParseExpr(expr)
	if err != nil {
		message := "the query does not parse as PromQL: " + err.Error()
		if strings.Contains(expr, "$") {
			message += ". Replace dashboard variables such as $__rate_interval with values"
		}
		return nil, refused("%s", message)
	}
	return parsed, nil
}

func checkVectorSelector(name string, matchers []*labels.Matcher) *Rejection {
	named := name != ""
	exact := false
	for _, matcher := range matchers {
		isName := matcher.Name == metricNameLabel
		switch matcher.Type {
		case labels.MatchEqual:
			if matcher.Value == "" {
				continue
			}
			if isName {
				named = true
			} else {
				exact = true
			}
		case labels.MatchRegexp:
			if isName && matchesEveryProbe(matcher) {
				return refused("the metric name pattern %q matches every metric. Name a metric", matcher.Value)
			}
		}
	}
	if !named && !exact {
		return refused("the selector %s has no metric name and no exact matcher. Name a metric or use an exact label matcher", describeMatchers(matchers))
	}
	return nil
}

func matchesEveryProbe(matcher *labels.Matcher) bool {
	return slices.IndexFunc(catchAllProbes, func(probe string) bool { return !matcher.Matches(probe) }) < 0
}

func describeMatchers(matchers []*labels.Matcher) string {
	parts := make([]string, 0, len(matchers))
	for _, matcher := range matchers {
		parts = append(parts, matcher.String())
	}
	return "{" + strings.Join(parts, ", ") + "}"
}

func subqueryDepth(path []parser.Node) int {
	depth := 0
	for _, node := range path {
		if _, ok := node.(*parser.SubqueryExpr); ok {
			depth++
		}
	}
	return depth
}

// selectorLookback adds the selector's offset to the range vectors, subqueries and
// their offsets above it, so an offset of a year counts as a year of range.
func selectorLookback(selector *parser.VectorSelector, path []parser.Node) time.Duration {
	lookback := absDuration(selector.OriginalOffset)
	for _, node := range path {
		switch n := node.(type) {
		case *parser.MatrixSelector:
			lookback = saturatingAdd(lookback, n.Range)
		case *parser.SubqueryExpr:
			lookback = saturatingAdd(lookback, n.Range)
			lookback = saturatingAdd(lookback, absDuration(n.OriginalOffset))
		}
	}
	return lookback
}

// labelNamePattern is the shape of a Prometheus or Loki label name. A label name
// becomes part of an upstream URL path, so nothing else gets through.
var labelNamePattern = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_.]*$`)

// CheckLabelName refuses anything that is not a label name.
func CheckLabelName(name string) *Rejection {
	if len(name) > 256 || !labelNamePattern.MatchString(name) {
		return refused("%q is not a label name", truncateForMessage(name))
	}
	return nil
}

// dashboardUIDPattern is the shape of a Grafana UID, which also becomes part of an
// upstream URL path.
var dashboardUIDPattern = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,128}$`)

// CheckDashboardUID refuses anything that is not a Grafana UID.
func CheckDashboardUID(uid string) *Rejection {
	if !dashboardUIDPattern.MatchString(uid) {
		return refused("%q is not a dashboard uid", truncateForMessage(uid))
	}
	return nil
}

// CheckAlertRuleUID refuses anything that is not the UID of an alert rule, which also becomes
// part of an upstream URL path.
func CheckAlertRuleUID(uid string) *Rejection {
	if !dashboardUIDPattern.MatchString(uid) {
		return refused("%q is not an alert rule uid", truncateForMessage(uid))
	}
	return nil
}

// CheckNamePattern checks the regex a metric name list is filtered by.
func CheckNamePattern(pattern string) *Rejection {
	if len(pattern) > MaxQueryBytes {
		return refused("match has %d bytes, more than the %d allowed", len(pattern), MaxQueryBytes)
	}
	if _, err := regexp.Compile(pattern); err != nil {
		return refused("match is not a regular expression: %s", err.Error())
	}
	return nil
}

// CheckSearchText bounds free text that a list capability passes on.
func CheckSearchText(field, text string) *Rejection {
	const maxSearchChars = 256
	if len(text) > maxSearchChars {
		return refused("%s has %d bytes, more than the %d allowed", field, len(text), maxSearchChars)
	}
	return nil
}

func truncateForMessage(s string) string {
	const limit = 64
	if len(s) <= limit {
		return s
	}
	return fmt.Sprintf("%s…", strings.ToValidUTF8(s[:limit], ""))
}
