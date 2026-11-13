package guard

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// The Loki parser is AGPL and stays out of the binary, so this is a small
// tokenizer and recursive descent parser for the part of LogQL the proxy allows.
// Anything else is refused, including valid LogQL it does not know.

const maxLogQLDepth = 16

var (
	logRangeFunctions = []string{
		"rate", "rate_counter", "count_over_time", "bytes_over_time", "bytes_rate", "avg_over_time", "sum_over_time",
		"min_over_time", "max_over_time", "first_over_time", "last_over_time", "stdvar_over_time", "stddev_over_time",
		"quantile_over_time", "absent_over_time",
	}
	logAggregations = []string{"sum", "avg", "min", "max", "count", "stddev", "stdvar", "topk", "bottomk", "sort", "sort_desc", "approx_topk"}
	// logLabelReducers keep only the labels a query names. The other aggregations
	// pick series and keep all their labels, even with by (...).
	logLabelReducers = []string{"sum", "avg", "min", "max", "count", "stddev", "stdvar"}
)

// logAllowedStages names the stages parseStage reads. line_format and label_format
// run templates and can rewrite what a result holds, so they stay out.
const logAllowedStages = "json, logfmt, unpack, pattern, regexp, decolorize, drop, keep, unwrap and label filters"

// LogQuery is what a checked LogQL expression reads.
type LogQuery struct {
	// Metric reports a metric query, which returns numbers, not log lines.
	Metric bool
	// Lookback is how far back the expression reads beyond each evaluation step.
	Lookback time.Duration
	// captureStage names a regexp or pattern stage. Either one can cut any part of a
	// line into a label, so a limit on the length of a value does not hold it back.
	captureStage string
	// ungroupedParser names a json, logfmt or unpack stage that takes every field of
	// a line and has no aggregation above it to keep only named labels.
	ungroupedParser string
}

// RefuseLogText returns a rejection for a metric query that can return log text as
// series labels. It applies while log lines are off. A query that reads a field
// under an aggregation, such as sum by (status) (count_over_time({job="api"} | json
// [5m])), passes: it names what it returns, and the executor cuts each value.
func (q LogQuery) RefuseLogText() *Rejection {
	switch {
	case !q.Metric:
		return nil
	case q.captureStage != "":
		return refused("log lines are off, so a metric query cannot use %s, which can return log text as labels. Use line filters, or json or logfmt under an aggregation such as sum by (status)", q.captureStage)
	case q.ungroupedParser != "":
		return refused("log lines are off, so a metric query that uses %s must name its labels, because every field of a line would become a label. Group it, such as sum by (status) (...), or name the fields, such as json status=\"status\"", q.ungroupedParser)
	}
	return nil
}

// CheckLogQL checks expr. Every stream selector needs an exact matcher, and every
// pipeline stage must be allowed. An expression that does not read is refused.
func CheckLogQL(expr string) (LogQuery, *Rejection) {
	if rejection := checkLength("LogQL", expr); rejection != nil {
		return LogQuery{}, rejection
	}
	tokens, rejection := tokenizeLogQL(expr)
	if rejection != nil {
		return LogQuery{}, rejection
	}
	p := &logParser{tokens: tokens}
	query, rejection := p.parseQuery()
	if rejection != nil {
		return LogQuery{}, rejection
	}
	return query, nil
}

// CheckLokiSelector checks an expression that must be a stream selector alone, the
// only shape the Loki patterns endpoint takes.
func CheckLokiSelector(expr string) *Rejection {
	if rejection := checkLength("LogQL", expr); rejection != nil {
		return rejection
	}
	tokens, rejection := tokenizeLogQL(expr)
	if rejection != nil {
		return rejection
	}
	p := &logParser{tokens: tokens}
	if rejection := p.parseSelector(); rejection != nil {
		return rejection
	}
	if p.peek().kind != logEOF {
		return refused("this capability takes a stream selector such as {job=\"api\"} with no pipeline")
	}
	return nil
}

type logTokenKind int

const (
	logEOF logTokenKind = iota
	logIdent
	logNumber
	logString
	logPunct
)

type logToken struct {
	kind logTokenKind
	text string
}

// logOperators lists the longest first, so |= is not read as | and =.
var logOperators = []string{"|=", "|~", "|>", "!=", "!~", "!>", "=~", "==", ">=", "<=", "--", "|", "=", ">", "<", "+", "-", "*", "/", "%", "^", "{", "}", "(", ")", "[", "]", ","}

func tokenizeLogQL(expr string) ([]logToken, *Rejection) {
	if !utf8.ValidString(expr) {
		return nil, refused("the LogQL query is not valid text")
	}
	var tokens []logToken
	for i := 0; i < len(expr); {
		c := expr[i]
		switch {
		case unicode.IsSpace(rune(c)):
			i++
		case c == '#':
			return nil, refused("comments are not allowed in a LogQL query")
		case c == '"' || c == '`':
			end, value, rejection := scanLogString(expr, i)
			if rejection != nil {
				return nil, rejection
			}
			tokens = append(tokens, logToken{logString, value})
			i = end
		case isLogIdentStart(c):
			end := i + 1
			for end < len(expr) && isLogIdentPart(expr[end]) {
				end++
			}
			tokens = append(tokens, logToken{logIdent, expr[i:end]})
			i = end
		case c >= '0' && c <= '9':
			end := i + 1
			for end < len(expr) && (isLogIdentPart(expr[end]) || expr[end] == '.') {
				end++
			}
			tokens = append(tokens, logToken{logNumber, expr[i:end]})
			i = end
		default:
			operator := ""
			for _, candidate := range logOperators {
				if strings.HasPrefix(expr[i:], candidate) {
					operator = candidate
					break
				}
			}
			if operator == "" {
				return nil, refused("the LogQL query has an unexpected character %q", string(rune(c)))
			}
			tokens = append(tokens, logToken{logPunct, operator})
			i += len(operator)
		}
	}
	return tokens, nil
}

func scanLogString(expr string, start int) (int, string, *Rejection) {
	quote := expr[start]
	var b strings.Builder
	for i := start + 1; i < len(expr); i++ {
		c := expr[i]
		switch {
		case c == quote:
			return i + 1, b.String(), nil
		case c == '\\' && quote == '"':
			i++
			if i >= len(expr) {
				return 0, "", refused("a LogQL string is not closed")
			}
			b.WriteByte(expr[i])
		default:
			b.WriteByte(c)
		}
	}
	return 0, "", refused("a LogQL string is not closed")
}

func isLogIdentStart(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isLogIdentPart(c byte) bool {
	return isLogIdentStart(c) || (c >= '0' && c <= '9')
}

type logParser struct {
	tokens   []logToken
	position int
	depth    int
	lookback time.Duration
	// captureStage and ungroupedParser fill the fields of LogQuery. pipelineParser is
	// the parser of the pipeline being read, which counts once its range function
	// has ended.
	captureStage    string
	ungroupedParser string
	pipelineParser  string
}

func (p *logParser) peek() logToken {
	return p.peekAt(0)
}

func (p *logParser) peekAt(offset int) logToken {
	if p.position+offset >= len(p.tokens) {
		return logToken{kind: logEOF}
	}
	return p.tokens[p.position+offset]
}

func (p *logParser) next() logToken {
	token := p.peek()
	p.position++
	return token
}

func (p *logParser) isPunct(text string) bool {
	token := p.peek()
	return token.kind == logPunct && token.text == text
}

func (p *logParser) accept(text string) bool {
	if p.isPunct(text) {
		p.position++
		return true
	}
	return false
}

func (p *logParser) expect(text string) *Rejection {
	if p.accept(text) {
		return nil
	}
	return p.unexpected("expected " + text)
}

func (p *logParser) unexpected(context string) *Rejection {
	token := p.peek()
	if token.kind == logEOF {
		return refused("the LogQL query ends early: %s", context)
	}
	return refused("the LogQL query has an unexpected %q: %s", truncateForMessage(token.text), context)
}

// parseQuery reads a whole query: a stream selector with a pipeline, or a metric
// expression.
func (p *logParser) parseQuery() (LogQuery, *Rejection) {
	if p.isPunct("{") {
		if rejection := p.parseSelector(); rejection != nil {
			return LogQuery{}, rejection
		}
		if rejection := p.parsePipeline(); rejection != nil {
			return LogQuery{}, rejection
		}
		if p.peek().kind != logEOF {
			return LogQuery{}, p.unexpected("a log query ends after its pipeline. A range such as [5m] needs a function such as count_over_time")
		}
		return LogQuery{}, nil
	}
	if rejection := p.parseMetricExpr(); rejection != nil {
		return LogQuery{}, rejection
	}
	if p.peek().kind != logEOF {
		return LogQuery{}, p.unexpected("expected the end of the query")
	}
	if p.lookback == 0 {
		return LogQuery{}, refused("the query reads no logs. Use a stream selector such as {job=\"api\"}")
	}
	return LogQuery{Metric: true, Lookback: p.lookback, captureStage: p.captureStage, ungroupedParser: p.ungroupedParser}, nil
}

// parseSelector reads {a="b", c=~"d"} and requires an exact matcher with a value.
func (p *logParser) parseSelector() *Rejection {
	if rejection := p.expect("{"); rejection != nil {
		return rejection
	}
	exact := false
	for !p.isPunct("}") {
		name := p.next()
		if name.kind != logIdent {
			p.position--
			return p.unexpected("expected a label name in the stream selector")
		}
		operator := p.next()
		if operator.kind != logPunct || !slices.Contains([]string{"=", "!=", "=~", "!~"}, operator.text) {
			p.position--
			return p.unexpected("expected =, !=, =~ or !~ in the stream selector")
		}
		value := p.next()
		if value.kind != logString {
			p.position--
			return p.unexpected("expected a quoted value in the stream selector")
		}
		if operator.text == "=" && value.text != "" {
			exact = true
		}
		if !p.accept(",") {
			break
		}
	}
	if rejection := p.expect("}"); rejection != nil {
		return rejection
	}
	if !exact {
		return refused("the stream selector needs an exact matcher such as {job=\"api\"}. A regex alone can scan every stream")
	}
	return nil
}

// parsePipeline reads line filters and allowed stages up to something that is not
// a pipeline.
func (p *logParser) parsePipeline() *Rejection {
	for {
		token := p.peek()
		if token.kind != logPunct {
			return nil
		}
		switch token.text {
		case "|=", "!=", "|~", "!~", "|>", "!>":
			p.position++
			if rejection := p.parseLineFilterValue(); rejection != nil {
				return rejection
			}
			for p.peek().kind == logIdent && p.peek().text == "or" {
				p.position++
				if rejection := p.parseLineFilterValue(); rejection != nil {
					return rejection
				}
			}
		case "|":
			p.position++
			if rejection := p.parseStage(); rejection != nil {
				return rejection
			}
		default:
			return nil
		}
	}
}

func (p *logParser) parseLineFilterValue() *Rejection {
	if p.peek().kind == logString {
		p.position++
		return nil
	}
	return p.parseIPCall("expected a quoted line filter")
}

func (p *logParser) parseIPCall(context string) *Rejection {
	if p.peek().kind != logIdent || p.peek().text != "ip" {
		return p.unexpected(context)
	}
	p.position++
	if rejection := p.expect("("); rejection != nil {
		return rejection
	}
	if p.next().kind != logString {
		p.position--
		return p.unexpected("ip() takes a quoted value")
	}
	return p.expect(")")
}

func (p *logParser) parseStage() *Rejection {
	if p.isPunct("(") {
		return p.parseLabelFilters()
	}
	stage := p.peek()
	if stage.kind != logIdent {
		return p.unexpected("expected a pipeline stage")
	}
	following := p.peekAt(1)
	isComparison := following.kind == logPunct && slices.Contains([]string{"=", "==", "!=", "=~", "!~", ">", ">=", "<", "<="}, following.text)
	if isComparison {
		return p.parseLabelFilters()
	}
	p.position++
	switch stage.text {
	case "json", "logfmt":
		named, rejection := p.parseParserParams()
		if rejection != nil {
			return rejection
		}
		if !named {
			p.pipelineParser = stage.text
		}
		return nil
	case "unpack":
		p.pipelineParser = stage.text
		return nil
	case "decolorize":
		return nil
	case "pattern", "regexp":
		if p.next().kind != logString {
			p.position--
			return p.unexpected(stage.text + " takes a quoted expression")
		}
		p.captureStage = stage.text
		return nil
	case "drop", "keep":
		return p.parseLabelList(stage.text)
	case "unwrap":
		return p.parseUnwrap()
	}
	return refused("the pipeline stage %q is not allowed. Use only line filters, %s", truncateForMessage(stage.text), logAllowedStages)
}

// parseParserParams reads json's and logfmt's flags and extraction list. named
// reports a list, which means the stage takes only the fields it names.
func (p *logParser) parseParserParams() (named bool, rejection *Rejection) {
	for p.isPunct("--") {
		p.position++
		flag := p.next()
		parts := []string{flag.text}
		for p.accept("-") {
			parts = append(parts, p.next().text)
		}
		if name := strings.Join(parts, "-"); name != "strict" && name != "keep-empty" {
			return false, refused("the parser flag --%s is not allowed", truncateForMessage(name))
		}
	}
	if p.peek().kind != logIdent {
		return false, nil
	}
	for {
		if p.next().kind != logIdent {
			p.position--
			return false, p.unexpected("expected a label name")
		}
		if p.accept("=") {
			if p.next().kind != logString {
				p.position--
				return false, p.unexpected("expected a quoted expression")
			}
		}
		if !p.accept(",") {
			return true, nil
		}
	}
}

func (p *logParser) parseLabelList(stage string) *Rejection {
	for {
		if p.next().kind != logIdent {
			p.position--
			return p.unexpected(stage + " takes a list of labels")
		}
		if p.peek().kind == logPunct && slices.Contains([]string{"=", "!=", "=~", "!~"}, p.peek().text) {
			p.position++
			if p.next().kind != logString {
				p.position--
				return p.unexpected("expected a quoted value")
			}
		}
		if !p.accept(",") {
			return nil
		}
	}
}

func (p *logParser) parseUnwrap() *Rejection {
	name := p.next()
	if name.kind != logIdent {
		p.position--
		return p.unexpected("unwrap takes a label name")
	}
	if !p.accept("(") {
		return nil
	}
	if !slices.Contains([]string{"bytes", "duration", "duration_seconds"}, name.text) {
		return refused("unwrap does not allow the function %q", truncateForMessage(name.text))
	}
	if p.next().kind != logIdent {
		p.position--
		return p.unexpected("unwrap takes a label name")
	}
	return p.expect(")")
}

// parseLabelFilters reads `a="b" and c>1 or (d!="e")`.
func (p *logParser) parseLabelFilters() *Rejection {
	p.depth++
	defer func() { p.depth-- }()
	if p.depth > maxLogQLDepth {
		return refused("the LogQL query nests too deeply")
	}
	for {
		if p.accept("(") {
			if rejection := p.parseLabelFilters(); rejection != nil {
				return rejection
			}
			if rejection := p.expect(")"); rejection != nil {
				return rejection
			}
		} else if rejection := p.parseLabelFilter(); rejection != nil {
			return rejection
		}
		token := p.peek()
		switch {
		case token.kind == logIdent && (token.text == "and" || token.text == "or"):
			p.position++
		case p.isPunct(","):
			p.position++
		case token.kind == logIdent && p.peekAt(1).kind == logPunct && slices.Contains([]string{"=", "==", "!=", "=~", "!~", ">", ">=", "<", "<="}, p.peekAt(1).text):
			// Two filters with no word between them mean "and".
		default:
			return nil
		}
	}
}

func (p *logParser) parseLabelFilter() *Rejection {
	if p.next().kind != logIdent {
		p.position--
		return p.unexpected("expected a label name")
	}
	operator := p.next()
	if operator.kind != logPunct || !slices.Contains([]string{"=", "==", "!=", "=~", "!~", ">", ">=", "<", "<="}, operator.text) {
		p.position--
		return p.unexpected("expected a comparison")
	}
	value := p.peek()
	switch value.kind {
	case logString, logNumber:
		p.position++
		return nil
	}
	return p.parseIPCall("expected a value to compare with")
}

// parseMetricExpr reads terms joined by binary operators.
func (p *logParser) parseMetricExpr() *Rejection {
	p.depth++
	defer func() { p.depth-- }()
	if p.depth > maxLogQLDepth {
		return refused("the LogQL query nests too deeply")
	}
	for {
		if rejection := p.parseMetricTerm(); rejection != nil {
			return rejection
		}
		if !p.acceptBinaryOperator() {
			return nil
		}
		if rejection := p.parseVectorMatching(); rejection != nil {
			return rejection
		}
	}
}

func (p *logParser) acceptBinaryOperator() bool {
	token := p.peek()
	switch {
	case token.kind == logPunct && slices.Contains([]string{"+", "-", "*", "/", "%", "^", "==", "!=", ">", ">=", "<", "<="}, token.text):
	case token.kind == logIdent && slices.Contains([]string{"and", "or", "unless"}, token.text):
	default:
		return false
	}
	p.position++
	return true
}

func (p *logParser) parseVectorMatching() *Rejection {
	if p.peek().kind == logIdent && p.peek().text == "bool" {
		p.position++
	}
	if p.peek().kind == logIdent && slices.Contains([]string{"on", "ignoring"}, p.peek().text) {
		p.position++
		if rejection := p.parseLabelGroup(); rejection != nil {
			return rejection
		}
		if p.peek().kind == logIdent && slices.Contains([]string{"group_left", "group_right"}, p.peek().text) {
			p.position++
			if p.isPunct("(") {
				return p.parseLabelGroup()
			}
		}
	}
	return nil
}

func (p *logParser) parseMetricTerm() *Rejection {
	token := p.peek()
	switch {
	case token.kind == logNumber:
		if _, err := strconv.ParseFloat(token.text, 64); err != nil {
			return p.unexpected("expected a number")
		}
		p.position++
		return nil
	case p.accept("("):
		if rejection := p.parseMetricExpr(); rejection != nil {
			return rejection
		}
		return p.expect(")")
	case token.kind == logIdent && slices.Contains(logRangeFunctions, token.text):
		p.position++
		return p.parseRangeFunction()
	case token.kind == logIdent && slices.Contains(logAggregations, token.text):
		p.position++
		return p.parseAggregation(token.text)
	case token.kind == logIdent:
		return refused("the function %q is not allowed in a LogQL query", truncateForMessage(token.text))
	}
	return p.unexpected("expected a function such as count_over_time")
}

// parseRangeFunction reads the part of rate({a="b"} |= "c" [5m] offset 1h) after
// the name.
func (p *logParser) parseRangeFunction() *Rejection {
	if rejection := p.expect("("); rejection != nil {
		return rejection
	}
	if p.peek().kind == logNumber {
		p.position++
		if rejection := p.expect(","); rejection != nil {
			return rejection
		}
	}
	if rejection := p.parseSelector(); rejection != nil {
		return rejection
	}
	p.pipelineParser = ""
	if rejection := p.parsePipeline(); rejection != nil {
		return rejection
	}
	parser := p.pipelineParser
	if rejection := p.expect("["); rejection != nil {
		return rejection
	}
	window, rejection := p.parseDuration()
	if rejection != nil {
		return rejection
	}
	if rejection := p.expect("]"); rejection != nil {
		return rejection
	}
	if p.peek().kind == logIdent && p.peek().text == "offset" {
		p.position++
		offset, rejection := p.parseDuration()
		if rejection != nil {
			return rejection
		}
		window = saturatingAdd(window, offset)
	}
	p.lookback = max(p.lookback, window)
	if rejection := p.expect(")"); rejection != nil {
		return rejection
	}
	grouping, rejection := p.parseOptionalGrouping()
	if rejection != nil {
		return rejection
	}
	if parser != "" && grouping != "by" {
		p.ungroupedParser = parser
	}
	return nil
}

// parseAggregation reads the part of sum by (a) (expr) or topk(5, expr) by (a)
// after the name. An aggregation that keeps only named labels settles the parsers
// below it.
func (p *logParser) parseAggregation(name string) *Rejection {
	outerParser := p.ungroupedParser
	p.ungroupedParser = ""
	grouping, rejection := p.parseOptionalGrouping()
	if rejection != nil {
		return rejection
	}
	if rejection := p.expect("("); rejection != nil {
		return rejection
	}
	if p.peek().kind == logNumber && p.peekAt(1).kind == logPunct && p.peekAt(1).text == "," {
		p.position += 2
	}
	if rejection := p.parseMetricExpr(); rejection != nil {
		return rejection
	}
	if rejection := p.expect(")"); rejection != nil {
		return rejection
	}
	trailing, rejection := p.parseOptionalGrouping()
	if rejection != nil {
		return rejection
	}
	if trailing != "" {
		grouping = trailing
	}
	if slices.Contains(logLabelReducers, name) && grouping != "without" {
		p.ungroupedParser = ""
	}
	if p.ungroupedParser == "" {
		p.ungroupedParser = outerParser
	}
	return nil
}

// parseOptionalGrouping reads by (...) or without (...) and returns which one it
// read, or "" for none.
func (p *logParser) parseOptionalGrouping() (string, *Rejection) {
	token := p.peek()
	if token.kind == logIdent && slices.Contains([]string{"by", "without"}, token.text) {
		p.position++
		return token.text, p.parseLabelGroup()
	}
	return "", nil
}

func (p *logParser) parseLabelGroup() *Rejection {
	if rejection := p.expect("("); rejection != nil {
		return rejection
	}
	for !p.isPunct(")") {
		if p.next().kind != logIdent {
			p.position--
			return p.unexpected("expected a label name")
		}
		if !p.accept(",") {
			break
		}
	}
	return p.expect(")")
}

func (p *logParser) parseDuration() (time.Duration, *Rejection) {
	token := p.next()
	if token.kind != logNumber {
		p.position--
		return 0, p.unexpected("expected a duration such as 5m")
	}
	duration, err := parseLogDuration(token.text)
	if err != nil {
		return 0, refused("%q is not a duration such as 5m", truncateForMessage(token.text))
	}
	return duration, nil
}

// parseLogDuration reads Go durations plus Prometheus's d, w and y.
func parseLogDuration(text string) (time.Duration, error) {
	total := time.Duration(0)
	rest := text
	for rest != "" {
		digits := 0
		for digits < len(rest) && rest[digits] >= '0' && rest[digits] <= '9' {
			digits++
		}
		if digits == 0 {
			return 0, fmt.Errorf("no number in %q", text)
		}
		value, err := strconv.ParseInt(rest[:digits], 10, 64)
		if err != nil {
			return 0, err
		}
		rest = rest[digits:]
		units := 0
		for units < len(rest) && (rest[units] < '0' || rest[units] > '9') {
			units++
		}
		unit, ok := logDurationUnits[rest[:units]]
		if !ok {
			return 0, fmt.Errorf("unknown unit in %q", text)
		}
		rest = rest[units:]
		if value > int64(maxDuration/unit) {
			return maxDuration, nil
		}
		total = saturatingAdd(total, time.Duration(value)*unit)
	}
	return total, nil
}

var logDurationUnits = map[string]time.Duration{
	"ms": time.Millisecond, "s": time.Second, "m": time.Minute, "h": time.Hour,
	"d": 24 * time.Hour, "w": 7 * 24 * time.Hour, "y": 365 * 24 * time.Hour,
}
