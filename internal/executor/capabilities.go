package executor

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	mcpgrafana "github.com/grafana/mcp-grafana/v2"
	"github.com/grafana/mcp-grafana/v2/tools"

	"github.com/tellagen/tellagen-proxy/internal/guard"
	"github.com/tellagen/tellagen-proxy/internal/policy"
	"github.com/tellagen/tellagen-proxy/internal/reduce"
	"github.com/tellagen/tellagen-proxy/protocol"
)

// capabilityVersions holds the version of each capability, from the protocol's
// catalog.
var capabilityVersions = func() map[string]int {
	versions := map[string]int{}
	for _, capability := range protocol.Capabilities() {
		versions[capability.Name] = capability.Version
	}
	return versions
}()

// capabilityTools maps each capability to the one tool it runs, so a test can hold
// the two lists together.
var capabilityTools = map[string]*mcpgrafana.Tool{
	protocol.CapabilityPrometheusQueryRange:      &tools.QueryPrometheus,
	protocol.CapabilityPrometheusQueryInstant:    &tools.QueryPrometheus,
	protocol.CapabilityPrometheusListMetricNames: &tools.ListPrometheusMetricNames,
	protocol.CapabilityPrometheusListLabelValues: &tools.ListPrometheusLabelValues,
	protocol.CapabilityLokiQueryRange:            &tools.QueryLokiLogs,
	protocol.CapabilityLokiQueryPatterns:         &tools.QueryLokiPatterns,
	protocol.CapabilityLokiListLabelValues:       &tools.ListLokiLabelValues,
	protocol.CapabilityGrafanaListDatasources:    &tools.ListDatasources,
	protocol.CapabilityGrafanaSearchDashboards:   &tools.SearchDashboards,
	protocol.CapabilityGrafanaGetPanelQueries:    &tools.GetDashboardPanelQueries,
	protocol.CapabilityGrafanaListAlertRules:     &tools.AlertRulesRead,
	protocol.CapabilityGrafanaAlertRuleVersions:  &tools.AlertRulesRead,
}

// toolCaller calls one tool and returns the JSON text of its answer.
type toolCaller func(tool *mcpgrafana.Tool, args any) (string, *callFailure)

// plan is one checked command, ready to run.
type plan struct {
	tool       string
	datasource string
	query      string
	explore    *exploreLink
	// logQuery is set for a Loki query, whose series labels can hold log text.
	logQuery *guard.LogQuery
	// started and deadline are set when the command starts to run. A plan that reads more than
	// one thing uses them to keep part of the time for its main answer.
	started, deadline time.Time
	// baseDone is set by a plan whose main answer is read, so a deadline that passes while it
	// reads extra details does not turn that answer into a timeout.
	baseDone bool
	run      func(call toolCaller) (data *protocol.ResultData, skipped []string, truncated bool, failure *callFailure)
}

type exploreLink struct {
	datasource string
	expr       string
	from, to   time.Time
}

// fingerprint identifies the query for both audit lists. It holds no time range, so
// the same query over two windows has one fingerprint.
func (p *plan) fingerprint(capability string) string {
	if p.query == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(capability + "\x00" + p.query))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// deepLink builds an Explore link in Grafana's panes format from the public address.
func (p *plan) deepLink(publicURL string, orgID int64) *protocol.DeepLink {
	if publicURL == "" || p.explore == nil {
		return nil
	}
	panes, err := json.Marshal(map[string]any{"a": map[string]any{
		"datasource": p.explore.datasource,
		"queries": []map[string]any{{
			"refId":      "A",
			"datasource": map[string]string{"uid": p.explore.datasource},
			"expr":       p.explore.expr,
		}},
		"range": map[string]string{
			"from": strconv.FormatInt(p.explore.from.UnixMilli(), 10),
			"to":   strconv.FormatInt(p.explore.to.UnixMilli(), 10),
		},
	}})
	if err != nil {
		return nil
	}
	query := url.Values{"schemaVersion": {"1"}, "panes": {string(panes)}}
	if orgID > 0 {
		query.Set("orgId", strconv.FormatInt(orgID, 10))
	}
	return &protocol.DeepLink{
		Kind: protocol.DeepLinkGrafanaExplore,
		URL:  strings.TrimRight(publicURL, "/") + "/explore?" + query.Encode(),
	}
}

// prepare checks a command's arguments and builds its plan. Nothing here reaches the
// network, so a refused query makes no Grafana call.
func (e *Executor) prepare(view *policy.View, capability string, args protocol.Args, limits protocol.Limits) (*plan, *guard.Rejection) {
	tool := capabilityTools[capability]
	base := plan{tool: tool.Tool.Name, datasource: args.Summary().DatasourceUID}
	switch typed := args.(type) {
	case *protocol.PrometheusQueryRangeArgs:
		return preparePrometheusRange(base, tool, typed, limits)
	case *protocol.PrometheusQueryInstantArgs:
		return preparePrometheusInstant(base, tool, typed, limits)
	case *protocol.PrometheusListMetricNamesArgs:
		return prepareMetricNames(base, tool, typed, limits)
	case *protocol.PrometheusListLabelValuesArgs:
		return preparePrometheusLabelValues(base, tool, typed, limits)
	case *protocol.LokiQueryRangeArgs:
		return prepareLokiRange(base, tool, typed, limits, view.LogLines())
	case *protocol.LokiQueryPatternsArgs:
		return prepareLokiPatterns(base, tool, typed, limits)
	case *protocol.LokiListLabelValuesArgs:
		return prepareLokiLabelValues(base, tool, typed, limits)
	case *protocol.GrafanaListDatasourcesArgs:
		return prepareListDatasources(base, tool, typed, limits, view)
	case *protocol.GrafanaSearchDashboardsArgs:
		return prepareSearchDashboards(base, tool, typed, limits)
	case *protocol.GrafanaGetPanelQueriesArgs:
		return preparePanelQueries(base, tool, typed, limits, view)
	case *protocol.GrafanaListAlertRulesArgs:
		return prepareAlertRules(base, tool, typed, limits)
	case *protocol.GrafanaAlertRuleVersionsArgs:
		return prepareAlertRuleVersions(base, tool, typed, limits)
	}
	return nil, &guard.Rejection{Code: protocol.CodePolicyCapabilityDisabled, Message: fmt.Sprintf("capability %q has no executor", capability)}
}

func requireDatasource(uid string) *guard.Rejection {
	if uid == "" {
		return &guard.Rejection{Code: protocol.CodePolicyDatasourceNotAllowed, Message: "the command names no datasource"}
	}
	return nil
}

func decodeFailure(tool *mcpgrafana.Tool) *callFailure {
	return &callFailure{status: protocol.StatusError, code: protocol.CodeSourceUnavailable, message: fmt.Sprintf("the answer of %s was not in the expected shape", tool.Tool.Name)}
}

func preparePrometheusRange(p plan, tool *mcpgrafana.Tool, args *protocol.PrometheusQueryRangeArgs, limits protocol.Limits) (*plan, *guard.Rejection) {
	if rejection := requireDatasource(args.DatasourceUID); rejection != nil {
		return nil, rejection
	}
	query, rejection := guard.CheckPromQL(args.Expr)
	if rejection != nil {
		return nil, rejection
	}
	if args.StepS <= 0 {
		return nil, &guard.Rejection{Code: protocol.CodeQueryGuardFailed, Message: "step_s must be above zero"}
	}
	if rejection := guard.CheckRange(guard.Range{Start: args.Start, End: args.End, StepS: args.StepS, Lookback: query.Lookback}, limits); rejection != nil {
		return nil, rejection
	}
	p.query = query.Normalized
	p.explore = &exploreLink{datasource: args.DatasourceUID, expr: args.Expr, from: args.Start, to: args.End}
	toolArgs := map[string]any{
		"datasourceUid": args.DatasourceUID, "expr": args.Expr, "queryType": "range", "stepSeconds": args.StepS,
		"startTime": args.Start.UTC().Format(time.RFC3339), "endTime": args.End.UTC().Format(time.RFC3339),
	}
	p.run = func(call toolCaller) (*protocol.ResultData, []string, bool, *callFailure) {
		text, failure := call(tool, toolArgs)
		if failure != nil {
			return nil, nil, false, failure
		}
		series, err := decodePrometheus(text)
		if err != nil {
			return nil, nil, false, decodeFailure(tool)
		}
		input := make([]reduce.InputSeries, 0, len(series))
		for _, one := range series {
			input = append(input, reduce.InputSeries{Labels: one.Metric, Points: one.points()})
		}
		data, truncated := reduce.Matrix(input, args.StepS, limits)
		return data, nil, truncated, nil
	}
	return &p, nil
}

func preparePrometheusInstant(p plan, tool *mcpgrafana.Tool, args *protocol.PrometheusQueryInstantArgs, limits protocol.Limits) (*plan, *guard.Rejection) {
	if rejection := requireDatasource(args.DatasourceUID); rejection != nil {
		return nil, rejection
	}
	query, rejection := guard.CheckPromQL(args.Expr)
	if rejection != nil {
		return nil, rejection
	}
	if rejection := guard.CheckLookback(query.Lookback, limits); rejection != nil {
		return nil, rejection
	}
	if args.At.IsZero() {
		return nil, &guard.Rejection{Code: protocol.CodeQueryGuardFailed, Message: "the query needs a time"}
	}
	p.query = query.Normalized
	p.explore = &exploreLink{datasource: args.DatasourceUID, expr: args.Expr, from: args.At.Add(-time.Hour), to: args.At}
	toolArgs := map[string]any{
		"datasourceUid": args.DatasourceUID, "expr": args.Expr, "queryType": "instant",
		"endTime": args.At.UTC().Format(time.RFC3339),
	}
	p.run = func(call toolCaller) (*protocol.ResultData, []string, bool, *callFailure) {
		text, failure := call(tool, toolArgs)
		if failure != nil {
			return nil, nil, false, failure
		}
		series, err := decodePrometheus(text)
		if err != nil {
			return nil, nil, false, decodeFailure(tool)
		}
		samples := make([]protocol.Sample, 0, len(series))
		for _, one := range series {
			if one.Value != nil {
				samples = append(samples, protocol.Sample{Labels: one.Metric, Value: one.Value.value, At: one.Value.at})
			}
		}
		data, truncated := reduce.Vector(samples, limits)
		return data, nil, truncated, nil
	}
	return &p, nil
}

func prepareMetricNames(p plan, tool *mcpgrafana.Tool, args *protocol.PrometheusListMetricNamesArgs, limits protocol.Limits) (*plan, *guard.Rejection) {
	if rejection := requireDatasource(args.DatasourceUID); rejection != nil {
		return nil, rejection
	}
	if rejection := guard.CheckNamePattern(args.Match); rejection != nil {
		return nil, rejection
	}
	p.query = args.Match
	toolArgs := map[string]any{"datasourceUid": args.DatasourceUID, "regex": args.Match, "limit": limits.MaxItems + 1}
	p.run = runNames(tool, toolArgs, limits)
	return &p, nil
}

func preparePrometheusLabelValues(p plan, tool *mcpgrafana.Tool, args *protocol.PrometheusListLabelValuesArgs, limits protocol.Limits) (*plan, *guard.Rejection) {
	if rejection := requireDatasource(args.DatasourceUID); rejection != nil {
		return nil, rejection
	}
	if rejection := guard.CheckLabelName(args.Label); rejection != nil {
		return nil, rejection
	}
	toolArgs := map[string]any{"datasourceUid": args.DatasourceUID, "labelName": args.Label, "limit": limits.MaxItems + 1}
	if args.Match != "" {
		if rejection := guard.CheckPromSelector(args.Match); rejection != nil {
			return nil, rejection
		}
		toolArgs["matches"] = []string{args.Match}
	}
	p.query = args.Label + " " + args.Match
	p.run = runNames(tool, toolArgs, limits)
	return &p, nil
}

func prepareLokiLabelValues(p plan, tool *mcpgrafana.Tool, args *protocol.LokiListLabelValuesArgs, limits protocol.Limits) (*plan, *guard.Rejection) {
	if rejection := requireDatasource(args.DatasourceUID); rejection != nil {
		return nil, rejection
	}
	if rejection := guard.CheckLabelName(args.Label); rejection != nil {
		return nil, rejection
	}
	p.query = args.Label
	p.run = runNames(tool, map[string]any{"datasourceUid": args.DatasourceUID, "labelName": args.Label}, limits)
	return &p, nil
}

func runNames(tool *mcpgrafana.Tool, toolArgs map[string]any, limits protocol.Limits) func(toolCaller) (*protocol.ResultData, []string, bool, *callFailure) {
	return func(call toolCaller) (*protocol.ResultData, []string, bool, *callFailure) {
		text, failure := call(tool, toolArgs)
		if failure != nil {
			return nil, nil, false, failure
		}
		var names []string
		if err := json.Unmarshal([]byte(text), &names); err != nil {
			return nil, nil, false, decodeFailure(tool)
		}
		data, truncated := reduce.Names(names, limits)
		return data, nil, truncated, nil
	}
}

func prepareLokiRange(p plan, tool *mcpgrafana.Tool, args *protocol.LokiQueryRangeArgs, limits protocol.Limits, logLines int) (*plan, *guard.Rejection) {
	if rejection := requireDatasource(args.DatasourceUID); rejection != nil {
		return nil, rejection
	}
	query, rejection := guard.CheckLogQL(args.Expr)
	if rejection != nil {
		return nil, rejection
	}
	if query.Metric != (args.StepS > 0) {
		if query.Metric {
			return nil, &guard.Rejection{Code: protocol.CodeQueryGuardFailed, Message: "a metric query needs step_s"}
		}
		return nil, &guard.Rejection{Code: protocol.CodeQueryGuardFailed, Message: "step_s needs a metric query such as count_over_time"}
	}
	lines := min(logLines, limits.MaxLines)
	if lines <= 0 {
		if rejection := query.RefuseLogText(); rejection != nil {
			return nil, rejection
		}
	}
	if rejection := guard.CheckRange(guard.Range{Start: args.Start, End: args.End, StepS: args.StepS, Lookback: query.Lookback}, limits); rejection != nil {
		return nil, rejection
	}
	p.query = strings.Join(strings.Fields(args.Expr), " ")
	p.explore = &exploreLink{datasource: args.DatasourceUID, expr: args.Expr, from: args.Start, to: args.End}
	p.logQuery = &query
	start, end := args.Start.UTC().Format(time.RFC3339), args.End.UTC().Format(time.RFC3339)
	if query.Metric {
		toolArgs := map[string]any{
			"datasourceUid": args.DatasourceUID, "logql": args.Expr, "queryType": "range", "stepSeconds": args.StepS,
			"startRfc3339": start, "endRfc3339": end,
		}
		p.run = func(call toolCaller) (*protocol.ResultData, []string, bool, *callFailure) {
			text, failure := call(tool, toolArgs)
			if failure != nil {
				return nil, nil, false, failure
			}
			entries, err := decodeLoki(text)
			if err != nil {
				return nil, nil, false, decodeFailure(tool)
			}
			input := make([]reduce.InputSeries, 0, len(entries))
			for _, entry := range entries {
				input = append(input, reduce.InputSeries{Labels: entry.Labels, Points: entry.points()})
			}
			data, truncated := reduce.Matrix(input, args.StepS, limits)
			return data, nil, truncated, nil
		}
		return &p, nil
	}

	window := int64(args.End.Sub(args.Start) / time.Second)
	countArgs := map[string]any{
		"datasourceUid": args.DatasourceUID,
		"logql":         fmt.Sprintf("sum(count_over_time(%s [%ds]))", args.Expr, max(window, 1)),
		"queryType":     "instant",
		"endRfc3339":    end,
	}
	lineArgs := map[string]any{
		"datasourceUid": args.DatasourceUID, "logql": args.Expr, "limit": lines, "direction": "backward",
		"startRfc3339": start, "endRfc3339": end,
	}
	p.run = func(call toolCaller) (*protocol.ResultData, []string, bool, *callFailure) {
		data := &protocol.ResultData{Kind: protocol.DataLogs}
		var skipped []string
		countText, countFailure := call(tool, countArgs)
		counted := false
		if countFailure == nil {
			if entries, err := decodeLoki(countText); err == nil {
				counted = true
				for _, entry := range entries {
					if entry.Value != nil {
						data.LinesTotal = int(*entry.Value)
					}
				}
			}
		}
		if lines <= 0 {
			if !counted {
				if countFailure != nil {
					return nil, nil, false, countFailure
				}
				return nil, nil, false, decodeFailure(tool)
			}
			return data, nil, false, nil
		}
		if !counted {
			skipped = append(skipped, "lines_total")
		}
		text, failure := call(tool, lineArgs)
		if failure != nil {
			if counted {
				return data, []string{"lines"}, false, nil
			}
			return nil, nil, false, failure
		}
		entries, err := decodeLoki(text)
		if err != nil {
			return nil, nil, false, decodeFailure(tool)
		}
		for _, entry := range entries {
			at, _ := parseLokiTimestamp(entry.Timestamp)
			data.Lines = append(data.Lines, protocol.LogLine{At: at, Labels: entry.Labels, Text: entry.Line})
		}
		if !counted {
			data.LinesTotal = len(data.Lines)
		}
		return data, skipped, data.LinesTotal > len(data.Lines), nil
	}
	return &p, nil
}

func prepareLokiPatterns(p plan, tool *mcpgrafana.Tool, args *protocol.LokiQueryPatternsArgs, limits protocol.Limits) (*plan, *guard.Rejection) {
	if rejection := requireDatasource(args.DatasourceUID); rejection != nil {
		return nil, rejection
	}
	if rejection := guard.CheckLokiSelector(args.Expr); rejection != nil {
		return nil, rejection
	}
	if rejection := guard.CheckRange(guard.Range{Start: args.Start, End: args.End}, limits); rejection != nil {
		return nil, rejection
	}
	p.query = strings.Join(strings.Fields(args.Expr), " ")
	p.explore = &exploreLink{datasource: args.DatasourceUID, expr: args.Expr, from: args.Start, to: args.End}
	toolArgs := map[string]any{
		"datasourceUid": args.DatasourceUID, "logql": args.Expr,
		"startRfc3339": args.Start.UTC().Format(time.RFC3339), "endRfc3339": args.End.UTC().Format(time.RFC3339),
	}
	p.run = func(call toolCaller) (*protocol.ResultData, []string, bool, *callFailure) {
		text, failure := call(tool, toolArgs)
		if failure != nil {
			return nil, nil, false, failure
		}
		var found []struct {
			Pattern    string `json:"pattern"`
			TotalCount int64  `json:"totalCount"`
		}
		if err := json.Unmarshal([]byte(text), &found); err != nil {
			return nil, nil, false, decodeFailure(tool)
		}
		patterns := make([]protocol.LogPattern, 0, len(found))
		for _, one := range found {
			patterns = append(patterns, protocol.LogPattern{Pattern: one.Pattern, Count: one.TotalCount})
		}
		data, truncated := reduce.Patterns(patterns, limits)
		return data, nil, truncated, nil
	}
	return &p, nil
}

var datasourceTypePattern = regexp.MustCompile(`^[a-zA-Z0-9_-]{0,64}$`)

func prepareListDatasources(p plan, tool *mcpgrafana.Tool, args *protocol.GrafanaListDatasourcesArgs, limits protocol.Limits, view *policy.View) (*plan, *guard.Rejection) {
	if !datasourceTypePattern.MatchString(args.Type) {
		return nil, &guard.Rejection{Code: protocol.CodeQueryGuardFailed, Message: "type must be a datasource type such as prometheus"}
	}
	p.query = args.Type
	toolArgs := map[string]any{"limit": maxUpstreamListLimit}
	if args.Type != "" {
		toolArgs["type"] = args.Type
	}
	p.run = func(call toolCaller) (*protocol.ResultData, []string, bool, *callFailure) {
		text, failure := call(tool, toolArgs)
		if failure != nil {
			return nil, nil, false, failure
		}
		listed, err := decodeDatasources(text)
		if err != nil {
			return nil, nil, false, decodeFailure(tool)
		}
		allowed := slices.DeleteFunc(listed, func(one protocol.Datasource) bool { return !view.DatasourceAllowed(one.UID) })
		kept, truncated := reduce.Items(allowed, limits)
		return &protocol.ResultData{Kind: protocol.DataDatasources, Datasources: kept}, nil, truncated, nil
	}
	return &p, nil
}

// maxUpstreamListLimit is the most that grafana-mcp's list and search tools return
// in one page.
const maxUpstreamListLimit = 100

func prepareSearchDashboards(p plan, tool *mcpgrafana.Tool, args *protocol.GrafanaSearchDashboardsArgs, limits protocol.Limits) (*plan, *guard.Rejection) {
	if rejection := guard.CheckSearchText("query", args.Query); rejection != nil {
		return nil, rejection
	}
	p.query = args.Query
	toolArgs := map[string]any{"query": args.Query, "limit": min(limits.MaxItems+1, maxUpstreamListLimit)}
	p.run = func(call toolCaller) (*protocol.ResultData, []string, bool, *callFailure) {
		text, failure := call(tool, toolArgs)
		if failure != nil {
			return nil, nil, false, failure
		}
		var found struct {
			Dashboards []struct {
				UID         string `json:"uid"`
				Title       string `json:"title"`
				FolderTitle string `json:"folderTitle"`
			} `json:"dashboards"`
			HasMore bool `json:"hasMore"`
		}
		if err := json.Unmarshal([]byte(text), &found); err != nil {
			return nil, nil, false, decodeFailure(tool)
		}
		dashboards := make([]protocol.Dashboard, 0, len(found.Dashboards))
		for _, one := range found.Dashboards {
			dashboards = append(dashboards, protocol.Dashboard{UID: one.UID, Title: one.Title, Folder: one.FolderTitle})
		}
		kept, truncated := reduce.Items(dashboards, limits)
		return &protocol.ResultData{Kind: protocol.DataDashboards, Dashboards: kept}, nil, truncated || found.HasMore, nil
	}
	return &p, nil
}

func preparePanelQueries(p plan, tool *mcpgrafana.Tool, args *protocol.GrafanaGetPanelQueriesArgs, limits protocol.Limits, view *policy.View) (*plan, *guard.Rejection) {
	if rejection := guard.CheckDashboardUID(args.DashboardUID); rejection != nil {
		return nil, rejection
	}
	p.query = args.DashboardUID
	toolArgs := map[string]any{"uid": args.DashboardUID}
	if args.PanelID > 0 {
		toolArgs["panelId"] = args.PanelID
	}
	p.run = func(call toolCaller) (*protocol.ResultData, []string, bool, *callFailure) {
		text, failure := call(tool, toolArgs)
		if failure != nil {
			return nil, nil, false, failure
		}
		var found []struct {
			Title      string `json:"title"`
			Query      string `json:"query"`
			Datasource struct {
				UID string `json:"uid"`
			} `json:"datasource"`
		}
		if err := json.Unmarshal([]byte(text), &found); err != nil {
			return nil, nil, false, decodeFailure(tool)
		}
		queries := make([]protocol.PanelQuery, 0, len(found))
		dropped := false
		for _, one := range found {
			// A panel on a datasource outside the policy stays out, and so does one
			// that names none, because it runs on Grafana's default datasource. A
			// variable such as $datasource names no datasource yet, and a query it
			// holds still has to pass the checks when it runs.
			if !strings.Contains(one.Datasource.UID, "$") && !view.DatasourceAllowed(one.Datasource.UID) {
				dropped = true
				continue
			}
			queries = append(queries, protocol.PanelQuery{PanelID: args.PanelID, Title: one.Title, DatasourceUID: one.Datasource.UID, Expr: one.Query})
		}
		kept, truncated := reduce.Items(queries, limits)
		return &protocol.ResultData{Kind: protocol.DataPanelQueries, PanelQueries: kept}, nil, truncated || dropped, nil
	}
	return &p, nil
}

func prepareAlertRules(p plan, tool *mcpgrafana.Tool, args *protocol.GrafanaListAlertRulesArgs, limits protocol.Limits) (*plan, *guard.Rejection) {
	if rejection := guard.CheckSearchText("query", args.Query); rejection != nil {
		return nil, rejection
	}
	p.query = args.Query
	toolArgs := map[string]any{"operation": "list", "rule_limit": min(limits.MaxItems+1, 200)}
	if args.Query != "" {
		toolArgs["search_rule_name"] = args.Query
	}
	p.run = func(call toolCaller) (*protocol.ResultData, []string, bool, *callFailure) {
		text, failure := call(tool, toolArgs)
		if failure != nil {
			return nil, nil, false, failure
		}
		var found []struct {
			UID    string            `json:"uid"`
			Title  string            `json:"title"`
			State  string            `json:"state"`
			Query  string            `json:"query"`
			For    string            `json:"for"`
			Labels map[string]string `json:"labels"`
		}
		if err := json.Unmarshal([]byte(text), &found); err != nil {
			return nil, nil, false, decodeFailure(tool)
		}
		rules := make([]protocol.AlertRule, 0, len(found))
		for _, one := range found {
			rules = append(rules, protocol.AlertRule{UID: one.UID, Title: one.Title, State: one.State, Expr: one.Query, For: shortDuration(one.For), Labels: one.Labels})
		}
		kept, truncated := reduce.Items(rules, limits)
		p.baseDone = true
		reader := &detailReader{call: call, tool: tool, started: p.started, deadline: p.deadline}
		skipped := reader.addDetails(kept)
		return &protocol.ResultData{Kind: protocol.DataAlertRules, AlertRules: kept}, skipped, truncated, nil
	}
	return &p, nil
}

// prepareAlertRuleVersions reads the version history of one rule. Where Grafana has no
// version endpoint the answer is an error that says so, never an empty list that would read
// as a rule that never changed.
func prepareAlertRuleVersions(p plan, tool *mcpgrafana.Tool, args *protocol.GrafanaAlertRuleVersionsArgs, limits protocol.Limits) (*plan, *guard.Rejection) {
	if rejection := guard.CheckAlertRuleUID(args.UID); rejection != nil {
		return nil, rejection
	}
	p.query = args.UID
	toolArgs := map[string]any{"operation": "versions", "rule_uid": args.UID}
	p.run = func(call toolCaller) (*protocol.ResultData, []string, bool, *callFailure) {
		text, failure := call(tool, toolArgs)
		if failure != nil {
			if failure.code == protocol.CodeUpstream4xx {
				failure.message = "no version history came back: the rule was not found, or Grafana is older than 12"
			}
			return nil, nil, false, failure
		}
		entries, err := ruleVersions(text)
		if err != nil {
			return nil, nil, false, decodeFailure(tool)
		}
		versions := make([]protocol.AlertRuleVersion, len(entries))
		for i, entry := range entries {
			versions[i] = entry.AlertRuleVersion
		}
		maxVersions := protocol.MaxAlertRuleVersions
		if limits.MaxItems > 0 {
			maxVersions = min(maxVersions, limits.MaxItems)
		}
		kept, truncated := reduce.Items(versions, protocol.Limits{MaxItems: maxVersions})
		return &protocol.ResultData{Kind: protocol.DataAlertRuleVersions, AlertRuleVersions: kept}, nil, truncated, nil
	}
	return &p, nil
}
