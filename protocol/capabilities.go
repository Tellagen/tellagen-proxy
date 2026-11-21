package protocol

import (
	"bytes"
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"
)

// The read capabilities of the proxy. A new one changes the digest in the hello.
const (
	CapabilityPrometheusQueryRange      = "prometheus.query_range"
	CapabilityPrometheusQueryInstant    = "prometheus.query_instant"
	CapabilityPrometheusListMetricNames = "prometheus.list_metric_names"
	CapabilityPrometheusListLabelValues = "prometheus.list_label_values"
	CapabilityLokiQueryRange            = "loki.query_range"
	CapabilityLokiQueryPatterns         = "loki.query_patterns"
	CapabilityLokiListLabelValues       = "loki.list_label_values"
	CapabilityGrafanaListDatasources    = "grafana.list_datasources"
	CapabilityGrafanaSearchDashboards   = "grafana.search_dashboards"
	CapabilityGrafanaGetPanelQueries    = "grafana.get_dashboard_panel_queries"
	CapabilityGrafanaListAlertRules     = "grafana.list_alert_rules"
	// CapabilityGrafanaAlertRuleVersions reads the version history of one alert rule.
	CapabilityGrafanaAlertRuleVersions = "grafana.alert_rule_versions"
)

// Capability families. A family is the part of the name before the dot.
const (
	FamilyPrometheus = "prometheus"
	FamilyLoki       = "loki"
	FamilyGrafana    = "grafana"
)

// Capability is one capability a proxy offers, with the highest limits it allows.
type Capability struct {
	Name    string `json:"name"`
	Version int    `json:"version"`
	Limits  Limits `json:"limits"`
}

// Limits bound one command. Zero means no value is set.
type Limits struct {
	MaxRangeS      int `json:"max_range_s,omitempty"`
	MaxPoints      int `json:"max_points,omitempty"`
	MaxSeries      int `json:"max_series,omitempty"`
	TimeoutMS      int `json:"timeout_ms,omitempty"`
	MaxResultBytes int `json:"max_result_bytes,omitempty"`
	MaxLines       int `json:"max_lines,omitempty"`
	MaxLineChars   int `json:"max_line_chars,omitempty"`
	MaxPatterns    int `json:"max_patterns,omitempty"`
	MaxItems       int `json:"max_items,omitempty"`
}

// Narrow returns the smallest value of each field, so a call can only lower a
// limit, never raise it. Zero means no value.
func (l Limits) Narrow(other Limits) Limits {
	return Limits{
		MaxRangeS:      smallest(l.MaxRangeS, other.MaxRangeS),
		MaxPoints:      smallest(l.MaxPoints, other.MaxPoints),
		MaxSeries:      smallest(l.MaxSeries, other.MaxSeries),
		TimeoutMS:      smallest(l.TimeoutMS, other.TimeoutMS),
		MaxResultBytes: smallest(l.MaxResultBytes, other.MaxResultBytes),
		MaxLines:       smallest(l.MaxLines, other.MaxLines),
		MaxLineChars:   smallest(l.MaxLineChars, other.MaxLineChars),
		MaxPatterns:    smallest(l.MaxPatterns, other.MaxPatterns),
		MaxItems:       smallest(l.MaxItems, other.MaxItems),
	}
}

func smallest(a, b int) int {
	switch {
	case a <= 0:
		return max(b, 0)
	case b <= 0:
		return a
	}
	return min(a, b)
}

const (
	day              = 24 * 60 * 60
	queryTimeoutMS   = 60_000
	resultBytesLimit = 64 * 1024
)

type catalogEntry struct {
	capability Capability
	args       func() Args
}

// capabilityCatalog holds version 1 of every capability with the ceilings of the
// binary. The policy file and Tellagen can only lower them.
var capabilityCatalog = []catalogEntry{
	{
		Capability{CapabilityPrometheusQueryRange, 1, Limits{MaxRangeS: 7 * day, MaxPoints: 500, MaxSeries: 50, TimeoutMS: queryTimeoutMS, MaxResultBytes: resultBytesLimit}},
		func() Args { return &PrometheusQueryRangeArgs{} },
	},
	{
		Capability{CapabilityPrometheusQueryInstant, 1, Limits{MaxSeries: 50, TimeoutMS: queryTimeoutMS, MaxResultBytes: resultBytesLimit}},
		func() Args { return &PrometheusQueryInstantArgs{} },
	},
	{
		Capability{CapabilityPrometheusListMetricNames, 1, Limits{MaxItems: 200, TimeoutMS: queryTimeoutMS, MaxResultBytes: resultBytesLimit}},
		func() Args { return &PrometheusListMetricNamesArgs{} },
	},
	{
		Capability{CapabilityPrometheusListLabelValues, 1, Limits{MaxItems: 200, TimeoutMS: queryTimeoutMS, MaxResultBytes: resultBytesLimit}},
		func() Args { return &PrometheusListLabelValuesArgs{} },
	},
	{
		Capability{CapabilityLokiQueryRange, 1, Limits{MaxRangeS: day, MaxPoints: 500, MaxSeries: 50, MaxLines: 50, MaxLineChars: 500, TimeoutMS: queryTimeoutMS, MaxResultBytes: resultBytesLimit}},
		func() Args { return &LokiQueryRangeArgs{} },
	},
	{
		Capability{CapabilityLokiQueryPatterns, 1, Limits{MaxRangeS: day, MaxPatterns: 5, TimeoutMS: queryTimeoutMS, MaxResultBytes: resultBytesLimit}},
		func() Args { return &LokiQueryPatternsArgs{} },
	},
	{
		Capability{CapabilityLokiListLabelValues, 1, Limits{MaxItems: 200, TimeoutMS: queryTimeoutMS, MaxResultBytes: resultBytesLimit}},
		func() Args { return &LokiListLabelValuesArgs{} },
	},
	{
		Capability{CapabilityGrafanaListDatasources, 1, Limits{MaxItems: 100, TimeoutMS: queryTimeoutMS, MaxResultBytes: resultBytesLimit}},
		func() Args { return &GrafanaListDatasourcesArgs{} },
	},
	{
		Capability{CapabilityGrafanaSearchDashboards, 1, Limits{MaxItems: 50, TimeoutMS: queryTimeoutMS, MaxResultBytes: resultBytesLimit}},
		func() Args { return &GrafanaSearchDashboardsArgs{} },
	},
	{
		Capability{CapabilityGrafanaGetPanelQueries, 1, Limits{MaxItems: 100, TimeoutMS: queryTimeoutMS, MaxResultBytes: resultBytesLimit}},
		func() Args { return &GrafanaGetPanelQueriesArgs{} },
	},
	{
		Capability{CapabilityGrafanaListAlertRules, 1, Limits{MaxItems: 100, TimeoutMS: queryTimeoutMS, MaxResultBytes: resultBytesLimit}},
		func() Args { return &GrafanaListAlertRulesArgs{} },
	},
	{
		Capability{CapabilityGrafanaAlertRuleVersions, 1, Limits{MaxItems: MaxAlertRuleVersions, TimeoutMS: queryTimeoutMS, MaxResultBytes: resultBytesLimit}},
		func() Args { return &GrafanaAlertRuleVersionsArgs{} },
	},
}

// Capabilities returns every capability with the binary's ceilings, sorted by
// name.
func Capabilities() []Capability {
	out := make([]Capability, 0, len(capabilityCatalog))
	for _, entry := range capabilityCatalog {
		out = append(out, entry.capability)
	}
	slices.SortFunc(out, func(a, b Capability) int { return cmp.Compare(a.Name, b.Name) })
	return out
}

// IsKnownCapability reports whether name is a capability of this protocol.
func IsKnownCapability(name string) bool {
	return slices.ContainsFunc(capabilityCatalog, func(entry catalogEntry) bool {
		return entry.capability.Name == name
	})
}

// DiscoveryCommandsPerRun is how many discovery commands one run may send.
const DiscoveryCommandsPerRun = 60

// IsDiscoveryCapability reports whether a capability lists what can be queried
// and reads no telemetry. Discovery has its own limit per run.
func IsDiscoveryCapability(name string) bool {
	switch name {
	case CapabilityPrometheusListMetricNames, CapabilityPrometheusListLabelValues,
		CapabilityLokiListLabelValues, CapabilityGrafanaListDatasources,
		CapabilityGrafanaSearchDashboards, CapabilityGrafanaGetPanelQueries,
		CapabilityGrafanaListAlertRules, CapabilityGrafanaAlertRuleVersions:
		return true
	}
	return false
}

// CapabilityFamily returns the part of a capability name before the dot.
func CapabilityFamily(name string) string {
	family, _, _ := strings.Cut(name, ".")
	return family
}

// CapabilitiesDigest returns the digest a proxy reports in its hello. It does not
// depend on the order of caps.
func CapabilitiesDigest(caps []Capability) (string, error) {
	sorted := slices.Clone(caps)
	slices.SortFunc(sorted, func(a, b Capability) int { return cmp.Compare(a.Name, b.Name) })
	encoded, err := json.Marshal(sorted)
	if err != nil {
		return "", fmt.Errorf("encode capabilities: %w", err)
	}
	sum := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// ArgsSummary is what an audit line shows about one command.
type ArgsSummary struct {
	DatasourceUID string
	Query         string
	Start         *time.Time
	End           *time.Time
	StepS         int
}

// Args are the typed arguments of one capability.
type Args interface {
	Summary() ArgsSummary
}

// ParseArgs decodes the arguments of a command strictly: a field that this
// version of the capability does not know is an error.
func ParseArgs(capability string, raw json.RawMessage) (Args, error) {
	for _, entry := range capabilityCatalog {
		if entry.capability.Name != capability {
			continue
		}
		args := entry.args()
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(args); err != nil {
			return nil, fmt.Errorf("decode %s args: %w", capability, err)
		}
		return args, nil
	}
	return nil, fmt.Errorf("unknown capability %q", capability)
}

// PrometheusQueryRangeArgs are the arguments of prometheus.query_range.
type PrometheusQueryRangeArgs struct {
	DatasourceUID string    `json:"datasource_uid"`
	Expr          string    `json:"expr"`
	Start         time.Time `json:"start"`
	End           time.Time `json:"end"`
	StepS         int       `json:"step_s"`
}

// Summary implements Args.
func (a *PrometheusQueryRangeArgs) Summary() ArgsSummary {
	return ArgsSummary{DatasourceUID: a.DatasourceUID, Query: a.Expr, Start: &a.Start, End: &a.End, StepS: a.StepS}
}

// PrometheusQueryInstantArgs are the arguments of prometheus.query_instant.
type PrometheusQueryInstantArgs struct {
	DatasourceUID string    `json:"datasource_uid"`
	Expr          string    `json:"expr"`
	At            time.Time `json:"at"`
}

// Summary implements Args.
func (a *PrometheusQueryInstantArgs) Summary() ArgsSummary {
	return ArgsSummary{DatasourceUID: a.DatasourceUID, Query: a.Expr, End: &a.At}
}

// PrometheusListMetricNamesArgs are the arguments of prometheus.list_metric_names.
type PrometheusListMetricNamesArgs struct {
	DatasourceUID string `json:"datasource_uid"`
	Match         string `json:"match,omitempty"`
}

// Summary implements Args.
func (a *PrometheusListMetricNamesArgs) Summary() ArgsSummary {
	return ArgsSummary{DatasourceUID: a.DatasourceUID, Query: a.Match}
}

// PrometheusListLabelValuesArgs are the arguments of prometheus.list_label_values.
type PrometheusListLabelValuesArgs struct {
	DatasourceUID string `json:"datasource_uid"`
	Label         string `json:"label"`
	Match         string `json:"match,omitempty"`
}

// Summary implements Args.
func (a *PrometheusListLabelValuesArgs) Summary() ArgsSummary {
	return ArgsSummary{DatasourceUID: a.DatasourceUID, Query: strings.TrimSpace(a.Label + " " + a.Match)}
}

// LokiQueryRangeArgs are the arguments of loki.query_range. With StepS set, Expr
// is a metric query that returns a matrix; without it Expr returns log lines.
type LokiQueryRangeArgs struct {
	DatasourceUID string    `json:"datasource_uid"`
	Expr          string    `json:"expr"`
	Start         time.Time `json:"start"`
	End           time.Time `json:"end"`
	StepS         int       `json:"step_s,omitempty"`
}

// Summary implements Args.
func (a *LokiQueryRangeArgs) Summary() ArgsSummary {
	return ArgsSummary{DatasourceUID: a.DatasourceUID, Query: a.Expr, Start: &a.Start, End: &a.End, StepS: a.StepS}
}

// LokiQueryPatternsArgs are the arguments of loki.query_patterns.
type LokiQueryPatternsArgs struct {
	DatasourceUID string    `json:"datasource_uid"`
	Expr          string    `json:"expr"`
	Start         time.Time `json:"start"`
	End           time.Time `json:"end"`
}

// Summary implements Args.
func (a *LokiQueryPatternsArgs) Summary() ArgsSummary {
	return ArgsSummary{DatasourceUID: a.DatasourceUID, Query: a.Expr, Start: &a.Start, End: &a.End}
}

// LokiListLabelValuesArgs are the arguments of loki.list_label_values.
type LokiListLabelValuesArgs struct {
	DatasourceUID string `json:"datasource_uid"`
	Label         string `json:"label"`
}

// Summary implements Args.
func (a *LokiListLabelValuesArgs) Summary() ArgsSummary {
	return ArgsSummary{DatasourceUID: a.DatasourceUID, Query: a.Label}
}

// GrafanaListDatasourcesArgs are the arguments of grafana.list_datasources.
type GrafanaListDatasourcesArgs struct {
	Type string `json:"type,omitempty"`
}

// Summary implements Args.
func (a *GrafanaListDatasourcesArgs) Summary() ArgsSummary {
	return ArgsSummary{Query: a.Type}
}

// GrafanaSearchDashboardsArgs are the arguments of grafana.search_dashboards.
type GrafanaSearchDashboardsArgs struct {
	Query string `json:"query,omitempty"`
}

// Summary implements Args.
func (a *GrafanaSearchDashboardsArgs) Summary() ArgsSummary {
	return ArgsSummary{Query: a.Query}
}

// GrafanaGetPanelQueriesArgs are the arguments of
// grafana.get_dashboard_panel_queries. Without PanelID it reads every panel.
type GrafanaGetPanelQueriesArgs struct {
	DashboardUID string `json:"dashboard_uid"`
	PanelID      int    `json:"panel_id,omitempty"`
}

// Summary implements Args.
func (a *GrafanaGetPanelQueriesArgs) Summary() ArgsSummary {
	return ArgsSummary{Query: a.DashboardUID}
}

// GrafanaListAlertRulesArgs are the arguments of grafana.list_alert_rules.
type GrafanaListAlertRulesArgs struct {
	Query string `json:"query,omitempty"`
}

// Summary implements Args.
func (a *GrafanaListAlertRulesArgs) Summary() ArgsSummary {
	return ArgsSummary{Query: a.Query}
}

// MaxAlertRuleVersions is how many versions of one rule grafana.alert_rule_versions returns.
const MaxAlertRuleVersions = 20

// GrafanaAlertRuleVersionsArgs are the arguments of grafana.alert_rule_versions.
type GrafanaAlertRuleVersionsArgs struct {
	UID string `json:"uid"`
}

// Summary implements Args.
func (a *GrafanaAlertRuleVersionsArgs) Summary() ArgsSummary {
	return ArgsSummary{Query: a.UID}
}
