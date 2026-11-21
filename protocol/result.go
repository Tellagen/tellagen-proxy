package protocol

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// Statuses of a command result.
const (
	// StatusOK means the query ran and returned a bounded result.
	StatusOK = "ok"
	// StatusPartial means data plus parts that were skipped.
	StatusPartial = "partial"
	// StatusRejected means the local policy refused the command before any
	// Grafana call. The result carries the code and a hint.
	StatusRejected = "rejected"
	// StatusError means the source failed.
	StatusError = "error"
	// StatusCancelled means the command was cancelled.
	StatusCancelled = "cancelled"
)

// Error codes of a command result.
const (
	CodePolicyRangeExceeded        = "policy_range_exceeded"
	CodePolicyDatasourceNotAllowed = "policy_datasource_not_allowed"
	CodePolicyCapabilityDisabled   = "policy_capability_disabled"
	CodeQueryGuardFailed           = "query_guard_failed"
	CodeSourceUnavailable          = "source_unavailable"
	CodeAuthFailed                 = "auth_failed"
	CodeTimeout                    = "timeout"
	CodeUpstream4xx                = "upstream_4xx"
)

// CommandResult is the body of POST /api/proxy/v1/commands/{id}/result.
type CommandResult struct {
	AttemptToken     string         `json:"attempt_token"`
	Status           string         `json:"status"`
	DurationMS       int            `json:"duration_ms"`
	Data             *ResultData    `json:"data,omitempty"`
	Skipped          []string       `json:"skipped,omitempty"`
	Truncated        bool           `json:"truncated"`
	Bytes            int            `json:"bytes"`
	Redactions       int            `json:"redactions"`
	RedactionsByKind map[string]int `json:"redactions_by_kind,omitempty"`
	QueryFingerprint string         `json:"query_fingerprint,omitempty"`
	ExecutedVia      string         `json:"executed_via,omitempty"`
	DeepLink         *DeepLink      `json:"deep_link,omitempty"`
	Error            *ResultError   `json:"error,omitempty"`
}

// DeepLink is the link the proxy built from its public Grafana address.
type DeepLink struct {
	Kind string `json:"kind"`
	URL  string `json:"url"`
}

// DeepLinkGrafanaExplore is the only kind of deep link today.
const DeepLinkGrafanaExplore = "grafana_explore"

// ResultError says why a command failed. Hint names the limits that would pass.
type ResultError struct {
	Code      string  `json:"code"`
	Message   string  `json:"message"`
	Retryable bool    `json:"retryable"`
	Hint      *Limits `json:"hint,omitempty"`
}

// Kinds of ResultData.
const (
	DataMatrix       = "matrix"
	DataVector       = "vector"
	DataLogs         = "logs"
	DataPatterns     = "patterns"
	DataNames        = "names"
	DataDatasources  = "datasources"
	DataDashboards   = "dashboards"
	DataPanelQueries = "panel_queries"
	DataAlertRules   = "alert_rules"
	// DataAlertRuleVersions holds the version history of one alert rule.
	DataAlertRuleVersions = "alert_rule_versions"
)

// ResultData is the reduced and redacted result of one command. Kind says which
// field holds it.
type ResultData struct {
	Kind                  string       `json:"kind"`
	SeriesTotal           int          `json:"series_total,omitempty"`
	Series                []Series     `json:"series,omitempty"`
	DownsampledFromPoints int          `json:"downsampled_from_points,omitempty"`
	Samples               []Sample     `json:"samples,omitempty"`
	LinesTotal            int          `json:"lines_total,omitempty"`
	Lines                 []LogLine    `json:"lines,omitempty"`
	Patterns              []LogPattern `json:"patterns,omitempty"`
	Names                 []string     `json:"names,omitempty"`
	Datasources           []Datasource `json:"datasources,omitempty"`
	Dashboards            []Dashboard  `json:"dashboards,omitempty"`
	PanelQueries          []PanelQuery `json:"panel_queries,omitempty"`
	AlertRules            []AlertRule  `json:"alert_rules,omitempty"`
	// AlertRuleVersions is newest first.
	AlertRuleVersions []AlertRuleVersion `json:"alert_rule_versions,omitempty"`
}

// Series is one reduced line of a matrix. A nil value is a gap.
type Series struct {
	Labels map[string]string `json:"labels"`
	Start  time.Time         `json:"start"`
	StepS  int               `json:"step_s"`
	Values []*float64        `json:"values"`
	Stats  *SeriesStats      `json:"stats,omitempty"`
}

// SeriesStats are computed over all points before any downsampling.
type SeriesStats struct {
	Min   float64   `json:"min"`
	Max   float64   `json:"max"`
	Avg   float64   `json:"avg"`
	First float64   `json:"first"`
	Last  float64   `json:"last"`
	MaxAt time.Time `json:"max_at"`
}

// Sample is one value of an instant vector.
type Sample struct {
	Labels map[string]string `json:"labels"`
	Value  float64           `json:"value"`
	At     time.Time         `json:"at"`
}

// LogLine is one redacted log line, cut to the line limit.
type LogLine struct {
	At     time.Time         `json:"at"`
	Labels map[string]string `json:"labels,omitempty"`
	Text   string            `json:"text"`
}

// LogPattern is one log pattern with its variables replaced by <_>. FirstSeen is
// left out when the source does not report it, as grafana-mcp does not.
type LogPattern struct {
	Pattern   string    `json:"pattern"`
	Count     int64     `json:"count"`
	FirstSeen time.Time `json:"first_seen,omitzero"`
}

// Datasource is one Grafana datasource.
type Datasource struct {
	UID     string `json:"uid"`
	Name    string `json:"name"`
	Type    string `json:"type"`
	Default bool   `json:"default,omitempty"`
}

// Dashboard is one Grafana dashboard found by a search.
type Dashboard struct {
	UID    string `json:"uid"`
	Title  string `json:"title"`
	Folder string `json:"folder,omitempty"`
}

// PanelQuery is one query of a dashboard panel.
type PanelQuery struct {
	PanelID       int    `json:"panel_id"`
	Title         string `json:"title"`
	DatasourceUID string `json:"datasource_uid"`
	Expr          string `json:"expr"`
}

// AlertRule is one Grafana alert rule. Every field after Expr is optional: a proxy that
// does not know it, or a Grafana that does not report it, leaves it out, and a reader treats
// a missing field as unknown, never as a default.
type AlertRule struct {
	UID   string `json:"uid"`
	Title string `json:"title"`
	State string `json:"state,omitempty"`
	Expr  string `json:"expr,omitempty"`
	// Threshold is the condition of the rule, read from its threshold expression or its
	// classic condition. It is left out when the rule has none or more than one, and when a
	// math or other transform stands between the condition and the query.
	Threshold *AlertThreshold `json:"threshold,omitempty"`
	// For is how long the condition must hold before the rule fires, as Grafana writes it
	// ("5m").
	For    string            `json:"for,omitempty"`
	Labels map[string]string `json:"labels,omitempty"`
	// Updated is when the current version of the rule was saved.
	Updated time.Time `json:"updated,omitzero"`
	// Version is the version number of the rule. It counts up with every save.
	Version int `json:"version,omitempty"`
	// DatasourceUID is the datasource of the query the rule reads, from the query node that
	// its condition reaches through plain reduce nodes. It is left out when that is not
	// certain.
	DatasourceUID string `json:"datasource_uid,omitempty"`
}

// Alert threshold operators, as Grafana names them in an evaluator.
const (
	ThresholdGreaterThan  = "gt"
	ThresholdLessThan     = "lt"
	ThresholdWithinRange  = "within_range"
	ThresholdOutsideRange = "outside_range"
	ThresholdNoValue      = "no_value"
)

// AlertThreshold is the value an alert rule compares against. For gt and lt, Value is the
// threshold. For within_range and outside_range, Value is the lower bound and To the upper
// bound. For no_value there is no number and Value is 0.
type AlertThreshold struct {
	Op    string   `json:"op"`
	Value float64  `json:"value"`
	To    *float64 `json:"to,omitempty"`
}

// AlertRuleVersion is one saved version of an alert rule.
type AlertRuleVersion struct {
	Version   int             `json:"version"`
	Updated   time.Time       `json:"updated,omitzero"`
	Expr      string          `json:"expr,omitempty"`
	Threshold *AlertThreshold `json:"threshold,omitempty"`
}

var (
	resultStatuses = map[string]bool{StatusOK: true, StatusPartial: true, StatusRejected: true, StatusError: true, StatusCancelled: true}
	resultCodes    = map[string]bool{
		CodePolicyRangeExceeded: true, CodePolicyDatasourceNotAllowed: true, CodePolicyCapabilityDisabled: true,
		CodeQueryGuardFailed: true, CodeSourceUnavailable: true, CodeAuthFailed: true, CodeTimeout: true, CodeUpstream4xx: true,
	}
)

// Validate reports the first problem that makes a result unusable.
func (r CommandResult) Validate() error {
	if strings.TrimSpace(r.AttemptToken) == "" {
		return errors.New("attempt_token is required")
	}
	if !resultStatuses[r.Status] {
		return fmt.Errorf("unknown status %q", r.Status)
	}
	switch r.Status {
	case StatusOK, StatusPartial:
		if r.Data == nil {
			return fmt.Errorf("status %s needs data", r.Status)
		}
		if r.Error != nil {
			return fmt.Errorf("status %s must not carry an error", r.Status)
		}
	case StatusRejected, StatusError:
		if r.Error == nil {
			return fmt.Errorf("status %s needs an error", r.Status)
		}
		if !resultCodes[r.Error.Code] {
			return fmt.Errorf("unknown error code %q", r.Error.Code)
		}
	}
	return nil
}
