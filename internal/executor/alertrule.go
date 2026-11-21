package executor

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	mcpgrafana "github.com/grafana/mcp-grafana/v2"

	"github.com/tellagen/tellagen-proxy/internal/guard"
	"github.com/tellagen/tellagen-proxy/protocol"
)

// alertRuleDetailLimit is how many rules of one list get their details read. Each rule costs
// one or two more Grafana calls, so a long list keeps its plain fields past this count and
// a reader asks again with a narrower search.
const alertRuleDetailLimit = 5

// alertQueryNode is one node of a Grafana-managed rule: a data query, or an expression that
// works on other nodes (reduce, math, threshold, classic conditions).
type alertQueryNode struct {
	RefID         string `json:"refId"`
	DatasourceUID string `json:"datasourceUid"`
	Model         struct {
		Expr       string `json:"expr"`
		Type       string `json:"type"`
		Expression string `json:"expression"`
		Conditions []struct {
			Evaluator struct {
				Type   string    `json:"type"`
				Params []float64 `json:"params"`
			} `json:"evaluator"`
			Query struct {
				Params []string `json:"params"`
			} `json:"query"`
		} `json:"conditions"`
	} `json:"model"`
}

func (n alertQueryNode) isExpression() bool {
	return n.DatasourceUID == "__expr__" || n.DatasourceUID == "-100"
}

// ruleCondition reads the threshold, the query expression and the datasource of a rule from
// its nodes. The threshold and the expression are given together or not at all: they belong
// together only when the condition reaches the query through nothing but plain reduce
// nodes. A math node, a resample or any other transform in between means that the number
// judges something other than the query, so both are left out. A value that cannot be read
// with certainty stays out as well: a rule with two thresholds, or whose condition is not a
// threshold, gets none, and a reader treats that as unknown.
func ruleCondition(condition string, nodes []alertQueryNode) (expr, datasourceUID string, threshold *protocol.AlertThreshold) {
	byRef := make(map[string]alertQueryNode, len(nodes))
	for _, node := range nodes {
		byRef[node.RefID] = node
	}
	isThreshold := func(node alertQueryNode) bool {
		return node.isExpression() && (node.Model.Type == "threshold" || node.Model.Type == "classic_conditions")
	}
	var found *alertQueryNode
	if condition != "" {
		if node, ok := byRef[condition]; ok && isThreshold(node) {
			found = &node
		}
	} else {
		for _, node := range nodes {
			if isThreshold(node) {
				if found != nil {
					found = nil
					break
				}
				one := node
				found = &one
			}
		}
	}
	start := condition
	if found != nil {
		threshold = thresholdOf(*found)
		start = found.RefID
	}
	expr, datasourceUID, transformed := chaseQuery(start, byRef)
	if transformed {
		return "", "", nil
	}
	return expr, datasourceUID, threshold
}

func thresholdOf(node alertQueryNode) *protocol.AlertThreshold {
	if len(node.Model.Conditions) != 1 {
		return nil
	}
	evaluator := node.Model.Conditions[0].Evaluator
	switch evaluator.Type {
	case protocol.ThresholdGreaterThan, protocol.ThresholdLessThan:
		if len(evaluator.Params) == 1 {
			return &protocol.AlertThreshold{Op: evaluator.Type, Value: evaluator.Params[0]}
		}
	case protocol.ThresholdWithinRange, protocol.ThresholdOutsideRange:
		if len(evaluator.Params) != 2 {
			return nil
		}
		low, high := evaluator.Params[0], evaluator.Params[1]
		if low > high {
			// A classic condition takes the bounds in either order. A threshold node does
			// not: Grafana reads the first number as the lower bound, so a reversed pair
			// is not a range this proxy can state.
			if node.Model.Type != "classic_conditions" {
				return nil
			}
			low, high = high, low
		}
		return &protocol.AlertThreshold{Op: evaluator.Type, Value: low, To: &high}
	case protocol.ThresholdNoValue:
		return &protocol.AlertThreshold{Op: evaluator.Type}
	}
	return nil
}

// chaseQuery follows the condition node back to the data query it judges. The first node may
// be a threshold, a classic condition or a reduce; every node after it must be a plain reduce.
// transformed is true when the chain passes through any other expression, such as math. A
// chain that breaks for another reason (a missing node, no reference) gives no expression
// and is not transformed.
func chaseQuery(start string, byRef map[string]alertQueryNode) (expr, datasourceUID string, transformed bool) {
	ref := start
	for hop := range 8 {
		node, ok := byRef[ref]
		if !ok {
			return "", "", false
		}
		if !node.isExpression() {
			return node.Model.Expr, node.DatasourceUID, false
		}
		switch {
		case node.Model.Type == "classic_conditions" && hop == 0:
			if len(node.Model.Conditions) == 0 || len(node.Model.Conditions[0].Query.Params) == 0 {
				return "", "", false
			}
			ref = node.Model.Conditions[0].Query.Params[0]
		case node.Model.Type == "threshold" && hop == 0, node.Model.Type == "reduce":
			ref = node.Model.Expression
		default:
			return "", "", true
		}
	}
	return "", "", false
}

// shortDuration writes a duration the way Grafana's rule editor does: 5m, not 5m0s.
func shortDuration(text string) string {
	if strings.HasSuffix(text, "m0s") {
		text = strings.TrimSuffix(text, "0s")
	}
	if strings.HasSuffix(text, "h0m") {
		text = strings.TrimSuffix(text, "0m")
	}
	return text
}

// ruleVersionNode is one entry of the ruler API's version list.
type ruleVersionNode struct {
	GrafanaAlert *struct {
		Version   int64            `json:"version"`
		Updated   string           `json:"updated"`
		Condition string           `json:"condition"`
		Data      []alertQueryNode `json:"data"`
	} `json:"grafana_alert"`
}

// ruleVersionEntry is one version with the datasource of its query, which the version list
// of the protocol does not carry.
type ruleVersionEntry struct {
	protocol.AlertRuleVersion
	datasourceUID string
}

// ruleVersions decodes the version list of one rule, newest first. A rule that is not
// Grafana-managed has no entry in it.
func ruleVersions(text string) ([]ruleVersionEntry, error) {
	var nodes []ruleVersionNode
	if err := json.Unmarshal([]byte(text), &nodes); err != nil {
		return nil, err
	}
	entries := make([]ruleVersionEntry, 0, len(nodes))
	for _, node := range nodes {
		if node.GrafanaAlert == nil {
			continue
		}
		alert := node.GrafanaAlert
		expr, datasourceUID, threshold := ruleCondition(alert.Condition, alert.Data)
		entry := ruleVersionEntry{AlertRuleVersion: protocol.AlertRuleVersion{Version: int(alert.Version), Expr: expr, Threshold: threshold}, datasourceUID: datasourceUID}
		if updated, err := time.Parse(time.RFC3339Nano, alert.Updated); err == nil {
			entry.Updated = updated.UTC()
		}
		entries = append(entries, entry)
	}
	slices.SortStableFunc(entries, func(a, b ruleVersionEntry) int { return b.Version - a.Version })
	return entries, nil
}

// ruleDetail is the single-rule answer of the alert rules tool.
type ruleDetail struct {
	Condition string           `json:"condition"`
	Data      []alertQueryNode `json:"data"`
}

// detailReader reads the extra details of the rules in one list. It has its own budget inside
// the command's deadline and remembers that this Grafana has no version history.
type detailReader struct {
	call     toolCaller
	tool     *mcpgrafana.Tool
	started  time.Time
	deadline time.Time
	// noVersions is set by the first version read that Grafana answers with a 4xx, which
	// is a Grafana older than 12 or a rule it does not know. The other rules then use
	// the plain read only.
	noVersions bool
}

// outOfTime is true when less than half of the command's time is left. The list itself came
// back, and it is worth more than the details of one more rule.
func (d *detailReader) outOfTime() bool {
	if d.deadline.IsZero() {
		return false
	}
	return time.Until(d.deadline) < d.deadline.Sub(d.started)/2
}

// add reads the threshold, the version and the time of a rule. Each read is best effort: a
// Grafana that has no version endpoint, or a token that cannot read one rule, leaves those
// fields out of the rule and does not fail the list.
func (d *detailReader) add(rule *protocol.AlertRule) {
	if rule.UID == "" || guard.CheckAlertRuleUID(rule.UID) != nil {
		return
	}
	if !d.noVersions {
		text, failure := d.call(d.tool, map[string]any{"operation": "versions", "rule_uid": rule.UID})
		switch {
		case failure == nil:
			if versions, err := ruleVersions(text); err == nil && len(versions) > 0 {
				newest := versions[0]
				rule.Version, rule.Updated, rule.Threshold = newest.Version, newest.Updated, newest.Threshold
				rule.DatasourceUID = newest.datasourceUID
				if rule.Expr == "" {
					rule.Expr = newest.Expr
				}
				return
			}
		case failure.code == protocol.CodeUpstream4xx:
			d.noVersions = true
		}
	}
	text, failure := d.call(d.tool, map[string]any{"operation": "get", "rule_uid": rule.UID})
	if failure != nil {
		return
	}
	var detail ruleDetail
	if err := json.Unmarshal([]byte(text), &detail); err != nil {
		return
	}
	expr, datasourceUID, threshold := ruleCondition(detail.Condition, detail.Data)
	if rule.Expr == "" {
		rule.Expr = expr
	}
	rule.DatasourceUID, rule.Threshold = datasourceUID, threshold
}

// addDetails reads the details of the first rules of a list and says in a skipped note when
// it stopped for time.
func (d *detailReader) addDetails(rules []protocol.AlertRule) (skipped []string) {
	count := min(len(rules), alertRuleDetailLimit)
	for i := range count {
		if d.outOfTime() {
			return []string{fmt.Sprintf("the details of %d alert rules were not read because the command ran out of time", count-i)}
		}
		d.add(&rules[i])
	}
	if !d.deadline.IsZero() && !time.Now().Before(d.deadline) {
		return []string{"the details of some alert rules were cut short because the command ran out of time"}
	}
	return nil
}
