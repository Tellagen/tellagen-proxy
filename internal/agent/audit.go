package agent

import (
	"encoding/json"
	"io"
	"sync"
	"time"

	"github.com/tellagen/tellagen-proxy/protocol"
)

// AuditLine is the JSON line the proxy writes to stdout for each command. It
// holds no token, no result body and no log text.
type AuditLine struct {
	Time             time.Time          `json:"time"`
	Event            string             `json:"event"`
	CommandID        string             `json:"command_id"`
	Attempt          int                `json:"attempt"`
	RunID            string             `json:"run_id,omitempty"`
	IncidentRef      string             `json:"incident_ref,omitempty"`
	Initiator        protocol.Initiator `json:"initiator"`
	Kind             string             `json:"kind"`
	DatasourceUID    string             `json:"datasource_uid,omitempty"`
	Query            string             `json:"query"`
	RangeFrom        *time.Time         `json:"range_from,omitempty"`
	RangeTo          *time.Time         `json:"range_to,omitempty"`
	StepSeconds      int                `json:"step_seconds,omitempty"`
	RequestedAt      time.Time          `json:"requested_at"`
	DurationMS       int                `json:"duration_ms"`
	Outcome          string             `json:"outcome"`
	OutcomeCode      string             `json:"outcome_code,omitempty"`
	OutcomeMessage   string             `json:"outcome_message,omitempty"`
	Series           int                `json:"series"`
	Points           int                `json:"points"`
	LogLinesReturned int                `json:"log_lines_returned"`
	LogLinesKept     int                `json:"log_lines_kept"`
	Bytes            int                `json:"bytes"`
	Truncated        bool               `json:"truncated"`
	RedactionCount   int                `json:"redaction_count"`
	Redactions       map[string]int     `json:"redactions,omitempty"`
	RedactionOff     bool               `json:"redaction_off"`
	PolicyRevision   string             `json:"policy_revision,omitempty"`
	QueryFingerprint string             `json:"query_fingerprint,omitempty"`
}

// auditWriter serializes audit lines on one writer.
type auditWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (a *auditWriter) write(line AuditLine) error {
	if a == nil || a.w == nil {
		return nil
	}
	data, err := json.Marshal(line)
	if err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	_, err = a.w.Write(append(data, '\n'))
	return err
}

// newAuditLine describes one finished command.
func newAuditLine(command protocol.Command, result protocol.CommandResult, requestedAt, finishedAt time.Time, policyRevision string, redactionOff bool) AuditLine {
	line := AuditLine{
		Time:             finishedAt.UTC(),
		Event:            "command",
		CommandID:        command.CommandID,
		Attempt:          command.Attempt,
		RunID:            command.RunID,
		IncidentRef:      command.IncidentRef,
		Initiator:        command.Initiator,
		Kind:             command.Capability,
		RequestedAt:      requestedAt.UTC(),
		DurationMS:       result.DurationMS,
		Outcome:          result.Status,
		Bytes:            result.Bytes,
		Truncated:        result.Truncated,
		RedactionCount:   result.Redactions,
		Redactions:       result.RedactionsByKind,
		RedactionOff:     redactionOff,
		PolicyRevision:   policyRevision,
		QueryFingerprint: result.QueryFingerprint,
	}
	if args, err := protocol.ParseArgs(command.Capability, command.Args); err == nil {
		summary := args.Summary()
		line.DatasourceUID, line.Query = summary.DatasourceUID, summary.Query
		line.RangeFrom, line.RangeTo, line.StepSeconds = summary.Start, summary.End, summary.StepS
	}
	if result.Error != nil {
		line.OutcomeCode, line.OutcomeMessage = result.Error.Code, result.Error.Message
	}
	if data := result.Data; data != nil {
		line.Series = len(data.Series) + len(data.Samples)
		for _, series := range data.Series {
			line.Points += len(series.Values)
		}
		line.Points += len(data.Samples)
		line.LogLinesReturned, line.LogLinesKept = max(data.LinesTotal, len(data.Lines)), len(data.Lines)
	}
	return line
}
