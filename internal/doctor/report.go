// Package doctor checks step by step whether the proxy can reach Tellagen and
// Grafana, and says what to do about each failure.
package doctor

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/tellagen/tellagen-proxy/protocol"
)

// Status of one check.
type Status string

// The four statuses. A warning does not fail the run.
const (
	OK   Status = "ok"
	Fail Status = "fail"
	Warn Status = "warn"
	Skip Status = "skip"
)

// Result is one line of the report.
type Result struct {
	Check   string `json:"check"`
	Status  Status `json:"status"`
	Code    string `json:"code,omitempty"`
	Message string `json:"message"`
	// More holds the continuation lines: the fix of a failure, or a hint for a
	// warning.
	More []string `json:"more,omitempty"`

	// public is the sentence that goes to Tellagen in the hello.
	public string
}

// Report is the outcome of a run.
type Report struct {
	Version string   `json:"version"`
	Results []Result `json:"results"`

	// Latency and role feed the hello summary.
	grafanaLatencyMS int
	grafanaRole      string
}

// Failed reports whether any check failed.
func (r *Report) Failed() bool {
	for _, result := range r.Results {
		if result.Status == Fail {
			return true
		}
	}
	return false
}

func (r *Report) add(check string, status Status, code, message string, more ...string) {
	r.Results = append(r.Results, Result{Check: check, Status: status, Code: code, Message: message, More: more})
}

func (r *Report) find(check string) (Result, bool) {
	for _, result := range r.Results {
		if result.Check == check {
			return result, true
		}
	}
	return Result{}, false
}

// status returns the status of the first check with this name, or Skip.
func (r *Report) status(check string) Status {
	if result, ok := r.find(check); ok {
		return result.Status
	}
	return Skip
}

// HelpURL is the guide that explains the doctor output.
const HelpURL = "https://tellagen.com/help/read-the-proxy-doctor-output"

// Write prints the report as text: one line per check, its continuation lines
// under it, and the address of the guide.
func (r *Report) Write(w io.Writer) {
	_, _ = fmt.Fprintf(w, "tellagen-proxy doctor (%s)\n", r.Version)
	for _, result := range r.Results {
		_, _ = fmt.Fprintf(w, "%-7s%-9s%s\n", "["+string(result.Status)+"]", result.Check, result.Message)
		for _, line := range result.More {
			_, _ = fmt.Fprintf(w, "         %s\n", line)
		}
	}
	if line := helpLine(HelpURL); line != "" {
		_, _ = fmt.Fprintln(w, line)
	}
}

// helpLine is the last line of the text report, or "" without an address.
func helpLine(url string) string {
	if url == "" {
		return ""
	}
	return "Help with each line: " + url
}

// WriteJSON prints the report as JSON. Every message is already free of secrets,
// so the report can go to support as it is.
func (r *Report) WriteJSON(w io.Writer) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(r)
}

// Summary is the short result that goes into the hello.
func (r *Report) Summary() protocol.Doctor {
	summary := protocol.Doctor{
		TLS:              word(r.status("tls")),
		Grafana:          r.grafanaWord(),
		GrafanaLatencyMS: r.grafanaLatencyMS,
		GrafanaRole:      r.grafanaRole,
	}
	for _, result := range r.Results {
		switch result.Status {
		case Warn:
			summary.Warnings = append(summary.Warnings, result.Code)
		case Fail:
			message := result.public
			if message == "" {
				message = "This check failed."
			}
			summary.Failures = append(summary.Failures, protocol.DoctorFailure{Check: result.Check, Code: result.Code, Message: message})
		}
	}
	return summary
}

func (r *Report) grafanaWord() string {
	word := protocol.DoctorSkip
	for _, result := range r.Results {
		if result.Check != "grafana" {
			continue
		}
		switch result.Status {
		case Fail:
			return protocol.DoctorFail
		case OK:
			word = protocol.DoctorOK
		}
	}
	return word
}

func word(status Status) string {
	switch status {
	case OK:
		return protocol.DoctorOK
	case Fail:
		return protocol.DoctorFail
	}
	return protocol.DoctorSkip
}
