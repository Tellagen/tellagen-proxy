// Package protocol defines the messages that tellagen-proxy and Tellagen exchange
// on the /api/proxy/v1 routes. Golden files pin their JSON. It imports only the
// standard library.
package protocol

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

const (
	// ProtocolVersion is the protocol version this build speaks.
	ProtocolVersion = "1"
	// SchemaHello names the hello message.
	SchemaHello = "tellagen.proxy.hello/v1"
)

// Poll modes. A proxy falls back to short polling when a corporate proxy cuts its
// held requests, and reports the mode on every poll.
const (
	PollModeLong  = "long_poll"
	PollModeShort = "short_poll"
)

// Health words of a source and of one doctor check.
const (
	HealthOK          = "ok"
	HealthDegraded    = "degraded"
	HealthUnavailable = "unavailable"

	DoctorOK   = "ok"
	DoctorFail = "fail"
	DoctorSkip = "skip"
)

// SessionReply carries the short-lived session token the proxy keeps in memory.
type SessionReply struct {
	SessionToken string    `json:"session_token"`
	ExpiresAt    time.Time `json:"expires_at"`
	ServerTime   time.Time `json:"server_time"`
}

// Hello is the first message after a token exchange. The session decides the
// workspace; a proxy never sends a company id.
type Hello struct {
	Schema             string       `json:"schema"`
	ProxyVersion       string       `json:"proxy_version"`
	ProtocolVersions   []string     `json:"protocol_versions"`
	InstanceID         string       `json:"instance_id"`
	InstallMethod      string       `json:"install_method,omitempty"`
	Labels             Labels       `json:"labels,omitempty"`
	Capabilities       []Capability `json:"capabilities"`
	CapabilitiesDigest string       `json:"capabilities_digest"`
	PolicyRevision     string       `json:"policy_revision"`
	Policy             PolicyReport `json:"policy"`
	Executor           Executor     `json:"executor"`
	Doctor             Doctor       `json:"doctor"`
	Sources            []Source     `json:"sources"`
}

// Labels are the free-form labels a proxy reports about itself, such as its
// environment and cluster.
type Labels map[string]string

// Executor says what runs the capabilities inside the proxy.
type Executor struct {
	Kind    string `json:"kind"`
	Version string `json:"version"`
	Mode    string `json:"mode"`
}

// PolicyReport is what the local policy file allows and which requested settings
// it stopped. The limit of each capability is in Hello.Capabilities.
type PolicyReport struct {
	DatasourceUIDs    []string        `json:"datasource_uids,omitempty"`
	MaxCommandsPerRun int             `json:"max_commands_per_run,omitempty"`
	RedactionAllowOff bool            `json:"redaction_allow_off"`
	Capped            []CappedSetting `json:"capped,omitempty"`
}

// CappedSetting is one setting from Tellagen that the policy file did not let
// through: the proxy ignored the requested value and applied its own.
type CappedSetting struct {
	Setting   string `json:"setting"`
	Requested string `json:"requested"`
	Applied   string `json:"applied"`
	Reason    string `json:"reason"`
}

// Doctor is the short doctor summary a proxy runs at start.
type Doctor struct {
	TLS              string          `json:"tls"`
	Grafana          string          `json:"grafana"`
	GrafanaLatencyMS int             `json:"grafana_latency_ms,omitempty"`
	GrafanaRole      string          `json:"grafana_role,omitempty"`
	Warnings         []string        `json:"warnings,omitempty"`
	Failures         []DoctorFailure `json:"failures,omitempty"`
}

// DoctorFailure is one failed check, with the sentence the setup page shows.
type DoctorFailure struct {
	Check   string `json:"check"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Source is one Grafana behind the proxy. PublicURL is the address people open;
// the address the proxy itself uses never leaves the customer network.
// PublicURLNetwork is NetworkPrivate when that address resolves only to private
// addresses, so a browser reaches it only from the company network or a VPN.
type Source struct {
	Key              string             `json:"key"`
	PublicURL        string             `json:"public_url,omitempty"`
	PublicURLNetwork string             `json:"public_url_network,omitempty"`
	GrafanaVersion   string             `json:"grafana_version,omitempty"`
	Health           string             `json:"health"`
	Datasources      []SourceDatasource `json:"datasources"`
}

// NetworkPrivate is the value of Source.PublicURLNetwork for a private address.
const NetworkPrivate = "private"

// SourceDatasource is one datasource that Grafana reported.
type SourceDatasource struct {
	UID     string `json:"uid"`
	Name    string `json:"name"`
	Type    string `json:"type"`
	Default bool   `json:"default,omitempty"`
}

// HelloReply answers a hello. Policy is the current narrowing, so a proxy that
// just started does not wait for its first poll.
type HelloReply struct {
	ProtocolVersion string        `json:"protocol_version"`
	Status          string        `json:"status"`
	Poll            PollSettings  `json:"poll"`
	ServerTime      time.Time     `json:"server_time"`
	Policy          *PolicyUpdate `json:"policy,omitempty"`
}

// HelloStatusActive is the status of a proxy that may poll.
const HelloStatusActive = "active"

// PollSettings tells the proxy how long to hold a poll.
type PollSettings struct {
	WaitMS int `json:"wait_ms"`
}

// PollRequest is the body of a poll. A poll is also the heartbeat and renews the
// leases of the commands in InFlight.
type PollRequest struct {
	InstanceID            string         `json:"instance_id"`
	WaitMS                int            `json:"wait_ms"`
	Mode                  string         `json:"mode"`
	FreeSlots             int            `json:"free_slots"`
	AppliedPolicyRevision string         `json:"applied_policy_revision,omitempty"`
	InFlight              []InFlight     `json:"in_flight,omitempty"`
	SourcesHealth         []SourceHealth `json:"sources_health,omitempty"`
}

// InFlight is one command the proxy is running.
type InFlight struct {
	CommandID string `json:"command_id"`
	Attempt   int    `json:"attempt"`
	ElapsedMS int    `json:"elapsed_ms"`
}

// SourceHealth is the latest cheap Grafana check of one source.
type SourceHealth struct {
	Key       string     `json:"key"`
	Health    string     `json:"health"`
	Code      string     `json:"code,omitempty"`
	Message   string     `json:"message,omitempty"`
	CheckedAt *time.Time `json:"checked_at,omitempty"`
}

// PollReply answers a poll with zero or more messages.
type PollReply struct {
	Messages []PollMessage `json:"messages"`
}

// Message types of a poll reply.
const (
	MessageCommand      = "command"
	MessageCancel       = "cancel"
	MessagePolicyUpdate = "policy_update"
)

// PollMessage is one message of a poll reply. Exactly one field is set. A
// message of a type this build does not know decodes with no field set, and the
// proxy ignores it.
type PollMessage struct {
	Command      *Command
	Cancel       *Cancel
	PolicyUpdate *PolicyUpdate
}

// Command asks the proxy to run one capability. Its Limits can only lower what
// the policy file allows.
type Command struct {
	CommandID         string          `json:"command_id"`
	Attempt           int             `json:"attempt"`
	AttemptToken      string          `json:"attempt_token"`
	RunID             string          `json:"run_id,omitempty"`
	IncidentRef       string          `json:"incident_ref,omitempty"`
	Initiator         Initiator       `json:"initiator"`
	Capability        string          `json:"capability"`
	CapabilityVersion int             `json:"capability_version"`
	Args              json.RawMessage `json:"args"`
	Limits            Limits          `json:"limits"`
	DeadlineMS        int             `json:"deadline_ms"`
	LeaseMS           int             `json:"lease_ms"`
}

// Initiator says who asked for a command, for the proxy's audit lines.
type Initiator struct {
	Kind string `json:"kind"`
	ID   string `json:"id,omitempty"`
}

// Initiator kinds: a person, or Tellagen itself.
const (
	InitiatorUser   = "user"
	InitiatorSystem = "system"
)

// Cancel asks the proxy to stop a running command.
type Cancel struct {
	CommandID string `json:"command_id"`
	Reason    string `json:"reason"`
}

// Cancel reasons.
const (
	CancelReasonRunCancelled = "run_cancelled"
	CancelReasonDeadline     = "deadline"
	CancelReasonDatasource   = "datasource_not_allowed"
	CancelReasonLeaseLost    = "lease_lost"
	CancelReasonCallerGone   = "caller_gone"
)

// PolicyUpdate carries the settings an admin chose in Tellagen. The proxy applies
// them only inside its policy file: Narrow can only tighten it, and Data is
// capped by it and reported back in the next hello.
type PolicyUpdate struct {
	Revision string       `json:"revision"`
	Narrow   PolicyNarrow `json:"narrow"`
	Data     PolicyData   `json:"data"`
}

// PolicyNarrow lowers what the policy file allows. DatasourceUIDs is always
// present: an empty list allows no datasource. Limits is keyed by capability
// family (see CapabilityFamily).
type PolicyNarrow struct {
	DatasourceUIDs    []string          `json:"datasource_uids"`
	Limits            map[string]Limits `json:"limits,omitempty"`
	MaxCommandsPerRun int               `json:"max_commands_per_run,omitempty"`
}

// PolicyData is the "AI and data" block. The proxy returns the points in both
// metrics modes, because Tellagen draws charts from them.
type PolicyData struct {
	Metrics    string          `json:"metrics"`
	LogLines   int             `json:"log_lines"`
	Redaction  string          `json:"redaction"`
	ExtraRules []RedactionRule `json:"extra_rules,omitempty"`
}

// Values of PolicyData.Metrics and PolicyData.Redaction.
const (
	MetricsSummaries = "summaries"
	MetricsPoints    = "points"

	RedactionOn  = "on"
	RedactionOff = "off"
)

// RedactionRule is one extra redaction rule: a field key or a pattern.
type RedactionRule struct {
	Kind  string `json:"kind"`
	Key   string `json:"key,omitempty"`
	Regex string `json:"regex,omitempty"`
}

// Kinds of RedactionRule.
const (
	RedactionRuleKey     = "key"
	RedactionRulePattern = "pattern"
)

// AcceptedReply answers a command result that Tellagen kept.
type AcceptedReply struct {
	Accepted bool `json:"accepted"`
}

// Error codes of ErrorReply, the body of every refused machine request.
const (
	ErrorTokenInvalid    = "proxy_token_invalid"
	ErrorSessionInvalid  = "proxy_session_invalid"
	ErrorRevoked         = "proxy_revoked"
	ErrorUpgradeRequired = "proxy_upgrade_required"
	ErrorResultConflict  = "proxy_result_conflict"
	ErrorStaleAttempt    = "proxy_stale_attempt"
	ErrorCompanyDisabled = "company_disabled"
	ErrorInternal        = "internal_error"
	ErrorInvalidMessage  = "invalid_message"
	ErrorTooManyReplicas = "proxy_too_many_replicas"

	// ErrorCloudDiagnosisDisabled means cloud diagnosis is off for the workspace.
	ErrorCloudDiagnosisDisabled = "cloud_diagnosis_disabled"
)

// ErrorReply is the body of a refused machine request. RevokedAt is set only for
// ErrorRevoked after the secret matched, so doctor can say when the proxy was
// revoked. MinVersion is set only for ErrorUpgradeRequired.
type ErrorReply struct {
	Code       string     `json:"code"`
	Message    string     `json:"message"`
	MinVersion string     `json:"min_version,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
}

// MarshalJSON writes the message with its type field.
func (m PollMessage) MarshalJSON() ([]byte, error) {
	switch {
	case m.Command != nil:
		return json.Marshal(struct {
			Type string `json:"type"`
			*Command
		}{MessageCommand, m.Command})
	case m.Cancel != nil:
		return json.Marshal(struct {
			Type string `json:"type"`
			*Cancel
		}{MessageCancel, m.Cancel})
	case m.PolicyUpdate != nil:
		return json.Marshal(struct {
			Type string `json:"type"`
			*PolicyUpdate
		}{MessagePolicyUpdate, m.PolicyUpdate})
	}
	return nil, errors.New("protocol: poll message has no payload")
}

// UnmarshalJSON reads the message by its type field.
func (m *PollMessage) UnmarshalJSON(data []byte) error {
	var head struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(data, &head); err != nil {
		return err
	}
	*m = PollMessage{}
	switch head.Type {
	case MessageCommand:
		m.Command = &Command{}
		return json.Unmarshal(data, m.Command)
	case MessageCancel:
		m.Cancel = &Cancel{}
		return json.Unmarshal(data, m.Cancel)
	case MessagePolicyUpdate:
		m.PolicyUpdate = &PolicyUpdate{}
		return json.Unmarshal(data, m.PolicyUpdate)
	}
	return nil
}

// NegotiateVersion picks the protocol version both sides speak. It reports false
// when the proxy speaks none that this build supports, which is a 426.
func NegotiateVersion(offered []string) (string, bool) {
	if slices.Contains(offered, ProtocolVersion) {
		return ProtocolVersion, true
	}
	return "", false
}

// Validate reports the first problem that makes a hello unusable. A capability
// this build does not know is not a problem: after a rollback a newer proxy may
// offer one, and Tellagen simply never asks for it.
func (h Hello) Validate() error {
	switch {
	case h.Schema != SchemaHello:
		return fmt.Errorf("schema must be %s", SchemaHello)
	case strings.TrimSpace(h.ProxyVersion) == "":
		return errors.New("proxy_version is required")
	case len(h.ProtocolVersions) == 0:
		return errors.New("protocol_versions is required")
	case strings.TrimSpace(h.InstanceID) == "":
		return errors.New("instance_id is required")
	}
	for _, capability := range h.Capabilities {
		if strings.TrimSpace(capability.Name) == "" {
			return errors.New("a capability needs a name")
		}
	}
	return nil
}

// Validate reports the first problem that makes a poll unusable.
func (p PollRequest) Validate() error {
	switch {
	case strings.TrimSpace(p.InstanceID) == "":
		return errors.New("instance_id is required")
	case p.Mode != PollModeLong && p.Mode != PollModeShort:
		return fmt.Errorf("mode must be %s or %s", PollModeLong, PollModeShort)
	case p.WaitMS < 0:
		return errors.New("wait_ms must not be negative")
	case p.FreeSlots < 0:
		return errors.New("free_slots must not be negative")
	}
	return nil
}
