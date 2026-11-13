package policy

import (
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tellagen/tellagen-proxy/protocol"
	"github.com/tellagen/tellagen-proxy/redact"
)

// Engine holds the policy file and the latest narrowing from Tellagen. A command
// reads one View and Apply publishes a new one, so no command sees half an update.
type Engine struct {
	file    *File
	binary  map[string]protocol.Capability
	current atomic.Pointer[View]
	applyMu sync.Mutex
}

// View is the policy as it stands at one moment. It never changes.
type View struct {
	file      *File
	binary    map[string]protocol.Capability
	revision  string
	allowed   map[string]bool
	narrow    map[string]protocol.Limits
	maxPerRun int
	logLines  int
	off       bool
	redactor  *redact.Redactor
	capped    []protocol.CappedSetting
}

// NewEngine returns an Engine with nothing narrowed yet: until the first
// policy_update, no datasource is allowed, log lines are off and redaction is on.
func NewEngine(file *File) *Engine {
	binary := map[string]protocol.Capability{}
	for _, capability := range protocol.Capabilities() {
		binary[capability.Name] = capability
	}
	engine := &Engine{file: file, binary: binary}
	// parseFile checked the file's rules, so New reports nothing here.
	redactor, _ := redact.New(file.ExtraRules)
	engine.current.Store(&View{
		file:      file,
		binary:    binary,
		allowed:   map[string]bool{},
		maxPerRun: file.MaxPerRun,
		redactor:  redactor,
	})
	return engine
}

// File returns the policy file the Engine was built from.
func (e *Engine) File() *File {
	return e.file
}

// Current returns the policy as it stands now.
func (e *Engine) Current() *View {
	return e.current.Load()
}

// Apply narrows the policy file with an update from Tellagen and returns the new
// View. Whatever asks for more than the file allows is held to the file and
// reported in the next hello.
func (e *Engine) Apply(update protocol.PolicyUpdate) *View {
	e.applyMu.Lock()
	defer e.applyMu.Unlock()

	file := e.file
	view := &View{file: file, binary: e.binary, revision: update.Revision, allowed: map[string]bool{}, narrow: map[string]protocol.Limits{}}
	report := func(setting, requested, applied, reason string) {
		view.capped = append(view.capped, protocol.CappedSetting{Setting: setting, Requested: requested, Applied: applied, Reason: reason})
	}

	for _, uid := range update.Narrow.DatasourceUIDs {
		if file.DatasourceUIDs != nil && !slices.Contains(file.DatasourceUIDs, uid) {
			report("datasource_uids", uid, "not allowed", "The policy file does not list this datasource.")
			continue
		}
		view.allowed[uid] = true
	}

	for family, requested := range update.Narrow.Limits {
		ceiling, known := file.limits[family]
		if !known {
			report("limits."+family, "set", "ignored", "This proxy has no capability family with this name.")
			continue
		}
		for _, field := range limitFields(requested) {
			highest := field.get(ceiling)
			if value := field.get(requested); value > highest && highest > 0 {
				report("limits."+family+"."+field.name, strconv.Itoa(value), strconv.Itoa(highest), "The policy file sets a lower highest value.")
			}
		}
		view.narrow[family] = requested
	}

	view.maxPerRun = file.MaxPerRun
	if requested := update.Narrow.MaxCommandsPerRun; requested > 0 {
		if requested > file.MaxPerRun {
			report("max_commands_per_run", strconv.Itoa(requested), strconv.Itoa(file.MaxPerRun), "The policy file sets a lower highest value.")
		} else {
			view.maxPerRun = requested
		}
	}

	view.logLines = max(update.Data.LogLines, 0)
	if highest := file.limits[protocol.FamilyLoki].MaxLines; view.logLines > highest {
		report("log_lines", strconv.Itoa(update.Data.LogLines), strconv.Itoa(highest), "The policy file sets a lower highest value.")
		view.logLines = highest
	}

	view.off = update.Data.Redaction == protocol.RedactionOff
	if view.off && !file.RedactionAllowOff {
		report("redaction", protocol.RedactionOff, protocol.RedactionOn, "The policy file does not allow redaction off.")
		view.off = false
	}

	rules := slices.Concat(file.ExtraRules, update.Data.ExtraRules)
	var errs []redact.RuleError
	if view.off {
		view.redactor, errs = redact.NewExtraOnly(rules)
	} else {
		view.redactor, errs = redact.New(rules)
	}
	for _, ruleError := range errs {
		report("extra_rules", ruleError.Rule.Key+ruleError.Rule.Regex, "ignored", ruleError.Reason)
	}

	e.current.Store(view)
	return view
}

// Revision returns the revision of the update this View came from, or "" before
// the first update.
func (v *View) Revision() string {
	return v.revision
}

// CapabilityAllowed reports whether the policy file allows a capability.
func (v *View) CapabilityAllowed(capability string) bool {
	if _, known := v.binary[capability]; !known {
		return false
	}
	return v.file.Capabilities == nil || slices.Contains(v.file.Capabilities, capability)
}

// DatasourceAllowed reports whether both the policy file and Tellagen allow a
// datasource.
func (v *View) DatasourceAllowed(uid string) bool {
	return v.allowed[uid]
}

// Limits returns the limits of one command: the smallest of the binary, the policy
// file, Tellagen's narrowing and the command.
func (v *View) Limits(capability string, command protocol.Limits) protocol.Limits {
	family := protocol.CapabilityFamily(capability)
	narrow := v.narrow[family]
	limits := v.binary[capability].Limits.Narrow(v.file.limits[family]).Narrow(narrow).Narrow(command)
	if narrow.TimeoutMS <= 0 && command.TimeoutMS <= 0 {
		limits.TimeoutMS = min(limits.TimeoutMS, int(DefaultQueryTimeout/time.Millisecond))
	}
	return limits
}

// MaxCommandsPerRun returns how many commands that read data one run may send.
func (v *View) MaxCommandsPerRun() int {
	return v.maxPerRun
}

// MaxListCommandsPerRun returns how many list and search commands one run may send.
// Only the policy file sets it, at most protocol.DiscoveryCommandsPerRun.
func (v *View) MaxListCommandsPerRun() int {
	return v.file.MaxListPerRun
}

// LogLines returns how many log lines a query may return. Zero means log lines are
// off: a log query returns only counts, and each label value is cut short.
func (v *View) LogLines() int {
	return v.logLines
}

// RedactionOff reports whether an admin turned redaction off and the policy file
// allowed it.
func (v *View) RedactionOff() bool {
	return v.off
}

// Redactor returns the rules that apply now.
func (v *View) Redactor() *redact.Redactor {
	return v.redactor
}

// Capabilities returns what the hello reports: the capabilities the policy file
// allows, with the highest limit of each field that the capability has.
func (v *View) Capabilities() []protocol.Capability {
	var out []protocol.Capability
	for _, capability := range protocol.Capabilities() {
		if !v.CapabilityAllowed(capability.Name) {
			continue
		}
		highest := capability.Limits.Narrow(v.file.limits[protocol.CapabilityFamily(capability.Name)])
		capability.Limits = keepFieldsOf(capability.Limits, highest)
		out = append(out, capability)
	}
	return out
}

// Report returns what the hello says about the policy file and which settings from
// Tellagen it stopped.
func (v *View) Report() protocol.PolicyReport {
	return protocol.PolicyReport{
		DatasourceUIDs:    slices.Clone(v.file.DatasourceUIDs),
		MaxCommandsPerRun: v.file.MaxPerRun,
		RedactionAllowOff: v.file.RedactionAllowOff,
		Capped:            slices.Clone(v.capped),
	}
}

type limitField struct {
	name string
	get  func(protocol.Limits) int
}

var allLimitFields = []limitField{
	{"max_range_s", func(l protocol.Limits) int { return l.MaxRangeS }},
	{"max_points", func(l protocol.Limits) int { return l.MaxPoints }},
	{"max_series", func(l protocol.Limits) int { return l.MaxSeries }},
	{"timeout_ms", func(l protocol.Limits) int { return l.TimeoutMS }},
	{"max_result_bytes", func(l protocol.Limits) int { return l.MaxResultBytes }},
	{"max_lines", func(l protocol.Limits) int { return l.MaxLines }},
	{"max_line_chars", func(l protocol.Limits) int { return l.MaxLineChars }},
	{"max_patterns", func(l protocol.Limits) int { return l.MaxPatterns }},
	{"max_items", func(l protocol.Limits) int { return l.MaxItems }},
}

// limitFields returns the fields set in limits, in a fixed order, so a report does
// not change between two applies of one update.
func limitFields(limits protocol.Limits) []limitField {
	return slices.DeleteFunc(slices.Clone(allLimitFields), func(field limitField) bool {
		return field.get(limits) <= 0
	})
}

func keepFieldsOf(shape, values protocol.Limits) protocol.Limits {
	keep := func(s, v int) int {
		if s <= 0 {
			return 0
		}
		return v
	}
	return protocol.Limits{
		MaxRangeS:      keep(shape.MaxRangeS, values.MaxRangeS),
		MaxPoints:      keep(shape.MaxPoints, values.MaxPoints),
		MaxSeries:      keep(shape.MaxSeries, values.MaxSeries),
		TimeoutMS:      keep(shape.TimeoutMS, values.TimeoutMS),
		MaxResultBytes: keep(shape.MaxResultBytes, values.MaxResultBytes),
		MaxLines:       keep(shape.MaxLines, values.MaxLines),
		MaxLineChars:   keep(shape.MaxLineChars, values.MaxLineChars),
		MaxPatterns:    keep(shape.MaxPatterns, values.MaxPatterns),
		MaxItems:       keep(shape.MaxItems, values.MaxItems),
	}
}
