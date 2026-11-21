// Package redact removes personal data and secrets from command results. The
// proxy runs it before a result leaves, and Tellagen runs it again on receipt.
package redact

import (
	"fmt"
	"maps"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"unicode"

	"github.com/tellagen/tellagen-proxy/protocol"
)

// Kinds of redaction, the keys of protocol.CommandResult.RedactionsByKind.
const (
	KindEmail = "email"
	KindIP    = "ip"
	KindToken = "token"
	KindKey   = "key"
	KindCard  = "card"
	KindField = "field"
	KindRule  = "rule"
)

const (
	placeholderPrefix = "[redacted:"

	// MaxExtraRules bounds the extra rules of one policy.
	MaxExtraRules = 50
	// MaxRuleChars bounds one extra rule's key or regex.
	MaxRuleChars = 512
)

func placeholder(kind string) string {
	return placeholderPrefix + kind + "]"
}

// RulePlaceholder is what an extra rule leaves in place of a value.
var RulePlaceholder = placeholder(KindRule)

// Counts holds the number of values removed per kind.
type Counts map[string]int

// Total returns the number of values removed.
func (c Counts) Total() int {
	total := 0
	for _, n := range c {
		total += n
	}
	return total
}

// patternRule replaces every match of pattern. An accept func, when set, decides
// about each match: it keeps a version string that only looks like an address.
type patternRule struct {
	kind    string
	pattern *regexp.Regexp
	accept  func(string) bool
}

// builtinPatterns run in order. Whole-value shapes come first, so that an email
// inside a URL with credentials or a token inside an Authorization header is
// counted once.
var builtinPatterns = []patternRule{
	{kind: KindKey, pattern: regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----(?s:.*?)(?:-----END [A-Z ]*PRIVATE KEY-----|$)`)},
	{kind: KindToken, pattern: regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}(?:\.[A-Za-z0-9_-]*)?`)},
	{kind: KindToken, pattern: regexp.MustCompile(`\b[a-zA-Z][a-zA-Z0-9+.-]*://[^\s/:@"']+:[^\s/@"']+@`)},
	{kind: KindToken, pattern: regexp.MustCompile(`(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}`)},
	{kind: KindToken, pattern: regexp.MustCompile(`\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9_-]{20,}|glsa_[A-Za-z0-9_]{20,}|glc_[A-Za-z0-9+/=_-]{20,}|npm_[A-Za-z0-9]{20,}|xox[abeprs]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9_-]{20,}|[sr]k_live_[A-Za-z0-9]{10,}|tlg_[a-z]+_[A-Za-z0-9._-]{8,})`)},
	{kind: KindKey, pattern: regexp.MustCompile(`\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b`)},
	{kind: KindKey, pattern: regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}`)},
	{kind: KindKey, pattern: regexp.MustCompile(`(?i)\b(?:AccountKey|SharedAccessKey|SharedAccessSignature)=[^;\s"']+`)},
}

// The shapes below run after the key-name pass, so a password that holds an email
// is one field, not an email.
var (
	emailPattern = regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b`)
	cardPattern  = regexp.MustCompile(`\b[3-6]\d(?:[ -]?\d){11,17}\b`)
	ipv4Pattern  = regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}\b`)
	ipv6Pattern  = regexp.MustCompile(`\b[0-9A-Fa-f]{1,4}(?:::?[0-9A-Fa-f]{1,4}){1,7}(?:::)?\b`)

	// headerPattern takes the whole value of a header whose value has spaces.
	headerPattern = regexp.MustCompile(`(?i)\b(authorization|proxy[-_]?authorization|cookie|set-cookie)(\\?["']?\s*[:=]\s*)([^\r\n]*)`)
	// secretPhrasePattern takes the rest of the line after `password: ` and the like,
	// because a password can hold spaces. A quoted value is left to fieldPattern, and
	// the match stops at a double quote, so JSON around it stays valid.
	secretPhrasePattern = regexp.MustCompile(`(?i)\b([A-Za-z0-9_.-]*(?:password|passwd|passphrase|pwd|secret))([ \t]*:[ \t]*)((?:[^\s"':\\]|\\[^"\r\n])(?:[^\r\n"\\]|\\[^"\r\n])*)`)
	// fieldPattern finds a key and its value in key=value, key: value and JSON
	// text, including JSON escaped inside a string.
	fieldPattern = regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_.-]*)(\\?["']?\s*[:=]\s*)(\\"(?:[^"\\]|\\[^"])*\\"|"(?:[^"\\]|\\.)*"|'[^']*'|[^\s,;&}\])"']+)`)
)

// Redactor holds the built-in rules plus a policy's extra rules. Create one with
// New. It is safe for concurrent use.
type Redactor struct {
	builtins bool
	keys     map[string]bool
	patterns []*regexp.Regexp
}

// RuleError says why one extra rule was not applied.
type RuleError struct {
	Rule   protocol.RedactionRule
	Reason string
}

// New returns a Redactor with the built-in rules and the extra rules. A rule that
// cannot apply is left out and returned, so the caller can report it.
func New(extra []protocol.RedactionRule) (*Redactor, []RuleError) {
	r, errs := compileExtra(extra)
	r.builtins = true
	return r, errs
}

// NewExtraOnly returns a Redactor with only the extra rules. The proxy uses it
// when redaction is turned off: the rules of the local policy file stay on.
func NewExtraOnly(extra []protocol.RedactionRule) (*Redactor, []RuleError) {
	return compileExtra(extra)
}

func compileExtra(extra []protocol.RedactionRule) (*Redactor, []RuleError) {
	r := &Redactor{keys: map[string]bool{}}
	var errs []RuleError
	for i, rule := range extra {
		if i >= MaxExtraRules {
			errs = append(errs, RuleError{Rule: rule, Reason: fmt.Sprintf("at most %d extra rules apply", MaxExtraRules)})
			continue
		}
		switch rule.Kind {
		case protocol.RedactionRuleKey:
			key := normalizeKey(rule.Key)
			switch {
			case key == "":
				errs = append(errs, RuleError{Rule: rule, Reason: "the key is empty"})
			case len(rule.Key) > MaxRuleChars:
				errs = append(errs, RuleError{Rule: rule, Reason: fmt.Sprintf("the key is longer than %d characters", MaxRuleChars)})
			default:
				r.keys[key] = true
			}
		case protocol.RedactionRulePattern:
			compiled, reason := compilePattern(rule.Regex)
			if reason != "" {
				errs = append(errs, RuleError{Rule: rule, Reason: reason})
				continue
			}
			r.patterns = append(r.patterns, compiled)
		default:
			errs = append(errs, RuleError{Rule: rule, Reason: fmt.Sprintf("unknown rule kind %q", rule.Kind)})
		}
	}
	return r, errs
}

func compilePattern(source string) (*regexp.Regexp, string) {
	if source == "" {
		return nil, "the regex is empty"
	}
	if len(source) > MaxRuleChars {
		return nil, fmt.Sprintf("the regex is longer than %d characters", MaxRuleChars)
	}
	compiled, err := regexp.Compile(source)
	if err != nil {
		return nil, "the regex does not compile"
	}
	if compiled.MatchString("") {
		return nil, "the regex matches empty text"
	}
	return compiled, ""
}

// Text returns s with every match removed and adds what it removed to counts.
func (r *Redactor) Text(s string, counts Counts) string {
	if s == "" {
		return s
	}
	s = stripNUL(s)
	if r.builtins {
		for _, rule := range builtinPatterns {
			s = rule.replace(s, counts)
		}
		s = redactHeaders(s, counts)
		s = redactSecretPhrases(s, counts)
	}
	for _, pattern := range r.patterns {
		s = patternRule{kind: KindRule, pattern: pattern}.replace(s, counts)
	}
	s = r.redactFields(s, counts)
	if r.builtins {
		s = patternRule{kind: KindEmail, pattern: emailPattern}.replace(s, counts)
		s = patternRule{kind: KindCard, pattern: cardPattern, accept: isCardNumber}.replace(s, counts)
		s = patternRule{kind: KindIP, pattern: ipv4Pattern, accept: isIPAddress}.replace(s, counts)
		s = patternRule{kind: KindIP, pattern: ipv6Pattern, accept: isIPAddress}.replace(s, counts)
	}
	return s
}

func (rule patternRule) replace(s string, counts Counts) string {
	return rule.pattern.ReplaceAllStringFunc(s, func(match string) string {
		if rule.accept != nil && !rule.accept(match) {
			return match
		}
		if isPlaceholder(match) {
			return match
		}
		counts[rule.kind]++
		return placeholder(rule.kind)
	})
}

func redactHeaders(s string, counts Counts) string {
	return headerPattern.ReplaceAllStringFunc(s, func(match string) string {
		groups := headerPattern.FindStringSubmatch(match)
		value := strings.TrimSpace(groups[3])
		if value == "" || isOnlyPlaceholders(value) {
			return match
		}
		// An Authorization header whose credentials are already gone keeps the
		// rest of its line. A cookie header can hold more values after a token.
		if strings.HasSuffix(strings.ToLower(groups[1]), "authorization") && isPlaceholder(value) {
			return match
		}
		counts[KindField]++
		return groups[1] + groups[2] + placeholder(KindField)
	})
}

func redactSecretPhrases(s string, counts Counts) string {
	return secretPhrasePattern.ReplaceAllStringFunc(s, func(match string) string {
		groups := secretPhrasePattern.FindStringSubmatch(match)
		if isPlaceholder(groups[3]) {
			return match
		}
		counts[KindField]++
		return groups[1] + groups[2] + placeholder(KindField)
	})
}

// stripNUL removes NUL bytes. Postgres jsonb refuses them, so one NUL in a logged
// field would fail the whole result and hide the evidence around it.
func stripNUL(s string) string {
	return strings.ReplaceAll(s, "\x00", "")
}

func (r *Redactor) redactFields(s string, counts Counts) string {
	return fieldPattern.ReplaceAllStringFunc(s, func(match string) string {
		groups := fieldPattern.FindStringSubmatch(match)
		kind, ok := r.fieldKind(groups[1])
		if !ok {
			// The value of an ordinary key can hold a secret key of its own: a URL
			// with a query string, or JSON inside a string. It is shorter than the
			// match, so this ends.
			return groups[1] + groups[2] + r.redactFields(groups[3], counts)
		}
		if strings.Contains(groups[3], placeholderPrefix) {
			return match
		}
		counts[kind]++
		return groups[1] + groups[2] + quoteLike(groups[3], placeholder(kind))
	})
}

// quoteLike keeps the quotes of the original value, so JSON stays valid.
func quoteLike(original, replacement string) string {
	switch {
	case strings.HasPrefix(original, `\"`):
		return `\"` + replacement + `\"`
	case strings.HasPrefix(original, `"`):
		return `"` + replacement + `"`
	case strings.HasPrefix(original, `'`):
		return `'` + replacement + `'`
	}
	return replacement
}

// Labels returns labels with each value redacted. A secret key removes the whole
// value. It does not change the map it receives.
func (r *Redactor) Labels(labels map[string]string, counts Counts) map[string]string {
	if labels == nil {
		return nil
	}
	out := make(map[string]string, len(labels))
	for key, value := range labels {
		key = stripNUL(key)
		if kind, ok := r.fieldKind(key); ok && value != "" {
			if isOnlyPlaceholders(value) {
				out[key] = value
				continue
			}
			counts[kind]++
			out[key] = placeholder(kind)
			continue
		}
		out[key] = r.Text(value, counts)
	}
	return out
}

// MatchesKey reports whether a field with this key has its whole value removed.
func (r *Redactor) MatchesKey(key string) bool {
	_, ok := r.fieldKind(key)
	return ok
}

func (r *Redactor) fieldKind(key string) (string, bool) {
	normalized := normalizeKey(key)
	if r.keys[normalized] {
		return KindRule, true
	}
	if r.builtins && isSecretKey(normalized) {
		return KindField, true
	}
	return "", false
}

func isPlaceholder(s string) bool {
	return strings.HasPrefix(s, placeholderPrefix)
}

func isOnlyPlaceholders(s string) bool {
	for rest := strings.TrimSpace(s); rest != ""; rest = strings.TrimSpace(rest) {
		if !strings.HasPrefix(rest, placeholderPrefix) {
			return false
		}
		end := strings.IndexByte(rest, ']')
		if end < 0 {
			return false
		}
		rest = rest[end+1:]
	}
	return s != ""
}

// normalizeKey lowers a key and turns camelCase, dashes and dots into underscores,
// so that apiKey, api-key, API_KEY and APIKey are one key.
func normalizeKey(key string) string {
	runes := []rune(strings.TrimSpace(key))
	var b strings.Builder
	for i, c := range runes {
		switch {
		case c == '-' || c == '.' || c == ' ':
			b.WriteByte('_')
		case unicode.IsUpper(c):
			if i > 0 && startsWord(runes[i-1], runes[i+1:]) {
				b.WriteByte('_')
			}
			b.WriteRune(unicode.ToLower(c))
		default:
			b.WriteRune(c)
		}
	}
	return b.String()
}

// startsWord reports whether an upper-case letter after previous begins a new word,
// such as the P in DBPassword. A run of capitals on its own is one word.
func startsWord(previous rune, rest []rune) bool {
	if unicode.IsLower(previous) || unicode.IsDigit(previous) {
		return true
	}
	return unicode.IsUpper(previous) && len(rest) > 0 && unicode.IsLower(rest[0])
}

var secretKeys = map[string]bool{
	"password": true, "passwd": true, "pwd": true, "pass": true, "secret": true, "token": true, "jwt": true,
	"api_key": true, "apikey": true, "auth": true, "authorization": true, "cookie": true, "set_cookie": true,
	"session": true, "session_id": true, "sessionid": true, "credential": true, "credentials": true,
	"private_key": true, "access_key": true, "secret_key": true, "client_secret": true, "basic_auth": true,
	"proxy_authorization": true, "sig": true, "signature": true, "x_amz_signature": true, "x_amz_credential": true, "x_goog_signature": true,
	"full_name": true, "first_name": true, "last_name": true, "customer_name": true, "user_name": true, "username": true,
	"email": true, "email_address": true, "phone": true, "phone_number": true, "ssn": true,
}

var secretKeySuffixes = []string{"_token", "_secret", "_password", "_passwd", "_api_key", "_access_key", "_secret_key", "_private_key"}

func isSecretKey(normalized string) bool {
	if secretKeys[normalized] {
		return true
	}
	return slices.ContainsFunc(secretKeySuffixes, func(suffix string) bool {
		return strings.HasSuffix(normalized, suffix)
	})
}

func isIPAddress(s string) bool {
	_, err := netip.ParseAddr(s)
	return err == nil
}

// isCardNumber applies the Luhn check, which keeps long ids and timestamps out.
func isCardNumber(s string) bool {
	digits := make([]int, 0, len(s))
	for _, c := range s {
		if c >= '0' && c <= '9' {
			digits = append(digits, int(c-'0'))
		}
	}
	if len(digits) < 13 || len(digits) > 19 {
		return false
	}
	sum := 0
	for i, digit := range slices.Backward(digits) {
		if (len(digits)-1-i)%2 == 1 {
			digit *= 2
			if digit > 9 {
				digit -= 9
			}
		}
		sum += digit
	}
	return sum%10 == 0
}

// Data redacts every text field of a result in place and returns what it removed.
// Numbers, times, and the ids that identify a source stay as they are.
func (r *Redactor) Data(data *protocol.ResultData) Counts {
	counts := Counts{}
	if data == nil {
		return counts
	}
	for i := range data.Series {
		data.Series[i].Labels = r.Labels(data.Series[i].Labels, counts)
	}
	for i := range data.Samples {
		data.Samples[i].Labels = r.Labels(data.Samples[i].Labels, counts)
	}
	for i := range data.Lines {
		data.Lines[i].Labels = r.Labels(data.Lines[i].Labels, counts)
		data.Lines[i].Text = r.Text(data.Lines[i].Text, counts)
	}
	for i := range data.Patterns {
		data.Patterns[i].Pattern = r.Text(data.Patterns[i].Pattern, counts)
	}
	for i := range data.Names {
		data.Names[i] = r.Text(data.Names[i], counts)
	}
	for i := range data.Datasources {
		data.Datasources[i].UID = stripNUL(data.Datasources[i].UID)
		data.Datasources[i].Type = stripNUL(data.Datasources[i].Type)
		data.Datasources[i].Name = r.Text(data.Datasources[i].Name, counts)
	}
	for i := range data.Dashboards {
		data.Dashboards[i].UID = stripNUL(data.Dashboards[i].UID)
		data.Dashboards[i].Title = r.Text(data.Dashboards[i].Title, counts)
		data.Dashboards[i].Folder = r.Text(data.Dashboards[i].Folder, counts)
	}
	for i := range data.PanelQueries {
		data.PanelQueries[i].DatasourceUID = stripNUL(data.PanelQueries[i].DatasourceUID)
		data.PanelQueries[i].Title = r.Text(data.PanelQueries[i].Title, counts)
		data.PanelQueries[i].Expr = r.Text(data.PanelQueries[i].Expr, counts)
	}
	for i := range data.AlertRules {
		data.AlertRules[i].UID = stripNUL(data.AlertRules[i].UID)
		data.AlertRules[i].State = stripNUL(data.AlertRules[i].State)
		data.AlertRules[i].Title = r.Text(data.AlertRules[i].Title, counts)
		data.AlertRules[i].Expr = r.Text(data.AlertRules[i].Expr, counts)
		data.AlertRules[i].For = stripNUL(data.AlertRules[i].For)
		data.AlertRules[i].Labels = r.Labels(data.AlertRules[i].Labels, counts)
		if threshold := data.AlertRules[i].Threshold; threshold != nil {
			threshold.Op = stripNUL(threshold.Op)
		}
	}
	for i := range data.AlertRuleVersions {
		data.AlertRuleVersions[i].Expr = r.Text(data.AlertRuleVersions[i].Expr, counts)
		if threshold := data.AlertRuleVersions[i].Threshold; threshold != nil {
			threshold.Op = stripNUL(threshold.Op)
		}
	}
	return counts
}

// Result redacts a command result in place, including its error message and its
// skipped parts, and adds what it removed to the result's counts. Text that is
// already redacted is left alone, so a value is counted once.
func (r *Redactor) Result(result *protocol.CommandResult) {
	counts := r.Data(result.Data)
	if result.Error != nil {
		result.Error.Message = r.Text(result.Error.Message, counts)
	}
	for i := range result.Skipped {
		result.Skipped[i] = r.Text(result.Skipped[i], counts)
	}
	addCounts(result, counts)
}

func addCounts(result *protocol.CommandResult, counts Counts) {
	if len(counts) == 0 {
		return
	}
	merged := maps.Clone(result.RedactionsByKind)
	if merged == nil {
		merged = map[string]int{}
	}
	for kind, n := range counts {
		merged[kind] += n
	}
	result.RedactionsByKind = merged
	result.Redactions += counts.Total()
}
