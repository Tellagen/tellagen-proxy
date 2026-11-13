package redact

import (
	"encoding/json"
	"go/parser"
	"go/token"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/tellagen/tellagen-proxy/protocol"
)

// The values below are made up. The AWS key is the example from AWS's own
// documentation, and the card number is a published test number.
const (
	corpusEmail = "mari.kask@example.ee"
	corpusIPv4  = "203.0.113.42"
	corpusIPv6  = "2001:db8::8a2e:370:7334"
	corpusJWT   = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1XzMxMSJ9.c2lnbmF0dXJlLWJ5dGVz"
	corpusAWS   = "AKIAIOSFODNN7EXAMPLE"
	corpusGCP   = "AIzaSyA1234567890abcdefghijklmnopqrstuv"
	corpusCard  = "4242 4242 4242 4242"
	corpusName  = "Mari Kask"
)

type corpusLine struct {
	name    string
	line    string
	secrets []string
	want    Counts
	keep    []string
}

func corpus() []corpusLine {
	return []corpusLine{
		{
			name:    "email in a plain message",
			line:    `level=error msg="payment failed for ` + corpusEmail + `" order=A1234`,
			secrets: []string{corpusEmail},
			want:    Counts{KindEmail: 1},
			keep:    []string{"level=error", "payment failed", "order=A1234"},
		},
		{
			name:    "IPv4 with a port",
			line:    "upstream connect error to " + corpusIPv4 + ":5432 after 30s",
			secrets: []string{corpusIPv4},
			want:    Counts{KindIP: 1},
			keep:    []string{":5432 after 30s"},
		},
		{
			name:    "IPv6",
			line:    "peer " + corpusIPv6 + " reset the connection at 12:30:45",
			secrets: []string{corpusIPv6},
			want:    Counts{KindIP: 1},
			keep:    []string{"reset the connection at 12:30:45"},
		},
		{
			name:    "JWT in a query string",
			line:    "GET /callback?state=ok&jwt_hint=" + corpusJWT + " 200",
			secrets: []string{corpusJWT},
			want:    Counts{KindToken: 1},
			keep:    []string{"GET /callback?state=ok", " 200"},
		},
		{
			name:    "bearer header counts once",
			line:    "Authorization: Bearer abcdefghijklmnop1234 path=/v1/orders",
			secrets: []string{"abcdefghijklmnop1234"},
			want:    Counts{KindToken: 1},
		},
		{
			name:    "basic header takes the whole value",
			line:    "authorization: Basic dXNlcjpwYXNz",
			secrets: []string{"dXNlcjpwYXNz"},
			want:    Counts{KindField: 1},
		},
		{
			name:    "cookie header takes the whole value",
			line:    "Cookie: sid=abc123; theme=dark",
			secrets: []string{"sid=abc123", "theme=dark"},
			want:    Counts{KindField: 1},
		},
		{
			name:    "AWS access key",
			line:    "assuming role with key " + corpusAWS + " in eu-north-1",
			secrets: []string{corpusAWS},
			want:    Counts{KindKey: 1},
			keep:    []string{"assuming role with key", "in eu-north-1"},
		},
		{
			name:    "Google API key",
			line:    "maps call failed key " + corpusGCP,
			secrets: []string{corpusGCP},
			want:    Counts{KindKey: 1},
		},
		{
			name:    "private key block",
			line:    "loaded -----BEGIN RSA PRIVATE KEY-----\nMIIEow\nabc\n-----END RSA PRIVATE KEY----- ok",
			secrets: []string{"MIIEow", "PRIVATE KEY"},
			want:    Counts{KindKey: 1},
			keep:    []string{"loaded", " ok"},
		},
		{
			name:    "vendor tokens",
			line:    "github ghp_abcdefghijklmnopqrstuvwxyz1234567890 slack xoxb-1234567890-abcdefghij stripe sk_live_abcdefghijklmn",
			secrets: []string{"ghp_abcd", "xoxb-1234", "sk_live_"},
			want:    Counts{KindToken: 3},
		},
		{
			name:    "database URL with credentials",
			line:    "dial postgres://app:s3cretpw@db.internal:5432/orders failed",
			secrets: []string{"s3cretpw"},
			want:    Counts{KindToken: 1},
			keep:    []string{"db.internal:5432/orders failed"},
		},
		{
			name:    "card number with spaces",
			line:    "charge declined card=" + corpusCard + " reason=insufficient_funds",
			secrets: []string{"4242 4242", "4242-4242"},
			want:    Counts{KindCard: 1},
			keep:    []string{"reason=insufficient_funds"},
		},
		{
			name:    "card number with dashes",
			line:    "number 5555-5555-5555-4444 was refused",
			secrets: []string{"5555-5555"},
			want:    Counts{KindCard: 1},
		},
		{
			name:    "key names in JSON",
			line:    `{"password":"hunter22","api_key":"k-123","status":500,"apiKey":"abc"}`,
			secrets: []string{"hunter22", "k-123", `"abc"`},
			want:    Counts{KindField: 3},
			keep:    []string{`"status":500`},
		},
		{
			name:    "key names in JSON inside a string",
			line:    `body="{\"client_secret\":\"hunter22\",\"count\":3}"`,
			secrets: []string{"hunter22"},
			want:    Counts{KindField: 1},
			keep:    []string{`\"count\":3`},
		},
		{
			name:    "secret key inside a URL value",
			line:    "url=https://api.example.ee/login?next=home&password=abc123 status=401",
			secrets: []string{"abc123"},
			want:    Counts{KindField: 1},
			keep:    []string{"status=401", "next=home"},
		},
		{
			name:    "key names in logfmt",
			line:    `user_name="` + corpusName + `" db_password=abc retry=2`,
			secrets: []string{corpusName, "db_password=abc"},
			want:    Counts{KindField: 2},
			keep:    []string{"retry=2"},
		},
		{
			name:    "password that holds an email is one field",
			line:    "password=" + corpusEmail + " attempt=1",
			secrets: []string{corpusEmail},
			want:    Counts{KindField: 1},
			keep:    []string{"attempt=1"},
		},
		{
			name:    "upper-case keys in an environment dump",
			line:    "env PASSWORD=hunter22 DB_PASSWORD=hunter23 API_KEY=abcdef123456 APIKEY=abcdef123457 AWS_SECRET_ACCESS_KEY=abcdefghijk TOKEN=abcdef SESSION=abcd LOG_LEVEL=info",
			secrets: []string{"hunter22", "hunter23", "abcdef123456", "abcdef123457", "abcdefghijk", "=abcdef ", "=abcd "},
			want:    Counts{KindField: 7},
			keep:    []string{"LOG_LEVEL=info"},
		},
		{
			name:    "upper-case keys in JSON",
			line:    `{"PASSWORD":"hunter22","DBPassword":"hunter23","APIKey":"abc","STATUS":500}`,
			secrets: []string{"hunter22", "hunter23", `"abc"`},
			want:    Counts{KindField: 3},
			keep:    []string{`"STATUS":500`},
		},
		{
			name:    "signatures of a presigned URL",
			line:    "GET https://files.example.ee/a?X-Amz-Signature=abcdef&X-Goog-Signature=abcdeg&sig=abcdeh&part=1 200",
			secrets: []string{"abcdef", "abcdeg", "abcdeh"},
			want:    Counts{KindField: 3},
			keep:    []string{"part=1", " 200"},
		},
		{
			name:    "Grafana Cloud and npm tokens",
			line:    "publish with glc_eyJvIjoiMTIzNDU2Nzg5MCIsIm4i and npm_abcdefghijklmnopqrstuvwxyz0123456789",
			secrets: []string{"glc_", "npm_"},
			want:    Counts{KindToken: 2},
			keep:    []string{"publish with"},
		},
		{
			name:    "a proxy authorization key in camelCase",
			line:    "proxyAuthorization: Basic dXNlcjpwYXNz",
			secrets: []string{"dXNlcjpwYXNz"},
			want:    Counts{KindField: 1},
		},
		{
			name:    "a secret with spaces takes the rest of the line",
			line:    "db secret : abc def ghi\nnext line stays",
			secrets: []string{"abc", "def", "ghi"},
			want:    Counts{KindField: 1},
			keep:    []string{"db secret : ", "\nnext line stays"},
		},
		{
			name:    "a password phrase inside a JSON string stays valid JSON",
			line:    `{"msg":"password: abc def","status":500}`,
			secrets: []string{"abc def"},
			want:    Counts{KindField: 1},
			keep:    []string{`","status":500}`},
		},
		{
			name: "code names and MAC addresses stay",
			line: "panic in std::bad_alloc at Foo::bar on aa:bb:cc:dd:ee:ff",
			want: Counts{},
			keep: []string{"panic in std::bad_alloc at Foo::bar on aa:bb:cc:dd:ee:ff"},
		},
		{
			name:    "short IPv6",
			line:    "bound to fe80::1 ok",
			secrets: []string{"fe80::1"},
			want:    Counts{KindIP: 1},
			keep:    []string{"bound to", "ok"},
		},
		{
			name: "plain values stay",
			line: "pool exhausted active=100 tokens=42 trace=4bf92f3577b34da6a3ce929d0e0e4736 at 1730880000000 v1.2.3",
			want: Counts{},
			keep: []string{"pool exhausted active=100 tokens=42 trace=4bf92f3577b34da6a3ce929d0e0e4736 at 1730880000000 v1.2.3"},
		},
	}
}

func TestCorpusRemovesAndCountsEachKind(t *testing.T) {
	redactor, errs := New(nil)
	if len(errs) != 0 {
		t.Fatalf("New() errors = %v", errs)
	}
	for _, tc := range corpus() {
		t.Run(tc.name, func(t *testing.T) {
			counts := Counts{}
			got := redactor.Text(tc.line, counts)
			for _, secret := range tc.secrets {
				if strings.Contains(got, secret) {
					t.Errorf("Text() = %q, still holds %q", got, secret)
				}
			}
			for _, keep := range tc.keep {
				if !strings.Contains(got, keep) {
					t.Errorf("Text() = %q, lost %q", got, keep)
				}
			}
			if !reflect.DeepEqual(counts, tc.want) {
				t.Errorf("counts = %v, want %v (text %q)", counts, tc.want, got)
			}
		})
	}
}

func TestNormalizeKey(t *testing.T) {
	tests := map[string]string{
		"PASSWORD": "password", "DB_PASSWORD": "db_password", "API_KEY": "api_key", "APIKEY": "apikey",
		"AWS_SECRET_ACCESS_KEY": "aws_secret_access_key", "apiKey": "api_key", "api-key": "api_key", "APIKey": "api_key",
		"DBPassword": "db_password", "proxyAuthorization": "proxy_authorization", "X-Amz-Signature": "x_amz_signature",
		"secret.key": "secret_key", " Token ": "token", "key2Name": "key2_name",
	}
	for key, want := range tests {
		if got := normalizeKey(key); got != want {
			t.Errorf("normalizeKey(%q) = %q, want %q", key, got, want)
		}
	}
}

func TestUpperCaseLabelKeysLoseTheirValueOnBothPasses(t *testing.T) {
	redactor, _ := New(nil)
	labels := map[string]string{"PASSWORD": "hunter22", "API_KEY": "abc", "AWS_SECRET_ACCESS_KEY": "def", "SERVICE": "checkout"}
	counts := Counts{}
	once := redactor.Labels(labels, counts)
	for _, key := range []string{"PASSWORD", "API_KEY", "AWS_SECRET_ACCESS_KEY"} {
		if once[key] != placeholder(KindField) {
			t.Errorf("%s = %q", key, once[key])
		}
	}
	if once["SERVICE"] != "checkout" || counts[KindField] != 3 {
		t.Errorf("labels = %v, counts = %v", once, counts)
	}
	second := Counts{}
	if twice := redactor.Labels(once, second); !reflect.DeepEqual(twice, once) || second.Total() != 0 {
		t.Errorf("second pass = %v, counts = %v", twice, second)
	}
}

func TestSecondPassCatchesAnUpperCaseSecretAnOldProxySent(t *testing.T) {
	result := &protocol.CommandResult{Data: &protocol.ResultData{Lines: []protocol.LogLine{{Text: "PASSWORD=hunter22 AWS_SECRET_ACCESS_KEY=abcdef"}}}}
	serverSide, _ := New(nil)
	serverSide.Result(result)
	if text := result.Data.Lines[0].Text; strings.Contains(text, "hunter22") || strings.Contains(text, "abcdef") {
		t.Errorf("Text = %q", text)
	}
	if result.RedactionsByKind[KindField] != 2 {
		t.Errorf("counts = %v", result.RedactionsByKind)
	}
}

func TestNULBytesLeaveEveryFieldOnBothRedactors(t *testing.T) {
	const nul = "a\x00b"
	build := func() *protocol.CommandResult {
		return &protocol.CommandResult{
			Skipped: []string{nul},
			Error:   &protocol.ResultError{Message: nul},
			Data: &protocol.ResultData{
				Series:       []protocol.Series{{Labels: map[string]string{nul: nul}}},
				Samples:      []protocol.Sample{{Labels: map[string]string{"k": nul}}},
				Lines:        []protocol.LogLine{{Labels: map[string]string{"k": nul}, Text: nul}},
				Patterns:     []protocol.LogPattern{{Pattern: nul}},
				Names:        []string{nul},
				Datasources:  []protocol.Datasource{{UID: nul, Name: nul, Type: nul}},
				Dashboards:   []protocol.Dashboard{{UID: nul, Title: nul, Folder: nul}},
				PanelQueries: []protocol.PanelQuery{{Title: nul, DatasourceUID: nul, Expr: nul}},
				AlertRules:   []protocol.AlertRule{{UID: nul, Title: nul, State: nul, Expr: nul}},
			},
		}
	}
	full, _ := New(nil)
	extraOnly, _ := NewExtraOnly(nil)
	for name, redactor := range map[string]*Redactor{"built-in rules": full, "redaction off": extraOnly} {
		t.Run(name, func(t *testing.T) {
			result := build()
			redactor.Result(result)
			encoded, err := json.Marshal(result)
			if err != nil {
				t.Fatalf("Marshal() error = %v", err)
			}
			if strings.Contains(string(encoded), "u0000") {
				t.Errorf("the result still holds a NUL: %s", encoded)
			}
			if result.Redactions != 0 {
				t.Errorf("Redactions = %d, a NUL is not a redaction", result.Redactions)
			}
		})
	}
}

func TestCorpusCoversEveryKind(t *testing.T) {
	seen := map[string]bool{}
	for _, tc := range corpus() {
		for kind := range tc.want {
			seen[kind] = true
		}
	}
	for _, kind := range []string{KindEmail, KindIP, KindToken, KindKey, KindCard, KindField} {
		if !seen[kind] {
			t.Errorf("the corpus has no line for kind %q", kind)
		}
	}
}

func TestCorpusExtraRules(t *testing.T) {
	redactor, errs := New([]protocol.RedactionRule{
		{Kind: protocol.RedactionRuleKey, Key: "customer"},
		{Kind: protocol.RedactionRulePattern, Regex: `ACC-\d{5}-EE`},
	})
	if len(errs) != 0 {
		t.Fatalf("New() errors = %v", errs)
	}
	counts := Counts{}
	got := redactor.Text(`customer="`+corpusName+`" account ACC-12345-EE plan=pro Customer: Jaan`, counts)
	for _, secret := range []string{corpusName, "ACC-12345-EE", "Jaan"} {
		if strings.Contains(got, secret) {
			t.Errorf("Text() = %q, still holds %q", got, secret)
		}
	}
	if !strings.Contains(got, "plan=pro") {
		t.Errorf("Text() = %q, lost plan=pro", got)
	}
	if want := (Counts{KindRule: 3}); !reflect.DeepEqual(counts, want) {
		t.Errorf("counts = %v, want %v", counts, want)
	}

	labels := redactor.Labels(map[string]string{"customer": corpusName, "service": "checkout"}, counts)
	if labels["customer"] != placeholder(KindRule) || labels["service"] != "checkout" {
		t.Errorf("Labels() = %v", labels)
	}
}

func TestDefaultRulesMissAFreeTextName(t *testing.T) {
	redactor, _ := New(nil)
	counts := Counts{}
	line := "refund issued to " + corpusName
	if got := redactor.Text(line, counts); got != line || counts.Total() != 0 {
		t.Fatalf("Text() = %q, counts %v: the page promises that redaction can miss a name, so a responder masks it", got, counts)
	}
}

func TestExtraOnlyKeepsThePolicyRulesAndNothingElse(t *testing.T) {
	redactor, errs := NewExtraOnly([]protocol.RedactionRule{{Kind: protocol.RedactionRuleKey, Key: "customer"}})
	if len(errs) != 0 {
		t.Fatalf("NewExtraOnly() errors = %v", errs)
	}
	for _, tc := range corpus() {
		counts := Counts{}
		if got := redactor.Text(tc.line, counts); got != tc.line || counts.Total() != 0 {
			t.Errorf("%s: Text() = %q, counts %v, want the line untouched", tc.name, got, counts)
		}
	}
	counts := Counts{}
	if got := redactor.Text("customer=Jaan "+corpusEmail, counts); got != placeholderLine("customer=", KindRule)+" "+corpusEmail {
		t.Errorf("Text() = %q", got)
	}
	empty, _ := NewExtraOnly(nil)
	data := &protocol.ResultData{Kind: protocol.DataLogs, Lines: []protocol.LogLine{{Text: corpusEmail, Labels: map[string]string{"password": "x"}}}}
	if counts := empty.Data(data); counts.Total() != 0 || data.Lines[0].Text != corpusEmail || data.Lines[0].Labels["password"] != "x" {
		t.Errorf("with redaction off and no policy rules the data changed: %+v, counts %v", data.Lines[0], counts)
	}
}

func placeholderLine(prefix, kind string) string {
	return prefix + placeholder(kind)
}

func TestRuleErrorsAreReportedAndOtherRulesStillApply(t *testing.T) {
	tooMany := make([]protocol.RedactionRule, 0, MaxExtraRules+1)
	for range MaxExtraRules {
		tooMany = append(tooMany, protocol.RedactionRule{Kind: protocol.RedactionRuleKey, Key: "a"})
	}
	tooMany = append(tooMany, protocol.RedactionRule{Kind: protocol.RedactionRuleKey, Key: "over_the_cap"})
	tests := []struct {
		name  string
		rules []protocol.RedactionRule
		want  int
	}{
		{"regex does not compile", []protocol.RedactionRule{{Kind: protocol.RedactionRulePattern, Regex: "("}}, 1},
		{"regex matches empty text", []protocol.RedactionRule{{Kind: protocol.RedactionRulePattern, Regex: "a*"}}, 1},
		{"regex is empty", []protocol.RedactionRule{{Kind: protocol.RedactionRulePattern}}, 1},
		{"regex is too long", []protocol.RedactionRule{{Kind: protocol.RedactionRulePattern, Regex: strings.Repeat("a", MaxRuleChars+1)}}, 1},
		{"key is empty", []protocol.RedactionRule{{Kind: protocol.RedactionRuleKey, Key: "  "}}, 1},
		{"key is too long", []protocol.RedactionRule{{Kind: protocol.RedactionRuleKey, Key: strings.Repeat("a", MaxRuleChars+1)}}, 1},
		{"unknown kind", []protocol.RedactionRule{{Kind: "other", Key: "a"}}, 1},
		{"too many rules", tooMany, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			redactor, errs := New(tt.rules)
			if len(errs) != tt.want {
				t.Fatalf("errors = %v, want %d", errs, tt.want)
			}
			counts := Counts{}
			if got := redactor.Text(corpusEmail, counts); got != placeholder(KindEmail) {
				t.Fatalf("the built-in rules stopped: %q", got)
			}
		})
	}
}

func fullResult() *protocol.CommandResult {
	value := 1.5
	at := time.Date(2026, 11, 4, 14, 4, 0, 0, time.UTC)
	return &protocol.CommandResult{
		AttemptToken: "at_1",
		Status:       protocol.StatusPartial,
		Skipped:      []string{"lines of " + corpusEmail},
		Data: &protocol.ResultData{
			Kind: protocol.DataLogs,
			Series: []protocol.Series{{
				Labels: map[string]string{"instance": corpusIPv4 + ":9090", "api_key": "abc", "service": "checkout"},
				Start:  at, StepS: 30, Values: []*float64{&value},
			}},
			Samples: []protocol.Sample{{Labels: map[string]string{"user": corpusEmail}, Value: 1, At: at}},
			Lines: []protocol.LogLine{{
				At: at, Labels: map[string]string{"pod": "checkout-1"},
				Text: "token " + corpusJWT + " for " + corpusEmail + " card " + corpusCard + " from " + corpusIPv4 + " key " + corpusAWS,
			}},
			Patterns:     []protocol.LogPattern{{Pattern: "login <_> from " + corpusIPv4, Count: 3}},
			Names:        []string{corpusEmail, "checkout"},
			Datasources:  []protocol.Datasource{{UID: "prom-prod", Name: "Owner " + corpusEmail, Type: "prometheus"}},
			Dashboards:   []protocol.Dashboard{{UID: "d1", Title: "Owner " + corpusEmail, Folder: corpusEmail}},
			PanelQueries: []protocol.PanelQuery{{PanelID: 1, Title: corpusEmail, DatasourceUID: "prom-prod", Expr: `up{instance="` + corpusIPv4 + `"}`}},
			AlertRules:   []protocol.AlertRule{{UID: "a1", Title: corpusEmail, Expr: `up{instance="` + corpusIPv4 + `"}`}},
		},
	}
}

func TestResultCoversEveryTextField(t *testing.T) {
	redactor, _ := New(nil)
	result := fullResult()
	redactor.Result(result)

	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	for _, secret := range []string{corpusEmail, corpusIPv4, corpusJWT, corpusAWS, "4242 4242"} {
		if strings.Contains(string(encoded), secret) {
			t.Errorf("result still holds %q: %s", secret, encoded)
		}
	}
	for _, keep := range []string{`"prom-prod"`, `"checkout-1"`, `"service":"checkout"`} {
		if !strings.Contains(string(encoded), keep) {
			t.Errorf("result lost %q: %s", keep, encoded)
		}
	}
	if got := result.Data.Patterns[0].Pattern; !strings.HasPrefix(got, "login <_> from ") {
		t.Errorf("Pattern = %q, lost its text", got)
	}
	if result.Redactions == 0 || result.Redactions != Counts(result.RedactionsByKind).Total() {
		t.Errorf("Redactions = %d, by kind %v", result.Redactions, result.RedactionsByKind)
	}
	for _, kind := range []string{KindEmail, KindIP, KindToken, KindKey, KindCard, KindField} {
		if result.RedactionsByKind[kind] == 0 {
			t.Errorf("kind %q was not counted: %v", kind, result.RedactionsByKind)
		}
	}
}

func TestSecondPassChangesNothingAndCountsNothing(t *testing.T) {
	rules := []protocol.RedactionRule{{Kind: protocol.RedactionRuleKey, Key: "customer"}, {Kind: protocol.RedactionRulePattern, Regex: `ACC-\d{5}-EE`}}
	redactor, _ := New(rules)
	for _, tc := range corpus() {
		first := Counts{}
		once := redactor.Text(tc.line, first)
		second := Counts{}
		if twice := redactor.Text(once, second); twice != once || second.Total() != 0 {
			t.Errorf("%s: second pass = %q (counts %v), first pass = %q", tc.name, twice, second, once)
		}
	}

	result := fullResult()
	redactor.Result(result)
	before, _ := json.Marshal(result)
	redactor.Result(result)
	after, _ := json.Marshal(result)
	if string(before) != string(after) {
		t.Errorf("the second pass changed the result:\n%s\n%s", before, after)
	}
}

func TestSecondPassCatchesARuleTheProxyDidNotHave(t *testing.T) {
	proxySide, _ := New(nil)
	result := &protocol.CommandResult{Data: &protocol.ResultData{Lines: []protocol.LogLine{{Text: "customer=Jaan from " + corpusEmail}}}}
	proxySide.Result(result)
	if result.Redactions != 1 {
		t.Fatalf("proxy pass Redactions = %d", result.Redactions)
	}

	serverSide, _ := New([]protocol.RedactionRule{{Kind: protocol.RedactionRuleKey, Key: "customer"}})
	serverSide.Result(result)
	if strings.Contains(result.Data.Lines[0].Text, "Jaan") {
		t.Errorf("Text = %q", result.Data.Lines[0].Text)
	}
	if want := map[string]int{KindEmail: 1, KindRule: 1}; result.Redactions != 2 || !reflect.DeepEqual(result.RedactionsByKind, want) {
		t.Errorf("Redactions = %d, by kind %v, want %v", result.Redactions, result.RedactionsByKind, want)
	}
}

func TestResultRedactsTheErrorMessage(t *testing.T) {
	redactor, _ := New(nil)
	result := &protocol.CommandResult{Status: protocol.StatusError, Error: &protocol.ResultError{Code: protocol.CodeUpstream4xx, Message: "parse error near " + corpusEmail}}
	redactor.Result(result)
	if strings.Contains(result.Error.Message, corpusEmail) || result.Redactions != 1 {
		t.Errorf("Error.Message = %q, Redactions = %d", result.Error.Message, result.Redactions)
	}
}

func TestDataDoesNotPanicOnNil(t *testing.T) {
	redactor, _ := New(nil)
	if counts := redactor.Data(nil); counts.Total() != 0 {
		t.Errorf("counts = %v", counts)
	}
	if got := redactor.Labels(nil, Counts{}); got != nil {
		t.Errorf("Labels(nil) = %v", got)
	}
}

// TestPackageImportsOnlyTheStandardLibraryAndTheProtocol keeps the package light,
// because Tellagen imports it too.
func TestPackageImportsOnlyTheStandardLibraryAndTheProtocol(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "redact.go", nil, parser.ImportsOnly)
	if err != nil {
		t.Fatal(err)
	}
	for _, imported := range file.Imports {
		path := strings.Trim(imported.Path.Value, `"`)
		first, _, _ := strings.Cut(path, "/")
		if strings.Contains(first, ".") && path != "github.com/tellagen/tellagen-proxy/protocol" {
			t.Errorf("redact.go imports %s", path)
		}
	}
}

func FuzzText(f *testing.F) {
	for _, tc := range corpus() {
		f.Add(tc.line)
	}
	redactor, _ := New([]protocol.RedactionRule{{Kind: protocol.RedactionRuleKey, Key: "customer"}})
	f.Fuzz(func(t *testing.T, line string) {
		counts := Counts{}
		once := redactor.Text(line, counts)
		for kind, n := range counts {
			if n <= 0 {
				t.Fatalf("kind %q counted %d", kind, n)
			}
		}
		if counts.Total() == 0 && once != strings.ReplaceAll(line, "\x00", "") {
			t.Fatalf("Text(%q) = %q with nothing counted", line, once)
		}
	})
}
