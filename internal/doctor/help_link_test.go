package doctor

import (
	"bytes"
	"strings"
	"testing"
)

// The address the report prints is the public guide that explains the doctor output.
func TestHelpURLNamesTheDoctorGuide(t *testing.T) {
	const want = "https://tellagen.com/help/read-the-proxy-doctor-output"
	if HelpURL != want {
		t.Fatalf("HelpURL = %q, want %q", HelpURL, want)
	}
	if rest, ok := strings.CutPrefix(HelpURL, "https://tellagen.com/help/"); !ok || rest == "" || strings.ContainsAny(rest, "/ ") {
		t.Fatalf("HelpURL = %q, want https://tellagen.com/help/ and one slug", HelpURL)
	}
	report := &Report{Version: "1.0.0"}
	report.add("dns", OK, "", "ok")
	var text bytes.Buffer
	report.Write(&text)
	if !strings.Contains(text.String(), "Help with each line: "+want) {
		t.Fatalf("the report does not print the help line:\n%s", text.String())
	}
}

func TestHelpLine(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want string
	}{
		{"no article yet", "", ""},
		{"a published article", "https://tellagen.com/help/read-the-proxy-doctor-output", "Help with each line: https://tellagen.com/help/read-the-proxy-doctor-output"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := helpLine(test.url); got != test.want {
				t.Fatalf("helpLine(%q) = %q, want %q", test.url, got, test.want)
			}
		})
	}
}

func TestJSONReportHasNoHelpLine(t *testing.T) {
	report := &Report{Version: "1.0.0"}
	report.add("dns", OK, "", "ok")

	var out bytes.Buffer
	if err := report.WriteJSON(&out); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "Help with each line") {
		t.Fatalf("the JSON report holds the help line:\n%s", out.String())
	}
}
