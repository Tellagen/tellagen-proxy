package agent

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tellagen/tellagen-proxy/internal/hub"
	"github.com/tellagen/tellagen-proxy/protocol"
)

func TestAuthMessageSaysWhatToDo(t *testing.T) {
	revokedAt := time.Date(2026, 11, 4, 10, 20, 0, 0, time.UTC)
	cases := map[string]struct {
		err  error
		want []string
	}{
		"revoked": {
			&hub.APIError{Status: 401, Reply: protocol.ErrorReply{Code: protocol.ErrorRevoked, RevokedAt: &revokedAt}},
			[]string{"revoked on 2026-11-04 10:20 UTC", "Create a new proxy token in Settings", "TELLAGEN_PROXY_TOKEN_FILE"},
		},
		"revoked without details": {
			&hub.APIError{Status: 401, Reply: protocol.ErrorReply{Code: protocol.ErrorRevoked}},
			[]string{"This proxy was revoked. Create a new proxy token"},
		},
		"token invalid": {
			&hub.APIError{Status: 401, Reply: protocol.ErrorReply{Code: protocol.ErrorTokenInvalid}},
			[]string{"does not accept this proxy token", "copied whole"},
		},
		"too old": {
			&hub.APIError{Status: 426, Reply: protocol.ErrorReply{Code: protocol.ErrorUpgradeRequired, MinVersion: "1.2.0"}},
			[]string{"too old", "1.2.0 or later", "Upgrade the image"},
		},
		"too old without a version": {
			&hub.APIError{Status: 426},
			[]string{"This proxy version is too old for Tellagen. Upgrade the image."},
		},
		"suspended": {
			&hub.APIError{Status: 403, Reply: protocol.ErrorReply{Code: protocol.ErrorCompanyDisabled}},
			[]string{"workspace is suspended"},
		},
		"cloud diagnosis off": {
			&hub.APIError{Status: 403, Reply: protocol.ErrorReply{Code: protocol.ErrorCloudDiagnosisDisabled}},
			[]string{"Cloud diagnosis is switched off for this workspace", "turns it on"},
		},
		"unknown refusal": {
			&hub.APIError{Status: 403, Reply: protocol.ErrorReply{Message: "No."}},
			[]string{"refused the proxy (403)", "No."},
		},
		"unreadable token": {
			&hub.TokenError{Err: errors.New("TELLAGEN_PROXY_TOKEN_FILE /run/secrets/token: the secret file is missing or empty")},
			[]string{"cannot be read", "/run/secrets/token"},
		},
		"anything else": {errors.New("boom"), []string{"boom"}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got := authMessage(tc.err)
			for _, want := range tc.want {
				if !strings.Contains(got, want) {
					t.Errorf("authMessage() = %q, want it to contain %q", got, want)
				}
			}
		})
	}
}

func TestDescribeErrorNamesNoAddress(t *testing.T) {
	cases := map[string]error{
		"Tellagen answered 502":                 &hub.APIError{Status: 502},
		"the connection failed":                 &hub.TransportError{Err: errors.New("dial tcp 10.1.2.3:3128: refused")},
		"the reply was not Tellagen's. A proxy": &hub.DecodeError{Err: errors.New("invalid character '<'")},
	}
	for want, err := range cases {
		got := describeError(err)
		if !strings.HasPrefix(got, want) {
			t.Errorf("describeError(%v) = %q, want prefix %q", err, got, want)
		}
		if strings.Contains(got, "10.1.2.3") {
			t.Errorf("describeError() = %q holds an address", got)
		}
	}
}
