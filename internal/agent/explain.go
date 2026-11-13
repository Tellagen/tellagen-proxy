package agent

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/tellagen/tellagen-proxy/internal/hub"
	"github.com/tellagen/tellagen-proxy/protocol"
)

// authMessage is the one clear log line for a credential that Tellagen does not
// accept. It says what to do, and never prints a token.
func authMessage(err error) string {
	var tokenErr *hub.TokenError
	if errors.As(err, &tokenErr) {
		return "The proxy token cannot be read: " + tokenErr.Error() + ". Check the file or the variable."
	}
	var apiErr *hub.APIError
	if !errors.As(err, &apiErr) {
		return err.Error()
	}
	reply := apiErr.Reply
	switch reply.Code {
	case protocol.ErrorRevoked:
		message := "This proxy was revoked"
		if reply.RevokedAt != nil {
			message += " on " + reply.RevokedAt.UTC().Format("2006-01-02 15:04 UTC")
		}
		return message + ". Create a new proxy token in Settings and put it in TELLAGEN_PROXY_TOKEN_FILE."
	case protocol.ErrorTokenInvalid:
		return "Tellagen does not accept this proxy token. Check that it was copied whole and that the token was not rotated out."
	case protocol.ErrorUpgradeRequired:
		return upgradeMessage(reply.MinVersion)
	case protocol.ErrorCompanyDisabled:
		return "This workspace is suspended in Tellagen. Ask a workspace admin."
	case protocol.ErrorCloudDiagnosisDisabled:
		return "Cloud diagnosis is switched off for this workspace. The proxy keeps trying and starts again when a workspace admin turns it on."
	}
	if apiErr.Status == http.StatusUpgradeRequired {
		return upgradeMessage(reply.MinVersion)
	}
	return fmt.Sprintf("Tellagen refused the proxy (%d). %s", apiErr.Status, strings.TrimSpace(reply.Message))
}

func upgradeMessage(minVersion string) string {
	if minVersion == "" {
		return "This proxy version is too old for Tellagen. Upgrade the image."
	}
	return fmt.Sprintf("This proxy version is too old for Tellagen, which needs %s or later. Upgrade the image.", minVersion)
}

// describeError is a short, address-free reason for the status endpoint and the
// logs.
func describeError(err error) string {
	var apiErr *hub.APIError
	if errors.As(err, &apiErr) {
		return fmt.Sprintf("Tellagen answered %d", apiErr.Status)
	}
	var decode *hub.DecodeError
	if errors.As(err, &decode) {
		return "the reply was not Tellagen's. A proxy on the way may be answering"
	}
	return "the connection failed"
}

// retryAfter is how long to wait after a 429.
func retryAfter(err error) time.Duration {
	const (
		fallback = 5 * time.Second
		ceiling  = 5 * time.Minute
	)
	var apiErr *hub.APIError
	if errors.As(err, &apiErr) && apiErr.RetryAfter > 0 {
		return min(apiErr.RetryAfter, ceiling)
	}
	return fallback
}
