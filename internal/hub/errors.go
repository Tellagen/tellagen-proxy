package hub

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/tellagen/tellagen-proxy/protocol"
)

// APIError is a refusal from Tellagen, or from a proxy on the way. Reply is empty
// when the body was not Tellagen's error body, for example an HTML 504 from an
// inspecting proxy.
type APIError struct {
	Status     int
	Reply      protocol.ErrorReply
	RetryAfter time.Duration
	ServerDate time.Time
}

// Error implements error.
func (e *APIError) Error() string {
	if e.Reply.Message != "" {
		return fmt.Sprintf("Tellagen answered %d: %s", e.Status, e.Reply.Message)
	}
	return fmt.Sprintf("Tellagen answered %d", e.Status)
}

// TransportError is a failure before a full reply arrived: a refused connection, a
// TLS error, a cut connection or a timeout.
type TransportError struct{ Err error }

// Error implements error.
func (e *TransportError) Error() string { return e.Err.Error() }

// Unwrap lets errors.As reach the cause.
func (e *TransportError) Unwrap() error { return e.Err }

// TokenError means the proxy token could not be read, for example because its file
// is gone. It is a credential problem, not a network one.
type TokenError struct{ Err error }

// Error implements error.
func (e *TokenError) Error() string { return e.Err.Error() }

// Unwrap lets errors.As reach the cause.
func (e *TokenError) Unwrap() error { return e.Err }

// DecodeError means a 2xx reply was not what the protocol says. An inspecting
// proxy that answers with a login page looks like this.
type DecodeError struct{ Err error }

// Error implements error.
func (e *DecodeError) Error() string { return "the reply is not valid: " + e.Err.Error() }

// Unwrap lets errors.As reach the cause.
func (e *DecodeError) Unwrap() error { return e.Err }

// Kind says what a failed call means for the poll loop.
type Kind int

const (
	// KindCut is a held request that did not complete: a transport error after the
	// connection opened, a bad reply, or a status that is not Tellagen's.
	KindCut Kind = iota
	// KindUnreachable means no connection could be opened at all.
	KindUnreachable
	// KindAuth is a 401 or 403: the credential is not accepted.
	KindAuth
	// KindUpgrade is a 426: this proxy version is too old.
	KindUpgrade
	// KindRateLimited is a 429.
	KindRateLimited
	// KindRefused is Tellagen saying no to this message (400, 404, 409, 410, 413).
	// Sending the same message again will not change the answer.
	KindRefused
	// KindStopped means the caller's context ended.
	KindStopped
)

// Classify sorts an error from the client. Only a KindCut counts toward the
// fallback to shorter polls. An answer with a status of Tellagen's own, such as a
// 401 or a 429, proves the path works.
func Classify(ctx context.Context, err error) Kind {
	if ctx.Err() != nil {
		return KindStopped
	}
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		switch apiErr.Status {
		case http.StatusUnauthorized, http.StatusForbidden:
			return KindAuth
		case http.StatusUpgradeRequired:
			return KindUpgrade
		case http.StatusTooManyRequests:
			return KindRateLimited
		case http.StatusBadRequest, http.StatusNotFound, http.StatusConflict, http.StatusGone, http.StatusRequestEntityTooLarge:
			return KindRefused
		}
		return KindCut
	}
	var tokenErr *TokenError
	if errors.As(err, &tokenErr) {
		return KindAuth
	}
	var transport *TransportError
	if errors.As(err, &transport) && neverConnected(transport.Err) {
		return KindUnreachable
	}
	return KindCut
}

// neverConnected reports a failure to open the connection at all, such as a DNS
// error or a refused connection. Nothing was held, so nothing was cut.
func neverConnected(err error) bool {
	var dns *net.DNSError
	if errors.As(err, &dns) {
		return true
	}
	var op *net.OpError
	return errors.As(err, &op) && (op.Op == "dial" || op.Op == "proxyconnect")
}
