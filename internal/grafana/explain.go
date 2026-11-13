package grafana

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"syscall"

	"github.com/tellagen/tellagen-proxy/internal/settings"
)

// Failure is a Grafana failure in words that are safe to send to Tellagen: they
// name no address.
type Failure struct {
	// Code is a short word for the doctor summary.
	Code string
	// Message is one sentence for the setup page.
	Message string
	// Auth is true when Grafana answered but refused the token.
	Auth bool
}

// Failure codes.
const (
	CodeUnauthorized = "grafana_unauthorized"
	CodeForbidden    = "grafana_forbidden"
	CodeUnknownCA    = "grafana_unknown_ca"
	CodeCertificate  = "grafana_certificate"
	CodeDNS          = "grafana_dns"
	CodeRefused      = "grafana_refused"
	CodeTimeout      = "grafana_timeout"
	CodeHTTP         = "grafana_http_error"
	CodeUnreachable  = "grafana_unreachable"
)

// Explain turns an error from a Grafana call into a Failure.
func Explain(err error) Failure {
	var status *StatusError
	if errors.As(err, &status) {
		switch status.Status {
		case 401:
			return Failure{Code: CodeUnauthorized, Message: "Grafana rejected the token (401)", Auth: true}
		case 403:
			return Failure{Code: CodeForbidden, Message: "Grafana refused the token for this request (403)", Auth: true}
		}
		return Failure{Code: CodeHTTP, Message: fmt.Sprintf("Grafana answered %d", status.Status)}
	}
	if issuer, ok := settings.IsUnknownAuthority(err); ok {
		return Failure{Code: CodeUnknownCA, Message: fmt.Sprintf("TLS error: the certificate is signed by an unknown authority, %q", issuer)}
	}
	var invalid x509.CertificateInvalidError
	var hostname x509.HostnameError
	switch {
	case errors.As(err, &hostname):
		return Failure{Code: CodeCertificate, Message: "TLS error: the certificate does not match the Grafana address"}
	case errors.As(err, &invalid):
		return Failure{Code: CodeCertificate, Message: "TLS error: the certificate has expired or is not valid yet"}
	}
	var dns *net.DNSError
	switch {
	case errors.As(err, &dns) && dns.IsNotFound:
		return Failure{Code: CodeDNS, Message: "the Grafana host name does not resolve"}
	case errors.As(err, &dns):
		return Failure{Code: CodeDNS, Message: "the Grafana host name could not be looked up"}
	case errors.Is(err, syscall.ECONNREFUSED):
		return Failure{Code: CodeRefused, Message: "Grafana refused the connection"}
	case errors.Is(err, context.DeadlineExceeded):
		return Failure{Code: CodeTimeout, Message: "Grafana did not answer in time"}
	}
	var timeout net.Error
	if errors.As(err, &timeout) && timeout.Timeout() {
		return Failure{Code: CodeTimeout, Message: "Grafana did not answer in time"}
	}
	return Failure{Code: CodeUnreachable, Message: "Grafana could not be reached"}
}
