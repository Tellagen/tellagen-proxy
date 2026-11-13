package doctor

// publicText is the sentence for each failure code that goes to Tellagen in the
// hello. It names no address, path or user: those stay in the customer's network.
var publicText = map[string]string{
	"config_invalid":           "The proxy settings are not valid.",
	"secret_missing":           "A required secret is not set.",
	"secret_file_missing":      "A secret file is missing or empty.",
	"secret_file_unreadable":   "A secret file cannot be read by the proxy's user.",
	"token_shape":              "The proxy token does not look like a Tellagen proxy token.",
	"policy_invalid":           "The policy file is not valid.",
	"ca_file":                  "A CA file cannot be read.",
	"dns":                      "The proxy cannot resolve Tellagen's address.",
	"tcp_blocked":              "The proxy cannot open a TCP connection to Tellagen.",
	"proxy_unreachable":        "The proxy cannot use the configured HTTPS proxy.",
	"proxy_407":                "The HTTPS proxy asks for a login.",
	"proxy_403":                "The HTTPS proxy blocks Tellagen.",
	"proxy_error":              "The HTTPS proxy refused the connection to Tellagen.",
	"tls_handshake":            "The TLS handshake with Tellagen failed.",
	"tls_time":                 "The certificate of Tellagen is not valid at the time of this machine.",
	"tls_hostname":             "The certificate presented for Tellagen is for another name.",
	"auth_unreachable":         "The token exchange with Tellagen did not complete.",
	"token_revoked":            "This proxy token was revoked.",
	"version_too_old":          "This proxy version is too old for Tellagen.",
	"token_invalid":            "Tellagen does not accept this proxy token.",
	"company_disabled":         "The workspace is suspended.",
	"cloud_diagnosis_disabled": "Cloud diagnosis is switched off for this workspace.",
	"auth_unexpected":          "A device on the path answered instead of Tellagen.",
	"clock_skew":               "The clock of this machine differs from Tellagen's by more than 2 minutes.",
	"proxy_blocked":            "The running proxy is stopped.",
	"grafana_localhost":        "GRAFANA_URL points to localhost inside a container.",
	"grafana_wrong_org":        "The Grafana token belongs to another org than GRAFANA_ORG_ID.",
}
