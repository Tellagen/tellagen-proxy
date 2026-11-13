package protocol

import "strings"

const (
	// TokenPrefix starts every proxy token: tlg_proxy_<proxy id>.<secret>.
	TokenPrefix = "tlg_proxy_"
	// SessionTokenPrefix starts the short-lived session token a proxy gets for
	// its proxy token.
	SessionTokenPrefix = "tlg_psess_"

	tokenHintIDChars     = 8
	tokenHintSecretChars = 4
)

// FormatToken builds a proxy token from the proxy's id and a secret.
func FormatToken(proxyID, secret string) string {
	return TokenPrefix + proxyID + "." + secret
}

// ParseToken splits a proxy token. It reports false for anything that does not
// have the proxy token's shape, including a session token.
func ParseToken(token string) (proxyID, secret string, ok bool) {
	rest, found := strings.CutPrefix(token, TokenPrefix)
	if !found {
		return "", "", false
	}
	proxyID, secret, found = strings.Cut(rest, ".")
	if !found || proxyID == "" || secret == "" {
		return "", "", false
	}
	return proxyID, secret, true
}

// TokenHint returns the short form of a proxy token that is safe to print, such
// as tlg_proxy_01JD8K2A…a3f9. It returns "" for anything that is not a proxy token.
func TokenHint(token string) string {
	proxyID, secret, ok := ParseToken(token)
	if !ok || len(secret) < tokenHintSecretChars {
		return ""
	}
	return TokenPrefix + proxyID[:min(len(proxyID), tokenHintIDChars)] + "…" + secret[len(secret)-tokenHintSecretChars:]
}
