package proxyconfig

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

var sessionRE = regexp.MustCompile(`_session-[^_]+`)
var lifetimeRE = regexp.MustCompile(`_lifetime-[^_]+`)

// HasEmbeddedSession is true when the proxy password already contains _session-<id>.
func HasEmbeddedSession(pass string) bool {
	return sessionRE.MatchString(pass)
}

// ExtractSession returns the sticky id from an iProyal _session-<id> password.
func ExtractSession(pass string) string {
	m := sessionRE.FindString(pass)
	return strings.TrimPrefix(m, "_session-")
}

// SessionRotatable reports whether the password uses iProyal-style _session-* rotation.
func SessionRotatable(pass string) bool {
	if pass == "" {
		return false
	}
	return sessionRE.MatchString(pass) ||
		strings.Contains(pass, "_country-") ||
		strings.Contains(pass, "_lifetime-")
}

// ApplySession replaces or appends iProyal _session-<id> in the proxy password.
func ApplySession(pass, sessionID string) string {
	if sessionID == "" {
		return pass
	}
	if !SessionRotatable(pass) {
		return pass
	}
	if sessionRE.MatchString(pass) {
		return sessionRE.ReplaceAllString(pass, "_session-"+sessionID)
	}
	return pass + "_session-" + sessionID
}

// ApplyLifetime sets iProyal _lifetime-* so a sticky session lasts the whole solve+register.
func ApplyLifetime(pass, lifetime string) string {
	if lifetime == "" || !SessionRotatable(pass) {
		return pass
	}
	if lifetimeRE.MatchString(pass) {
		return lifetimeRE.ReplaceAllString(pass, "_lifetime-"+lifetime)
	}
	return pass + "_lifetime-" + lifetime
}

// Build returns an HTTP proxy URL for golang.org/x/net/proxy and httpclient.
func Build(host, port, user, pass string, rotateSession string) (string, error) {
	if rotateSession != "" {
		pass = ApplySession(pass, rotateSession)
		pass = ApplyLifetime(pass, "30m")
	}
	u := &url.URL{
		Scheme: "http",
		Host:   fmt.Sprintf("%s:%s", host, port),
	}
	if user != "" {
		u.User = url.UserPassword(user, pass)
	}
	return u.String(), nil
}
