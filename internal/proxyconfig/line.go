package proxyconfig

import (
	"fmt"
	"net/url"
	"strings"
)

// ParseHostPortUserPass parses host:port:user:pass (password may contain colons if exactly 4 segments).
func ParseHostPortUserPass(line string) (host, port, user, pass string, err error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return "", "", "", "", fmt.Errorf("empty proxy line")
	}
	if strings.HasPrefix(line, "http://") || strings.HasPrefix(line, "https://") {
		u, err := url.Parse(line)
		if err != nil {
			return "", "", "", "", err
		}
		host = u.Hostname()
		port = u.Port()
		if port == "" {
			port = "80"
		}
		if u.User != nil {
			user = u.User.Username()
			pass, _ = u.User.Password()
		}
		return host, port, user, pass, nil
	}
	parts := strings.Split(line, ":")
	if len(parts) < 4 {
		return "", "", "", "", fmt.Errorf("expected host:port:user:pass, got %d parts", len(parts))
	}
	host = parts[0]
	port = parts[1]
	user = parts[2]
	pass = strings.Join(parts[3:], ":")
	return host, port, user, pass, nil
}
