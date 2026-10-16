package proxyconfig

import (
	"fmt"
	"net/url"
)

// CapSkipAddress converts an HTTP proxy URL to CapSkip's proxy field format.
func CapSkipAddress(proxyURL string) (string, error) {
	if proxyURL == "" {
		return "", nil
	}
	u, err := url.Parse(proxyURL)
	if err != nil {
		return "", err
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "80"
	}
	addr := fmt.Sprintf("%s:%s", host, port)
	if u.User != nil {
		user := u.User.Username()
		pass, _ := u.User.Password()
		return fmt.Sprintf("%s:%s@%s", user, pass, addr), nil
	}
	return addr, nil
}
