package proxyconfig

import (
	"fmt"
	"net/url"
)

// Parts holds HTTP proxy connection fields for Capzy and similar APIs.
type Parts struct {
	Host     string
	Port     string
	User     string
	Password string
}

func ParseHTTPProxyURL(proxyURL string) (Parts, error) {
	u, err := url.Parse(proxyURL)
	if err != nil {
		return Parts{}, err
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "80"
	}
	var user, pass string
	if u.User != nil {
		user = u.User.Username()
		pass, _ = u.User.Password()
	}
	if host == "" {
		return Parts{}, fmt.Errorf("invalid proxy URL")
	}
	return Parts{Host: host, Port: port, User: user, Password: pass}, nil
}
