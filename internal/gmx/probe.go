package gmx

import (
	"fmt"
	"strings"
	"time"
)

// ProbeSignup loads the signup page and fetches account configuration (GMX pre-check).
func (c *Client) ProbeSignup(maxLoadAttempts int) error {
	var loadErr error
	for attempt := 0; attempt < maxLoadAttempts; attempt++ {
		loadErr = c.LoadSignup()
		if loadErr == nil {
			break
		}
		time.Sleep(2 * time.Second)
	}
	if loadErr != nil {
		return fmt.Errorf("load signup: %w", loadErr)
	}
	cfg, err := c.FetchConfiguration()
	if err != nil {
		return err
	}
	if cfg.Captcha != "" && cfg.Captcha != "CAPTCHA_FOX" {
		return fmt.Errorf("unexpected captcha type %q", cfg.Captcha)
	}
	return nil
}

// RetryableProxyError reports whether another proxy exit may help.
func RetryableProxyError(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "403") ||
		strings.Contains(s, "Access Denied") ||
		strings.Contains(s, "407") ||
		strings.Contains(s, "Gateway Timeout") ||
		strings.Contains(s, "timeout") ||
		strings.Contains(s, "EOF") ||
		strings.Contains(s, "connection reset") ||
		strings.Contains(s, "Proxy Authentication") ||
		strings.Contains(s, "access token not found") ||
		strings.Contains(s, "signup page") ||
		strings.Contains(s, "IP_INFO_D") ||
		strings.Contains(s, "blocked this proxy IP") ||
		strings.Contains(s, "access-forbidden")
}
