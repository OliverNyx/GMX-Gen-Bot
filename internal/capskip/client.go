package capskip

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	defaultBaseURL = "http://127.0.0.1:8080"
	pollInterval   = 5 * time.Second
	maxPollTime    = 3 * time.Minute
)

// Client talks to a local CapSkip instance (2Captcha-compatible in.php / res.php).
type Client struct {
	BaseURL string
	APIKey  string
	HTTP    *http.Client
}

func New(baseURL, apiKey string) *Client {
	if baseURL == "" {
		baseURL = defaultBaseURL
	}
	baseURL = strings.TrimRight(baseURL, "/")
	return &Client{
		BaseURL: baseURL,
		APIKey:  apiKey,
		HTTP:    &http.Client{Timeout: 120 * time.Second},
	}
}

// CaptchaFoxRequest parameters for GMX signup (MAM-packaged CaptchaFox widget).
type CaptchaFoxRequest struct {
	SiteKey   string
	PageURL   string
	APIServer string // e.g. https://s.uicdn.com/mampkg/@mamdev/core.frontend.libs.captchafox/<hash>/
	Proxy     string // CapSkip format: host:port or user:pass@host:port
	ProxyType string // HTTP, HTTPS, SOCKS5, SOCKS5H
}

// CaptchaFoxResult token and browser UA to use on registration requests.
type CaptchaFoxResult struct {
	Token     string
	UserAgent string
	TaskID    string
}

type submitJSON struct {
	Status  int    `json:"status"`
	Request string `json:"request"`
}

type resultJSON struct {
	Status    int    `json:"status"`
	Request   string `json:"request"`
	ErrorID   int    `json:"errorId"`
	UserAgent string `json:"userAgent"`
	Solution  *struct {
		Token     string `json:"token"`
		UserAgent string `json:"userAgent"`
	} `json:"solution"`
}

// SolveCaptchaFox submits a CaptchaFox task and polls until MAM_ token is ready.
func (c *Client) SolveCaptchaFox(ctx context.Context, req CaptchaFoxRequest) (*CaptchaFoxResult, error) {
	if req.SiteKey == "" || req.PageURL == "" {
		return nil, fmt.Errorf("capskip: sitekey and pageurl required")
	}
	taskID, err := c.submit(ctx, req)
	if err != nil {
		return nil, err
	}

	deadline := time.Now().Add(maxPollTime)
	time.Sleep(pollInterval)

	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("capskip: timed out waiting for captcha task %s", taskID)
		}

		res, ready, err := c.poll(ctx, taskID)
		if err != nil {
			return nil, err
		}
		if ready {
			ua := res.UserAgent
			if res.Solution != nil && res.Solution.UserAgent != "" {
				ua = res.Solution.UserAgent
			}
			token := res.Request
			if res.Solution != nil && res.Solution.Token != "" {
				token = res.Solution.Token
			}
			if token == "" {
				return nil, fmt.Errorf("capskip: empty token for task %s", taskID)
			}
			return &CaptchaFoxResult{
				Token:     token,
				UserAgent: ua,
				TaskID:    taskID,
			}, nil
		}
		time.Sleep(pollInterval)
	}
}

func (c *Client) submit(ctx context.Context, req CaptchaFoxRequest) (string, error) {
	form := url.Values{}
	if c.APIKey != "" {
		form.Set("key", c.APIKey)
	}
	form.Set("method", "captchafox")
	form.Set("sitekey", req.SiteKey)
	form.Set("pageurl", req.PageURL)
	form.Set("json", "1")
	if req.APIServer != "" {
		form.Set("api_server", req.APIServer)
	}
	if req.Proxy != "" {
		form.Set("proxy", req.Proxy)
		if req.ProxyType != "" {
			form.Set("proxytype", req.ProxyType)
		} else {
			form.Set("proxytype", "HTTP")
		}
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/in.php", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.HTTP.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("capskip submit: %w", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("capskip submit: HTTP %s: %s", resp.Status, truncate(body))
	}

	var j submitJSON
	if err := json.Unmarshal(body, &j); err == nil && j.Request != "" {
		if strings.HasPrefix(j.Request, "ERROR_") {
			return "", fmt.Errorf("capskip: %s", j.Request)
		}
		return j.Request, nil
	}
	text := strings.TrimSpace(string(body))
	if strings.HasPrefix(text, "OK|") {
		return strings.TrimPrefix(text, "OK|"), nil
	}
	return "", fmt.Errorf("capskip submit: unexpected response: %s", text)
}

func (c *Client) poll(ctx context.Context, taskID string) (*resultJSON, bool, error) {
	q := url.Values{}
	if c.APIKey != "" {
		q.Set("key", c.APIKey)
	}
	q.Set("action", "get")
	q.Set("id", taskID)
	q.Set("json", "1")

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/res.php?"+q.Encode(), nil)
	if err != nil {
		return nil, false, err
	}

	resp, err := c.HTTP.Do(httpReq)
	if err != nil {
		return nil, false, fmt.Errorf("capskip poll: %w", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, false, fmt.Errorf("capskip poll: HTTP %s: %s", resp.Status, truncate(body))
	}

	text := strings.TrimSpace(string(body))
	if text == "CAPCHA_NOT_READY" || strings.Contains(text, "CAPCHA_NOT_READY") {
		return nil, false, nil
	}

	var j resultJSON
	if err := json.Unmarshal(body, &j); err != nil {
		if strings.HasPrefix(text, "OK|") {
			token := strings.TrimPrefix(text, "OK|")
			ua := resp.Header.Get("X-CaptchaFox-User-Agent")
			return &resultJSON{Request: token, UserAgent: ua, ErrorID: 0}, true, nil
		}
		return nil, false, fmt.Errorf("capskip poll: parse error: %w body=%s", err, truncate(body))
	}

	if j.Request == "CAPCHA_NOT_READY" {
		return nil, false, nil
	}
	if strings.HasPrefix(j.Request, "ERROR_") {
		return nil, false, fmt.Errorf("capskip: %s", j.Request)
	}

	token := j.Request
	if j.Solution != nil && j.Solution.Token != "" {
		token = j.Solution.Token
	}
	if token != "" && (j.ErrorID == 0 || j.Solution != nil) {
		j.Request = token
		return &j, true, nil
	}
	return nil, false, nil
}

func truncate(b []byte) string {
	if len(b) <= 200 {
		return string(b)
	}
	return string(b[:200]) + "..."
}
