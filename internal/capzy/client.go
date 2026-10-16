package capzy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"gmxgen/internal/proxyconfig"
)

const defaultAPI = "https://api.capzy.ai"

// Client for createTask / getTaskResult captcha APIs.
// Works with Capzy (api.capzy.ai) and 2Captcha (api.2captcha.com)
// because both implement the same endpoint schema.
type Client struct {
	APIKey  string
	BaseURL string
	HTTP    *http.Client
}

func New(apiKey string) *Client {
	return &Client{
		APIKey:  apiKey,
		BaseURL: defaultAPI,
		HTTP:    &http.Client{Timeout: 90 * time.Second},
	}
}

// NewWithURL creates a client with a custom API base URL.
// Use "https://api.2captcha.com" for 2Captcha.
func NewWithURL(apiKey, baseURL string) *Client {
	if baseURL == "" {
		baseURL = defaultAPI
	}
	return &Client{
		APIKey:  apiKey,
		BaseURL: strings.TrimRight(baseURL, "/"),
		HTTP:    &http.Client{Timeout: 90 * time.Second},
	}
}

// CaptchaFoxRequest GMX uses MAM-packaged CaptchaFox; proxy must match registration IP.
type CaptchaFoxRequest struct {
	WebsiteURL string
	WebsiteKey string
	APIServer  string
	UserAgent  string
	ProxyURL   string
}

type Result struct {
	Token     string
	TaskID    string
	Cost      float64
	UserAgent string
	SolveIP   string // 2Captcha "ip": address that submitted the task. Call the API through the registration proxy so this matches the bot exit.
}

type createTaskReq struct {
	ClientKey string      `json:"clientKey"`
	Task      interface{} `json:"task"`
}

type createTaskResp struct {
	ErrorID          int    `json:"errorId"`
	ErrorCode        string `json:"errorCode"`
	ErrorDescription string `json:"errorDescription"`
	TaskID           flexID `json:"taskId"` // UUID string (Capzy) or number (2Captcha)
	Status           string `json:"status"`
}

type getResultReq struct {
	ClientKey string `json:"clientKey"`
	TaskID    flexID `json:"taskId"`
}

type getResultResp struct {
	ErrorID          int             `json:"errorId"`
	ErrorCode        string          `json:"errorCode"`
	ErrorDescription string          `json:"errorDescription"`
	Status           string          `json:"status"`
	Cost             flexFloat       `json:"cost"` // number from Capzy, string from 2Captcha
	IP               string          `json:"ip"`   // 2Captcha returns the solver exit IP
	Solution         *solutionResult `json:"solution"`
}

// flexID accepts a JSON string or number and emits a number when the value is numeric.
type flexID string

func (f *flexID) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) == 0 || string(b) == "null" {
		*f = ""
		return nil
	}
	if b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		*f = flexID(s)
		return nil
	}
	*f = flexID(b)
	return nil
}

func (f flexID) MarshalJSON() ([]byte, error) {
	s := string(f)
	if s == "" {
		return []byte("null"), nil
	}
	if _, err := strconv.ParseInt(s, 10, 64); err == nil {
		return []byte(s), nil
	}
	return json.Marshal(s)
}

// flexFloat accepts a JSON number or a numeric string.
type flexFloat float64

func (f *flexFloat) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) == 0 || string(b) == "null" {
		return nil
	}
	if b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		if s == "" {
			return nil
		}
		v, err := strconv.ParseFloat(s, 64)
		if err != nil {
			return err
		}
		*f = flexFloat(v)
		return nil
	}
	v, err := strconv.ParseFloat(string(b), 64)
	if err != nil {
		return err
	}
	*f = flexFloat(v)
	return nil
}

type solutionResult struct {
	Token     string `json:"token"`
	UserAgent string `json:"userAgent"`
}

func (c *Client) label() string {
	if strings.Contains(c.BaseURL, "2captcha") {
		return "2captcha"
	}
	return "capzy"
}

// SolveCaptchaFox creates CaptchaFoxTask and polls until ready.
func (c *Client) SolveCaptchaFox(ctx context.Context, req CaptchaFoxRequest) (*Result, error) {
	label := c.label()
	if c.APIKey == "" {
		return nil, fmt.Errorf("%s: missing API key", label)
	}
	parts, err := proxyconfig.ParseHTTPProxyURL(req.ProxyURL)
	if err != nil {
		return nil, err
	}
	portNum, err := strconv.Atoi(parts.Port)
	if err != nil || portNum <= 0 {
		return nil, fmt.Errorf("%s: invalid proxy port %q", label, parts.Port)
	}
	task := map[string]interface{}{
		"type":         "CaptchaFoxTask",
		"websiteURL":   req.WebsiteURL,
		"websiteKey":   req.WebsiteKey,
		"userAgent":    req.UserAgent,
		"proxyType":    "http",
		"proxyAddress": parts.Host,
		"proxyPort":    portNum,
	}
	if parts.User != "" {
		task["proxyLogin"] = parts.User
		task["proxyPassword"] = parts.Password
	}
	if req.APIServer != "" {
		api := req.APIServer
		if i := strings.Index(api, "/core.frontend.libs.captchafox/"); i >= 0 {
			api = api[:i+len("/core.frontend.libs.captchafox/")]
		}
		task["apiServer"] = api
	}

	taskID, err := c.createTask(ctx, task)
	if err != nil {
		return nil, err
	}

	deadline := time.Now().Add(3 * time.Minute)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("%s: timeout waiting for task %s", label, taskID)
		}
		res, err := c.getTaskResult(ctx, taskID)
		if err != nil {
			return nil, err
		}
		switch res.Status {
		case "ready":
			if res.Solution == nil || res.Solution.Token == "" {
				return nil, fmt.Errorf("%s: empty token for task %s", label, taskID)
			}
			return &Result{
				Token:     res.Solution.Token,
				TaskID:    taskID,
				Cost:      float64(res.Cost),
				UserAgent: res.Solution.UserAgent,
				SolveIP:   res.IP,
			}, nil
		case "failed":
			return nil, fmt.Errorf("%s: solve failed: %s %s", label, res.ErrorCode, res.ErrorDescription)
		}
		wait := time.Second
		if label == "2captcha" {
			wait = 5 * time.Second
		}
		time.Sleep(wait)
	}
}

func (c *Client) createTask(ctx context.Context, task map[string]interface{}) (string, error) {
	label := c.label()
	body, _ := json.Marshal(createTaskReq{ClientKey: c.APIKey, Task: task})
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/createTask", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTP.Do(httpReq)
	if err != nil {
		return "", err
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	var out createTaskResp
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", fmt.Errorf("%s createTask: %w body=%s", label, err, truncate(raw))
	}
	if out.ErrorID != 0 || out.TaskID == "" {
		return "", fmt.Errorf("%s createTask: %s %s", label, out.ErrorCode, out.ErrorDescription)
	}
	return string(out.TaskID), nil
}

func (c *Client) getTaskResult(ctx context.Context, taskID string) (*getResultResp, error) {
	label := c.label()
	body, _ := json.Marshal(getResultReq{ClientKey: c.APIKey, TaskID: flexID(taskID)})
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/getTaskResult", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTP.Do(httpReq)
	if err != nil {
		return nil, err
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	var out getResultResp
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("%s getTaskResult: %w", label, err)
	}
	if out.ErrorID != 0 && out.Status != "ready" && out.Status != "processing" {
		return nil, fmt.Errorf("%s getTaskResult: %s %s", label, out.ErrorCode, out.ErrorDescription)
	}
	return &out, nil
}

func truncate(b []byte) string {
	if len(b) <= 200 {
		return string(b)
	}
	return string(b[:200]) + "..."
}
