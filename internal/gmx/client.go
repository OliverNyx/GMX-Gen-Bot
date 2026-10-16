package gmx

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"gmxgen/internal/fingerprint"
	"gmxgen/internal/ids"
)

const (
	uiAppVersion     = "@mamdev/umreg.registration-app2/8.38.0"
	campaignHeader   = "#kid_autoref_www.gmx.com"
	defaultSiteKey   = "sk_vKdD8WGlPF5FKpRDs1U4qTuu6Jv0w"
	defaultPulse     = "2bd77e6f8a17bc0e"
	defaultMAMFox    = "https://s.uicdn.com/mampkg/@mamdev/core.frontend.libs.captchafox/2bd77e6f8a17bc0e/"
	signupOrigin     = "https://signup.gmx.com"
	SignupPageURL    = signupOrigin + "/"
	productGMXFree   = "gmxcomFree"
)

var siteKeyRE = regexp.MustCompile(`sk_[A-Za-z0-9_]+`)
var mamFoxRE = regexp.MustCompile(`https://s\.uicdn\.com/mampkg/@mamdev/core\.frontend\.libs\.captchafox/[a-f0-9]+/`)

// appConfigRE extracts the <script id="application-config" type="application/json">{...}</script>
// payload that the GMX signup HTML embeds. It carries the Bearer access token the WAF requires.
var appConfigRE = regexp.MustCompile(`(?s)<script[^>]*id=['"]application-config['"][^>]*>(.*?)</script>`)

type Client struct {
	HTTP      *http.Client
	FP        fingerprint.Profile
	CCGUID    string
	SiteKey      string
	MAMApiServer string
	Pulse        string
	lastProto    string

	// Populated from the signup HTML application-config (required by the GMX WAF).
	AccessToken     string
	TemplateName    string
	SoftwareVariant string
	ReferrerSource  string
	LoginStatistics string
}

// appConfig mirrors the fields we need from the embedded application-config JSON.
type appConfig struct {
	AccessToken          string `json:"accessToken"`
	ClientCredentialGuid string `json:"clientCredentialGuid"`
	SoftwareVariant      string `json:"softwareVariant"`
	ReferrerSource       string `json:"referrerSource"`
	TemplateName         string `json:"templateName"`
	Core                 struct {
		LoginConfig struct {
			Statistics string `json:"statistics"`
		} `json:"loginConfig"`
		Services struct {
			Captcha struct {
				CaptchaFox struct {
					SiteKey string `json:"siteKey"`
				} `json:"captchaFox"`
			} `json:"captcha"`
		} `json:"services"`
	} `json:"core"`
}

func NewClient(h *http.Client, fp fingerprint.Profile) *Client {
	return &Client{
		HTTP:    h,
		FP:      fp,
		CCGUID:  ids.NewV4(),
		SiteKey:      defaultSiteKey,
		MAMApiServer: defaultMAMFox,
		Pulse:        defaultPulse,
	}
}

func (c *Client) LastProtocol() string {
	return c.lastProto
}

// setBrowserHeaders sets the headers common to every signup XHR. It intentionally
// does NOT set Origin: Chrome only sends Origin on cross-origin or POST requests,
// and sending it on a same-origin GET is a classic bot tell the GMX WAF rejects.
func (c *Client) setBrowserHeaders(req *http.Request, referer string) {
	req.Header.Set("User-Agent", c.FP.UserAgent)
	req.Header.Set("Accept-Language", c.FP.AcceptLanguage)
	req.Header.Set("sec-ch-ua", c.FP.SecCHUA)
	req.Header.Set("sec-ch-ua-mobile", c.FP.SecCHUAMobile)
	req.Header.Set("sec-ch-ua-platform", c.FP.SecCHUAPlatform)
	// Chrome always sends sec-ch-ua-model, as an empty quoted string on desktop.
	model := c.FP.SecCHUAModel
	if model == "" {
		model = `""`
	}
	req.Header.Set("sec-ch-ua-model", model)
	req.Header.Set("sec-fetch-site", "same-origin")
	req.Header.Set("sec-fetch-mode", "cors")
	req.Header.Set("sec-fetch-dest", "empty")
	if referer != "" {
		req.Header.Set("Referer", referer)
	}
	req.Header.Set("x-ccguid", c.CCGUID)
	req.Header.Set("x-ui-app", uiAppVersion)
}

// setSentryHeaders adds the Sentry tracing headers Chrome sends on signup XHRs,
// with a baggage trace_id that matches the sentry-trace header.
func (c *Client) setSentryHeaders(req *http.Request) {
	traceID := strings.ReplaceAll(ids.NewV4(), "-", "")
	spanID := strings.ReplaceAll(ids.NewV4(), "-", "")[:16]
	req.Header.Set("sentry-trace", traceID+"-"+spanID+"-0")
	req.Header.Set("baggage", "sentry-environment=live,"+
		"sentry-release=registration-app2%408.38.0,"+
		"sentry-public_key=3a5b6ce168339211e7bd2d0dd3d696d3,"+
		"sentry-trace_id="+traceID+","+
		"sentry-transaction=%2F,"+
		"sentry-sampled=false,sentry-sample_rate=0.1")
	req.Header.Set("priority", "u=1, i")
}

func (c *Client) do(req *http.Request) (*http.Response, []byte, error) {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 && req.GetBody != nil {
			body, err := req.GetBody()
			if err != nil {
				return nil, nil, err
			}
			req.Body = body
		}
		resp, err := c.HTTP.Do(req)
		if err != nil {
			lastErr = err
			if !isTransientNet(err) {
				return nil, nil, err
			}
			time.Sleep(time.Duration(attempt+1) * time.Second)
			continue
		}
		c.lastProto = resp.Proto
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return resp, nil, err
		}
		return resp, body, nil
	}
	return nil, nil, lastErr
}

func isTransientNet(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "EOF") ||
		strings.Contains(s, "timeout") ||
		strings.Contains(s, "Gateway Timeout") ||
		strings.Contains(s, "connection reset") ||
		strings.Contains(s, "broken pipe")
}

// LoadSignup loads the registration SPA and extracts CaptchaFox site key when present.
func (c *Client) LoadSignup() error {
	req, err := http.NewRequest(http.MethodGet, signupOrigin+"/", nil)
	if err != nil {
		return err
	}
	c.setBrowserHeaders(req, "")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
	req.Header.Set("sec-fetch-site", "none")
	req.Header.Set("sec-fetch-mode", "navigate")
	req.Header.Set("sec-fetch-dest", "document")
	req.Header.Set("Upgrade-Insecure-Requests", "1")

	resp, body, err := c.do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("signup page: %s", resp.Status)
	}
	html := string(body)
	if m := mamFoxRE.FindString(html); m != "" {
		c.MAMApiServer = m
	}

	// Parse the embedded application-config: it holds the Bearer access token and
	// the client credential GUID the GMX "neo" WAF requires on the API endpoints.
	if m := appConfigRE.FindStringSubmatch(html); len(m) == 2 {
		var cfg appConfig
		if err := json.Unmarshal([]byte(strings.TrimSpace(m[1])), &cfg); err == nil {
			c.AccessToken = cfg.AccessToken
			if cfg.ClientCredentialGuid != "" {
				c.CCGUID = cfg.ClientCredentialGuid
			}
			c.TemplateName = cfg.TemplateName
			c.SoftwareVariant = cfg.SoftwareVariant
			c.ReferrerSource = cfg.ReferrerSource
			c.LoginStatistics = cfg.Core.LoginConfig.Statistics
			if sk := cfg.Core.Services.Captcha.CaptchaFox.SiteKey; sk != "" {
				c.SiteKey = sk
			}
		}
	}
	// Fallback: raw site key scan if config was absent.
	if c.SiteKey == "" {
		if m := siteKeyRE.FindString(html); m != "" {
			c.SiteKey = m
		}
	}
	if c.AccessToken == "" {
		// Some exits return a 200 interstitial without the SPA config.
		return fmt.Errorf("signup page: application-config access token not found (len=%d)", len(html))
	}
	return nil
}

// setAuth adds the Bearer access token extracted from the signup HTML.
func (c *Client) setAuth(req *http.Request) {
	if c.AccessToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.AccessToken)
	}
}

type Configuration struct {
	Captcha string `json:"captcha"`
}

func (c *Client) FetchConfiguration() (*Configuration, error) {
	req, err := http.NewRequest(http.MethodGet, signupOrigin+"/account/configuration", nil)
	if err != nil {
		return nil, err
	}
	c.setBrowserHeaders(req, signupOrigin+"/")
	c.setSentryHeaders(req)
	c.setAuth(req)
	req.Header.Set("Accept", "application/vnd.ui.mam.configuration-v1+json")
	req.Header.Set("Content-Type", "application/vnd.ui.mam.configuration-v1+json")
	req.Header.Set("x-request-id", ids.NewV4())

	resp, body, err := c.do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("configuration: %s body=%s", resp.Status, truncate(body, 300))
	}
	var cfg Configuration
	if err := json.Unmarshal(body, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

type AvailabilityRequest struct {
	EmailAddress                 string            `json:"emailAddress"`
	FirstName                    string            `json:"firstName"`
	LastName                     string            `json:"lastName"`
	BirthDate                    string            `json:"birthDate"`
	City                         string            `json:"city"`
	CountryCode                  string            `json:"countryCode"`
	InitialRequestedEmailAddress string            `json:"initialRequestedEmailAddress"`
	SuggestionProducts           []string          `json:"suggestionProducts"`
	MaxResultCountToProduct      map[string]string `json:"maxResultCountToProduct"`
	MdhMaxResultCount            string            `json:"mdhMaxResultCount"`
	RequestedEmailAddressProduct string            `json:"requestedEmailAddressProduct"`
}

type AvailabilityResponse struct {
	RequestedEmailAddress string                   `json:"requestedEmailAddress"`
	EmailAddressAvailable bool                     `json:"emailAddressAvailable"`
	SuggestedEmails       map[string][]interface{} `json:"suggestedEmails"`
}

// FirstSuggestion returns the first usable GMX free-product email from the availability reply.
func (a *AvailabilityResponse) FirstSuggestion() string {
	if a == nil {
		return ""
	}
	for _, key := range []string{productGMXFree, "gmxcomFree"} {
		if pick := firstEmailFromList(a.SuggestedEmails[key]); pick != "" {
			return pick
		}
	}
	for _, list := range a.SuggestedEmails {
		if pick := firstEmailFromList(list); pick != "" {
			return pick
		}
	}
	return ""
}

func firstEmailFromList(list []interface{}) string {
	for _, item := range list {
		switch v := item.(type) {
		case string:
			if strings.Contains(v, "@") {
				return v
			}
		case map[string]interface{}:
			for _, k := range []string{"emailAddress", "email", "address", "requestedEmailAddress"} {
				if s, ok := v[k].(string); ok && strings.Contains(s, "@") {
					return s
				}
			}
		}
	}
	return ""
}

func (c *Client) CheckEmailAvailability(email, first, last, birth string) (*AvailabilityResponse, error) {
	payload := AvailabilityRequest{
		EmailAddress:                 email,
		FirstName:                    first,
		LastName:                     last,
		BirthDate:                    birth,
		City:                         "",
		CountryCode:                  "US",
		InitialRequestedEmailAddress: "",
		SuggestionProducts:           []string{productGMXFree},
		MaxResultCountToProduct:      map[string]string{productGMXFree: "4"},
		MdhMaxResultCount:            "0",
		RequestedEmailAddressProduct: productGMXFree,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodPost, "https://register-suggest.gmx.com/rest/email-alias/availability", bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	c.setBrowserHeaders(req, signupOrigin+"/")
	c.setSentryHeaders(req)
	c.setAuth(req)
	req.Header.Set("Origin", signupOrigin) // POST XHR: Chrome sends Origin
	req.Header.Set("sec-fetch-site", "same-site")
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Content-Type", "application/vnd.ui.mam.suggestion.creation-v1+json")
	req.Header.Set("x-request-id", ids.NewV4())

	resp, body, err := c.do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("availability: %s body=%s", resp.Status, truncate(body, 400))
	}
	var out AvailabilityResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

type RegistrationRequest struct {
	User        RegistrationUser `json:"user"`
	MailAccount MailAccount      `json:"mailAccount"`
	Product     string           `json:"product"`
	MediaCode   *string          `json:"mediaCode"`
}

type RegistrationUser struct {
	GivenName    string              `json:"givenName"`
	FamilyName   string              `json:"familyName"`
	Gender       string              `json:"gender"`
	BirthDate    string              `json:"birthDate"`
	MobileNumber string              `json:"mobileNumber"`
	Address      RegistrationAddress `json:"address"`
	Credentials  RegistrationCreds   `json:"credentials"`
}

type RegistrationAddress struct {
	CountryCode   string `json:"countryCode"`
	Region        string `json:"region"`
	PostalCode    string `json:"postalCode"`
	Locality      string `json:"locality"`
	StreetAddress string `json:"streetAddress"`
}

type RegistrationCreds struct {
	Password string `json:"password"`
}

type MailAccount struct {
	Email string `json:"email"`
}

func (c *Client) RegisterEmail(captchaToken string, person RegistrationUser, email string) (int, []byte, error) {
	payload := RegistrationRequest{
		User: person,
		MailAccount: MailAccount{Email: email},
		Product:     productGMXFree,
		MediaCode:   nil,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return 0, nil, err
	}
	req, err := http.NewRequest(http.MethodPost, signupOrigin+"/account/email-registration", bytes.NewReader(raw))
	if err != nil {
		return 0, nil, err
	}
	c.setBrowserHeaders(req, signupOrigin+"/")
	c.setSentryHeaders(req)
	c.setAuth(req)
	req.Header.Set("Origin", signupOrigin)
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Content-Type", "application/vnd.ui.mam.account.creation+json")
	// CaptchaFox: Angular sends the widget verify value as cf-captcha-response
	// (userSolution), not a separate X-CAPTCHA-TOKEN.
	if captchaToken != "" {
		req.Header.Set("cf-captcha-response", captchaToken)
	}
	req.Header.Set("Campaign", campaignHeader)
	templateName := c.TemplateName
	if templateName == "" {
		templateName = c.FP.TemplateName
	}
	req.Header.Set("Template-Name", templateName)
	if c.SoftwareVariant != "" {
		req.Header.Set("Software-Variant", c.SoftwareVariant)
	}
	if c.ReferrerSource != "" {
		req.Header.Set("Source", c.ReferrerSource)
	}
	req.Header.Set("x-request-id", ids.NewV4())

	resp, body, err := c.do(req)
	if err != nil {
		return 0, nil, err
	}
	return resp.StatusCode, body, nil
}

func (c *Client) LoginAfterRegistration(email, password string) (int, string, error) {
	form := url.Values{}
	form.Set("successURL", "https://interception-bs.gmx.com/logininterceptionfrontend/?interceptiontype=RegistrationWelcomeInterception&tgt=https%3A%2F%2Fnavigator-bs.gmx.com%2Flogin&tsid=mailint")
	form.Set("loginErrorURL", "https://www.gmx.com/int/")
	form.Set("loginFailedURL", "https://www.gmx.com/int/")
	form.Set("statistics", c.LoginStatistics) // from application-config loginConfig
	form.Set("service", "RegistrationWelcomeInterception")
	form.Set("username", email)
	form.Set("password", password)
	form.Set("iid", c.CCGUID)
	form.Set("registrationcountry", "us")
	form.Set("brand", "gmxcom")
	form.Set("contentposition", "web")
	form.Set("source", "")

	req, err := http.NewRequest(http.MethodPost, "https://login.gmx.com/login", strings.NewReader(form.Encode()))
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("User-Agent", c.FP.UserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8")
	req.Header.Set("Accept-Language", c.FP.AcceptLanguage)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", signupOrigin)
	req.Header.Set("Referer", signupOrigin+"/")
	req.Header.Set("sec-ch-ua", c.FP.SecCHUA)
	req.Header.Set("sec-ch-ua-mobile", c.FP.SecCHUAMobile)
	req.Header.Set("sec-ch-ua-platform", c.FP.SecCHUAPlatform)
	req.Header.Set("sec-fetch-dest", "document")
	req.Header.Set("sec-fetch-mode", "navigate")
	req.Header.Set("sec-fetch-site", "same-site")
	req.Header.Set("sec-fetch-user", "?1")
	req.Header.Set("Upgrade-Insecure-Requests", "1")

	resp, _, err := c.do(req)
	if err != nil {
		return 0, "", err
	}
	loc := resp.Header.Get("Location")
	return resp.StatusCode, loc, nil
}

func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "..."
}
