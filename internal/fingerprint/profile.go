package fingerprint

import (
	"fmt"
	"math/rand"
	"regexp"
)

var chromeVersionRE = regexp.MustCompile(`Chrome/(\d+)\.`)

// Profile mimics a desktop Chrome session (per HAR: signup.gmx.com uses Chrome 155 / Windows).
type Profile struct {
	UserAgent       string
	SecCHUA         string
	SecCHUAMobile   string
	SecCHUAPlatform string
	SecCHUAModel    string
	AcceptLanguage  string
	TemplateName    string // registration A/B template header
}

var chromeReleases = []struct {
	major int
	full  string
}{
	{155, "155.0.0.0"},
}

// Random returns a new browser fingerprint for multi-account runs.
func Random(r *rand.Rand) Profile {
	ch := chromeReleases[r.Intn(len(chromeReleases))]
	ua := fmt.Sprintf(
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%s Safari/537.36",
		ch.full,
	)
	sec := fmt.Sprintf(
		"\"Google Chrome\";v=\"%d\", \"Chromium\";v=\"%d\", \"Not(A:Brand\";v=\"24\"",
		ch.major, ch.major,
	)
	templates := []string{"A", "B"}
	return Profile{
		UserAgent:       ua,
		SecCHUA:         sec,
		SecCHUAMobile:   "?0",
		SecCHUAPlatform: "\"Windows\"",
		SecCHUAModel:    "",
		AcceptLanguage:  "en-US,en;q=0.9",
		TemplateName:    templates[r.Intn(len(templates))],
	}
}

// WithUserAgent applies the User-Agent returned by CapSkip (token is bound to it).
func WithUserAgent(p Profile, ua string) Profile {
	if ua == "" {
		return p
	}
	p.UserAgent = ua
	if m := chromeVersionRE.FindStringSubmatch(ua); len(m) == 2 {
		major := m[1]
		p.SecCHUA = fmt.Sprintf(
			"\"Google Chrome\";v=\"%s\", \"Chromium\";v=\"%s\", \"Not(A:Brand\";v=\"24\"",
			major, major,
		)
	}
	return p
}
