package main

import (
	"context"
	"fmt"
	"log"
	"math/rand"
	"os"
	"strings"
	"time"

	"gmxgen/internal/capskip"
	"gmxgen/internal/capzy"
	"gmxgen/internal/fingerprint"
	"gmxgen/internal/gmx"
	"gmxgen/internal/httpclient"
	"gmxgen/internal/identity"
	"gmxgen/internal/proxyconfig"
)

type attemptResult struct {
	Res          *gmx.RegisterResult
	Err          error
	SessionID    string
	ProxySource  string
	ProxyURL     string
	Capzy        map[string]interface{}
	Capskip      map[string]interface{}
	HTTPProtocol string
}

func ipForbidden(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "mam.registration:Forbidden") ||
		strings.Contains(s, "IP_INFO_D") ||
		strings.Contains(s, "access-forbidden") ||
		strings.Contains(s, "blocked this proxy IP")
}

func attemptAccount(rng *rand.Rand, fileLines []string, sessionHint string, proxyURL string, gc *gmx.Client, probed bool, person identity.Person, email string, fp fingerprint.Profile, capzyKey, captchaAPIURL, capskipURL, capskipKey, captchaToken string, noCapSkip, skipLogin bool, proxyMaxTry int) attemptResult {
	out := attemptResult{ProxyURL: proxyURL, SessionID: sessionHint}

	if len(fileLines) > 0 {
		pick, client, err := pickProxyFromFile(fileLines, rng, fp, "", proxyMaxTry)
		if err != nil {
			out.Err = err
			return out
		}
		proxyURL = pick.URL
		gc = client
		probed = true
		out.ProxyURL = proxyURL
		out.ProxySource = pick.Host + ":" + pick.Port
		out.SessionID = pick.SessionID
		log.Printf("proxy sticky session: %s", pick.SessionID)
	} else if gc == nil {
		client, err := httpclient.New(proxyURL)
		if err != nil {
			out.Err = err
			return out
		}
		gc = gmx.NewClient(client, fp)
	}

	token := captchaToken
	skipSignupLoad := probed
	if token == "" {
		if !probed {
			if err := gc.ProbeSignup(5); err != nil {
				out.Err = fmt.Errorf("gmx precheck: %w", err)
				return out
			}
			skipSignupLoad = true
		}
		if capzyKey != "" {
			cz := capzy.NewWithURL(capzyKey, captchaAPIURL)
			// Same HTTP client as GMX, so 2Captcha records the proxy exit
			// (the IP that submits the task) instead of this machine.
			cz.HTTP = gc.HTTP
			exitIP := lookupExitIP(gc.HTTP)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			defer cancel()
			log.Printf("captcha: solving CaptchaFox via %s botIP=%s proxy=%s siteKey=%s", cz.BaseURL, exitIP, maskProxy(proxyURL), gc.SiteKey)
			solved, err := cz.SolveCaptchaFox(ctx, capzy.CaptchaFoxRequest{
				WebsiteURL: gmx.SignupPageURL,
				WebsiteKey: gc.SiteKey,
				APIServer:  gc.MAMApiServer,
				UserAgent:  gc.FP.UserAgent,
				ProxyURL:   proxyURL,
			})
			if err != nil {
				out.Err = fmt.Errorf("captcha solver: %w", err)
				return out
			}
			token = solved.Token
			if solved.UserAgent != "" {
				gc.FP = fingerprint.WithUserAgent(gc.FP, solved.UserAgent)
			}
			if solved.SolveIP != "" && exitIP != "?" && solved.SolveIP != exitIP {
				out.Err = fmt.Errorf("captcha IP %s does not match bot exit %s", solved.SolveIP, exitIP)
				return out
			}
			out.Capzy = map[string]interface{}{
				"task_id":    solved.TaskID,
				"cost":       solved.Cost,
				"site_key":   gc.SiteKey,
				"api_server": gc.MAMApiServer,
				"token_pfx":  tokenPrefix(token),
				"proxy_sent": maskProxy(proxyURL),
				"bot_ip":     exitIP,
				"captcha_ip": solved.SolveIP,
			}
			log.Printf("captcha: OK task=%s token=%s cost=%.4f botIP=%s captchaIP=%s", solved.TaskID, tokenPrefix(token), solved.Cost, exitIP, solved.SolveIP)
		} else if !noCapSkip {
			capProxy, err := proxyconfig.CapSkipAddress(proxyURL)
			if err != nil {
				out.Err = err
				return out
			}
			cs := capskip.New(capskipURL, capskipKey)
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
			defer cancel()
			solved, err := cs.SolveCaptchaFox(ctx, capskip.CaptchaFoxRequest{
				SiteKey:   gc.SiteKey,
				PageURL:   gmx.SignupPageURL,
				APIServer: gc.MAMApiServer,
				Proxy:     capProxy,
				ProxyType: "HTTP",
			})
			if err != nil {
				out.Err = fmt.Errorf("capskip: %w", err)
				return out
			}
			token = solved.Token
			gc.FP = fingerprint.WithUserAgent(gc.FP, solved.UserAgent)
			out.Capskip = map[string]interface{}{
				"task_id":    solved.TaskID,
				"user_agent": solved.UserAgent,
			}
		} else {
			out.Err = fmt.Errorf("missing captcha: set CAPZY_API_KEY, CAPTCHA_TOKEN, or enable CapSkip")
			return out
		}
	}

	res, err := gc.Register(gmx.RegisterInput{
		Person:         person,
		Email:          email,
		CaptchaToken:   token,
		SkipLogin:      skipLogin,
		SkipSignupLoad: skipSignupLoad,
	})
	out.Res = res
	out.Err = err
	out.HTTPProtocol = gc.LastProtocol()
	return out
}

func tokenPrefix(s string) string {
	if len(s) < 8 {
		return s
	}
	return s[:8]
}

func appendAccount(path string, res *gmx.RegisterResult) {
	if res == nil || res.Email == "" {
		return
	}
	line := fmt.Sprintf("%s:%s\n", res.Email, res.Password)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		log.Printf("could not write %s: %v", path, err)
		return
	}
	defer f.Close()
	_, _ = f.WriteString(line)
}
