package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"os"
	"strings"
	"time"

	"gmxgen/internal/envfile"
	"gmxgen/internal/fingerprint"
	"gmxgen/internal/gmx"
	"gmxgen/internal/httpclient"
	"gmxgen/internal/identity"
	"gmxgen/internal/ids"
	"gmxgen/internal/proxyconfig"
)

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	var n int
	if _, err := fmt.Sscanf(v, "%d", &n); err != nil || n < 1 {
		return def
	}
	return n
}

func envBool(key string, def bool) bool {
	v := strings.TrimSpace(strings.ToLower(os.Getenv(key)))
	if v == "" {
		return def
	}
	return v == "1" || v == "true" || v == "yes"
}

func main() {
	envfile.Load(".env")
	var (
		captchaToken = flag.String("captcha-token", env("CAPTCHA_TOKEN", ""), "CaptchaFox token (MAM_...); skips solvers")
		capzyKey     = flag.String("capzy-key", env("CAPZY_API_KEY", ""), "Capzy / 2Captcha API key")
		captchaAPI   = flag.String("captcha-api", env("CAPTCHA_API_URL", ""), "captcha API base URL (default: api.capzy.ai; set to https://api.2captcha.com for 2Captcha)")
		capskipURL   = flag.String("capskip-url", env("CAPSKIP_URL", "http://127.0.0.1:8080"), "CapSkip local API base URL")
		capskipKey   = flag.String("capskip-key", env("CAPSKIP_KEY", ""), "CapSkip API key (if validation enabled)")
		noCapSkip    = flag.Bool("no-capskip", true, "do not call local CapSkip")
		proxyHost    = flag.String("proxy-host", env("PROXY_HOST", "geo.iproyal.com"), "proxy host")
		proxyPort    = flag.String("proxy-port", env("PROXY_PORT", "12321"), "proxy port")
		proxyUser    = flag.String("proxy-user", env("PROXY_USER", ""), "proxy username")
		proxyPass    = flag.String("proxy-pass", env("PROXY_PASS", ""), "proxy password")
		proxySession = flag.String("proxy-session", env("PROXY_SESSION", ""), "fixed iProyal _session-* (only used with -rotate-proxy-session=false)")
		proxyLine    = flag.String("proxy", env("PROXY", ""), "host:port:user:pass (overrides PROXY_HOST/PORT/USER/PASS)")
		proxyFile    = flag.String("proxy-file", env("PROXY_FILE", ""), "file with host:port:user:pass lines (default: proxy.txt if present)")
		proxyMaxTry  = flag.Int("proxy-max-tries", envInt("PROXY_MAX_TRIES", 40), "when using -proxy-file, try up to N random lines until GMX config OK")
		regTries     = flag.Int("reg-tries", envInt("REG_TRIES", 5), "retry with a new sticky IP when GMX returns IP_INFO_D_FORBIDDEN")
		probeOnly    = flag.Bool("probe", false, "only test proxies from -proxy-file against GMX signup+configuration")
		rotateProxy  = flag.Bool("rotate-proxy-session", envBool("ROTATE_PROXY_SESSION", true), "iProyal: new _session-* per run (ignored for generic proxies)")
		dryRun       = flag.Bool("dry-run", false, "build identity and print planned requests only")
		skipLogin    = flag.Bool("skip-login", false, "stop after registration API")
		seed         = flag.Int64("seed", 0, "RNG seed (0 = random)")
	)
	flag.Parse()

	if strings.TrimSpace(*proxyFile) == "" && strings.TrimSpace(*proxyLine) == "" && strings.TrimSpace(*proxyUser) == "" {
		if _, err := os.Stat("proxy.txt"); err == nil {
			*proxyFile = "proxy.txt"
		}
	}

	if strings.TrimSpace(*proxyLine) != "" {
		h, p, u, pw, err := proxyconfig.ParseHostPortUserPass(*proxyLine)
		if err != nil {
			log.Fatal(err)
		}
		*proxyHost, *proxyPort, *proxyUser, *proxyPass = h, p, u, pw
	}

	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	if *seed != 0 {
		rng = rand.New(rand.NewSource(*seed))
	}

	fp := fingerprint.Random(rng)
	person := identity.Random(rng)
	email := gmx.PersonEmail(person.EmailLocal)

	var sessionID string
	if *rotateProxy && proxyconfig.SessionRotatable(*proxyPass) {
		sessionID = strings.ReplaceAll(ids.NewV4(), "-", "")[:12]
	} else if !*rotateProxy {
		sessionID = strings.TrimSpace(*proxySession)
	}

	var proxyURL string
	var gc *gmx.Client
	var proxyFromFile string
	var fileLines []string
	probedSignup := false

	if strings.TrimSpace(*proxyFile) != "" {
		lines, err := proxyconfig.LoadLines(*proxyFile)
		if err != nil {
			log.Fatal(err)
		}
		fileLines = lines
		log.Printf("loaded %d proxies from %s", len(lines), *proxyFile)
		if *probeOnly {
			ok := 0
			tries := *proxyMaxTry
			if tries > len(lines) {
				tries = len(lines)
			}
			for i := 0; i < tries; i++ {
				line := proxyconfig.PickLine(lines, rng.Intn(len(lines)))
				host, port, user, pass, err := proxyconfig.ParseHostPortUserPass(line)
				if err != nil {
					continue
				}
				sid := sessionID
				if sid == "" {
					sid = proxyconfig.ExtractSession(pass)
				}
				if sid == "" && proxyconfig.SessionRotatable(pass) {
					sid = randomSession(rng)
				}
				u, err := proxyconfig.Build(host, port, user, pass, sid)
				if err != nil {
					continue
				}
				client, err := httpclient.New(u)
				if err != nil {
					continue
				}
				c := gmx.NewClient(client, fp)
				if err := c.ProbeSignup(2); err != nil {
					log.Printf("probe %s:%s: %v", host, port, err)
					continue
				}
				ok++
				log.Printf("probe OK %s:%s", host, port)
			}
			_ = json.NewEncoder(os.Stdout).Encode(map[string]interface{}{
				"ok": ok > 0, "passed": ok, "tried": tries, "file": *proxyFile,
			})
			if ok == 0 {
				os.Exit(1)
			}
			return
		}
		pick, client, err := pickProxyFromFile(lines, rng, fp, sessionID, *proxyMaxTry)
		if err != nil {
			log.Fatal(err)
		}
		proxyURL = pick.URL
		gc = client
		proxyFromFile = pick.Host + ":" + pick.Port
		probedSignup = true
		sessionID = pick.SessionID
	} else {
		u, err := proxyconfig.Build(*proxyHost, *proxyPort, *proxyUser, *proxyPass, sessionID)
		if err != nil {
			log.Fatal(err)
		}
		proxyURL = u
	}

	plan := map[string]interface{}{
		"email":          email,
		"mobile":         person.Mobile,
		"region":         person.Region,
		"fingerprint":    fp,
		"ccguid":         ids.NewV4(),
		"proxy":          maskProxy(proxyURL),
		"sticky_session": sessionID,
		"proxy_source":   proxyFromFile,
	}
	if *dryRun {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(plan)
		return
	}

	if proxyURL == "" && len(fileLines) == 0 {
		log.Fatal("set PROXY, PROXY_FILE, or PROXY_USER and PROXY_PASS")
	}

	var last attemptResult
	for attempt := 1; attempt <= *regTries; attempt++ {
		if attempt > 1 {
			fp = fingerprint.Random(rng)
			person = identity.Random(rng)
			email = gmx.PersonEmail(person.EmailLocal)
			gc = nil
			probedSignup = false
			log.Printf("GMX blocked previous IP (IP intelligence). retry %d/%d with new session", attempt, *regTries)
		}
		last = attemptAccount(rng, fileLines, sessionID, proxyURL, gc, probedSignup, person, email, fp, *capzyKey, *captchaAPI, *capskipURL, *capskipKey, *captchaToken, *noCapSkip, *skipLogin, *proxyMaxTry)
		if last.Err == nil {
			appendAccount("accounts.txt", last.Res)
			break
		}
		if !ipForbidden(last.Err) || attempt == *regTries {
			break
		}
	}

	out := map[string]interface{}{
		"ok":             last.Err == nil,
		"error":          errString(last.Err),
		"result":         last.Res,
		"sticky_session": last.SessionID,
		"proxy_source":   last.ProxySource,
		"capzy":          last.Capzy,
		"capskip":        last.Capskip,
		"http_protocol":  last.HTTPProtocol,
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(out)
	if last.Err != nil {
		os.Exit(1)
	}
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func maskProxy(u string) string {
	if i := strings.Index(u, "@"); i > 0 {
		return "http://***:***" + u[i:]
	}
	return u
}
