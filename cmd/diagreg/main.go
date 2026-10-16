package main

import (
	"context"
	"encoding/json"
	"log"
	"math/rand"
	"os"
	"time"

	"gmxgen/internal/capzy"
	"gmxgen/internal/envfile"
	"gmxgen/internal/fingerprint"
	"gmxgen/internal/gmx"
	"gmxgen/internal/httpclient"
	"gmxgen/internal/identity"
	"gmxgen/internal/proxyconfig"
)

func main() {
	envfile.Load(".env")
	line := "79.176.28.144:47880:peedwn8k5cqyky4:RLwzLCxnObFr"
	if len(os.Args) > 1 {
		line = os.Args[1]
	}
	capzyKey := os.Getenv("CAPZY_API_KEY")
	captchaAPI := os.Getenv("CAPTCHA_API_URL") // set to https://api.2captcha.com for 2Captcha

	h, p, u, pw, err := proxyconfig.ParseHostPortUserPass(line)
	if err != nil {
		log.Fatal(err)
	}
	proxyURL, err := proxyconfig.Build(h, p, u, pw, "")
	if err != nil {
		log.Fatal(err)
	}
	client, err := httpclient.New(proxyURL)
	if err != nil {
		log.Fatal(err)
	}
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	fp := fingerprint.Random(rng)
	gc := gmx.NewClient(client, fp)
	if err := gc.LoadSignup(); err != nil {
		log.Fatal("signup:", err)
	}
	log.Printf("signup OK — token=%s siteKey=%s apiServer=%s",
		prefix(gc.AccessToken, 8), gc.SiteKey, gc.MAMApiServer)

	person := identity.Random(rng)
	email := gmx.PersonEmail(person.EmailLocal)
	user := gmx.RegistrationUser{
		GivenName:    person.GivenName,
		FamilyName:   person.FamilyName,
		Gender:       person.Gender,
		BirthDate:    person.BirthDate,
		MobileNumber: person.Mobile,
		Address: gmx.RegistrationAddress{
			CountryCode: "US",
			Region:      person.Region,
		},
		Credentials: gmx.RegistrationCreds{Password: person.Password},
	}

	// Test 1: fake token → should be 424 (confirms IP allowed)
	status1, body1, _ := gc.RegisterEmail("MAM_0000000000000000000000000000000000000000000000000000000000000000", user, email)
	log.Printf("TEST fake-token  → status=%d body=%s", status1, string(body1))

	// Test 2: real captcha-solver token (if key available)
	if capzyKey != "" {
		cz := capzy.NewWithURL(capzyKey, captchaAPI)
		cz.HTTP = client
		log.Printf("calling %s through proxy=%s:%s siteKey=%s", cz.BaseURL, h, p, gc.SiteKey)
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()
		solved, err := cz.SolveCaptchaFox(ctx, capzy.CaptchaFoxRequest{
			WebsiteURL: gmx.SignupPageURL,
			WebsiteKey: gc.SiteKey,
			APIServer:  gc.MAMApiServer,
			UserAgent:  gc.FP.UserAgent,
			ProxyURL:   proxyURL,
		})
		if err != nil {
			log.Printf("captcha solver error: %v", err)
		} else {
			log.Printf("captcha OK — taskID=%s cost=%.4f tokenPrefix=%s solveIP=%s",
				solved.TaskID, solved.Cost, prefix(solved.Token, 12), solved.SolveIP)
			if solved.UserAgent != "" {
				gc.FP = fingerprint.WithUserAgent(gc.FP, solved.UserAgent)
			}
			status2, body2, _ := gc.RegisterEmail(solved.Token, user, email)
			log.Printf("TEST solver-token → status=%d body=%s", status2, string(body2))
		}
	} else {
		log.Printf("skipping captcha test (CAPZY_API_KEY not set)")
	}

	_ = json.NewEncoder(os.Stdout).Encode(map[string]string{
		"email": email, "proxy": h + ":" + p, "ccguid": gc.CCGUID,
	})
}

func prefix(s string, n int) string {
	if len(s) < n {
		return s
	}
	return s[:n]
}
