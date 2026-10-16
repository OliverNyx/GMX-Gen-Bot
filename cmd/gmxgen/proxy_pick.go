package main

import (
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"strings"

	"gmxgen/internal/fingerprint"
	"gmxgen/internal/gmx"
	"gmxgen/internal/httpclient"
	"gmxgen/internal/proxyconfig"
)

type pickedProxy struct {
	URL       string
	Host      string
	Port      string
	User      string
	Line      string
	SessionID string
}

func pickProxyFromFile(lines []string, rng *rand.Rand, fp fingerprint.Profile, sessionID string, maxTries int) (*pickedProxy, *gmx.Client, error) {
	if len(lines) == 0 {
		return nil, nil, fmt.Errorf("empty proxy list")
	}
	if maxTries < 1 {
		maxTries = 1
	}
	// iProyal lines can mint a new sticky IP per try; don't cap to file length.
	if !proxyconfig.SessionRotatable(guessPass(lines[0])) && maxTries > len(lines) {
		maxTries = len(lines)
	}
	indices := rng.Perm(len(lines))
	if maxTries > len(indices) {
		maxTries = len(indices)
	}
	for i := 0; i < maxTries; i++ {
		line := lines[indices[i]]
		host, port, user, pass, err := proxyconfig.ParseHostPortUserPass(line)
		if err != nil {
			log.Printf("proxy file: skip invalid line: %v", err)
			continue
		}
		// Keep a session id already on the line. Mint one only when the
		// password can rotate and the line has no _session-* yet.
		sid := sessionID
		if sid == "" {
			sid = proxyconfig.ExtractSession(pass)
		}
		if sid == "" && proxyconfig.SessionRotatable(pass) {
			sid = randomSession(rng)
		}
		proxyURL, err := proxyconfig.Build(host, port, user, pass, sid)
		if err != nil {
			continue
		}
		client, err := httpclient.New(proxyURL)
		if err != nil {
			continue
		}
		gc := gmx.NewClient(client, fp)
		if err := gc.ProbeSignup(3); err != nil {
			log.Printf("proxy %s:%s try %d/%d: %v", host, port, i+1, maxTries, err)
			if !gmx.RetryableProxyError(err) {
				return nil, nil, err
			}
			continue
		}
		exitIP := lookupExitIP(client)
		log.Printf("proxy OK: %s:%s exit=%s session=%s", host, port, exitIP, sid)
		return &pickedProxy{
			URL:       proxyURL,
			Host:      host,
			Port:      port,
			User:      user,
			Line:      line,
			SessionID: sid,
		}, gc, nil
	}
	return nil, nil, fmt.Errorf("no working proxy in file after %d tries", maxTries)
}

func guessPass(line string) string {
	_, _, _, pass, err := proxyconfig.ParseHostPortUserPass(line)
	if err != nil {
		return ""
	}
	return pass
}

func lookupExitIP(client *http.Client) string {
	resp, err := client.Get("https://api.ipify.org")
	if err != nil {
		return "?"
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	ip := strings.TrimSpace(string(b))
	if ip == "" {
		return "?"
	}
	return ip
}

func randomSession(rng *rand.Rand) string {
	const hex = "0123456789abcdef"
	b := make([]byte, 12)
	for i := range b {
		b[i] = hex[rng.Intn(len(hex))]
	}
	return string(b)
}
