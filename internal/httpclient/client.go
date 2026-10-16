package httpclient

import (
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"time"

	fhttp "github.com/bogdanfinn/fhttp"
	tls_client "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
)

// New builds an HTTP client whose TLS ClientHello and HTTP/2 SETTINGS
// frames mimic Google Chrome 152, preventing GMX's enterprise WAF from
// fingerprinting Go's default crypto/tls handshake (JA3/JA4).
//
// It returns a standard *http.Client so callers need no code changes.
// Internally a bogdanfinn/tls-client round-trips through a Chrome-
// profiled TLS stack and an fhttp/http2 transport; the thin
// chromeRoundTripper adapter converts between net/http and fhttp types.
func New(proxyURL string) (*http.Client, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}

	opts := []tls_client.HttpClientOption{
		tls_client.WithTimeoutSeconds(120),
		tls_client.WithClientProfile(profiles.Chrome_152),
		tls_client.WithRandomTLSExtensionOrder(),
		tls_client.WithNotFollowRedirects(),
		// No cookie jar on the inner client — the outer http.Client.Jar
		// manages cookies so they survive the fhttp→net/http conversion.
	}
	if proxyURL != "" {
		opts = append(opts, tls_client.WithProxyUrl(proxyURL))
	}

	inner, err := tls_client.NewHttpClient(tls_client.NewNoopLogger(), opts...)
	if err != nil {
		return nil, fmt.Errorf("tls-client: %w", err)
	}

	return &http.Client{
		Timeout: 90 * time.Second,
		Jar:     jar,
		Transport: &chromeRoundTripper{inner: inner},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}, nil
}

// chromeRoundTripper adapts bogdanfinn/tls-client (which speaks fhttp)
// to the standard net/http.RoundTripper interface expected by http.Client.
type chromeRoundTripper struct {
	inner tls_client.HttpClient
}

func (rt *chromeRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	fReq, err := stdToFHTTP(req)
	if err != nil {
		return nil, err
	}
	fResp, err := rt.inner.Do(fReq)
	if err != nil {
		return nil, err
	}
	return fhttpToStd(fResp), nil
}

// stdToFHTTP converts a standard net/http.Request to bogdanfinn/fhttp.Request.
// Both types share the same struct layout (fhttp is a fork of net/http),
// so named-type conversions (e.g. fhttp.Header(h)) are valid in Go.
func stdToFHTTP(req *http.Request) (*fhttp.Request, error) {
	fReq := &fhttp.Request{
		Method:        req.Method,
		URL:           req.URL,
		Header:        fhttp.Header(req.Header),
		Body:          req.Body,
		ContentLength: req.ContentLength,
		Host:          req.Host,
	}
	if req.GetBody != nil {
		fReq.GetBody = func() (io.ReadCloser, error) {
			return req.GetBody()
		}
	}
	return fReq.WithContext(req.Context()), nil
}

// fhttpToStd converts a bogdanfinn/fhttp.Response to a standard net/http.Response.
func fhttpToStd(resp *fhttp.Response) *http.Response {
	return &http.Response{
		Status:           resp.Status,
		StatusCode:       resp.StatusCode,
		Proto:            resp.Proto,
		ProtoMajor:       resp.ProtoMajor,
		ProtoMinor:       resp.ProtoMinor,
		Header:           http.Header(resp.Header),
		Body:             resp.Body,
		ContentLength:    resp.ContentLength,
		TransferEncoding: resp.TransferEncoding,
		Close:            resp.Close,
		Uncompressed:     resp.Uncompressed,
	}
}
