// Package client — HTTP client dengan full browser fingerprint via tls-client.
//
// Mengganti custom utls transport dengan bogdanfinn/tls-client yang
// meniru Chrome secara utuh: JA3/JA4 TLS fingerprint, HTTP/2 frame
// ordering (SETTINGS, WINDOW_UPDATE, PRIORITY), dan header ordering —
// ketiganya sekaligus, bukan hanya handshake (PRD 4.1 + 4.2).
package client

import (
	http "github.com/bogdanfinn/fhttp"
	tls_client "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
)

// newChromeClient membuat tls-client dengan profile Chrome desktop.
// Proxy direspon via environment (HTTP_PROXY/HTTPS_PROXY).
func newChromeClient(proxyURL string) (tls_client.HttpClient, error) {
	options := []tls_client.HttpClientOption{
		tls_client.WithTimeoutSeconds(30),
		tls_client.WithClientProfile(profiles.Chrome_131),
		tls_client.WithNotFollowRedirects(),
		tls_client.WithInsecureSkipVerify(),
	}
	if proxyURL != "" {
		options = append(options, tls_client.WithProxyUrl(proxyURL))
	}
	return tls_client.NewHttpClient(tls_client.NewNoopLogger(), options...)
}

// chromeHeaders mengembalikan header set identik browser Chromium di
// platform Windows (PRD 4.2 — UA & Client-Hints parity, Accept standar).
func chromeHeaders() http.Header {
	return http.Header{
		"sec-ch-ua":            {`"Chromium";v="131", "Not_A Brand";v="24"`},
		"sec-ch-ua-mobile":     {"?0"},
		"sec-ch-ua-platform":   {`"Windows"`},
		"upgrade-insecure-requests": {"1"},
		"user-agent":           {"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"},
		"accept":               {"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
		"sec-fetch-site":       {"none"},
		"sec-fetch-mode":       {"navigate"},
		"sec-fetch-user":       {"?1"},
		"sec-fetch-dest":       {"document"},
		"accept-encoding":      {"gzip, deflate, br, zstd"},
		"accept-language":      {"id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7"},
	}
}


// NewChromeClientForProxy membuat tls-client Chrome fingerprint dengan proxy.
// Dipakai server.go untuk proxy pool per-akun.
func NewChromeClientForProxy(proxyURL string) (tls_client.HttpClient, error) {
    return newChromeClient(proxyURL)
}
