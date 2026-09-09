package client

// tlsfingerprint.go — TLS fingerprint spoofing (utls): jabat tangan TLS kita
// meniru Chrome/Chromium (yang dipakai app AutoClaw/Electron), bukan fingerprint
// bawaan Go yang gampang dibedakan WAF (JA3 check).

import (
	"context"
	"net"
	neturl "net/url"
	"net/http"
	"time"

	utls "github.com/refraction-networking/utls"
)

// utlsTransport: http.RoundTripper yang dial-nya pakai utls ClientHelloID Chrome.
type utlsTransport struct {
	proxy *http.Transport // fallback transport untuk setting proxy/timeout dasar
}

func newChromeTransport(proxyURL string) http.RoundTripper {
	base := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	if proxyURL != "" {
		if pu, err := parseProxyURL(proxyURL); err == nil {
			base.Proxy = http.ProxyURL(pu)
		}
	}
	base.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		rawConn, err := (&net.Dialer{Timeout: 15 * time.Second}).DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		host, _, serr := net.SplitHostPort(addr)
		if serr != nil {
			host = addr
		}
		cfg := &utls.Config{ServerName: host}
		uconn := utls.UClient(rawConn, cfg, utls.HelloChrome_Auto)
		forceHTTP1ALPN(uconn)
		if err := uconn.HandshakeContext(ctx); err != nil {
			rawConn.Close()
			return nil, err
		}
		return uconn, nil
	}
	return base
}

// applyChromeTLS: ganti HTTP client dengan transport ber-fingerprint Chrome.
// Apply ke client utama + semua proxy client yang sudah ter-cache.
func (c *Client) applyChromeTLS() {
	if c.HTTP == nil {
		c.HTTP = &http.Client{}
	}
	c.HTTP.Transport = newChromeTransport("")
}

func parseProxyURL(raw string) (*neturl.URL, error) {
	return neturl.Parse(raw)
}

// forceHTTP1ALPN: hapus "h2" dari ALPN di ClientHello yang sudah dibangun
// preset Chrome — request kita HTTP/1.1, negotiated h2 bikin framing error.
func forceHTTP1ALPN(uconn *utls.UConn) {
	if err := uconn.BuildHandshakeState(); err != nil {
		return
	}
	for i, ext := range uconn.Extensions {
		if alpn, ok := ext.(*utls.ALPNExtension); ok {
			alpn.AlpnProtocols = []string{"http/1.1"}
			uconn.Extensions[i] = alpn
			break
		}
	}
	// rebuild handshake setelah patch
	_ = uconn.BuildHandshakeState()
}

// newChromeTransportForProxy: transport dengan proxy + TLS fingerprint Chrome.
func NewChromeTransportForProxy(pu *neturl.URL) http.RoundTripper {
	base := &http.Transport{
		Proxy:               http.ProxyURL(pu),
		TLSHandshakeTimeout: 10 * time.Second,
	}
	base.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		rawConn, err := (&net.Dialer{Timeout: 15 * time.Second}).DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		host, _, serr := net.SplitHostPort(addr)
		if serr != nil {
			host = addr
		}
		cfg := &utls.Config{ServerName: host}
		uconn := utls.UClient(rawConn, cfg, utls.HelloChrome_Auto)
		forceHTTP1ALPN(uconn)
		if err := uconn.HandshakeContext(ctx); err != nil {
			rawConn.Close()
			return nil, err
		}
		return uconn, nil
	}
	return base
}
