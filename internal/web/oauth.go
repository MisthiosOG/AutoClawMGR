package web

// Login OAuth Z.ai langsung dari web panel — tanpa app AutoClaw.
// Flow: captcha Aliyun di browser → oauth-url → login di Z.ai → callback →
// tukar code jadi token → simpan/update akun → balik ke panel.
//
// Callback punya 2 jalur (dicoba berurutan di /accounts/login/verify):
//  1. port panel sendiri (http://<host-panel>/auth/callback-zai) — tidak butuh
//     listener tambahan, jalan walau app AutoClaw pegang semua port terdaftar.
//  2. port terdaftar Z.ai (18432/19654/19723/53699) — jalur bawaan app.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	neturl "net/url"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/MisthiosOG/autoclawpi/internal/client"
	"github.com/MisthiosOG/autoclawpi/internal/db"
)

// oauthPorts = port yang terdaftar di OAuth client Z.ai (sama seperti app asli).
var oauthPorts = []int{18432, 19654, 19723, 53699}

// oauthPending menyimpan state login yang sedang berjalan (satu user, satu sesi).
type oauthPending struct {
	vendor        string
	panelHost     string // host:port panel, mis. "127.0.0.1:8787"
	navigateURI   string // di-set saat verify: jalur panel atau jalur port terdaftar
	state         string
	loginProxyURL string // opsional: keluar lewat proxy pool saat login (fingerprint IP bersih)
}

// clientFor: client dengan proxy bila sesi login memakai proxy pool.
func (s *Server) clientFor(pend *oauthPending) *client.Client {
	if pend == nil || pend.loginProxyURL == "" {
		return s.cl
	}
	pu, err := neturl.Parse(pend.loginProxyURL)
	if err != nil || pu.Host == "" {
		return s.cl
	}
	tr := &http.Transport{Proxy: http.ProxyURL(pu), TLSHandshakeTimeout: 10 * time.Second}
	cl := client.New(s.cl.InferenceBase, s.cl.UserAPIBase)
	cl.HTTP = &http.Client{Transport: tr}
	cl.Version = s.cl.Version
	return cl
}

// ensureOAuthListener mengikat satu port callback terdaftar (fallback), dipakai ulang.
func (s *Server) ensureOAuthListener() (int, error) {
	s.oauthMu.Lock()
	defer s.oauthMu.Unlock()
	if s.oauthLn != nil {
		return s.oauthPort, nil
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/auth/callback-zai", s.handleOAuthCallback)
	for _, p := range oauthPorts {
		ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", p))
		if err != nil {
			continue
		}
		s.oauthLn = ln
		s.oauthPort = p
		srv := &http.Server{Handler: mux, ReadHeaderTimeout: 15 * time.Second}
		go func() { _ = srv.Serve(ln) }()
		return p, nil
	}
	return 0, fmt.Errorf("semua port callback %v terpakai", oauthPorts)
}

// handleOAuthLogin menampilkan halaman login OAuth (captcha + redirect).
func (s *Server) handleOAuthLogin(w http.ResponseWriter, r *http.Request) {
	// ponytail: satu sesi login global — panel single-user, sesi paralel tidak perlu.
	// loginProxy: ?proxy=ID → OAuth keluar lewat proxy pool (IP bersih untuk akun baru).
	var loginProxyURL string
	loginProxyName := ""
	if pid, perr := strconv.ParseInt(r.URL.Query().Get("proxy"), 10, 64); perr == nil && pid > 0 {
		if pp, gerr := db.GetProxy(pid); gerr == nil && pp.Active {
			loginProxyURL = pp.URL
			loginProxyName = pp.Name
		}
	}
	s.oauthMu.Lock()
	s.oauthPending = &oauthPending{
		vendor:        "zai",
		panelHost:     r.Host,
		loginProxyURL: loginProxyURL,
	}
	s.oauthMu.Unlock()

	// captcha-config lewat proxy terpilih — IP konsisten dengan oauth-url nanti
	// (mismatch IP browser/server bikin Aliyun challenge loop).
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	capCfg, cerr := s.clientFor(s.oauthPending).CaptchaConfig(ctx)
	enabled, scene, prefix, region := false, "", "", "ga"
	if cerr == nil && capCfg.Data != nil {
		enabled = capCfg.Data.Enabled
		scene = capCfg.Data.SceneID
		prefix = capCfg.Data.Prefix
		if capCfg.Data.Region != "" {
			region = capCfg.Data.Region
		}
	}

	proxies, _ := db.ListProxies()
	data := map[string]any{"CaptchaEnabled": enabled, "Scene": scene, "Prefix": prefix, "Region": region,
		"LoginViaProxy": loginProxyName, "Proxies": proxies}
	if cerr != nil {
		data["Error"] = "captcha-config: " + cerr.Error() + " (captcha kemungkinan wajib — refresh halaman ini)"
	}
	// Cek dini: kalau app AutoClaw pegang semua port callback, beri tahu user
	// sebelum dia buang waktu solve captcha.
	if _, lerr := s.ensureOAuthListener(); lerr != nil {
		if data["Error"] != nil {
			data["Error"] = data["Error"].(string) + " | Tutup app AutoClaw dulu (semua port callback sedang dipakai app)."
		} else {
			data["Error"] = "Tutup app AutoClaw dulu — semua port callback (18432/19654/19723/53699) sedang dipakai app. Setelah ditutup, klik login lagi."
		}
	}
	s.renderTemplate(w, "oauth.html", "accounts", data)
}

// handleOAuthVerify menukar verifyParam captcha menjadi URL OAuth Z.ai.
// Backend cuma meng-echo navigate_uri yang terdaftar di OAuth client-nya
// (port localhost app asli); nilai lain diganti autoclaw.cyou yang bikin
// Z.ai menolak ("Redirect URI not registered"). Jadi wajib pakai port itu.
func (s *Server) handleOAuthVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "msg": "POST only"})
		return
	}
	var req struct {
		VerifyParam string `json:"verify_param"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req)

	s.oauthMu.Lock()
	pend := s.oauthPending
	s.oauthMu.Unlock()
	if pend == nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "msg": "sesi login habis — buka ulang halaman login"})
		return
	}

	// Bind port callback dulu — sebelum captcha terpakai — supaya kalau
	// app AutoClaw lagi pegang semua port, user langsung tahu tanpa buang captcha.
	port, lerr := s.ensureOAuthListener()
	if lerr != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "msg": "Semua port callback dipakai app AutoClaw. Tutup app AutoClaw dulu, lalu klik login lagi."})
		return
	}

	var captcha map[string]any
	if req.VerifyParam != "" {
		captcha = map[string]any{"ali_captcha_verify_param": req.VerifyParam}
	}

	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()

	navigateURI := fmt.Sprintf("http://localhost:%d/auth/callback-zai", port)
	url, state, err := s.clientFor(pend).OAuthURL(ctx, pend.vendor, navigateURI, "autoclaw", captcha)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "msg": err.Error()})
		return
	}

	// Validasi echo: redirect_uri di URL authorize harus persis callback kita.
	// Kalau backend diam-diam mengganti (mis. ke autoclaw.cyou), Z.ai pasti
	// menolak — laporkan sekarang, jangan sampai user login sia-sia.
	if u, perr := neturl.Parse(url); perr == nil {
		if ru := u.Query().Get("redirect_uri"); ru != "" && ru != navigateURI {
			writeJSON(w, http.StatusOK, map[string]any{"ok": false,
				"msg": "Backend pakai redirect URI lain (" + ru + "), bukan callback lokal. Coba lagi atau pakai Import dari App."})
			return
		}
	}

	s.oauthMu.Lock()
	pend.navigateURI = navigateURI
	pend.state = state
	s.oauthMu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "url": url})
}

// handleOAuthCallback menerima redirect dari Z.ai (di mux panel ATAU listener
// port terdaftar): tukar code → token → simpan/update akun → balik ke panel.
func (s *Server) handleOAuthCallback(w http.ResponseWriter, r *http.Request) {
	s.oauthMu.Lock()
	pend := s.oauthPending
	s.oauthMu.Unlock()

	q := r.URL.Query()
	if pend == nil || q.Get("code") == "" {
		oauthResultPage(w, pend, "callback tanpa code / sesi login tidak ada")
		return
	}
	if pend.state != "" && q.Get("state") != pend.state {
		oauthResultPage(w, pend, "state mismatch — ulangi login dari panel")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	out, err := s.clientFor(pend).Login(ctx, pend.vendor, q.Get("code"), q.Get("state"), pend.navigateURI)
	if err != nil {
		oauthResultPage(w, pend, "OAuth login: "+err.Error())
		return
	}
	if out.Code != 0 || out.Data == nil || out.Data.AccessToken == "" {
		msg := fmt.Sprintf("login ditolak: code=%d msg=%s", out.Code, out.Msg)
		if out.Trace != "" {
			msg += " [trace: " + out.Trace + "]"
		}
		if out.Code == 631001 {
			msg += " — INGAT: logout dulu akun Z.ai lama di browser (chat.z.ai → logout), LALU ulangi login dan pakai akun baru. Kalau akun barunya memang beda dan masih gagal, tunggu 10 menit lalu coba lagi (bisa jadi IP kena throttle AutoClaw)."
		}
		oauthResultPage(w, pend, msg)
		return
	}

	access, refresh := out.Data.AccessToken, out.Data.RefreshToken
	uid := ""
	if out.Data.UserID != nil {
		uid = fmt.Sprint(out.Data.UserID)
	}
	name := out.Data.UserName
	if name == "" {
		if jti, _ := decodeJWT(access); jti != "" {
			name = jti
		}
	}
	if name == "" {
		name = "zai-" + uid
	}

	// Re-login akun sama → update token, bukan bikin duplikat.
	accts, _ := db.ListAccounts()
	var existing *db.Account
	for i := range accts {
		if accts[i].Name == name {
			existing = &accts[i]
			break
		}
	}
	if existing != nil {
		existing.AccessToken = access
		existing.RefreshToken = refresh
		existing.UserID = uid
		if err := db.UpdateAccount(existing); err != nil {
			oauthResultPage(w, pend, "update akun: "+err.Error())
			return
		}
	} else {
		deviceID := "web-oauth-" + fmt.Sprintf("%x", time.Now().UnixNano())
		if _, err := db.AddAccount(name, access, refresh, pend.vendor, uid, out.Data.UserName, deviceID); err != nil {
			oauthResultPage(w, pend, "simpan akun: "+err.Error())
			return
		}
	}
	log.Printf("[autoclawpi] oauth login via web: %s", name)
	oauthResultPage(w, pend, "")
}

// oauthResultPage menampilkan hasil login di tab callback, lalu balik ke panel.
func oauthResultPage(w http.ResponseWriter, pend *oauthPending, errMsg string) {
	back := "/accounts"
	if pend != nil && pend.panelHost != "" {
		back = "http://" + pend.panelHost + "/accounts"
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if errMsg != "" {
		fmt.Fprintf(w, `<!DOCTYPE html><html><head><meta charset="utf-8"><title>Login gagal</title></head>
<body style="font-family:sans-serif;background:#07070a;color:#e2e8f0;display:flex;align-items:center;justify-content:center;min-height:100vh">
<div style="text-align:center"><h2 style="color:#f87171">Login gagal</h2><p style="color:#94a3b8;max-width:480px">%s</p><a href="%s" style="color:#818cf8">Kembali ke panel</a></div>
</body></html>`, htmlEscape(errMsg), back)
		return
	}
	fmt.Fprintf(w, `<!DOCTYPE html><html><head><meta charset="utf-8"><meta http-equiv="refresh" content="2;url=%s"><title>Login sukses</title></head>
<body style="font-family:sans-serif;background:#07070a;color:#e2e8f0;display:flex;align-items:center;justify-content:center;min-height:100vh">
<div style="text-align:center"><h2 style="color:#34d399">&#10003; Login sukses</h2><p style="color:#94a3b8">Mengembalikan ke panel...</p><a href="%s" style="color:#818cf8">Klik di sini jika tidak otomatis</a></div>
</body></html>`, back, back)
}

func htmlEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&#34;").Replace(s)
}
