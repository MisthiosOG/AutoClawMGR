package web

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net"
	neturl "net/url"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/MisthiosOG/autoclawpi/internal/client"
	"github.com/MisthiosOG/autoclawpi/internal/config"
	"github.com/MisthiosOG/autoclawpi/internal/db"
	"github.com/MisthiosOG/autoclawpi/internal/sign"

	fhttp "github.com/bogdanfinn/fhttp"
)

//go:embed templates/*.html
var templateFS embed.FS

// Server adalah web panel server.
type Server struct {
	mux        *http.ServeMux
	tmpl       *template.Template
	password   string
	apiKey     string
	strategy   string
	ratePerSec string
	rateBurst  string
	cl         *client.Client

	// OAuth login dari web (lihat oauth.go)
	oauthMu      sync.Mutex
	oauthLn      net.Listener
	oauthPort    int
	oauthPending *oauthPending

	// Session panel: cookie berisi token acak, bukan password.
	sessMu   sync.Mutex
	sessTok  string
	sessExp  time.Time
	loginFai map[string]loginFail
}

type loginFail struct {
	count int
	until time.Time // lockout sampai
}

// newSessionToken buat token sesi acak 32 byte (hex) — berlaku 30 hari.
func newSessionToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%x", time.Now().UnixNano()) // fallback jarang terjadi
	}
	return hex.EncodeToString(b)
}

func (s *Server) setSession(tok string) {
	s.sessMu.Lock()
	s.sessTok = tok
	s.sessExp = time.Now().Add(30 * 24 * time.Hour)
	s.sessMu.Unlock()
}

func (s *Server) checkSession(tok string) bool {
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	return s.sessTok != "" && tok == s.sessTok && time.Now().Before(s.sessExp)
}

// CurrentSessionToken dipakai internal/server untuk validasi cookie
// panel_session di endpoint /v1 (Playground tanpa API key).
func (s *Server) CurrentSessionToken() string {
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	if time.Now().After(s.sessExp) {
		return ""
	}
	return s.sessTok
}

// loginThrottled: 5 password salah per IP → lockout 10 menit.
func (s *Server) loginThrottled(ip string) (bool, int) {
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	f, ok := s.loginFai[ip]
	if !ok {
		return false, 0
	}
	if f.until.IsZero() || time.Now().After(f.until) {
		if f.count >= 5 { // window 10 menit lewat — reset
			delete(s.loginFai, ip)
		}
		return false, 0
	}
	if f.count >= 5 {
		return true, int(time.Until(f.until).Minutes()) + 1
	}
	return false, 0
}

func (s *Server) recordLoginFail(ip string) {
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	if s.loginFai == nil {
		s.loginFai = make(map[string]loginFail)
	}
	f := s.loginFai[ip]
	if time.Now().After(f.until) {
		f.count = 0
	}
	f.count++
	if f.count >= 5 {
		f.until = time.Now().Add(10 * time.Minute)
	}
	s.loginFai[ip] = f
}

// Option untuk konfigurasi web panel.
type Option func(*Server)

// WithPassword mengatur password panel.
func WithPassword(pwd string) Option {
	return func(s *Server) { s.password = pwd }
}

// WithAPIKey menyimpan API key untuk fetch models internal.
func WithAPIKey(key string) Option {
	return func(s *Server) { s.apiKey = key }
}

// New membuat web panel server baru.
func New(cl *client.Client, opts ...Option) *Server {
	s := &Server{
		mux:      http.NewServeMux(),
		strategy: "round-robin",
		cl:       cl,
	}
	for _, o := range opts {
		o(s)
	}

	tmpl := template.New("").Funcs(template.FuncMap{
		"pageTitle": pageTitle,
		"stringsHasPrefix": strings.HasPrefix,
	})
	tmpl = template.Must(tmpl.ParseFS(templateFS, "templates/*.html"))
	s.tmpl = tmpl

	// Routes
	s.mux.HandleFunc("/", s.authMiddleware(s.handleDashboard))
	s.mux.HandleFunc("/api/live-stats", s.authMiddleware(s.handleLiveStats))
	s.mux.HandleFunc("/accounts", s.authMiddleware(s.handleAccounts))
	s.mux.HandleFunc("/accounts/", s.authMiddleware(s.handleAccounts))
	s.mux.HandleFunc("/accounts/login", s.authMiddleware(s.handleOAuthLogin))
	s.mux.HandleFunc("/accounts/login/verify", s.authMiddleware(s.handleOAuthVerify))
	s.mux.HandleFunc("/accounts/login/proxy", s.authMiddleware(s.handleOAuthLoginProxy))
	s.mux.HandleFunc("/auth/callback-zai", s.handleOAuthCallback)
	s.mux.HandleFunc("/accounts/import", s.authMiddleware(s.handleAccountsImport))
	s.mux.HandleFunc("/accounts/import-from-app", s.authMiddleware(s.handleImportFromApp))
	s.mux.HandleFunc("/accounts/claim", s.authMiddleware(s.handleClaim100M))
	s.mux.HandleFunc("/checkin", s.authMiddleware(s.handleCheckin))
	s.mux.HandleFunc("/checkin/run", s.authMiddleware(s.handleCheckinRun))
	s.mux.HandleFunc("/settings", s.authMiddleware(s.handleSettings))
	s.mux.HandleFunc("/settings/password", s.authMiddleware(s.handleSettingsPassword))
	s.mux.HandleFunc("/settings/strategy", s.authMiddleware(s.handleSettingsStrategy))
	s.mux.HandleFunc("/settings/ratelimit", s.authMiddleware(s.handleSettingsRateLimit))
	s.mux.HandleFunc("/proxies", s.authMiddleware(s.handleProxies))
	s.mux.HandleFunc("/proxies/add", s.authMiddleware(s.handleProxyAdd))
	s.mux.HandleFunc("/proxies/batch", s.authMiddleware(s.handleProxyBatch))
	s.mux.HandleFunc("/proxies/delete", s.authMiddleware(s.handleProxyDelete))
	s.mux.HandleFunc("/proxies/toggle", s.authMiddleware(s.handleProxyToggle))
	s.mux.HandleFunc("/proxies/test", s.authMiddleware(s.handleProxyTest))
	s.mux.HandleFunc("/accounts/set-proxy", s.authMiddleware(s.handleAccountSetProxy))
	s.mux.HandleFunc("/apikeys", s.authMiddleware(s.handleAPIKeys))
	s.mux.HandleFunc("/apikeys/add", s.authMiddleware(s.handleAPIKeyAdd))
	s.mux.HandleFunc("/apikeys/delete", s.authMiddleware(s.handleAPIKeyDelete))
	s.mux.HandleFunc("/docs", s.authMiddleware(s.handleDocs))
	s.mux.HandleFunc("/health", s.authMiddleware(s.handleHealth))
	s.mux.HandleFunc("/health/run", s.authMiddleware(s.handleHealthRun))
	s.mux.HandleFunc("/logs", s.authMiddleware(s.handleLogs))
	s.mux.HandleFunc("/models", s.authMiddleware(s.handleModels))
	s.mux.HandleFunc("/playground", s.authMiddleware(s.handlePlayground))
	s.mux.HandleFunc("/login", s.handleLogin)
	s.mux.HandleFunc("/logout", s.handleLogout)

	return s
}

func (s *Server) Handler() http.Handler {
	return s.mux
}

func (s *Server) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.password != "" {
			cookie, err := r.Cookie("panel_auth")
			if err != nil || !s.checkSession(cookie.Value) {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}
		}
		next(w, r)
	}
}

func (s *Server) renderTemplate(w http.ResponseWriter, page string, currentPage string, data any) {
	d := map[string]any{
		"Page":  currentPage,
		"Title": pageTitle(currentPage),
	}
	if data != nil {
		if m, ok := data.(map[string]any); ok {
			for k, v := range m {
				d[k] = v
			}
		}
	}
	tmpl := template.Must(template.Must(template.New("").Funcs(template.FuncMap{
		"pageTitle":        pageTitle,
		"stringsHasPrefix": strings.HasPrefix,
	}).Parse(s.tmplStr("base.html"))).Parse(s.tmplStr(page)))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	err := tmpl.ExecuteTemplate(w, "base", d)
	if err != nil {
		http.Error(w, err.Error(), 500)
	}
}

func (s *Server) tmplStr(name string) string {
	data, err := templateFS.ReadFile("templates/" + name)
	if err != nil {
		return ""
	}
	return string(data)
}

func pageTitle(page string) string {
	switch page {
	case "dashboard":
		return "Dashboard — autoclawpi"
	case "accounts":
		return "Accounts — autoclawpi"
	case "checkin":
		return "Check-In — autoclawpi"
	case "settings":
		return "Settings — autoclawpi"
	case "apikeys":
		return "API Keys — autoclawpi"
	case "proxies":
		return "Proxy Pools — autoclawpi"
	case "login":
		return "Login — autoclawpi"
	case "docs":
		return "API Docs — autoclawpi"
	case "health":
		return "Health — autoclawpi"
	case "logs":
		return "Logs — autoclawpi"
	default:
		return "autoclawpi"
	}
}

func renderStandalone(w http.ResponseWriter, tmplName string, data any) {
	content, err := templateFS.ReadFile("templates/" + tmplName)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	t, err := template.New(tmplName).Parse(string(content))
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	t.Execute(w, data)
}

func (s *Server) renderString(name string, data any) (string, error) {
	var buf strings.Builder
	err := s.tmpl.ExecuteTemplate(io.Writer(&buf), name, data)
	return buf.String(), err
}

// ── Handlers ────────────────────────────────────────────────────────

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	ip := strings.SplitN(r.RemoteAddr, ":", 2)[0]
	if r.Method == "POST" {
		if locked, mins := s.loginThrottled(ip); locked {
			renderStandalone(w, "panel-login.html", map[string]any{
				"Error": fmt.Sprintf("Terlalu banyak percobaan gagal — coba lagi %d menit", mins),
			})
			return
		}
		pwd := r.FormValue("password")
		if pwd == s.password {
			tok := newSessionToken()
			s.setSession(tok)
			http.SetCookie(w, &http.Cookie{
				Name: "panel_auth", Value: tok,
				Path: "/", MaxAge: 86400 * 30,
				HttpOnly: true, SameSite: http.SameSiteLaxMode,
			})
			// window 10 menit buat IP yang barusan sukses
			s.sessMu.Lock()
			delete(s.loginFai, ip)
			s.sessMu.Unlock()
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		s.recordLoginFail(ip)
		renderStandalone(w, "panel-login.html", map[string]any{"Error": "Wrong password"})
		return
	}
	renderStandalone(w, "panel-login.html", nil)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	s.setSession("") // hapus sesi server-side
	http.SetCookie(w, &http.Cookie{Name: "panel_auth", Value: "", Path: "/", MaxAge: -1})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// handleLiveStats data JSON buat live counter dashboard (poll tiap 2s).
func (s *Server) handleLiveStats(w http.ResponseWriter, _ *http.Request) {
	totalReq, totalTokens, _ := db.LogStatsAllTotal()
	writeJSON(w, 200, map[string]any{
		"tokens":        totalTokens,
		"requests":      totalReq,
		"tokens_per_min": db.LogTokensLastMinute(),
	})
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	accounts, _ := db.ListAccounts()
	totalPts := 0
	activeCount := 0
	type accountView struct {
		db.Account
		LastCheckinDate string
	}
	var views []accountView
	for _, a := range accounts {
		if a.Active {
			activeCount++
		}
		// Auto-fetch balance from server for each account
		balance := fetchBalanceDashboard(a.AccessToken)
		if balance > 0 && balance != a.Points {
			_ = db.UpdatePoints(a.ID, balance)
			a.Points = balance
		}
		totalPts += a.Points
		logs, _ := db.ListCheckinLog(a.ID, 1)
		lastDate := ""
		if len(logs) > 0 {
			lastDate = logs[0].Date
		}
		views = append(views, accountView{Account: a, LastCheckinDate: lastDate})
	}
	models := fetchModels("http://"+r.Host+"/v1/models", s.apiKey)
	totalReq, totalTokens, totalCost, _ := db.LogStats()
	s.renderTemplate(w, "dashboard.html", "dashboard", map[string]any{
		"Accounts":       views,
		"TotalAccounts":  len(accounts),
		"ActiveAccounts": activeCount,
		"TotalPoints":    totalPts,
		"CheckedInToday": 0,
		"Models":         models,
		"TotalReq":       totalReq,
		"TotalTokens":    totalTokens,
		"TotalCost":      totalCost,
		"LatencyMs":      db.LogAvgLatencyMs(),
	})
}

// fetchBalanceDashboard ambil balance dari server. Mirip fetchBalance di checkin.go
func fetchBalanceDashboard(token string) int {
	ts := time.Now().Unix()
	req, err := http.NewRequest("GET", "https://autoglm-api.autoglm.ai/agent-assetmgr/api/v1/wallet-instances?biz_app_id=autoclaw", nil)
	if err != nil {
		return 0
	}
	req.Header.Set("authorization", token)
	req.Header.Set("X-Auth-Appid", "100003")
	req.Header.Set("X-Auth-TimeStamp", fmt.Sprintf("%d", ts))
	req.Header.Set("X-Auth-Sign", sign.Sign(ts))
	req.Header.Set("X-Product", "autoclaw")
	req.Header.Set("X-Version", "1.17.9")
	req.Header.Set("X-Tm", "linux")
	req.Header.Set("X-Lang", "en")
	req.Header.Set("X-Client-Type", "pc")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("X-Trace-Id", sign.UUID())

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0
	}
	defer resp.Body.Close()

	var data struct {
		Data *struct {
			TotalBalance float64 `json:"total_balance"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return 0
	}
	if data.Data == nil {
		return 0
	}
	return int(data.Data.TotalBalance)
}

func fetchModels(url string, apikey string) []string {
	models := []string{}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return models
	}
	if apikey != "" {
		req.Header.Set("Authorization", "Bearer "+apikey)
	}
	resp, err := http.DefaultClient.Do(req)
	if err == nil {
		defer resp.Body.Close()
		var data struct {
			Data []struct {
				ID string `json:"id"`
			} `json:"data"`
		}
		json.NewDecoder(resp.Body).Decode(&data)
		for _, m := range data.Data {
			models = append(models, m.ID)
		}
	}
	return models
}

func (s *Server) handleAccounts(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/accounts")
	if path != "" && path != "/" {
		parts := strings.Split(strings.Trim(path, "/"), "/")
		if len(parts) >= 2 {
			id, err := parseInt64(parts[0])
			if err == nil && id > 0 {
				switch parts[1] {
				case "delete":
								db.DeleteAccount(id)
								http.Redirect(w, r, "/accounts", http.StatusSeeOther)
								return
							case "refresh":
								refreshBalance(id)
								w.WriteHeader(204)
								return
							case "claim":
								s.handleClaim100MForAccount(w, r, id)
								return
				}
			}
		}
		if len(parts) >= 1 {
			id, err := parseInt64(parts[0])
			if err == nil && id > 0 {
				s.handleAccountDetail(w, r, id)
				return
			}
		}
		http.NotFound(w, r)
		return
	}
	accounts, _ := db.ListAccounts()
	s.renderTemplate(w, "accounts.html", "accounts", map[string]any{"Accounts": accounts})
}

func parseInt64(s string) (int64, error) {
	var id int64
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("not a number")
		}
		id = id*10 + int64(c-'0')
	}
	return id, nil
}

func (s *Server) handleAccountDetail(w http.ResponseWriter, r *http.Request, id int64) {
	a, err := db.GetAccount(id)
	if err != nil || a == nil {
		http.NotFound(w, r)
		return
	}
	balance := refreshBalance(id)
	history, _ := db.ListCheckinLog(id, 20)

	// Decode JWT to get user info
	userEmail, userID := decodeJWT(a.AccessToken)

	// Update DB if we got user info from JWT
	if userEmail != "" && a.Name == "" {
		a.Name = userEmail
		a.UserName = userEmail
		a.UserID = userID
		_ = db.UpdateAccount(a)
	}

	proxies, _ := db.ListProxies()
	curProxyID, curProxyName := db.AccountProxyName(id)

	type infoRow struct {
		Key   string
		Value string
	}
	infoRows := []infoRow{
		{"ID", fmt.Sprintf("%d", a.ID)},
		{"Name", a.Name},
		{"Provider", a.Provider},
		{"User ID", a.UserID},
		{"Device ID", a.DeviceID},
		{"Created", strings.Split(a.CreatedAt, "T")[0]},
	}

	s.renderTemplate(w, "account.html", "accounts", map[string]any{
		"Account":        a,
		"Balance":        balance,
		"CheckinHistory": history,
		"InfoRows":       infoRows,
		"Proxies":        proxies,
		"ProxyID":        curProxyID,
		"ProxyName":      curProxyName,
	})
}

// decodeJWT extracts user info from a JWT token (second segment, base64).
func decodeJWT(token string) (email, userID string) {
	// Strip "Bearer " prefix
	raw := strings.TrimPrefix(token, "Bearer ")
	parts := strings.Split(raw, ".")
	if len(parts) < 2 {
		return "", ""
	}
	// Add padding
	payload := parts[1]
	switch len(payload) % 4 {
	case 2:
		payload += "=="
	case 3:
		payload += "="
	}
	decoded, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return "", ""
	}
	var data struct {
		UserID any    `json:"user_id"`
		JTI    string `json:"jti"`
	}
	if err := json.Unmarshal(decoded, &data); err != nil {
		return "", ""
	}
	uid := ""
	if data.UserID != nil {
		uid = fmt.Sprint(data.UserID)
	}
	return data.JTI, uid
}

func refreshBalance(id int64) int {
	a, err := db.GetAccount(id)
	if err != nil || a == nil {
		return 0
	}
	return a.Points
}

// handleAccountsImportPage renders the import page (GET). Alias of handleAccountsImport GET branch.
func (s *Server) handleAccountsImportPage(w http.ResponseWriter, r *http.Request) {
	s.renderTemplate(w, "import.html", "accounts", nil)
}

func (s *Server) handleAccountsImport(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		name := r.FormValue("name")
		accessToken := r.FormValue("access_token")
		refreshToken := r.FormValue("refresh_token")
		if accessToken == "" {
			s.renderTemplate(w, "import.html", "accounts", map[string]any{"Error": "Access token required", "Name": name})
			return
		}
		deviceID := "import-" + fmt.Sprintf("%x", time.Now().UnixNano())
		_, err := db.AddAccount(name, accessToken, refreshToken, "zai", "", "", deviceID)
		if err != nil {
			s.renderTemplate(w, "import.html", "accounts", map[string]any{"Error": err.Error(), "Name": name})
			return
		}
		http.Redirect(w, r, "/accounts", http.StatusSeeOther)
		return
	}
	s.renderTemplate(w, "import.html", "accounts", nil)
}

// handleClaim100MForAccount handles /accounts/{id}/claim (HTMX button).
func (s *Server) handleClaim100MForAccount(w http.ResponseWriter, r *http.Request, id int64) {
	a, err := db.GetAccount(id)
	if err != nil || a == nil || a.AccessToken == "" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, `<div style="padding:12px;border-radius:10px;background:rgba(220,38,38,0.12);color:#f87171;font-size:13px"><i class="fas fa-times-circle"></i> Account not found</div>`)
		return
	}
	s.doClaim100M(w, r, a)
}

// handleClaim100M mengklaim reward 100M token untuk akun (JSON body).
func (s *Server) handleClaim100M(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "msg": "POST only"})
		return
	}
	var req struct {
		AccountID int64 `json:"account_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "msg": "invalid body"})
		return
	}
	if req.AccountID <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "msg": "account_id required"})
		return
	}
	a, err := db.GetAccount(req.AccountID)
	if err != nil || a == nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"ok": false, "msg": "account not found"})
		return
	}
	if a.AccessToken == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "msg": "account has no token"})
		return
	}
	s.doClaim100M(w, r, a)
}

// doClaim100M mengklaim token newbie guide dan mengembalikan HTML.
func (s *Server) doClaim100M(w http.ResponseWriter, r *http.Request, a *db.Account) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	token, err := s.cl.ClaimNewbieToken(ctx, a.AccessToken)
	if err != nil {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, `<div style="padding:12px;border-radius:10px;background:rgba(220,38,38,0.12);color:#f87171;font-size:13px"><i class="fas fa-times-circle"></i> Claim gagal: %s</div>`, template.HTMLEscapeString(err.Error()))
		return
	}

	// Refresh balance after claim
	ctx2, cancel2 := context.WithTimeout(context.Background(), 15*time.Second)
	points := fetchBalance(ctx2, a.AccessToken, s.cl)
	cancel2()
	if points > 0 {
		_ = db.UpdatePoints(a.ID, points)
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<div style="margin-top:14px;background:#111116;border:1px solid #1c1c22;border-radius:14px;padding:16px;text-align:left">
  <div style="display:flex;align-items:center;gap:8px;margin-bottom:12px">
    <span class="status-dot online" style="display:inline-block"></span>
    <span style="font-size:13px;font-weight:600;color:#e7e7ec">100M Token Claimed</span>
  </div>
  <div style="position:relative">
    <input type="text" readonly value="%s" id="claim-token" style="background:#08080a;border:1px solid #1c1c22;border-radius:10px;padding:10px 40px 10px 12px;color:#9a9aa6;font-family:mono;font-size:12px;width:100%%;text-overflow:ellipsis" />
    <button type="button" onclick="copyClaimToken()" style="position:absolute;right:6px;top:50%%;transform:translateY(-50%%);background:#18181e;border:1px solid #2a2a34;border-radius:8px;width:28px;height:28px;display:flex;align-items:center;justify-content:center;cursor:pointer;color:#c9c9d1;transition:background .15s" onmouseover="this.style.background='#1f1f26'" onmouseout="this.style.background='#18181e'">
      <svg id="copy-icon" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
    </button>
  </div>
  <div style="display:flex;align-items:center;justify-content:space-between;margin-top:12px">
    <span style="font-size:12px;color:#6b6b76">Balance</span>
    <span style="font-size:16px;font-weight:600;color:#f5f5f7">%d pts</span>
  </div>
</div>
<script>
function copyClaimToken(){
  var el=document.getElementById('claim-token');
  el.select();el.setSelectionRange(0,99999);
  navigator.clipboard.writeText(el.value).then(function(){
    var ic=document.getElementById('copy-icon');
    ic.outerHTML='<svg id="copy-icon" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#34d399" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>';
    setTimeout(function(){var n=document.getElementById('copy-icon');if(n)n.outerHTML='<svg id="copy-icon" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>';},1500);
  });
}
</script>`, template.HTMLEscapeString(token), points)
}

func (s *Server) handleCheckin(w http.ResponseWriter, r *http.Request) {
	accounts, _ := db.ListAccounts()
	s.renderTemplate(w, "checkin.html", "checkin", map[string]any{"Accounts": accounts})
}

func (s *Server) handleCheckinRun(w http.ResponseWriter, r *http.Request) {
	accounts, _ := db.ListAccounts()
	type taskResult struct {
		Name    string `json:"name"`
		Points  int    `json:"points"`
		Success bool   `json:"success"`
		Status  string `json:"status"`
	}
	type accountResult struct {
		AccountName   string       `json:"account_name"`
		Status        string       `json:"status"`
		BalanceBefore int          `json:"balance_before"`
		BalanceAfter  int          `json:"balance_after"`
		Tasks         []taskResult `json:"tasks"`
	}
	var results []accountResult
	today := time.Now().UTC().Format("2006-01-02")
	tasks := []struct{ ID, Name string }{
		{"daily_signin", "Daily Check-In"},
		{"daily_inspiration_center", "Inspiration Hub"},
		{"newbie_cloud_lobster", "Cloud Lobster"},
		{"newbie_local_lobster", "Local Lobster"},
	}

	for _, a := range accounts {
		if !a.Active {
			continue
		}
		ar := accountResult{
			AccountName:   ifEmpty(a.Name, fmt.Sprintf("Account #%d", a.ID)),
			BalanceBefore: a.Points,
			Status:        "success",
		}
		for _, t := range tasks {
			existing, _ := db.GetCheckinLog(a.ID, today, t.ID)
			if existing != nil {
				ar.Tasks = append(ar.Tasks, taskResult{Name: t.Name, Points: existing.Points, Success: true, Status: "already"})
				continue
			}
			ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
			points, alreadyDone, err := s.cl.ClaimTask(ctx, a.AccessToken, t.ID)
			cancel()
			if err != nil {
				ar.Tasks = append(ar.Tasks, taskResult{Name: t.Name, Points: 0, Success: false, Status: "failed: " + err.Error()})
				db.AddCheckinLog(a.ID, today, t.ID, 0, "failed: "+err.Error(), a.DeviceID)
				continue
			}
			if alreadyDone {
				ar.Tasks = append(ar.Tasks, taskResult{Name: t.Name, Points: 0, Success: true, Status: "already"})
				db.AddCheckinLog(a.ID, today, t.ID, 0, "already", a.DeviceID)
				continue
			}
			ar.Tasks = append(ar.Tasks, taskResult{Name: t.Name, Points: points, Success: true, Status: "claimed"})
			db.AddCheckinLog(a.ID, today, t.ID, points, "success", a.DeviceID)
			db.UpdatePoints(a.ID, a.Points+points)
			ar.BalanceAfter += points
		}
		if ar.BalanceAfter == 0 {
			ar.BalanceAfter = ar.BalanceBefore
		}
		results = append(results, ar)
	}
	// HTMX request: balikin fragment #checkin-results aja (jangan seluruh halaman).
	if r.Header.Get("HX-Request") == "true" {
		if err := s.tmpl.ExecuteTemplate(w, "checkin-results", map[string]any{"Results": results}); err != nil {
			http.Error(w, err.Error(), 500)
		}
		return
	}
	s.renderTemplate(w, "checkin.html", "checkin", map[string]any{
		"Results": results,
	})
}

func ifEmpty(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	apikey, _ := db.GetConfig("api_key")
	accounts, _ := db.ListAccounts()
	// Nilai rate limiter utk form (default kalau belum pernah disimpan)
	ratePerSec := s.ratePerSec
	burst := s.rateBurst
	if ratePerSec == "" || burst == "" {
		if cfg, err := config.Load(); err == nil {
			if ratePerSec == "" {
				if cfg.RateLimitPerSec > 0 {
					ratePerSec = strconv.FormatFloat(cfg.RateLimitPerSec, 'f', -1, 64)
				} else {
					ratePerSec = "0.667"
				}
			}
			if burst == "" {
				if cfg.RateLimitBurst > 0 {
					burst = strconv.Itoa(cfg.RateLimitBurst)
				} else {
					burst = "3"
				}
			}
		}
	}
	s.ratePerSec = ratePerSec
	s.rateBurst = burst
	// Fetch models with API key
	models := []string{}
	modelsReq, _ := http.NewRequest("GET", "http://"+r.Host+"/v1/models", nil)
	if s.apiKey != "" {
		modelsReq.Header.Set("Authorization", "Bearer "+s.apiKey)
	}
	resp, err := http.DefaultClient.Do(modelsReq)
	if err == nil {
		defer resp.Body.Close()
		var data struct {
			Data []struct {
				ID string `json:"id"`
			} `json:"data"`
		}
		json.NewDecoder(resp.Body).Decode(&data)
		for _, m := range data.Data {
			models = append(models, m.ID)
		}
	}
	s.renderTemplate(w, "settings.html", "settings", map[string]any{
		"Strategy":      s.strategy,
		"DBPath":        "~/.autoclawpi/autoclawpi.db",
		"DBSize":        "OK",
		"TotalAccounts": len(accounts),
		"Models":        models,
		"APIKey":        apikey,
		"RatePerSec":    s.ratePerSec,
		"RateBurst":     s.rateBurst,
	})
}

// CurrentPassword mengembalikan password panel aktif (utk auth API via cookie).
func (s *Server) CurrentPassword() string { return s.password }

// handleOAuthLoginProxy: set/batal proxy untuk sesi login aktif (dipanggil via fetch).
func (s *Server) handleOAuthLoginProxy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "msg": "POST only"})
		return
	}
	pid, _ := strconv.ParseInt(r.FormValue("proxy_id"), 10, 64)
	var name string
	s.oauthMu.Lock()
	if pend := s.oauthPending; pend != nil {
		if pid > 0 {
			if pp, err := db.GetProxy(pid); err == nil && pp.Active {
				pend.loginProxyURL = pp.URL
				name = pp.Name
			}
		} else {
			pend.loginProxyURL = ""
		}
	}
	s.oauthMu.Unlock()
	writeJSON(w, 200, map[string]any{"ok": true, "proxy": name})
}

// handleProxies menampilkan tab Proxy Pool.
func (s *Server) handleProxies(w http.ResponseWriter, _ *http.Request) {
	proxies, _ := db.ListProxies()
	s.renderTemplate(w, "proxies.html", "proxies", map[string]any{"Proxies": proxies})
}

func (s *Server) handleProxyAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Redirect(w, r, "/proxies", http.StatusSeeOther)
		return
	}
	// Format mudah: ip | port | user | pass (name otomatis = ip)
	ip := strings.TrimSpace(r.FormValue("ip"))
	port := strings.TrimSpace(r.FormValue("port"))
	user := strings.TrimSpace(r.FormValue("user"))
	pass := r.FormValue("pass")
	name := strings.TrimSpace(r.FormValue("name"))

	if name == "" && ip != "" && port != "" {
		name = ip
	}
	var url string
	switch {
	case ip != "" && port != "" && user != "":
		url = fmt.Sprintf("http://%s:%s@%s:%s", neturl.QueryEscape(user), neturl.QueryEscape(pass), ip, port)
	case ip != "" && port != "":
		url = fmt.Sprintf("http://%s:%s", ip, port)
	default:
		// fallback format lama (name+url)
		name = strings.TrimSpace(r.FormValue("name"))
		url = strings.TrimSpace(r.FormValue("url"))
	}
	if name == "" || url == "" {
		w.Write([]byte(`<span style="color:#e08585">IP dan Port wajib diisi</span>`))
		return
	}
	if _, err := db.AddProxy(name, url); err != nil {
		w.Write([]byte(`<span style="color:#e08585">` + template.HTMLEscapeString(err.Error()) + `</span>`))
		return
	}
	w.Write([]byte(`<span style="color:var(--ok)">Proxy "` + template.HTMLEscapeString(name) + `" added</span>`))
}

// handleProxyBatch: import banyak proxy sekaligus dari textarea.
// Format per baris (auto-deteksi): ip:port:user:pass | ip:port | scheme://user:pass@host:port
func (s *Server) handleProxyBatch(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Redirect(w, r, "/proxies", http.StatusSeeOther)
		return
	}
	raw := r.FormValue("proxies")
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	lines := strings.Split(raw, "\n")
	added, skipped := 0, 0
	for _, line := range lines {
		line = strings.TrimSpace(line)
		// buang prefix log macam "[+]  1.2.3.4:3129:u:p  OK 1073ms (1.2.3.4)"
		line = strings.TrimPrefix(line, "[+]")
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "[-]") {
			continue
		}
		// ambil token pertama yang mengandung ":" (buang status/latency di belakang)
		if idx := strings.IndexAny(line, " 	"); idx > 0 {
			line = line[:idx]
		}
		url := normalizeProxyLine(line)
		if url == "" {
			skipped++
			continue
		}
		// dedup: skip kalau URL sudah ada
		dup := false
		if existing, _ := db.ListProxies(); existing != nil {
			for _, p := range existing {
				if p.URL == url {
					dup = true
					break
				}
			}
		}
		if dup {
			skipped++
			continue
		}
		name := fmt.Sprintf("proxy-%d", added+1)
		if u, err := neturl.Parse(url); err == nil && u.Host != "" {
			name = strings.Split(u.Host, ":")[0]
		}
		if _, err := db.AddProxy(name, url); err == nil {
			added++
		} else {
			skipped++
		}
	}
	msg := fmt.Sprintf(`<span style="color:var(--ok)">Import %d proxy</span>`, added)
	if skipped > 0 {
		msg += fmt.Sprintf(` <span style="color:var(--faint)">(%d dilewati: duplikat/format salah)</span>`, skipped)
	}
	w.Write([]byte(msg))
}

// normalizeProxyLine: "ip:port:user:pass" → "http://user:pass@ip:port";
// "ip:port" → "http://ip:port"; URL lengkap → apa adanya. "" = format salah.
func normalizeProxyLine(line string) string {
	parts := strings.Split(line, ":")
	switch {
	case len(parts) >= 4 && !strings.Contains(line, "://"):
		// ip:port:user:pass (user/pass bisa mengandung ":" → gabung sisanya)
		ip, port := parts[0], parts[1]
		user := parts[2]
		pass := strings.Join(parts[3:], ":")
		if ip == "" || port == "" || user == "" {
			return ""
		}
		return fmt.Sprintf("http://%s:%s@%s:%s", neturl.QueryEscape(user), neturl.QueryEscape(pass), ip, port)
	case len(parts) == 2 && !strings.Contains(line, "://"):
		if parts[0] == "" || parts[1] == "" {
			return ""
		}
		return fmt.Sprintf("http://%s:%s", parts[0], parts[1])
	case strings.Contains(line, "://"):
		return line
	default:
		return ""
	}
}

func (s *Server) handleProxyDelete(w http.ResponseWriter, r *http.Request) {
	if id, err := strconv.ParseInt(r.FormValue("id"), 10, 64); err == nil {
		_ = db.DeleteProxy(id)
	}
	http.Redirect(w, r, "/proxies", http.StatusSeeOther)
}

func (s *Server) handleProxyToggle(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.FormValue("id"), 10, 64)
	active := r.FormValue("active") == "1"
	_ = db.SetProxyActive(id, active)
	http.Redirect(w, r, "/proxies", http.StatusSeeOther)
}

// handleProxyTest: cek koneksi keluar via proxy (GET ke IP echo service).
func (s *Server) handleProxyTest(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.FormValue("id"), 10, 64)
	p, err := db.GetProxy(id)
	if err != nil || p == nil {
		w.Write([]byte(`<span style="color:#e08585">not found</span>`))
		return
	}
	pu, perr := neturl.Parse(p.URL)
	status := "bad URL"
	if perr == nil && pu.Host != "" {
		tr := &http.Transport{Proxy: http.ProxyURL(pu), TLSHandshakeTimeout: 10 * time.Second}
		cl := &http.Client{Transport: tr, Timeout: 15 * time.Second}
		resp, rerr := cl.Get("https://api.ipify.org?format=json")
		if rerr != nil {
			status = "failed: " + rerr.Error()
		} else {
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
			resp.Body.Close()
			var out struct {
				IP string `json:"ip"`
			}
			if json.Unmarshal(b, &out) == nil && out.IP != "" {
				status = "OK · IP " + out.IP
			} else {
				status = "unexpected response"
			}
		}
	}
	_ = db.UpdateProxyTest(p.ID, status)
	w.Write([]byte(template.HTMLEscapeString(status)))
}

// handleAccountSetProxy: bind/unbind proxy ke akun (dari dropdown detail akun).
func (s *Server) handleAccountSetProxy(w http.ResponseWriter, r *http.Request) {
	accID, _ := strconv.ParseInt(r.FormValue("account_id"), 10, 64)
	proxyID, _ := strconv.ParseInt(r.FormValue("proxy_id"), 10, 64)
	if accID > 0 {
		_ = db.SetAccountProxy(accID, proxyID)
	}
	http.Redirect(w, r, fmt.Sprintf("/accounts/%d", accID), http.StatusSeeOther)
}

// handleAPIKeys menampilkan tab API Keys (kelola + generate).
func (s *Server) handleAPIKeys(w http.ResponseWriter, r *http.Request) {
	keys := loadAPIKeys()
	baseURL := requestBaseURL(r) + "/v1"
	s.renderTemplate(w, "apikeys.html", "apikeys", map[string]any{
		"APIKeys": keys,
		"BaseURL": baseURL,
	})
}

// handleAPIKeyAdd menambah key baru dari tab API Keys.
func (s *Server) handleAPIKeyAdd(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	key := r.FormValue("apikey")
	if name == "" || key == "" {
		w.Write([]byte(`<span style="color:#f87171">Name and key required</span>`))
		return
	}
	for _, k := range loadAPIKeys() {
		if k.Name == name {
			w.Write([]byte(`<span style="color:#f87171">Name "`+name+`" already exists</span>`))
			return
		}
		if k.Key == key {
			w.Write([]byte(`<span style="color:#f87171">This key already exists</span>`))
			return
		}
	}
	keys := loadAPIKeys()
	keys = append(keys, apiKeyEntry{Name: name, Key: key})
	saveAPIKeys(keys)
	w.Write([]byte(`<span style="color:#34d399">API key "` + name + `" added</span>`))
}

// handleAPIKeyDelete menghapus key dari tab API Keys.
func (s *Server) handleAPIKeyDelete(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	if name == "" {
		w.Write([]byte(`<span style="color:#f87171">Name required</span>`))
		return
	}
	keys := loadAPIKeys()
	filtered := keys[:0]
	for _, k := range keys {
		if k.Name != name {
			filtered = append(filtered, k)
		}
	}
	saveAPIKeys(filtered)
	w.Write([]byte(`<span style="color:#34d399">API key "` + name + `" deleted</span>`))
}

// handleSettingsRateLimit menyimpan pengaturan token bucket ke config.json.
// Berlaku setelah restart service (rate limiter dibuat saat startup).
func (s *Server) handleSettingsRateLimit(w http.ResponseWriter, r *http.Request) {
	perSec := r.FormValue("rate_per_sec")
	burst := r.FormValue("burst")
	rate, err1 := strconv.ParseFloat(perSec, 64)
	b, err2 := strconv.Atoi(burst)
	if err1 != nil || err2 != nil || rate <= 0 || b < 1 {
		w.Write([]byte(`<span style="color:#f87171">Invalid values (rate &gt; 0, burst &ge; 1)</span>`))
		return
	}
	cfg, err := config.Load()
	if err != nil {
		w.Write([]byte(`<span style="color:#f87171">Load config: ` + err.Error() + `</span>`))
		return
	}
	cfg.RateLimitPerSec = rate
	cfg.RateLimitBurst = b
	if err := config.Save(cfg); err != nil {
		w.Write([]byte(`<span style="color:#f87171">Save: ` + err.Error() + `</span>`))
		return
	}
	s.ratePerSec = perSec
	s.rateBurst = burst
	w.Write([]byte(`<span style="color:#34d399">Rate limit saved — restart service to apply</span>`))
}

type apiKeyEntry struct {
	Name string `json:"name"`
	Key  string `json:"key"`
}

func loadAPIKeys() []apiKeyEntry {
	data, _ := db.GetConfig("api_keys")
	if data == "" {
		return nil
	}
	var keys []apiKeyEntry
	json.Unmarshal([]byte(data), &keys)
	return keys
}

func saveAPIKeys(keys []apiKeyEntry) {
	b, _ := json.Marshal(keys)
	db.SetConfig("api_keys", string(b))
}

func (s *Server) handleSettingsPassword(w http.ResponseWriter, r *http.Request) {
	pwd := r.FormValue("password")
	if pwd == "" {
		w.Write([]byte(`<span style="color:#e08585">Password cannot be empty</span>`))
		return
	}
	s.password = pwd
	// Rotasi sesi: token lama hangus, set cookie baru untuk sesi ini.
	tok := newSessionToken()
	s.setSession(tok)
	http.SetCookie(w, &http.Cookie{Name: "panel_auth", Value: tok, Path: "/", MaxAge: 86400 * 30, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	w.Write([]byte(`<span style="color:var(--ok)">Password updated</span>`))
}

func (s *Server) handleSettingsStrategy(w http.ResponseWriter, r *http.Request) {
	strat := r.FormValue("strategy")
	if strat != "" {
		s.strategy = strat
	}
	w.Write([]byte(`<span style="color:#34d399">Strategy updated</span>`))
}

func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	logs, _ := db.ListLogs(100)
	totalReq, totalTokens, totalCost, _ := db.LogStats()
	s.renderTemplate(w, "logs.html", "logs", map[string]any{
		"Logs":       logs,
		"TotalReq":   totalReq,
		"TotalTokens": totalTokens,
		"TotalCost":  totalCost,
	})
}

func (s *Server) handleModels(w http.ResponseWriter, r *http.Request) {
	// Daftar model tersedia (dari /v1/models)
	available := fetchModels("http://"+r.Host+"/v1/models", s.apiKey)
	// Statistik dari logs
	stats, _ := db.ModelStats()

	// Map statistik by model name; route ID di-log upstream (zai_auto, tdpsk_...)
	// dinormalisasi balik ke friendly name biar gak dobel di tab.
	routeToModel := make(map[string]string)
	for _, m := range available {
		routeToModel[client.RouteID(m)] = m
	}
	statMap := make(map[string]db.ModelStat)
	for _, st := range stats {
		if m, ok := routeToModel[st.Model]; ok {
			st.Model = m
		}
		statMap[st.Model] = st
	}

	type modelView struct {
		Model        string
		Available    bool
		Total        int
		Success      int
		Failed       int
		TotalTokens  int
		SuccessRate  float64
	}

	var online, offline []modelView
	seen := make(map[string]bool)

	// 1. Model tersedia (online)
	for _, m := range available {
		st := statMap[m]
		v := modelView{
			Model:       m,
			Available:   true,
			Total:       st.Total,
			Success:     st.Success,
			Failed:      st.Failed,
			TotalTokens: st.TotalTokens,
		}
		if v.Total > 0 {
			v.SuccessRate = float64(v.Success) / float64(v.Total) * 100
		}
		online = append(online, v)
		seen[m] = true
	}

	// 2. Model yang pernah dipakai tapi gak di list (offline) — pakai stats
	// yang udah dinormalisasi (statMap), biar route ID gak bocor ke sini.
	for _, st := range statMap {
		if !seen[st.Model] {
			v := modelView{
				Model:       st.Model,
				Available:   false,
				Total:       st.Total,
				Success:     st.Success,
				Failed:      st.Failed,
				TotalTokens: st.TotalTokens,
			}
			if v.Total > 0 {
				v.SuccessRate = float64(v.Success) / float64(v.Total) * 100
			}
			offline = append(offline, v)
		}
	}

	s.renderTemplate(w, "models.html", "models", map[string]any{
		"Online":  online,
		"Offline": offline,
	})
}

// requestBaseURL balikin scheme://host dari request, hormati proxy header.
func requestBaseURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		scheme = proto
	}
	return scheme + "://" + r.Host
}

func (s *Server) handleDocs(w http.ResponseWriter, r *http.Request) {
	models := fetchModels("http://"+r.Host+"/v1/models", s.apiKey)
	s.renderTemplate(w, "docs.html", "docs", map[string]any{
		"Models":  models,
		"BaseURL": requestBaseURL(r),
	})
}

func (s *Server) handlePlayground(w http.ResponseWriter, r *http.Request) {
	models := fetchModels("http://"+r.Host+"/v1/models", s.apiKey)
	s.renderTemplate(w, "playground.html", "playground", map[string]any{"Models": models})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	accounts, _ := db.ListAccounts()
	s.renderTemplate(w, "health.html", "health", map[string]any{"Accounts": accounts})
}

func (s *Server) handleHealthRun(w http.ResponseWriter, r *http.Request) {
	accounts, _ := db.ListAccounts()
	type result struct {
		ID        int64  `json:"id"`
		OK        bool   `json:"ok"`
		Refreshed bool   `json:"refreshed"`
		Error     string `json:"error,omitempty"`
	}
	var results []result
	for _, a := range accounts {
		if !a.Active {
			results = append(results, result{ID: a.ID, OK: false, Error: "inactive"})
			continue
		}
		// Try refresh directly
		rerr := s.refreshTokenAPI(&a)
		if rerr == nil {
			_ = db.UpdateAccount(&a)
			results = append(results, result{ID: a.ID, OK: true, Refreshed: true})
			continue
		}
		a.Active = false
		_ = db.UpdateAccount(&a)
		results = append(results, result{ID: a.ID, OK: false, Error: rerr.Error()})
	}
	writeJSON(w, 200, map[string]any{"results": results})
}

func (s *Server) refreshTokenAPI(acct *db.Account) error {
	if acct.RefreshToken == "" {
		return fmt.Errorf("no refresh token")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := s.cl.Refresh(ctx, acct.RefreshToken)
	if err != nil {
		return err
	}
	if out.Code != 0 || out.Data == nil || out.Data.AccessToken == "" {
		return fmt.Errorf("refresh code=%d msg=%s", out.Code, out.Msg)
	}
	acct.AccessToken = out.Data.AccessToken
	if out.Data.RefreshToken != "" {
		acct.RefreshToken = out.Data.RefreshToken
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// fetchBalance mengambil saldo points dari server.
func fetchBalance(ctx context.Context, token string, cl *client.Client) int {
	ts := time.Now().Unix()
	hdrs := map[string]string{
		"authorization":    token,
		"X-Lang":           "en",
		"X-Product":        "autoclaw",
		"X-Version":        "1.17.9",
		"X-Tm":             "linux",
		"X-Client-Type":    "pc",
		"X-Auth-Appid":     "100003",
		"X-Auth-TimeStamp": fmt.Sprintf("%d", ts),
		"X-Auth-Sign":      sign.Sign(ts),
		"X-Trace-Id":       sign.UUID(),
	}
	req, err := fhttp.NewRequestWithContext(ctx, "GET", cl.UserAPIBase+"/agent-assetmgr/api/v1/wallet-instances?biz_app_id=autoclaw", nil)
	if err != nil {
		return 0
	}
	for k, v := range hdrs {
		req.Header.Set(k, v)
	}
	resp, err := cl.Do(req)
	if err != nil {
		return 0
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var data struct {
		Code int `json:"code"`
		Data *struct {
			TotalBalance float64 `json:"total_balance"`
		} `json:"data"`
	}
	if err := json.Unmarshal(b, &data); err != nil {
		return 0
	}
	if data.Data == nil {
		return 0
	}
	return int(data.Data.TotalBalance)
}