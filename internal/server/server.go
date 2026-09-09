// Package server menyediakan endpoint OpenAI-compatible yang
// meneruskan request ke proxy inference AutoClaw dengan round-robin multi-akun.
package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	neturl "net/url"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/MisthiosOG/autoclawpi/internal/client"
	"github.com/MisthiosOG/autoclawpi/internal/db"

	tls_client "github.com/bogdanfinn/tls-client"
	fhttp "github.com/bogdanfinn/fhttp"
)

// Server adalah proxy server OpenAI-compatible.
type Server struct {
	cl            *client.Client
	rrIndex       int
	mu            sync.Mutex
	refreshMu     sync.Mutex // cegah refresh token bareng-bareng (rotasi refresh token bisa salin-invalidasi)
	newbieMu      sync.Mutex
	apiKey        string
	webPasswordFn func() string // password panel dinamis — biar ganti password panel langsung ngefek ke API
	webSessionFn  func() string // token sesi panel (cookie acak, bukan password)
	limiter       *RateLimiter

	// cache newbie guide token (bonus 100M) per akun: acctID → {token, exp}
	newbieTok    map[int64]newbieEntry

	// cache http.Client per proxy URL (proxy pool — outbound IP per akun)
	proxyMu      sync.Mutex
	proxyClients map[string]tls_client.HttpClient

	// pacing humanlike per akun: request terakhir per acctID (anti anomali)
	lastReqMu sync.Mutex
	lastReqAt map[int64]time.Time
}

// paceAccount: tunggu gap humanlike sejak request terakhir akun yang sama.
// Pola app asli: satu user, request bergantian dengan jeda natral — bukan burst.
func (s *Server) paceAccount(acctID int64) {
	s.lastReqMu.Lock()
	last, ok := s.lastReqAt[acctID]
	now := time.Now()
	// gap acak 1.2–2.8 detik (rata2 ~2s, menyerupai ritme interaksi manusia)
	gap := 1200*time.Millisecond + time.Duration(rand.Int63n(1600))*time.Millisecond
	s.lastReqAt[acctID] = now
	s.lastReqMu.Unlock()
	if ok {
		if wait := gap - now.Sub(last); wait > 0 {
			time.Sleep(wait)
		}
	}
}

type newbieEntry struct {
	token string
	exp   time.Time
}

const newbieTTL = 150 * time.Minute // server TTL 3 jam — ambil aman 2.5 jam

// newbieToken ambil (dan cache) newbie guide token akun. ok=false kalau gak tersedia.
func (s *Server) newbieToken(acct db.Account) (string, bool) {
	// Hanya untuk upstream produksi — test mock gak punya endpoint newbie
	// dan fetch-nya bikin deadlock di test yang butuh 1 request upstream pas.
	if !strings.Contains(s.cl.UserAPIBase, "autoglm.ai") {
		return "", false
	}
	s.newbieMu.Lock()
	defer s.newbieMu.Unlock()
	if e, ok := s.newbieTok[acct.ID]; ok && time.Now().Before(e.exp) {
		return e.token, true
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	nt, err := s.cl.NewbieGuideToken(ctx, acct.AccessToken)
	if err != nil || nt == "" {
		return "", false // request tetap jalan pakai points
	}
	if s.newbieTok == nil {
		s.newbieTok = make(map[int64]newbieEntry)
	}
	s.newbieTok[acct.ID] = newbieEntry{token: nt, exp: time.Now().Add(newbieTTL)}
	return nt, true
}

// New membuat server baru.
func New(cl *client.Client) *Server {
	return &Server{
		cl:        cl,
		rrIndex:   0,
		limiter:   NewRateLimiter(1.0/1.5, 3), // default: 1 req/1.5s, burst 3
		lastReqAt: make(map[int64]time.Time),
	}
}

// WithRateLimit mengatur rate limiter (token/detik + burst).
func (s *Server) WithRateLimit(ratePerSec float64, burst int) *Server {
	if ratePerSec > 0 && burst > 0 {
		s.limiter = NewRateLimiter(ratePerSec, burst)
	}
	return s
}

// WithAPIKey mengatur API key untuk proteksi endpoint.
func (s *Server) WithAPIKey(key string) *Server {
	if key != "" {
		s.apiKey = key
	}
	return s
}

// WithWebPassword mengatur password panel utk validasi cookie session
// (Playground web panel nge-fetch /v1 tanpa API key).
func (s *Server) WithWebPassword(pwd string) *Server {
	if pwd != "" {
		s.webPasswordFn = func() string { return pwd }
	}
	return s
}

// WithWebPasswordFunc mengatur sumber password panel secara dinamis
// (biar perubahan password dari panel langsung ngefek tanpa restart).
func (s *Server) WithWebPasswordFunc(fn func() string) *Server {
	if fn != nil {
		s.webPasswordFn = fn
	}
	return s
}

// WithWebSessionFunc mengatur sumber token sesi panel (dari web.Server).
func (s *Server) WithWebSessionFunc(fn func() string) *Server {
	if fn != nil {
		s.webSessionFn = fn
	}
	return s
}

// Handler mengembalikan http.Handler yang menangani route OpenAI.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/chat/completions", s.wrapAuth(s.handleChat))
	mux.HandleFunc("/v1/models", s.wrapAuth(s.handleModels))
	mux.HandleFunc("/healthz", s.handleHealth)
	return mux
}

// wrapAuth melindungi endpoint dengan API key jika dikonfigurasi.
// Menerima: (1) key dari flag/config tunggal, (2) semua key yang
// didaftarkan via web panel (config db "api_keys"),
// (3) cookie session panel (biar Playground web panel jalan tanpa key).
// Header: Authorization: Bearer <key> maupun X-Api-Key: <key>.
func (s *Server) wrapAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.apiKey != "" {
			got := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
			if got == "" {
				got = strings.TrimSpace(r.Header.Get("X-Api-Key"))
			}
			if got != s.apiKey && !panelKeyMatch(got) && !s.panelSession(r) {
				writeOpenAIError(w, 401, "invalid_api_key", "API key lokal salah")
				return
			}
		}
		next(w, r)
	}
}

// panelSession true jika request bawa cookie sesi web panel yang valid.
// Cookie panel_auth = token sesi acak (bukan password) — dibuat saat login
// panel, dirotasi saat ganti password, dihapus saat logout/restart.
func (s *Server) panelSession(r *http.Request) bool {
	cookie, err := r.Cookie("panel_auth")
	if err != nil || cookie.Value == "" || s.webSessionFn == nil {
		return false
	}
	return cookie.Value != "" && cookie.Value == s.webSessionFn()
}

// panelKeyMatch cek apakah key terdaftar di web panel (config "api_keys").
// Query per request: SQLite lokal, murah (<1ms) dan langsung refleksikan
// perubahan key dari panel tanpa restart.
func panelKeyMatch(got string) bool {
	if got == "" {
		return false
	}
	data, _ := db.GetConfig("api_keys")
	if data == "" {
		return false
	}
	var keys []struct {
		Key string `json:"key"`
	}
	if json.Unmarshal([]byte(data), &keys) != nil {
		return false
	}
	for _, k := range keys {
		if k.Key != "" && k.Key == got {
			return true
		}
	}
	return false
}

// handleChat menangani /v1/chat/completions.
func (s *Server) handleChat(w http.ResponseWriter, r *http.Request) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, 32<<20))
	_ = r.Body.Close()
	if err != nil {
		writeOpenAIError(w, 400, "invalid_request_error", "gagal baca body: "+err.Error())
		return
	}

	var req struct {
		Model  string `json:"model"`
		Stream bool   `json:"stream"`
	}
	if err := json.Unmarshal(raw, &req); err != nil {
		writeOpenAIError(w, 400, "invalid_request_error", "gagal parse body: "+err.Error())
		return
	}
	if req.Model == "" {
		writeOpenAIError(w, 400, "invalid_request_error", "model required")
		return
	}

	route := client.RouteID(req.Model)
	upstreamBody, err := replaceModel(raw, client.BodyModel(route))
	if err != nil {
		writeOpenAIError(w, 400, "invalid_request_error", "gagal olah body: "+err.Error())
		return
	}

	// Round-robin: coba setiap akun hingga salah satu berhasil
	accounts, _ := db.ListAccounts()
	if len(accounts) == 0 {
		writeOpenAIError(w, 503, "no_accounts", "tidak ada akun tersedia")
		return
	}

	// Rate limit: tunggu token sebelum menyentuh upstream (hindari WAF block)
	if s.limiter != nil {
		if err := s.limiter.Wait(r.Context()); err != nil {
			writeOpenAIError(w, 503, "rate_limited", "request dibatalkan: "+err.Error())
			return
		}
	}

	s.mu.Lock()
	startIdx := s.rrIndex % len(accounts)
	s.rrIndex = (s.rrIndex + 1) % len(accounts)
	s.mu.Unlock()

	// Strategy dari Settings (default round-robin): atur urutan coba akun.
	switch db.GetConfigDefault("strategy", "round-robin") {
	case "first":
		// Selalu mulai dari akun pertama (urutan ID).
		startIdx = 0
	case "least-used":
		// Mulai dari akun dengan last_used_at paling lama.
		oldest := 0
		for i, a := range accounts {
			if accounts[oldest].LastUsedAt == "" || (a.LastUsedAt != "" && a.LastUsedAt < accounts[oldest].LastUsedAt) {
				oldest = i
			}
		}
		startIdx = oldest
	}

	// Kumpulkan alasan gagal per akun — dilaporkan di 503 biar gak opaque.
	var failures []string

	for i := 0; i < len(accounts); i++ {
		idx := (startIdx + i) % len(accounts)
		acct := accounts[idx]
		if !acct.Active || acct.AccessToken == "" {
			failures = append(failures, fmt.Sprintf("#%d inactive/kosong", acct.ID))
			continue
		}
		// PRD 4.4: akun yang baru kena WAF block di-quarantine 15 menit —
		// jangan buang request lagi ke akun yang fingerprint-nya lagi di-flag.
		if breaker.isQuarantined(acct.ID) {
			failures = append(failures, fmt.Sprintf("#%d WAF quarantine", acct.ID))
			continue
		}
		attemptStart := time.Now()
		s.paceAccount(acct.ID) // humanlike pacing per akun

		status, _, ferr := s.forward(r, acct, route, upstreamBody, req.Stream, w)
		if ferr != nil {
			// Klien putus koneksi (mis. user cancel / timeout) — jangan lanjut failover,
			// upstream sudah di-bill dan klien tak akan baca hasilnya.
			if r.Context().Err() != nil {
				return
			}
			log.Printf("[autoclawpi] akun #%d error: %v", acct.ID, ferr)
			failures = append(failures, fmt.Sprintf("#%d error: %v", acct.ID, ferr))
			go logAttempt(acct.ID, route, 0, fmt.Errorf("error: %v", ferr), time.Since(attemptStart))
			continue
		}
		// 401 — token expired, coba refresh
		if status == 401 {
			refreshed, rerr := s.refreshToken(&acct)
			if rerr != nil {
				log.Printf("[autoclawpi] akun #%d refresh gagal: %v", acct.ID, rerr)
				failures = append(failures, fmt.Sprintf("#%d refresh gagal: %v", acct.ID, rerr))
				go logAttempt(acct.ID, route, 401, fmt.Errorf("refresh gagal: %v", rerr), time.Since(attemptStart))
				continue
			}
			// Retry dengan token baru
			status, _, ferr2 := s.forward(r, acct, route, upstreamBody, req.Stream, w)
			if ferr2 != nil {
				log.Printf("[autoclawpi] akun #%d retry error: %v", acct.ID, ferr2)
				failures = append(failures, fmt.Sprintf("#%d retry error: %v", acct.ID, ferr2))
				continue
			}
			_ = refreshed
			if status == 200 {
				db.TouchAccount(acct.ID) // untuk strategi least-used
				return
			}
			failures = append(failures, fmt.Sprintf("#%d retry status %d", acct.ID, status))
			continue
		}
		// 403 — WAF block: PRD 4.4 circuit breaker. Quarantine akun ini +
		// backoff with jitter SEBELUM coba akun berikutnya. Tanpa ini satu
		// request kena 403 membakar seluruh pool dalam hitungan detik
		// (blind failover loop — WAF memblokir berdasarkan IP/fingerprint,
		// bukan akun, jadi failover cepat hanya mempercepat pemblokiran
		// seluruh pool).
		if status == 403 {
			breaker.quarantine(acct.ID)
			tripped, wait := breaker.record()
			log.Printf("[autoclawpi] akun #%d WAF block → quarantine %v", acct.ID, quarantineDuration)
			if tripped && wait > 0 {
				log.Printf("[autoclawpi] circuit trip: menunggu %v sebelum lanjut (backoff+jitter)", wait.Round(time.Millisecond))
				select {
				case <-time.After(wait):
				case <-r.Context().Done():
					return
				}
			} else {
				time.Sleep(500 * time.Millisecond)
			}
			failures = append(failures, fmt.Sprintf("#%d WAF block (403)", acct.ID))
			go logAttempt(acct.ID, route, 403, fmt.Errorf("WAF block"), time.Since(attemptStart))
			continue
		}
		// 429 rate-limit upstream — tunggu lalu coba akun berikutnya
		if status == 429 {
			log.Printf("[autoclawpi] akun #%d 429, tunggu 2s lalu coba berikutnya", acct.ID)
			failures = append(failures, fmt.Sprintf("#%d rate-limit (429)", acct.ID))
			go logAttempt(acct.ID, route, 429, fmt.Errorf("rate-limit"), time.Since(attemptStart))
			select {
			case <-time.After(2 * time.Second):
			case <-r.Context().Done():
				return
			}
			continue
		}
		// 5xx upstream error — coba akun berikutnya
		if status >= 500 {
			log.Printf("[autoclawpi] akun #%d upstream %d, coba berikutnya", acct.ID, status)
			failures = append(failures, fmt.Sprintf("#%d upstream %d", acct.ID, status))
			go logAttempt(acct.ID, route, status, fmt.Errorf("upstream %d", status), time.Since(attemptStart))
			continue
		}
		if status == 200 {
			db.TouchAccount(acct.ID) // untuk strategi least-used
			return
		}
		// Status lain (4xx) — coba akun berikutnya
		failures = append(failures, fmt.Sprintf("#%d status %d", acct.ID, status))
		go logAttempt(acct.ID, route, status, fmt.Errorf("status %d", status), time.Since(attemptStart))
	}

	// Semua akun gagal — kirim error HANYA jika belum ada data terkirim ke klien.
	if w.Header().Get("Content-Type") == "" {
		detail := "semua akun gagal memproses request"
		if len(failures) > 0 {
			detail += " — " + strings.Join(failures, "; ")
		}
		writeOpenAIError(w, 503, "all_accounts_failed", detail)
	}
}

// forward mengirim request ke upstream dan menulis response ke klien.
// Return: (status, content-type, error).
// Untuk response non-streaming, membaca tubuh penuh dulu, parse token usage, lalu log.
// Untuk streaming, melewatkan data langsung (dengan strip prefix WAF yang aman antar-chunk).
func (s *Server) forward(r *http.Request, acct db.Account, route string, body []byte, stream bool, w http.ResponseWriter) (int, string, error) {
	fwdStart := time.Now()
	baseURL := s.cl.InferenceBase
	if baseURL == "" {
		baseURL = "https://autoglm-api.autoglm.ai"
	}

	// baseURL default sudah mengandung /autoclaw-proxy/proxy/autoclaw.
	// Custom base yang setara juga di-normalize di sini (hindari double path).
	base := strings.TrimSuffix(baseURL, "/")
	if !strings.HasSuffix(base, "/autoclaw") {
		base += "/autoclaw-proxy/proxy/autoclaw"
	}
	url := base + "/v1/chat/completions"
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
	defer cancel()
	req, err := fhttp.NewRequestWithContext(ctx, fhttp.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return 0, "", fmt.Errorf("buat request: %w", err)
	}

	headers := s.cl.InferenceHeader(acct.AccessToken, route)
	headers["Content-Type"] = "application/json"
	// Proxy pool: kalau akun punya proxy aktif, keluar lewat IP itu.
	var hc tls_client.HttpClient = s.cl.HTTP
	if proxyURL := db.AccountProxyURL(acct.ID); proxyURL != "" {
		if pc := s.proxyHTTPClient(proxyURL); pc != nil {
			hc = pc
			req.Header.Set("User-Agent", "AutoClaw/"+s.cl.Version)
		}
	}
	// Newbie guide (bonus 100M): server pakai kuota bonus dulu kalau 2 header
	// ini ada — terbukti lewat A/B test balance. Cache per akun, TTL 2.5 jam
	// (server TTL 3 jam). Kalau gagal fetch, request tetap jalan pakai points.
	if ng, ok := s.newbieToken(acct); ok {
		headers["X-Newbie-Guide"] = "1"
		headers["X-Newbie-Guide-Token"] = ng
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if stream {
		req.Header.Set("Accept", "text/event-stream")
	} else {
		req.Header.Set("Accept", "application/json")
	}

	resp, err := hc.Do(req)
	if err != nil {
		return 0, "", fmt.Errorf("request: %w", err)
	}
	defer resp.Body.Close()

	ct := resp.Header.Get("Content-Type")
	if ct == "" {
		ct = "application/json"
	}

	if resp.StatusCode == 401 {
		return resp.StatusCode, ct, nil
	}

	// WAF 403 — ditangani caller sebagai failover akun
	if resp.StatusCode == 403 {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		return 403, ct, nil
	}

	if resp.StatusCode != 200 {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		return resp.StatusCode, ct, nil
	}

	// Deteksi WAF block yang menyamar jadi 200: body kecil berisi forbidden
	// → failover akun berikutnya alih-alih meneruskan sampah ke klien.
	if !stream {
		rawBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
		cleaned := stripNonStandard(rawBody)
		if cleaned == nil || isWAFBlockOnly(rawBody) {
			if cleaned != nil {
				log.Printf("[autoclawpi] WAF hard block: %s", truncateResp(rawBody, 80))
			}
			return http.StatusForbidden, ct, nil
		}
		w.Header().Set("Content-Type", ct)
		w.WriteHeader(200)
		w.Write(cleaned)

		// Log token usage
		go logUsage(acct.ID, route, rawBody, time.Since(fwdStart))

		return 200, ct, nil
	}

	// ── Streaming ──
	// Strip prefix WAF `{"message":"forbidden"}` (bisa bertumpuk) dengan aman:
	// objek WAF bisa kepotong di batas chunk, jadi scan buffer kontinu —
	// hanya buang objek utuh di posisi 0, tahan fragment yang belum lengkap.
	// Header 200 baru ditulis saat konten asli pertama siap dikirim, sehingga
	// stream yang 100% WAF block bisa di-failover ke akun berikutnya.
	flusher, _ := w.(http.Flusher)
	wrote := false
	emit := func(data []byte) error {
		if !wrote {
			w.Header().Set("Content-Type", ct)
			w.Header().Set("Cache-Control", "no-cache")
			w.Header().Set("X-Accel-Buffering", "no")
			w.WriteHeader(200)
			wrote = true
		}
		if _, werr := w.Write(data); werr != nil {
			return werr // klien putus
		}
		if flusher != nil {
			flusher.Flush()
		}
		return nil
	}

	var pending []byte
	// Kumpulkan stream untuk logging usage — hanya chunk terakhir yang
	// mengandung `usage`, jadi cukup simpan tail kecil (4KB).
	var tailBuf []byte
	const tailKeep = 8 * 1024
	streamErr := func() error {
		buf := make([]byte, 64*1024)
		for {
			n, rerr := resp.Body.Read(buf)
			if n > 0 {
				pending = append(pending, buf[:n]...)
				tailBuf = append(tailBuf, buf[:n]...)
				if len(tailBuf) > tailKeep {
					tailBuf = tailBuf[len(tailBuf)-tailKeep:]
				}
				// Buang semua objek WAF utuh di depan (bisa bertumpuk)
				for bytes.HasPrefix(pending, wafObj) {
					pending = pending[len(wafObj):]
				}
				// Jika pending adalah prefix dari objek WAF (kepotong di batas
				// chunk), tahan dulu sampai chunk berikutnya menentukan.
				if len(pending) > 0 && bytes.HasPrefix(wafObj, pending) {
					continue
				}
				if len(pending) > 0 {
					if err := emit(pending); err != nil {
						return err
					}
					pending = pending[:0]
				}
			}
			if rerr != nil {
				// Stream selesai: flush sisa pending yang bukan fragment WAF
				if len(pending) > 0 && !bytes.HasPrefix(wafObj, pending) {
					if err := emit(pending); err != nil {
						return err
					}
				}
				if rerr != io.EOF {
					return rerr
				}
				return nil
			}
		}
	}()
	if streamErr != nil {
		if !wrote {
			return 0, "", streamErr
		}
		return 200, ct, nil
	}
	if !wrote {
		// ponytail: stream kosong diperlakukan WAF block biar failover akun;
		// kalau upstream legit kirim SSE kosong, ganti jadi return 200.
		return 403, ct, nil
	}
	// Log token usage dari chunk terakhir stream (punya field usage).
	go logStreamUsage(acct.ID, route, tailBuf, time.Since(fwdStart))
	return 200, ct, nil
}

// logStreamUsage parse usage dari tail buffer SSE stream: cari objek
// "usage":{...} terakhir (chunk penutup OpenAI-compatible) lalu catat ke DB.
// ponytail: brace-matching sederhana — key usage baku dari upstream, aman.
func logStreamUsage(acctID int64, model string, tail []byte, dur time.Duration) {
	idx := bytes.LastIndex(tail, []byte(`"usage":`))
	if idx < 0 {
		return
	}
	objStart := bytes.IndexAny(tail[idx:], "{[")
	if objStart < 0 {
		return
	}
	depth := 0
	end := -1
	inStr := false
	esc := false
	for i := idx + objStart; i < len(tail); i++ {
		c := tail[i]
		if inStr {
			if esc {
				esc = false
			} else if c == '\\' {
				esc = true
			} else if c == '"' {
				inStr = false
			}
			continue
		}
		switch c {
		case '"':
			inStr = true
		case '{', '[':
			depth++
		case '}', ']':
			depth--
			if depth == 0 {
				end = i + 1
			}
		}
		if end > 0 {
			break
		}
	}
	if end < 0 {
		return
	}
	usageJSON := tail[idx+objStart : end]
	var usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
		TotalTokens      int `json:"total_tokens"`
	}
	if err := json.Unmarshal(usageJSON, &usage); err != nil {
		return
	}
	tts := usage.TotalTokens
	if tts == 0 {
		tts = usage.PromptTokens + usage.CompletionTokens
	}
	if tts == 0 {
		return // chunk tanpa usage — skip
	}
	cost := float64(tts) * 0.001 / 1000.0
	_, _ = db.AddLog(&db.LogEntry{
		AccountID:        acctID,
		Model:            model,
		PromptTokens:     usage.PromptTokens,
		CompletionTokens: usage.CompletionTokens,
		TotalTokens:      tts,
		DurationMs:       dur.Milliseconds(),
		Cost:             cost,
		Status:           "success",
	})
}

// wafObj adalah objek WAF block yang muncul sebagai prefix garbage
// di awal response upstream (bisa muncul bertumpuk).
var wafObj = []byte(`{"message":"forbidden"}`)

// stripNonStandard removes non-OpenAI fields from chat completion response.
func stripNonStandard(body []byte) []byte {
	// Strip all WAF prefixes
	for {
		idx := bytes.Index(body, []byte(`"message":"forbidden"`))
		if idx < 0 {
			break
		}
		// Find the end of this forbidden object
		end := bytes.Index(body[idx+1:], []byte(`{`))
		if end < 0 {
			break
		}
		body = body[idx+end+1:]
	}
	if len(body) == 0 {
		return nil
	}
	var data map[string]any
	if err := json.Unmarshal(body, &data); err != nil {
		return nil
	}
	// Remove reasoning_content from choices
	if choices, ok := data["choices"].([]any); ok {
		for _, c := range choices {
			if choice, ok := c.(map[string]any); ok {
				if msg, ok := choice["message"].(map[string]any); ok {
					// Move reasoning_content to content if content is empty
					if content, _ := msg["content"].(string); content == "" {
						if reasoning, ok := msg["reasoning_content"].(string); ok && reasoning != "" {
							msg["content"] = reasoning[:min(len(reasoning), 500)]
						}
					}
					delete(msg, "reasoning_content")
				}
			}
		}
	}
	// Remove non-standard usage details
	if usage, ok := data["usage"].(map[string]any); ok {
		delete(usage, "completion_tokens_details")
		delete(usage, "prompt_tokens_details")
	}
	cleaned, _ := json.Marshal(data)
	return cleaned
}

// logUsage parse response body dan catat ke database.
func logUsage(acctID int64, model string, body []byte, dur time.Duration) {
	// Strip ALL WAF prefixes
	for bytes.Contains(body, []byte(`"message":"forbidden"`)) {
		idx := bytes.Index(body, []byte(`"message":"forbidden"`))
		next := bytes.Index(body[idx+1:], []byte(`{`))
		if next < 0 {
			break
		}
		body = body[idx+next+1:]
	}
	var data struct {
		Usage *struct {
			PromptTokens     int `json:"prompt_tokens"`
			CompletionTokens int `json:"completion_tokens"`
			TotalTokens      int `json:"total_tokens"`
		} `json:"usage"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return
	}
	status := "success"
	errMsg := ""
	if data.Error != nil {
		status = "error"
		errMsg = data.Error.Message
	}
	pts := 0
	cts := 0
	tts := 0
	if data.Usage != nil {
		pts = data.Usage.PromptTokens
		cts = data.Usage.CompletionTokens
		tts = data.Usage.TotalTokens
	}
	cost := float64(tts) * 0.001 / 1000.0
	_, _ = db.AddLog(&db.LogEntry{
		AccountID:        acctID,
		Model:            model,
		PromptTokens:     pts,
		CompletionTokens: cts,
		TotalTokens:      tts,
		Cost:             cost,
		Status:           status,
		Error:            errMsg,
		DurationMs:       dur.Milliseconds(),
	})
}

// proxyHTTPClient: http.Client dengan transport proxy (cached per URL).
func (s *Server) proxyHTTPClient(proxyURL string) tls_client.HttpClient {
	s.proxyMu.Lock()
	defer s.proxyMu.Unlock()
	if c, ok := s.proxyClients[proxyURL]; ok {
		return c
	}
	pu, err := neturl.Parse(proxyURL)
	if err != nil || pu.Scheme == "" || pu.Host == "" {
		return nil
	}
	c, cerr := client.NewChromeClientForProxy(proxyURL)
	if cerr != nil {
		return nil
	}
	if s.proxyClients == nil {
		s.proxyClients = make(map[string]tls_client.HttpClient)
	}
	s.proxyClients[proxyURL] = c
	return c
}

// logAttempt: catat percobaan yang gagal (401/WAF/429/5xx dll) ke DB.
func logAttempt(acctID int64, model string, status int, cause error, dur time.Duration) {
	msg := ""
	if cause != nil {
		msg = cause.Error()
	}
	_, _ = db.AddLog(&db.LogEntry{
		AccountID:  acctID,
		Model:      model,
		Status:     fmt.Sprintf("failed (%d)", status),
		Error:      msg,
		DurationMs: dur.Milliseconds(),
	})
}

// handleModels menangani /v1/models.
func (s *Server) handleModels(w http.ResponseWriter, _ *http.Request) {
	// Model yang sudah diverifikasi bisa inference (2026-09-05).
	models := []map[string]any{
		{"id": "auto", "object": "model", "created": 1, "owned_by": "autoclaw"},
		{"id": "auto-fast", "object": "model", "created": 1, "owned_by": "autoclaw"},
		{"id": "glm-5-turbo", "object": "model", "created": 1, "owned_by": "autoclaw"},
		{"id": "glm-5.3", "object": "model", "created": 1, "owned_by": "autoclaw"},
		{"id": "glm-5.3-flash", "object": "model", "created": 1, "owned_by": "autoclaw"},
		{"id": "deepseek-v4-pro", "object": "model", "created": 1, "owned_by": "autoclaw"},
		{"id": "deepseek-v4-flash", "object": "model", "created": 1, "owned_by": "autoclaw"},
	}
	writeJSON(w, 200, map[string]any{"object": "list", "data": models})
}

// handleHealth menangani /healthz.
func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	accounts, _ := db.ListAccounts()
	activeCount := 0
	for _, a := range accounts {
		if a.Active {
			activeCount++
		}
	}
	writeJSON(w, 200, map[string]any{
		"ok":       true,
		"status":   "healthy",
		"accounts": len(accounts),
		"active":   activeCount,
		"time":     time.Now().Format(time.RFC3339),
	})
}

// refreshToken mencoba memperbarui token akun.
// Dikunci mutex: refresh token berotasi, dua refresh paralel bisa salin-invalidasi.
func (s *Server) refreshToken(acct *db.Account) (bool, error) {
	s.refreshMu.Lock()
	defer s.refreshMu.Unlock()
	if acct.RefreshToken == "" {
		return false, fmt.Errorf("no refresh token")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := s.cl.Refresh(ctx, acct.RefreshToken)
	if err != nil {
		return false, err
	}
	if out.Code != 0 || out.Data == nil || out.Data.AccessToken == "" {
		msg := "refresh gagal"
		if out != nil {
			msg = out.Msg
		}
		return false, fmt.Errorf("%s", msg)
	}
	newRefresh := acct.RefreshToken
	if out.Data.RefreshToken != "" {
		newRefresh = out.Data.RefreshToken
	}
	acct.AccessToken = out.Data.AccessToken
	acct.RefreshToken = newRefresh
	_ = db.UpdateAccount(acct)
	log.Printf("[autoclawpi] akun #%d token diperbarui", acct.ID)
	return true, nil
}

// ── helpers ─────────────────────────────────────────────────────────

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeOpenAIError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]any{
		"error": map[string]string{
			"message": message,
			"type":    code,
		},
	})
}

func replaceModel(raw []byte, model string) ([]byte, error) {
	var data map[string]any
	if err := json.Unmarshal(raw, &data); err != nil {
		return nil, err
	}
	data["model"] = model
	return json.Marshal(data)
}

// isWAFBlockOnly checks if the response body is just a WAF block (no actual content).
func isWAFBlockOnly(body []byte) bool {
	if len(body) < 30 {
		return bytes.Contains(body, []byte(`"message":"forbidden"`))
	}
	return false
}

func truncateResp(b []byte, n int) string {
	if len(b) > n {
		return string(b[:n]) + "..."
	}
	return string(b)
}
