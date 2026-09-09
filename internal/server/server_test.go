package server

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/MisthiosOG/autoclawpi/internal/client"
	"github.com/MisthiosOG/autoclawpi/internal/db"
)

// TestMain init DB in-memory-ish sekali untuk semua test (logUsage butuh DB).
// Dir sengaja tidak dihapus: SQLite di Windows mengunci file sampai proses mati.
func TestMain(m *testing.M) {
	dir, _ := os.MkdirTemp("", "autoclawpi-test-db")
	if err := db.Init(dir); err != nil {
		fmt.Fprintln(os.Stderr, "db init:", err)
		os.Exit(1)
	}
	code := m.Run()
	db.DB.Close()
	os.RemoveAll(dir)
	os.Exit(code)
}

// upstreamMock membuat server yang mengarah ke mock upstream + recorder.
func upstreamMock(t *testing.T, status int, body string) (*Server, *httptest.ResponseRecorder) {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(status)
		w.Write([]byte(body))
	}))
	t.Cleanup(ts.Close)

	cl := client.New(ts.URL, ts.URL)
	s := New(cl)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(`{"model":"auto"}`))
	acct := db.Account{ID: 1, Active: true, AccessToken: "test-token"}

	if status, _, err := s.forward(req, acct, "zai_auto", []byte(`{"model":"auto"}`), true, rec); err != nil || status != 200 {
		t.Fatalf("forward: status=%d err=%v", status, err)
	}
	return s, rec
}

// forwardDirect menjalankan s.forward ke mock upstream tanpa assert status.
func forwardDirect(t *testing.T, upstreamURL string, stream bool, upstreamBody string) (*httptest.ResponseRecorder, int) {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		w.Write([]byte(upstreamBody))
	}))
	t.Cleanup(ts.Close)

	s := New(client.New(ts.URL, ts.URL))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(`{"model":"auto"}`))
	acct := db.Account{ID: 1, Active: true, AccessToken: "test-token"}
	status, _, err := s.forward(req, acct, "zai_auto", []byte(`{"model":"auto"}`), stream, rec)
	if err != nil {
		t.Fatalf("forward error: %v", err)
	}
	return rec, status
}

// 1. WAF prefix utuh (bertumpuk) di depan SSE harus dibuang, SSE tetap utuh.
func TestStreamStripWAFPefix(t *testing.T) {
	_, rec := upstreamMock(t, 200,
		`{"message":"forbidden"}{"message":"forbidden"}data: {"id":"x"}\n\ndata: [DONE]\n\n`)
	got := rec.Body.String()
	if strings.Contains(got, "forbidden") {
		t.Errorf("WAF prefix bocor ke klien: %q", got)
	}
	if !strings.Contains(got, `data: {"id":"x"}`) || !strings.Contains(got, "[DONE]") {
		t.Errorf("SSE hilang/rusak: %q", got)
	}
	if rec.Code != 200 {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

// 2. Objek WAF kepotong di batas chunk tidak boleh bocor.
func TestStreamStripWAFPartial(t *testing.T) {
	_, rec := upstreamMock(t, 200,
		`{"message":"forb`+`idden"}data: {"ok":true}\n\n`)
	got := rec.Body.String()
	if strings.Contains(got, "forbidden") || strings.Contains(got, `{"mess`) {
		t.Errorf("fragment WAF bocor ke klien: %q", got)
	}
	if !strings.Contains(got, `data: {"ok":true}`) {
		t.Errorf("SSE hilang: %q", got)
	}
}

// 3. Stream 200 tapi isinya WAF block saja → forward return 403 (sinyal failover),
// klien tak menerima body apa pun.
func TestStreamWAFOnlyReturns403(t *testing.T) {
	rec, status := forwardDirect(t, "", true, `{"message":"forbidden"}`)
	if status != http.StatusForbidden {
		t.Errorf("status = %d, want 403", status)
	}
	if rec.Body.Len() != 0 {
		t.Errorf("klien terlanjur menerima body: %q", rec.Body.String())
	}
}

// 4. Non-stream 200 dengan body WAF-only → 403.
func TestNonStreamWAFOnlyReturns403(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write([]byte(`{"message":"forbidden"}`))
	}))
	defer ts.Close()

	s := New(client.New(ts.URL, ts.URL))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(`{"model":"auto"}`))
	acct := db.Account{ID: 1, Active: true, AccessToken: "test-token"}
	status, _, err := s.forward(req, acct, "zai_auto", []byte(`{"model":"auto"}`), false, rec)
	if err != nil {
		t.Fatalf("forward error: %v", err)
	}
	if status != http.StatusForbidden {
		t.Errorf("status = %d, want 403", status)
	}
}

// 6. wrapAuth: key web panel (config "api_keys") harus diterima.
func TestPanelKeyAuth(t *testing.T) {
	if err := db.SetConfig("api_keys", `[{"name":"t","key":"sk-panel-test"}]`); err != nil {
		t.Fatalf("set config: %v", err)
	}
	s := New(client.New("http://127.0.0.1:1", "http://127.0.0.1:1")).WithAPIKey("flag-key")
	h := s.Handler()

	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer sk-panel-test")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	// 400 (model required) = auth lolos; 401 = auth gagal
	if rec.Code == 401 {
		t.Errorf("key panel ditolak, harusnya lolos auth")
	}

	req2 := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(`{}`))
	req2.Header.Set("Authorization", "Bearer ngasal")
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if rec2.Code != 401 {
		t.Errorf("key ngasal = %d, harusnya 401", rec2.Code)
	}
}

// 7. wrapAuth: cookie session panel valid (token acak) harus lolos tanpa API key.
func TestPanelSessionBypass(t *testing.T) {
	tok := "sess-token-abc123"
	s := New(client.New("http://127.0.0.1:1", "http://127.0.0.1:1")).
		WithAPIKey("flag-key").WithWebSessionFunc(func() string { return tok })
	h := s.Handler()

	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(`{}`))
	req.AddCookie(&http.Cookie{Name: "panel_auth", Value: tok})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code == 401 {
		t.Errorf("cookie panel valid ditolak, harusnya lolos auth")
	}

	req2 := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(`{}`))
	req2.AddCookie(&http.Cookie{Name: "panel_auth", Value: "salah"})
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if rec2.Code != 401 {
		t.Errorf("cookie salah = %d, harusnya 401", rec2.Code)
	}
}

// 5. Request body besar (mis. context coding assistant) tidak kepotong di 1MB.
func TestLargeRequestBody(t *testing.T) {
	var big bytes.Buffer
	big.WriteString(`{"model":"auto","messages":[{"role":"user","content":"`)
	big.WriteString(strings.Repeat("x", 2<<20)) // 2MB
	big.WriteString(`"}]}`)

	seen := make(chan int, 1)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := new(bytes.Buffer)
		buf.ReadFrom(r.Body)
		seen <- buf.Len()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write([]byte(`{"choices":[{"message":{"content":"ok"}}],"usage":{"total_tokens":1}}`))
	}))
	defer ts.Close()

	s := New(client.New(ts.URL, ts.URL))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/v1/chat/completions", &big)
	acct := db.Account{ID: 1, Active: true, AccessToken: "test-token"}
	status, _, err := s.forward(req, acct, "zai_auto", big.Bytes(), false, rec)
	if err != nil {
		t.Fatalf("forward error: %v", err)
	}
	if status != 200 {
		t.Errorf("status = %d, want 200", status)
	}
	if n := <-seen; n < 2<<20 {
		t.Errorf("body kepotong di upstream: %d bytes", n)
	}
}

// TestLogStreamUsage: parser harus ambil usage dari chunk terakhir SSE.
func TestLogStreamUsage(t *testing.T) {
	sse := `data: {"choices":[{"delta":{"content":"1"}}]}

data: {"choices":[{"delta":{"content":"2"}}]}

data: {"choices":[{"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}

data: [DONE]

`
	logStreamUsage(99, "zai_test", []byte(sse), 1230*time.Millisecond)
	logs, _ := db.ListLogs(1)
	if len(logs) == 0 {
		t.Fatal("log gak tercatat")
	}
	l := logs[0]
	if l.TotalTokens != 15 || l.PromptTokens != 10 || l.CompletionTokens != 5 {
		t.Errorf("usage salah: %+v", l)
	}
	if l.Model != "zai_test" || l.AccountID != 99 || l.DurationMs != 1230 {
		t.Errorf("meta salah: acct=%d model=%s", l.AccountID, l.Model)
	}
}
