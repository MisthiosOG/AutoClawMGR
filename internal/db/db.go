// Package db menyediakan akses SQLite untuk autoclawpi.
// Schema: accounts + checkin_log + config.
package db

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

var DB *sql.DB

// Account menyimpan satu akun AutoClaw.
type Account struct {
	ID           int64  `json:"id"`
	Name         string `json:"name"`
	AccessToken  string `json:"-"` // plaintext di memory, encrypted di disk
	RefreshToken string `json:"-"`
	Provider     string `json:"provider"` // zai | google
	UserID       string `json:"user_id"`
	UserName     string `json:"user_name"`
	DeviceID     string `json:"device_id"`
	Points       int    `json:"points"`
	Active       bool   `json:"active"`
	CreatedAt    string `json:"created_at"`
	LastUsedAt   string `json:"last_used_at"`
}

// CheckinLog mencatat history check-in.
type CheckinLog struct {
	ID         int64  `json:"id"`
	AccountID  int64  `json:"account_id"`
	Date       string `json:"date"`       // YYYY-MM-DD
	TaskID     string `json:"task_id"`    // daily_signin, dll
	Points     int    `json:"points"`
	Status     string `json:"status"`     // success | already_done | failed
	DeviceID   string `json:"device_id"`
	CreatedAt  string `json:"created_at"`
}

// Init membuka/membuat database dan menjalankan migrasi.
func Init(dir string) error {
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		dir = filepath.Join(home, ".autoclawpi")
	}
	_ = os.MkdirAll(dir, 0o700)
	dbPath := filepath.Join(dir, "autoclawpi.db")

	var err error
	DB, err = sql.Open("sqlite", dbPath+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	DB.SetMaxOpenConns(1) // SQLite single-writer

	if err := migrate(); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	return nil
}

// Close menutup database.
func Close() {
	if DB != nil {
		DB.Close()
	}
}

func migrate() error {
	schema := `
	CREATE TABLE IF NOT EXISTS accounts (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL DEFAULT '',
		access_token TEXT NOT NULL DEFAULT '',
		refresh_token TEXT NOT NULL DEFAULT '',
		provider TEXT NOT NULL DEFAULT 'zai',
		user_id TEXT NOT NULL DEFAULT '',
		user_name TEXT NOT NULL DEFAULT '',
		device_id TEXT NOT NULL DEFAULT '',
		points INTEGER NOT NULL DEFAULT 0,
		active INTEGER NOT NULL DEFAULT 1,
		created_at TEXT NOT NULL,
		last_used_at TEXT NOT NULL DEFAULT ''
	);

	CREATE TABLE IF NOT EXISTS checkin_log (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		account_id INTEGER NOT NULL,
		date TEXT NOT NULL,
		task_id TEXT NOT NULL,
		points INTEGER NOT NULL DEFAULT 0,
		status TEXT NOT NULL DEFAULT 'failed',
		device_id TEXT NOT NULL DEFAULT '',
		created_at TEXT NOT NULL,
		FOREIGN KEY (account_id) REFERENCES accounts(id)
	);

	CREATE INDEX IF NOT EXISTS idx_checkin_log_account_date ON checkin_log(account_id, date);

	CREATE TABLE IF NOT EXISTS config (
		key TEXT PRIMARY KEY,
		value TEXT NOT NULL DEFAULT ''
	);

	CREATE TABLE IF NOT EXISTS logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		account_id INTEGER NOT NULL DEFAULT 0,
		model TEXT NOT NULL DEFAULT '',
		prompt_tokens INTEGER NOT NULL DEFAULT 0,
		completion_tokens INTEGER NOT NULL DEFAULT 0,
		total_tokens INTEGER NOT NULL DEFAULT 0,
		cost REAL NOT NULL DEFAULT 0,
		status TEXT NOT NULL DEFAULT 'success',
		error TEXT NOT NULL DEFAULT '',
		created_at TEXT NOT NULL DEFAULT (datetime('now'))
	);
	`
	if _, err := DB.Exec(schema); err != nil {
		return err
	}
	// Migrasi ringan: kolom duration_ms (ada di semua request sejak v1.1).
	_, _ = DB.Exec(`ALTER TABLE logs ADD COLUMN duration_ms INTEGER NOT NULL DEFAULT 0`)
	// Proxy pool (outbound IP per akun).
	_, _ = DB.Exec(`CREATE TABLE IF NOT EXISTS proxies (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		url TEXT NOT NULL,
		active INTEGER NOT NULL DEFAULT 1,
		last_tested TEXT NOT NULL DEFAULT '',
		last_status TEXT NOT NULL DEFAULT '',
		created_at TEXT NOT NULL DEFAULT (datetime('now'))
	)`)
	_, _ = DB.Exec(`ALTER TABLE accounts ADD COLUMN proxy_id INTEGER NOT NULL DEFAULT 0`)
	return nil
}

// --- Account CRUD ---

// AddAccount menyimpan akun baru.
func AddAccount(name, accessToken, refreshToken, provider, userID, userName, deviceID string) (int64, error) {
	now := time.Now().UTC().Format(time.RFC3339)
	res, err := DB.Exec(`INSERT INTO accounts (name, access_token, refresh_token, provider, user_id, user_name, device_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		name, accessToken, refreshToken, provider, userID, userName, deviceID, now)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// ListAccounts mengembalikan semua akun.
func ListAccounts() ([]Account, error) {
	rows, err := DB.Query(`SELECT id, name, access_token, refresh_token, provider, user_id, user_name, device_id, points, active, created_at, last_used_at FROM accounts ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var accounts []Account
	for rows.Next() {
		var a Account
		if err := rows.Scan(&a.ID, &a.Name, &a.AccessToken, &a.RefreshToken, &a.Provider, &a.UserID, &a.UserName, &a.DeviceID, &a.Points, &a.Active, &a.CreatedAt, &a.LastUsedAt); err != nil {
			return nil, err
		}
		accounts = append(accounts, a)
	}
	return accounts, nil
}

// GetAccount mengambil satu akun berdasarkan ID.
func GetAccount(id int64) (*Account, error) {
	row := DB.QueryRow(`SELECT id, name, access_token, refresh_token, provider, user_id, user_name, device_id, points, active, created_at, last_used_at FROM accounts WHERE id = ?`, id)
	var a Account
	if err := row.Scan(&a.ID, &a.Name, &a.AccessToken, &a.RefreshToken, &a.Provider, &a.UserID, &a.UserName, &a.DeviceID, &a.Points, &a.Active, &a.CreatedAt, &a.LastUsedAt); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &a, nil
}

// GetActiveAccount mengembalikan akun aktif pertama (untuk single-account mode).
func GetActiveAccount() (*Account, error) {
	row := DB.QueryRow(`SELECT id, name, access_token, refresh_token, provider, user_id, user_name, device_id, points, active, created_at, last_used_at FROM accounts WHERE active = 1 ORDER BY id LIMIT 1`)
	var a Account
	if err := row.Scan(&a.ID, &a.Name, &a.AccessToken, &a.RefreshToken, &a.Provider, &a.UserID, &a.UserName, &a.DeviceID, &a.Points, &a.Active, &a.CreatedAt, &a.LastUsedAt); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &a, nil
}

// UpdateAccount memperbarui data akun.
func UpdateAccount(a *Account) error {
	_, err := DB.Exec(`UPDATE accounts SET name=?, access_token=?, refresh_token=?, provider=?, user_id=?, user_name=?, device_id=?, points=?, active=?, last_used_at=? WHERE id=?`,
		a.Name, a.AccessToken, a.RefreshToken, a.Provider, a.UserID, a.UserName, a.DeviceID, a.Points, a.Active, a.LastUsedAt, a.ID)
	return err
}

// DeleteAccount menghapus akun.
func DeleteAccount(id int64) error {
	_, err := DB.Exec(`DELETE FROM accounts WHERE id = ?`, id)
	return err
}

// UpdatePoints menambah poin akun.
func UpdatePoints(id int64, points int) error {
	_, err := DB.Exec(`UPDATE accounts SET points = ? WHERE id = ?`, points, id)
	return err
}

// TouchAccount: tandai akun baru saja dipakai (untuk strategi least-used).
func TouchAccount(id int64) {
	_, _ = DB.Exec(`UPDATE accounts SET last_used_at = ? WHERE id = ?`, time.Now().UTC().Format(time.RFC3339), id)
}

// --- Proxy Pool ---

type Proxy struct {
	ID         int64  `json:"id"`
	Name       string `json:"name"`
	URL        string `json:"url"`
	Active     bool   `json:"active"`
	LastTested string `json:"last_tested"`
	LastStatus string `json:"last_status"`
	CreatedAt  string `json:"created_at"`
}

func AddProxy(name, url string) (int64, error) {
	res, err := DB.Exec(`INSERT INTO proxies (name, url) VALUES (?, ?)`, name, url)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func ListProxies() ([]Proxy, error) {
	rows, err := DB.Query(`SELECT id, name, url, active, last_tested, last_status, created_at FROM proxies ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Proxy
	for rows.Next() {
		var p Proxy
		var active int
		if err := rows.Scan(&p.ID, &p.Name, &p.URL, &active, &p.LastTested, &p.LastStatus, &p.CreatedAt); err != nil {
			return nil, err
		}
		p.Active = active == 1
		out = append(out, p)
	}
	return out, rows.Err()
}

func GetProxy(id int64) (*Proxy, error) {
	var p Proxy
	var active int
	err := DB.QueryRow(`SELECT id, name, url, active, last_tested, last_status, created_at FROM proxies WHERE id = ?`, id).
		Scan(&p.ID, &p.Name, &p.URL, &active, &p.LastTested, &p.LastStatus, &p.CreatedAt)
	if err != nil {
		return nil, err
	}
	p.Active = active == 1
	return &p, nil
}

func SetProxyActive(id int64, active bool) error {
	_, err := DB.Exec(`UPDATE proxies SET active = ? WHERE id = ?`, active, id)
	return err
}

func DeleteProxy(id int64) error {
	_, err := DB.Exec(`DELETE FROM proxies WHERE id = ?`, id)
	if err != nil {
		return err
	}
	_, _ = DB.Exec(`UPDATE accounts SET proxy_id = 0 WHERE proxy_id = ?`, id)
	return nil
}

// UpdateProxyTest simpan hasil tes koneksi terakhir.
func UpdateProxyTest(id int64, status string) error {
	_, err := DB.Exec(`UPDATE proxies SET last_tested = datetime('now'), last_status = ? WHERE id = ?`, status, id)
	return err
}

// SetAccountProxy: 0 = tanpa proxy (langsung).
func SetAccountProxy(accID, proxyID int64) error {
	_, err := DB.Exec(`UPDATE accounts SET proxy_id = ? WHERE id = ?`, proxyID, accID)
	return err
}

// AccountProxyURL: URL proxy aktif untuk akun ("" = langsung).
func AccountProxyURL(accID int64) string {
	var pid int64
	if err := DB.QueryRow(`SELECT proxy_id FROM accounts WHERE id = ?`, accID).Scan(&pid); err != nil || pid == 0 {
		return ""
	}
	var url string
	var active int
	if err := DB.QueryRow(`SELECT url, active FROM proxies WHERE id = ?`, pid).Scan(&url, &active); err != nil || active != 1 {
		return ""
	}
	return url
}

// AccountProxyName: nama proxy yang terpasang (untuk UI).
func AccountProxyName(accID int64) (int64, string) {
	var pid int64
	if err := DB.QueryRow(`SELECT proxy_id FROM accounts WHERE id = ?`, accID).Scan(&pid); err != nil || pid == 0 {
		return 0, ""
	}
	var name string
	if err := DB.QueryRow(`SELECT name FROM proxies WHERE id = ?`, pid).Scan(&name); err != nil {
		return pid, ""
	}
	return pid, name
}

// --- Checkin Log ---

// AddCheckinLog mencatat hasil check-in.
func AddCheckinLog(accountID int64, date, taskID string, points int, status, deviceID string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := DB.Exec(`INSERT INTO checkin_log (account_id, date, task_id, points, status, device_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		accountID, date, taskID, points, status, deviceID, now)
	return err
}

// GetCheckinLog mengembalikan log check-in untuk akun pada tanggal tertentu.
func GetCheckinLog(accountID int64, date, taskID string) (*CheckinLog, error) {
	row := DB.QueryRow(`SELECT id, account_id, date, task_id, points, status, device_id, created_at FROM checkin_log WHERE account_id = ? AND date = ? AND task_id = ?`, accountID, date, taskID)
	var l CheckinLog
	if err := row.Scan(&l.ID, &l.AccountID, &l.Date, &l.TaskID, &l.Points, &l.Status, &l.DeviceID, &l.CreatedAt); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &l, nil
}

// ListCheckinLog mengembalikan semua log check-in untuk akun.
func ListCheckinLog(accountID int64, limit int) ([]CheckinLog, error) {
	rows, err := DB.Query(`SELECT id, account_id, date, task_id, points, status, device_id, created_at FROM checkin_log WHERE account_id = ? ORDER BY created_at DESC LIMIT ?`, accountID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []CheckinLog
	for rows.Next() {
		var l CheckinLog
		if err := rows.Scan(&l.ID, &l.AccountID, &l.Date, &l.TaskID, &l.Points, &l.Status, &l.DeviceID, &l.CreatedAt); err != nil {
			return nil, err
		}
		logs = append(logs, l)
	}
	return logs, nil
}

// --- Config ---

// GetConfig mengambil nilai konfigurasi.
func GetConfig(key string) (string, error) {
	row := DB.QueryRow(`SELECT value FROM config WHERE key = ?`, key)
	var val string
	if err := row.Scan(&val); err != nil {
		if err == sql.ErrNoRows {
			return "", nil
		}
		return "", err
	}
	return val, nil
}

// GetConfigDefault: GetConfig dengan fallback kalau kosong/error.
func GetConfigDefault(key, def string) string {
	v, err := GetConfig(key)
	if err != nil || v == "" {
		return def
	}
	return v
}

// SetConfig menyimpan nilai konfigurasi.
func SetConfig(key, value string) error {
	_, err := DB.Exec(`INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)`, key, value)
	return err
}

// ── Logs ────────────────────────────────────────────────────────────

type LogEntry struct {
	ID               int64   `json:"id"`
	AccountID        int64   `json:"account_id"`
	Model            string  `json:"model"`
	PromptTokens     int     `json:"prompt_tokens"`
	CompletionTokens int     `json:"completion_tokens"`
	TotalTokens      int     `json:"total_tokens"`
	Cost             float64 `json:"cost"`
	Status           string  `json:"status"`
	Error            string  `json:"error"`
	DurationMs       int64   `json:"duration_ms"`
	CreatedAt        string  `json:"created_at"`
}

func AddLog(l *LogEntry) (int64, error) {
	res, err := DB.Exec(`INSERT INTO logs (account_id, model, prompt_tokens, completion_tokens, total_tokens, cost, status, error, duration_ms, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`,
		l.AccountID, l.Model, l.PromptTokens, l.CompletionTokens, l.TotalTokens, l.Cost, l.Status, l.Error, l.DurationMs)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func ListLogs(limit int) ([]LogEntry, error) {
	if limit < 1 {
		limit = 50
	}
	rows, err := DB.Query(`SELECT id, account_id, model, prompt_tokens, completion_tokens, total_tokens, cost, status, error, duration_ms, created_at FROM logs ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var logs []LogEntry
	for rows.Next() {
		var l LogEntry
		if err := rows.Scan(&l.ID, &l.AccountID, &l.Model, &l.PromptTokens, &l.CompletionTokens, &l.TotalTokens, &l.Cost, &l.Status, &l.Error, &l.DurationMs, &l.CreatedAt); err != nil {
			return nil, err
		}
		logs = append(logs, l)
	}
	return logs, rows.Err()
}

// PruneLogs: hapus log lebih lama dari keepDays. Return jumlah baris terhapus.
func PruneLogs(keepDays int) int64 {
	if keepDays < 1 {
		keepDays = 30
	}
	res, err := DB.Exec(`DELETE FROM logs WHERE created_at < datetime('now', ?)`, fmt.Sprintf("-%d days", keepDays))
	if err != nil {
		return 0
	}
	n, _ := res.RowsAffected()
	return n
}

func LogStats() (totalReq int, totalTokens int, totalCost float64, err error) {
	err = DB.QueryRow(`SELECT COUNT(*), COALESCE(SUM(total_tokens),0), COALESCE(SUM(cost),0) FROM logs WHERE created_at >= datetime('now', 'start of day')`).Scan(&totalReq, &totalTokens, &totalCost)
	return
}

// LogStatsAllTotal: total token kumulatif sepanjang masa (untuk live counter).
func LogStatsAllTotal() (totalReq int, totalTokens int, err error) {
	err = DB.QueryRow(`SELECT COUNT(*), COALESCE(SUM(total_tokens),0) FROM logs`).Scan(&totalReq, &totalTokens)
	return
}

// LogTokensLastMinute: token dalam 60 detik terakhir (untuk tokens/min live).
func LogTokensLastMinute() int {
	var n int
	_ = DB.QueryRow(`SELECT COALESCE(SUM(total_tokens),0) FROM logs WHERE created_at >= datetime('now', '-60 seconds')`).Scan(&n)
	return n
}

// LogAvgLatencyMs: rata-rata durasi request sukses 24 jam terakhir.
func LogAvgLatencyMs() int64 {
	var n int64
	_ = DB.QueryRow(`SELECT COALESCE(AVG(duration_ms),0) FROM logs WHERE status='success' AND duration_ms > 0 AND created_at >= datetime('now', '-1 day')`).Scan(&n)
	return n
}

type ModelStat struct {
	Model        string `json:"model"`
	Total        int    `json:"total"`
	Success      int    `json:"success"`
	Failed       int    `json:"failed"`
	TotalTokens  int    `json:"total_tokens"`
	SuccessRate  float64 `json:"success_rate"`
}

func ModelStats() ([]ModelStat, error) {
	rows, err := DB.Query(`SELECT model, COUNT(*) AS total,
		SUM(CASE WHEN status='success' THEN 1 ELSE 0 END) AS success,
		SUM(CASE WHEN status='success' THEN 0 ELSE 1 END) AS failed,
		COALESCE(SUM(total_tokens),0) AS tokens
		FROM logs WHERE model != '' GROUP BY model ORDER BY total DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var stats []ModelStat
	for rows.Next() {
		var m ModelStat
		if err := rows.Scan(&m.Model, &m.Total, &m.Success, &m.Failed, &m.TotalTokens); err != nil {
			return nil, err
		}
		if m.Total > 0 {
			m.SuccessRate = float64(m.Success) / float64(m.Total) * 100
		}
		stats = append(stats, m)
	}
	return stats, rows.Err()
}