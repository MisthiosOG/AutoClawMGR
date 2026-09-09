// Command autoclawpi adalah CLI untuk mengelola kredensial AutoClaw
// dan menyajikan API OpenAI-compatible lokal.
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/MisthiosOG/autoclawpi/internal/client"
	"github.com/MisthiosOG/autoclawpi/internal/config"
	"github.com/MisthiosOG/autoclawpi/internal/db"
	"github.com/MisthiosOG/autoclawpi/internal/server"
	"github.com/MisthiosOG/autoclawpi/internal/store"
	"github.com/MisthiosOG/autoclawpi/internal/web"
)

var version = "dev"

const usage = `autoclawpi — OpenAI-compatible proxy untuk AutoClaw (Z.ai)

Pemakaian:
  autoclawpi serve                 jalankan server OpenAI-compatible (default :8787)
  autoclawpi import                import token manual (stdin: access [refresh])
  autoclawpi refresh               perbarui access token via refresh token
  autoclawpi status                tampilkan status login (token disensor)
  autoclawpi logout                hapus kredensial tersimpan
  autoclawpi version               tampilkan versi
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	// Init DB
	cfgDir := os.Getenv("AUTOCLAWPI_DIR")
	if cfgDir == "" {
		home, _ := os.UserHomeDir()
		cfgDir = home + "/.autoclawpi"
	}
	if err := db.Init(cfgDir); err != nil {
		fmt.Fprintln(os.Stderr, "db error:", err)
		os.Exit(1)
	}
	defer db.Close()

	var err error
	switch os.Args[1] {
	case "serve":
		err = cmdServe(os.Args[2:])
	case "import":
		err = cmdImport(os.Args[2:])
	case "refresh":
		err = cmdRefresh(os.Args[2:])
	case "status":
		err = cmdStatus()
	case "logout":
		err = store.Clear()
		fmt.Println("kredensial dihapus")
	case "account", "accounts":
		err = cmdAccount(os.Args[2:])
	case "checkin":
		err = cmdCheckin(os.Args[2:])
	case "version", "--version", "-v":
		fmt.Println("autoclawpi", version)
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func loadAll() (*config.Config, *client.Client) {
	cfg, err := config.Load()
	if err != nil {
		fatal(err)
	}
	return cfg, client.New(cfg.InferenceBase, cfg.UserAPIBase)
}

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	port := fs.Int("port", 0, "port listen (override config)")
	host := fs.String("host", "", "host listen (override config)")
	apiKey := fs.String("api-key", "", "API key utk melindungi server ini")
	webPwd := fs.String("web-password", "", "password web panel (opsional)")
	fs.Parse(args)

	cfg, cl := loadAll()
	if *port != 0 {
		cfg.Port = *port
	}
	if *host != "" {
		cfg.Host = *host
	}
	if *apiKey != "" {
		cfg.APIKey = *apiKey
	}

	// Main handler: OpenAI API
	apiSrv := server.New(cl).WithAPIKey(cfg.APIKey).WithWebPassword(*webPwd)
	if cfg.RateLimitPerSec > 0 || cfg.RateLimitBurst > 0 {
		apiSrv.WithRateLimit(cfg.RateLimitPerSec, cfg.RateLimitBurst)
	}
	apiHandler := apiSrv.Handler()

	// Web panel handler
	var webOpts []web.Option
	if *webPwd != "" {
		webOpts = append(webOpts, web.WithPassword(*webPwd))
	}
	if cfg.APIKey != "" {
		webOpts = append(webOpts, web.WithAPIKey(cfg.APIKey))
	}
	webHandler := web.New(cl, webOpts...)

	// Password panel dinamis: ganti password dari Settings langsung ngefek
	// ke auth cookie API (Playground), tanpa restart.
	apiSrv.WithWebPasswordFunc(webHandler.CurrentPassword)
	apiSrv.WithWebSessionFunc(webHandler.CurrentSessionToken)

	// Merge: web panel di path /, API di /v1/ dan /healthz
	mux := http.NewServeMux()
	mux.Handle("/v1/", apiHandler)
	mux.Handle("/healthz", apiHandler)
	mux.Handle("/", webHandler.Handler())

	addr := net.JoinHostPort(cfg.Host, fmt.Sprintf("%d", cfg.Port))
	httpSrv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 15 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Auto-prune log: hapus log > 30 hari, tiap 1 jam.
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if n := db.PruneLogs(30); n > 0 {
					fmt.Printf("[autoclawpi] prune %d log lama (>30 hari)\n", n)
				}
			}
		}
	}()

	// Auto check-in harian jam 08:00 lokal (idempoten — task yang sudah
	// di-claim hari ini otomatis dilewati).
	go func() {
		for {
			now := time.Now()
			next := time.Date(now.Year(), now.Month(), now.Day(), 8, 0, 0, 0, now.Location())
			if now.After(next) {
				next = next.Add(24 * time.Hour)
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(next.Sub(now)):
				fmt.Printf("[autoclawpi] auto check-in %s mulai...\n", next.Format("2006-01-02"))
				_ = cmdCheckin([]string{})
			}
		}
	}()

	go func() {
		<-ctx.Done()
		shCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shCtx)
	}()

	fmt.Printf("autoclawpi listen di http://%s\n", addr)
	fmt.Printf("  API:  /v1/chat/completions, /v1/models\n")
	fmt.Printf("  Panel: /, /accounts, /checkin, /settings\n")
	if *webPwd != "" {
		fmt.Println("  Panel login: /login (password required)")
	}
	if cfg.APIKey != "" {
		fmt.Println("  API auth: Authorization: Bearer <api-key>")
	}

	if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

func cmdImport(args []string) error {
	fs := flag.NewFlagSet("import", flag.ExitOnError)
	access := fs.String("access", "", "access token")
	refresh := fs.String("refresh", "", "refresh token (opsional)")
	provider := fs.String("provider", "zai", "zai | google")
	fs.Parse(args)

	a, r := *access, *refresh
	if a == "" {
		// baca dari stdin: baris1 access, baris2 refresh (opsional)
		rd := bufio.NewReader(os.Stdin)
		fmt.Print("access token: ")
		line, _ := rd.ReadString('\n')
		a = strings.TrimSpace(line)
		if a == "" {
			return fmt.Errorf("access token kosong")
		}
		fmt.Print("refresh token (opsional, enter utk lewati): ")
		line, _ = rd.ReadString('\n')
		r = strings.TrimSpace(line)
	}
	c := &store.Creds{
		AccessToken:  a,
		RefreshToken: r,
		Provider:     *provider,
		SavedAt:      time.Now().Format(time.RFC3339),
	}
	if err := store.Save(c); err != nil {
		return err
	}
	fmt.Println("kredensial tersimpan.")
	return cmdStatus()
}

func cmdRefresh(args []string) error {
	_, cl := loadAll()
	c, err := store.Load()
	if err != nil {
		return err
	}
	if c.RefreshToken == "" {
		return fmt.Errorf("tidak ada refresh token tersimpan")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := cl.Refresh(ctx, c.RefreshToken)
	if err != nil {
		return err
	}
	if out.Code != 0 || out.Data == nil || out.Data.AccessToken == "" {
		return fmt.Errorf("refresh gagal code=%d msg=%s", out.Code, out.Msg)
	}
	c.AccessToken = out.Data.AccessToken
	if out.Data.RefreshToken != "" {
		c.RefreshToken = out.Data.RefreshToken
	}
	c.SavedAt = time.Now().Format(time.RFC3339)
	if err := store.Save(c); err != nil {
		return err
	}
	fmt.Println("token diperbarui.")
	return cmdStatus()
}

func cmdStatus() error {
	c, err := store.Load()
	if err != nil {
		return err
	}
	// if --raw flag, print raw token
	if len(os.Args) > 2 && os.Args[2] == "--raw" {
		fmt.Println(c.AccessToken)
		return nil
	}
	fmt.Println("status   : login")
	fmt.Println("provider :", c.Provider)
	fmt.Println("user     :", c.UserName, c.UserID)
	fmt.Println("access   :", redact(c.AccessToken))
	fmt.Println("refresh  :", redact(c.RefreshToken))
	fmt.Println("disimpan :", c.SavedAt)
	return nil
}

// redact menampilkan hanya karakter awal.
func redact(s string) string {
	if s == "" {
		return "(kosong)"
	}
	prefix := s
	if len(prefix) > 12 {
		prefix = prefix[:12]
	}
	return fmt.Sprintf("%s... (len=%d)", prefix, len(s))
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}
