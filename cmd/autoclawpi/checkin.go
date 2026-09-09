package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/MisthiosOG/autoclawpi/internal/db"
	"github.com/MisthiosOG/autoclawpi/internal/sign"
)

// task yang bisa di-check-in
var checkinTasks = []struct {
	ID     string
	Points int
}{
	{"daily_signin", 400},
	{"daily_inspiration_center", 200},
	{"newbie_cloud_lobster", 500},
	{"newbie_local_lobster", 500},
}

func cmdCheckin(args []string) error {
	fs := flag.NewFlagSet("checkin", flag.ExitOnError)
	accountID := fs.Int64("account", 0, "ID akun (0 = semua akun)")
	dryRun := fs.Bool("dry-run", false, "cek tanpa klaim")
	fs.Parse(args)

	accounts, err := db.ListAccounts()
	if err != nil {
		return err
	}
	if len(accounts) == 0 {
		return fmt.Errorf("tidak ada akun, login dulu")
	}

	today := time.Now().UTC().Format("2006-01-02")
	anyClaimed := false

	for _, a := range accounts {
		if !a.Active {
			continue
		}
		if *accountID > 0 && a.ID != *accountID {
			continue
		}

		fmt.Printf("\n=== Akun #%d (%s) ===\n", a.ID, a.Name)
		if a.AccessToken == "" {
			fmt.Println("  SKIP: token kosong")
			continue
		}

		// fetch saldo sebelum check-in
		balance, _ := fetchBalance(a.AccessToken)
		fmt.Printf("  Saldo: %d pts\n", balance)

		for _, task := range checkinTasks {
			// cek apakah udah check-in hari ini
			existing, _ := db.GetCheckinLog(a.ID, today, task.ID)
			if existing != nil {
				fmt.Printf("  %s: sudah (%d pts)\n", task.ID, existing.Points)
				continue
			}

			if *dryRun {
				fmt.Printf("  %s: akan klaim %d pts\n", task.ID, task.Points)
				continue
			}

			// klaim
			points, err := claimTask(a, task.ID)
			if err != nil {
				fmt.Printf("  %s: GAGAL — %v\n", task.ID, err)
				db.AddCheckinLog(a.ID, today, task.ID, 0, "failed:"+err.Error(), a.DeviceID)
				continue
			}

			fmt.Printf("  %s: ✅ %d pts\n", task.ID, points)
			db.AddCheckinLog(a.ID, today, task.ID, points, "success", a.DeviceID)
			anyClaimed = true
		}

		// fetch saldo setelah check-in (update)
		if !*dryRun {
			newBalance, _ := fetchBalance(a.AccessToken)
			if newBalance > balance {
				db.UpdatePoints(a.ID, newBalance)
			}
			fmt.Printf("  Saldo akhir: %d pts\n", newBalance)
		}
	}

	if !anyClaimed && !*dryRun {
		fmt.Println("\nsemua task udah di-claim hari ini")
	}
	return nil
}

// fetchBalance mengambil saldo dari server.
func fetchBalance(token string) (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	hdrs := commonHeaders(token)
	req, _ := http.NewRequestWithContext(ctx, "GET",
		"https://autoglm-api.autoglm.ai/agent-assetmgr/api/v1/wallet-instances?biz_app_id=autoclaw", nil)
	for k, v := range hdrs {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var r struct {
		Data *struct {
			TotalBalance int `json:"total_balance"`
		} `json:"data"`
	}
	json.Unmarshal(b, &r)
	if r.Data != nil {
		return r.Data.TotalBalance, nil
	}
	return 0, nil
}

// claimTask mengirim POST task-complete dan mengembalikan points.
func claimTask(a db.Account, taskID string) (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	hdrs := commonHeaders(a.AccessToken)
	body := fmt.Sprintf(`{"task_id":"%s"}`, taskID)

	req, err := http.NewRequestWithContext(ctx, "POST",
		"https://autoglm-api.autoglm.ai/autoclaw-proxy/proxy/autoclaw-task-complete",
		strings.NewReader(body))
	if err != nil {
		return 0, err
	}
	for k, v := range hdrs {
		req.Header.Set(k, v)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	var result struct {
		Data *struct {
			Success         bool   `json:"success"`
			AlreadyComplete bool   `json:"already_completed"`
			RewardPoints    int    `json:"reward_points"`
			TaskID          string `json:"task_id"`
		} `json:"data"`
	}
	json.Unmarshal(b, &result)

	if result.Data == nil {
		return 0, fmt.Errorf("response: %s", string(b))
	}
	if result.Data.AlreadyComplete {
		return 0, nil // udah check-in, catat aja
	}
	if !result.Data.Success {
		return 0, fmt.Errorf("server: success=false")
	}
	return result.Data.RewardPoints, nil
}

// commonHeaders membangun header yang sama kayak app asli (commonHeaders).
func commonHeaders(token string) map[string]string {
	ts := time.Now().Unix()
	h := sign.HeadersAt(ts)
	h["X-Lang"] = "en"
	h["X-Client-Type"] = "pc"
	h["authorization"] = token // lowercase!
	delete(h, "Accept")        // gak di commonHeaders
	return h
}