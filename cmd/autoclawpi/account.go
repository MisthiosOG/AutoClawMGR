package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/MisthiosOG/autoclawpi/internal/db"
)

func cmdAccount(args []string) error {
	if len(args) == 0 {
		return listAccounts()
	}
	switch args[0] {
	case "list", "ls":
		return listAccounts()
	case "add":
		return addAccount(args[1:])
	case "remove", "rm", "delete":
		return removeAccount(args[1:])
	case "show":
		return showAccount(args[1:])
	default:
		return fmt.Errorf("subcommand: list | add | remove | show")
	}
}

func listAccounts() error {
	accounts, err := db.ListAccounts()
	if err != nil {
		return err
	}
	if len(accounts) == 0 {
		fmt.Println("tidak ada akun. jalankan 'autoclawpi login' atau 'autoclawpi import'")
		return nil
	}
	fmt.Printf("%-4s %-20s %-8s %-12s %-8s %s\n", "ID", "Name", "Provider", "User", "Points", "Last Used")
	for _, a := range accounts {
		active := "✓"
		if !a.Active {
			active = "✗"
		}
		fmt.Printf("%-4d %-20s %-8s %-12s %-8d %s %s\n", a.ID, truncate(a.Name, 18), a.Provider, truncate(a.UserName, 10), a.Points, active, truncate(a.LastUsedAt, 16))
	}
	return nil
}

func addAccount(args []string) error {
	fs := flag.NewFlagSet("add", flag.ExitOnError)
	name := fs.String("name", "", "nama akun")
	access := fs.String("access", "", "access token")
	refresh := fs.String("refresh", "", "refresh token (opsional)")
	provider := fs.String("provider", "zai", "zai | google")
	fs.Parse(args)

	if *access == "" {
		fmt.Fprintf(os.Stderr, "usage: autoclawpi account add --access <token> [--refresh <token>] [--name <name>] [--provider zai|google]\n")
		os.Exit(2)
	}
	deviceID := fmt.Sprintf("autoclawpi-%d", time.Now().UnixNano())
	id, err := db.AddAccount(*name, *access, *refresh, *provider, "", "", deviceID)
	if err != nil {
		return err
	}
	fmt.Printf("akun #%d ditambahkan\n", id)
	return nil
}

func removeAccount(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: autoclawpi account remove <id>")
	}
	var id int64
	if _, err := fmt.Sscanf(args[0], "%d", &id); err != nil {
		return fmt.Errorf("id harus angka")
	}
	if err := db.DeleteAccount(id); err != nil {
		return err
	}
	fmt.Printf("akun #%d dihapus\n", id)
	return nil
}

func showAccount(args []string) error {
	var id int64
	if len(args) > 0 {
		fmt.Sscanf(args[0], "%d", &id)
	}
	var a *db.Account
	var err error
	if id > 0 {
		a, err = db.GetAccount(id)
	} else {
		a, err = db.GetActiveAccount()
	}
	if err != nil {
		return err
	}
	if a == nil {
		return fmt.Errorf("akun tidak ditemukan")
	}

	// fetch saldo real-time dari server
	balance, _ := fetchBalance(a.AccessToken)
	if balance > 0 {
		db.UpdatePoints(a.ID, balance) // update total
		a.Points = balance             // refresh local struct
	}

	fmt.Printf("ID        : %d\n", a.ID)
	fmt.Printf("Name      : %s\n", a.Name)
	fmt.Printf("Provider  : %s\n", a.Provider)
	fmt.Printf("UserID    : %s\n", a.UserID)
	fmt.Printf("UserName  : %s\n", a.UserName)
	fmt.Printf("DeviceID  : %s\n", a.DeviceID)
	fmt.Printf("Points    : %d pts (server: %d)\n", a.Points, balance)
	fmt.Printf("Active    : %v\n", a.Active)
	fmt.Printf("Created   : %s\n", a.CreatedAt)
	fmt.Printf("LastUsed  : %s\n", a.LastUsedAt)
	fmt.Printf("Access    : %s... (len=%d)\n", redactToken(a.AccessToken), len(a.AccessToken))
	fmt.Printf("Refresh   : %s... (len=%d)\n", redactToken(a.RefreshToken), len(a.RefreshToken))
	return nil
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func redactToken(s string) string {
	if s == "" {
		return "(kosong)"
	}
	if len(s) > 20 {
		return s[:20]
	}
	return s
}