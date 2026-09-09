//go:build windows

package web

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"github.com/MisthiosOG/autoclawpi/internal/db"
	"golang.org/x/sys/windows"
)

// ─────────────────────────────────────────────────────────────
// Import dari app AutoClaw (auth.json terenkripsi safeStorage).
// Skema: enc:v10 (Chromium OSCrypt) = AES-256-GCM,
// master key disimpan di Local State -> os_crypt.encrypted_key (DPAPI).
// ─────────────────────────────────────────────────────────────

var (
	crypt32DLL     = windows.NewLazySystemDLL("crypt32.dll")
	cryptUnprotect = crypt32DLL.NewProc("CryptUnprotectData")
	kernel32DLL    = windows.NewLazySystemDLL("kernel32.dll")
	localFree      = kernel32DLL.NewProc("LocalFree")
)

type dataBlob struct {
	cbData uint32
	pbData *byte
}

// dpapiDecrypt mendekripsi blob DPAPI (CryptUnprotectData).
func dpapiDecrypt(blob []byte) ([]byte, error) {
	var in dataBlob
	in.cbData = uint32(len(blob))
	if len(blob) > 0 {
		in.pbData = &blob[0]
	}
	var out dataBlob
	r, _, err := cryptUnprotect.Call(
		uintptr(unsafe.Pointer(&in)),
		0,
		0,
		0,
		0,
		0,
		uintptr(unsafe.Pointer(&out)),
	)
	if r == 0 {
		return nil, fmt.Errorf("CryptUnprotectData failed: %v", err)
	}
	defer localFree.Call(uintptr(unsafe.Pointer(out.pbData)))
	res := make([]byte, out.cbData)
	if out.cbData > 0 {
		copy(res, unsafe.Slice(out.pbData, out.cbData))
	}
	return res, nil
}

// decryptTokenV10 mendekripsi token format enc:v10 (AES-256-GCM).
func decryptTokenV10(enc string, aesKey []byte) (string, error) {
	body, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(enc, "enc:"))
	if err != nil {
		return "", fmt.Errorf("base64 decode: %w", err)
	}
	if len(body) < 3 || string(body[:3]) != "v10" {
		return "", fmt.Errorf("bukan format v10")
	}
	payload := body[3:]
	if len(payload) < 12+16 {
		return "", fmt.Errorf("payload terlalu pendek")
	}
	nonce := payload[:12]
	ct := payload[12 : len(payload)-16]
	tag := payload[len(payload)-16:]

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	ciphertext := append(append([]byte{}, ct...), tag...)
	pt, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("gcm open: %w", err)
	}
	return string(pt), nil
}

// loadAppAuth membaca auth.json + Local State dari AutoClaw, lalu decrypt token.
func loadAppAuth() (accessToken, refreshToken, email string, err error) {
	home, _ := os.UserHomeDir()
	acDir := filepath.Join(home, "AppData", "Roaming", "autoclaw")

	authPath := filepath.Join(acDir, "auth.json")
	raw, err := os.ReadFile(authPath)
	if err != nil {
		return "", "", "", fmt.Errorf("auth.json tidak ditemukan (pastikan AutoClaw sudah login): %w", err)
	}
	var auth struct {
		Token        string `json:"token"`
		RefreshToken string `json:"refreshToken"`
		UserInfo     struct {
			Email string `json:"email"`
			Name  string `json:"user_name"`
		} `json:"userInfo"`
	}
	if err := json.Unmarshal(raw, &auth); err != nil {
		return "", "", "", fmt.Errorf("parse auth.json: %w", err)
	}

	lsRaw, err := os.ReadFile(filepath.Join(acDir, "Local State"))
	if err != nil {
		return "", "", "", fmt.Errorf("Local State tidak ditemukan: %w", err)
	}
	var ls struct {
		OSCrypt struct {
			EncryptedKey string `json:"encrypted_key"`
		} `json:"os_crypt"`
	}
	if err := json.Unmarshal(lsRaw, &ls); err != nil {
		return "", "", "", fmt.Errorf("parse Local State: %w", err)
	}
	encKey, err := base64.StdEncoding.DecodeString(ls.OSCrypt.EncryptedKey)
	if err != nil {
		return "", "", "", fmt.Errorf("decode encrypted_key: %w", err)
	}
	if len(encKey) < 5 || string(encKey[:5]) != "DPAPI" {
		return "", "", "", fmt.Errorf("encrypted_key bukan format DPAPI")
	}
	aesKey, err := dpapiDecrypt(encKey[5:])
	if err != nil {
		return "", "", "", fmt.Errorf("DPAPI decrypt: %w", err)
	}

	accessToken, err = decryptTokenV10(auth.Token, aesKey)
	if err != nil {
		return "", "", "", fmt.Errorf("decrypt access token: %w", err)
	}
	refreshToken, err = decryptTokenV10(auth.RefreshToken, aesKey)
	if err != nil {
		return "", "", "", fmt.Errorf("decrypt refresh token: %w", err)
	}
	email = auth.UserInfo.Email
	if email == "" {
		email = auth.UserInfo.Name
	}
	if email == "" {
		email = "autoclaw-import"
	}
	return accessToken, refreshToken, email, nil
}

// handleImportFromApp mengimpor akun dari app AutoClaw yang sedang login.
func (s *Server) handleImportFromApp(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/accounts", http.StatusSeeOther)
		return
	}
	accessToken, refreshToken, email, err := loadAppAuth()
	if err != nil {
		s.renderTemplate(w, "import.html", "accounts", map[string]any{
			"Error": "Import dari app gagal: " + err.Error(),
			"Name":  "",
		})
		return
	}

	accounts, _ := db.ListAccounts()
	for _, a := range accounts {
		if a.Name == email {
			s.renderTemplate(w, "import.html", "accounts", map[string]any{
				"Error": "Akun " + email + " sudah terdaftar.",
			})
			return
		}
	}

	deviceID := "app-import-" + fmt.Sprintf("%x", time.Now().UnixNano())
	if _, err := db.AddAccount(email, accessToken, refreshToken, "zai", "", "", deviceID); err != nil {
		s.renderTemplate(w, "import.html", "accounts", map[string]any{
			"Error": "Simpan gagal: " + err.Error(),
		})
		return
	}
	log.Printf("[autoclawpi] imported account from app: %s", email)
	http.Redirect(w, r, "/accounts", http.StatusSeeOther)
}
