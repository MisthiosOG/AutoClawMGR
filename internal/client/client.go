// Package client menyediakan HTTP client untuk API AutoClaw.
package client

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/MisthiosOG/autoclawpi/internal/sign"
)

// Client adalah HTTP client ke API AutoClaw.
type Client struct {
	HTTP          *http.Client
	InferenceBase string // https://autoglm-api.autoglm.ai/autoclaw-proxy/proxy/autoclaw
	UserAPIBase   string // https://autoglm-api.autoglm.ai
	Version       string
}

// New membuat client dengan default yang masuk akal.
func New(inferenceBase, userAPIBase string) *Client {
	c := &Client{
		HTTP:          &http.Client{Timeout: 0},
		InferenceBase: inferenceBase,
		UserAPIBase:   userAPIBase,
		Version:       "1.17.8",
	}
	c.applyChromeTLS() // TLS fingerprint meniru Chrome — WAF gak bedain dengan app Electron
	return c
}

// deviceID mengembalikan ID perangkat persisten.
var deviceIDCache string

// deviceID acak per proses — JANGAN hostname-based: AutoClaw nge-flag
// device (hostname), akun baru dari device yang sama langsung ikut kena ban.
// ponytail: random 16 hex per proses; kalau mau persisten per-install,
// simpan ke config (upgrade path).
func deviceID() string {
	if deviceIDCache != "" {
		return deviceIDCache
	}
	b := make([]byte, 8)
	rand.Read(b)
	deviceIDCache = hex.EncodeToString(b)
	return deviceIDCache
}

// Do melakukan request dengan User-Agent aplikasi.
func (c *Client) Do(req *http.Request) (*http.Response, error) {
	req.Header.Set("User-Agent", "AutoClaw/"+c.Version)
	return c.HTTP.Do(req)
}

// LoginResponse adalah payload balikan oauth login.
type LoginResponse struct {
	Code  int    `json:"code"`
	Msg   string `json:"msg"`
	Trace string `json:"trace,omitempty"`
	Data  *struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		UserID       any    `json:"user_id,omitempty"`
		UserName     string `json:"user_name,omitempty"`
	} `json:"data,omitempty"`
}

// OAuthURL meminta URL OAuth. Return: url, state, error.
func (c *Client) OAuthURL(ctx context.Context, vendor, navigateURI, sourceID string, captcha map[string]any) (string, string, error) {
	ts := time.Now().Unix()
	body := map[string]any{
		"source_id":    sourceID,
		"navigate_uri": navigateURI,
		"device_id":    deviceID(),
	}
	if captcha != nil {
		for k, v := range captcha {
			body[k] = v
		}
	}
	if vendor == "google" {
		body["client_type"] = "pc"
	}
	var out struct {
		Code  int             `json:"code"`
		Msg   string          `json:"msg"`
		Trace string          `json:"trace"`
		Data  json.RawMessage `json:"data"`
	}
	if err := c.userapiPostWithHeaders(ctx, "/userapi/overseasv1/"+vendor+"-oauth-url", body, &out, sign.HeadersAt(ts)); err != nil {
		return "", "", err
	}
	if out.Code != 0 || out.Data == nil {
		return "", "", fmt.Errorf("oauth-url code=%d msg=%s trace=%s data=%s", out.Code, out.Msg, out.Trace, string(out.Data))
	}
	var urlData struct {
		OAuthURL string `json:"oauth_url"`
		State    string `json:"state"`
	}
	if err := json.Unmarshal(out.Data, &urlData); err != nil || urlData.OAuthURL == "" {
		return "", "", fmt.Errorf("oauth-url code=%d msg=%s trace=%s data=%s (url parse: %v)", out.Code, out.Msg, out.Trace, string(out.Data), err)
	}
	return urlData.OAuthURL, urlData.State, nil
}

// CaptchaConfig mengambil konfigurasi captcha OAuth.
func (c *Client) CaptchaConfig(ctx context.Context) (*CaptchaConfigResponse, error) {
	var out CaptchaConfigResponse
	if err := c.userapiPost(ctx, "/userapi/overseasv1/oauth-captcha-config", map[string]any{}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// CaptchaConfigResponse adalah balikan oauth-captcha-config.
type CaptchaConfigResponse struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
	Data *struct {
		Enabled   bool   `json:"enabled"`
		Region    string `json:"region"`
		Prefix    string `json:"prefix"`
		SceneID   string `json:"scene_id"`
		Supplier  string `json:"captcha_supplier"`
	} `json:"data"`
}

// OAuthURLVerbose meminta URL OAuth dan melaporkan apakah captcha wajib.
func (c *Client) OAuthURLVerbose(ctx context.Context, vendor, navigateURI, sourceID string) (string, bool, error) {
	url, _, err := c.OAuthURL(ctx, vendor, navigateURI, sourceID, nil)
	if err == nil {
		return url, false, nil
	}
	return "", true, nil
}

// Login menukar kode OAuth jadi access/refresh token.
func (c *Client) Login(ctx context.Context, vendor, code, state, navigateURI string) (*LoginResponse, error) {
	body := map[string]any{
		"code":         code,
		"state":        state,
		"navigate_uri": navigateURI,
		"device_id":    deviceID(),
		"source_id":    "autoclaw",
	}
	var out LoginResponse
	if err := c.userapiPost(ctx, "/userapi/overseasv1/"+vendor+"-oauth-login", body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Refresh memperbarui access token pakai refresh token.
func (c *Client) Refresh(ctx context.Context, refreshToken string) (*LoginResponse, error) {
	body := map[string]any{
		"refresh_token": refreshToken,
		"device_id":     deviceID(),
		"source_id":     "autoclaw",
	}
	var out LoginResponse
	if err := c.userapiPost(ctx, "/userapi/v1/agent-refresh", body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ClaimTask mengklaim task check-in (daily_signin, dll).
// Token harus sudah include "Bearer " prefix.
func (c *Client) ClaimTask(ctx context.Context, token, taskID string) (int, bool, error) {
	hdrs := c.InferenceHeader(token, "")
	// Tambah header yang diperlukan userapi
	hdrs["X-Lang"] = "en"
	hdrs["X-Client-Type"] = "pc"
	hdrs["authorization"] = token // lowercase untuk userapi
	delete(hdrs, "X-Authorization") // inference header gak dipake

	body := fmt.Sprintf(`{"task_id":"%s"}`, taskID)
	req, err := http.NewRequestWithContext(ctx, "POST",
		c.UserAPIBase+"/autoclaw-proxy/proxy/autoclaw-task-complete",
		strings.NewReader(body))
	if err != nil {
		return 0, false, err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hdrs {
		req.Header.Set(k, v)
	}

	resp, err := c.Do(req)
	if err != nil {
		return 0, false, err
	}
	defer resp.Body.Close()

	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	var result struct {
		Data *struct {
			Success         bool `json:"success"`
			AlreadyComplete bool `json:"already_completed"`
			RewardPoints    int  `json:"reward_points"`
		} `json:"data"`
	}
	json.Unmarshal(b, &result)

	if result.Data == nil {
		return 0, false, fmt.Errorf("response: %s", string(b))
	}
	if result.Data.AlreadyComplete {
		return 0, true, nil // already done
	}
	if !result.Data.Success {
		return 0, false, fmt.Errorf("server: success=false")
	}
	return result.Data.RewardPoints, false, nil
}

// ClaimNewbieToken mengklaim token newbie guide (reward 100M token untuk akun baru).
// Endpoint ini pakai header X-Authorization (uppercase, mirip inference proxy),
// BUKAN commonHeaders userapi — tanpa signature X-Auth-*.
// Body kosong. Return token guide (base64 user_id|timestamp|signature).
func (c *Client) ClaimNewbieToken(ctx context.Context, accessToken string) (string, error) {
	tok := accessToken
	if !strings.HasPrefix(tok, "Bearer ") {
		tok = "Bearer " + tok
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.UserAPIBase+"/autoclaw-proxy/proxy/autoclaw-newbie-guide/token", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("X-Authorization", tok)
	req.Header.Set("Accept", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("HTTP %d: %s", resp.StatusCode, truncate(b, 300))
	}
	var out struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return "", fmt.Errorf("payload bukan JSON: %s", truncate(b, 200))
	}
	if out.Token == "" {
		return "", fmt.Errorf("token kosong: %s", truncate(b, 300))
	}
	return out.Token, nil
}

// NewbieGuideToken mengambil token bonus 100M untuk akun (TTL ~3 jam dari server).
func (c *Client) NewbieGuideToken(ctx context.Context, accessToken string) (string, error) {
	tok := accessToken
	if !strings.HasPrefix(tok, "Bearer ") {
		tok = "Bearer " + tok
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.UserAPIBase+"/autoclaw-proxy/proxy/autoclaw-newbie-guide/token", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("X-Authorization", tok)
	req.Header.Set("Accept", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("HTTP %d: %s", resp.StatusCode, truncate(b, 300))
	}
	var out struct {
		Token string `json:"token"`
		Data  *struct {
			Token string `json:"token"`
		} `json:"data"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return "", fmt.Errorf("payload bukan JSON: %s", truncate(b, 200))
	}
	if out.Token == "" && out.Data != nil {
		out.Token = out.Data.Token
	}
	if out.Token == "" {
		return "", fmt.Errorf("token kosong: %s", truncate(b, 300))
	}
	return out.Token, nil
}

// ClaimPromotionReward mengklaim reward promosi (modal_id + reward_type).
// Header X-Authorization sama kayak ClaimNewbieToken.
func (c *Client) ClaimPromotionReward(ctx context.Context, accessToken, modalID, rewardType string) (json.RawMessage, error) {
	tok := accessToken
	if !strings.HasPrefix(tok, "Bearer ") {
		tok = "Bearer " + tok
	}
	body, _ := json.Marshal(map[string]string{
		"modal_id":    modalID,
		"reward_type": rewardType,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.UserAPIBase+"/autoclaw-proxy/proxy/autoclaw-promotion-reward", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Authorization", tok)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, truncate(b, 300))
	}
	return json.RawMessage(b), nil
}

func (c *Client) userapiPost(ctx context.Context, path string, body any, out any) error {
	return c.userapiPostWithHeaders(ctx, path, body, out, sign.Headers())
}

func (c *Client) userapiPostWithHeaders(ctx context.Context, path string, body any, out any, hdrs map[string]string) error {
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			return err
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.UserAPIBase+path, &buf)
	if err != nil {
		return err
	}
	for k, v := range hdrs {
		req.Header.Set(k, v)
	}
	// Add common headers (authorization with token, X-Lang, etc.)
	req.Header.Set("X-Lang", "en")
	req.Header.Set("X-Client-Type", "pc")
	// Note: Token is NOT added here - it's only used for inference and agentdr endpoints
	return c.doJSON(req, out)
}

func (c *Client) doJSON(req *http.Request, out any) error {
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if out != nil && len(b) > 0 {
		if err := json.Unmarshal(b, out); err != nil {
			return fmt.Errorf("HTTP %d: payload bukan JSON: %s", resp.StatusCode, truncate(b, 200))
		}
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, truncate(b, 300))
	}
	return nil
}

func truncate(b []byte, n int) string {
	if len(b) > n {
		return string(b[:n]) + "..."
	}
	return string(b)
}

// InferenceHeader membangun header untuk proxy inference.
func (c *Client) InferenceHeader(accessToken, routeModelID string) map[string]string {
	tok := accessToken
	if !strings.HasPrefix(tok, "Bearer ") {
		tok = "Bearer " + tok
	}
	return map[string]string{
		"X-Authorization":  tok,
		"X-Request-Id":     sign.UUID(),
		"X-Request-Model":  routeModelID,
		"X-Product":        "autoclaw",
		"X-Harness-Type":   "zcode",
		"X-Tm":             "win",
		"X-Version":        c.Version,
		"X-Lang":           "id",
		"x_trace_id":       sign.UUID(),
	}
}

// RouteID memetakan nama model OpenAI-style ke route id AutoClaw.
func RouteID(model string) string {
	if containsUnderscore(model) {
		return model // sudah route id
	}
	// DeepSeek model pakai prefix tdpsk_ + versi date.
	switch model {
	case "deepseek-v4-pro":
		return "tdpsk_deepseek-v4-pro-202606"
	case "deepseek-v4-flash":
		return "tdpsk_deepseek-v4-flash-202605"
	}
	if isVersioned(model) {
		return "zaicoding_" + model
	}
	return "zai_" + model
}

// BodyModel membalik RouteID: "zaicoding_glm-5.3" -> "glm-5.3".
func BodyModel(routeID string) string {
	for i := 0; i < len(routeID); i++ {
		if routeID[i] == '_' {
			return routeID[i+1:]
		}
	}
	return routeID
}

func containsUnderscore(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '_' {
			return true
		}
	}
	return false
}

// isVersioned true untuk glm-5.3 / glm-5.2 (versi coding plan).
func isVersioned(model string) bool {
	return model == "glm-5.3" || model == "glm-5.2"
}