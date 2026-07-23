package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/input"
	"github.com/go-rod/rod/lib/proto"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: go run test_login.go <email> <password>")
		os.Exit(1)
	}
	email := os.Args[1]
	password := os.Args[2]

	fmt.Println("=== BITB Headless Chrome Login Test ===")
	fmt.Printf("Email:    %s\n", email)
	fmt.Printf("Password: %s\n\n", password)

	wsURL, err := getChromeWS()
	if err != nil {
		fmt.Printf("FAIL: Cannot find Chrome debugger: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Chrome WS: %s\n\n", wsURL)

	browser := rod.New().ControlURL(wsURL)
	if err := browser.Connect(); err != nil {
		fmt.Printf("FAIL: Could not connect to Chrome: %v\n", err)
		os.Exit(1)
	}
	defer browser.Close()

	page, err := browser.Page(proto.TargetCreateTarget{URL: "about:blank"})
	if err != nil {
		fmt.Printf("FAIL: Could not create page: %v\n", err)
		os.Exit(1)
	}
	defer page.Close()

	page.SetViewport(&proto.EmulationSetDeviceMetricsOverride{
		Width: 1920, Height: 1080, DeviceScaleFactor: 1, Mobile: false,
	})

	fmt.Println("[1/5] Navigating to accounts.google.com ...")
	if err := page.Navigate("https://accounts.google.com/"); err != nil {
		fmt.Printf("FAIL: Navigate error: %v\n", err)
		os.Exit(1)
	}
	page.MustWaitLoad()
	fmt.Println("      Page loaded")
	printURL(page)
	saveSS(page, "01_after_nav")

	fmt.Println("[2/5] Looking for email field (#identifierId) ...")
	el, err := page.Element("#identifierId")
	if err != nil {
		fmt.Printf("FAIL: Email field not found: %v\n", err)
		saveSS(page, "02_no_email_field")
		os.Exit(1)
	}
	fmt.Println("      Found email field")
	saveSS(page, "02_email_field")

	fmt.Println("[3/5] Typing email and pressing Enter ...")
	if err := el.Input(email); err != nil {
		fmt.Printf("FAIL: Could not type email: %v\n", err)
		os.Exit(1)
	}
	time.Sleep(500 * time.Millisecond)
	saveSS(page, "03_before_enter")

	if err := page.Keyboard.Press(input.Enter); err != nil {
		fmt.Printf("FAIL: Could not press Enter: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("      Waiting for page transition (up to 30s)...")
	found := false
	for i := 0; i < 60; i++ {
		time.Sleep(500 * time.Millisecond)
		printURL(page)
		page.MustWaitLoad()

		// Save screenshot every 5 seconds
		if i%10 == 0 {
			saveSS(page, fmt.Sprintf("03_wait_%ds", (i+1)/2))
		}

		// Get page title to understand what Google shows
		title, _ := page.Eval("document.title")
		if title != nil {
			fmt.Printf("      Title: %s\n", title.Value.String())
		}

		// Check for password field
		pwEl, err := page.Element("input[type=\"password\"]")
		if err == nil && pwEl != nil {
			visible, _ := pwEl.Visible()
			if visible {
				found = true
				fmt.Printf("      Password field found after %ds!\n", (i+1)/2)
				saveSS(page, "03_password_found")
				break
			}
		}

		// Check for known non-password Google pages
		url, err := page.Eval("window.location.href")
		if err == nil {
			urlStr := url.Value.String()
			if strings.Contains(urlStr, "signin/recovery") {
				fmt.Println("      WARNING: Google showed RECOVERY page!")
				saveSS(page, "03_recovery")
			}
			if strings.Contains(urlStr, "challenge") || strings.Contains(urlStr, "totp") {
				fmt.Println("      WARNING: Google showed 2FA CHALLENGE!")
				saveSS(page, "03_challenge")
			}
			if strings.Contains(urlStr, "webauth") {
				fmt.Println("      WARNING: Google showed WEBAUTHN prompt!")
				saveSS(page, "03_webauthn")
			}
		}

		// Dump visible text to understand the page
		if i%10 == 0 {
			text, _ := page.Eval("document.body ? document.body.innerText.substring(0, 500) : ''")
			if text != nil {
				fmt.Printf("      Text: %s\n", text.Value.String())
			}
		}
	}

	if !found {
		fmt.Println("FAIL: Password field did NOT appear within 30s")
		saveSS(page, "03_timeout")
		// Dump the page HTML for analysis
		html, err := page.Eval("document.body ? document.body.innerHTML.substring(0, 2000) : ''")
		if err == nil {
			fmt.Printf("      HTML: %s\n", html.Value.String())
		}
		os.Exit(1)
	}

	fmt.Println("[4/5] Typing password and pressing Enter ...")
	pwEl, _ := page.Element("input[type=\"password\"]")
	if err := pwEl.Input(password); err != nil {
		fmt.Printf("FAIL: Could not type password: %v\n", err)
		os.Exit(1)
	}
	time.Sleep(500 * time.Millisecond)
	saveSS(page, "04_before_enter")
	if err := page.Keyboard.Press(input.Enter); err != nil {
		fmt.Printf("FAIL: Could not press Enter: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("      Waiting for login redirect (up to 30s)...")
	loggedIn := false
	for i := 0; i < 60; i++ {
		time.Sleep(500 * time.Millisecond)
		url, err := page.Eval("window.location.href")
		if err == nil {
			urlStr := url.Value.String()
			fmt.Printf("      URL: %s\n", urlStr)
			if strings.Contains(urlStr, "myaccount.google.com") ||
				strings.Contains(urlStr, "mail.google.com") ||
				strings.Contains(urlStr, "accounts.google.com/signin/v2/success") ||
				strings.Contains(urlStr, "www.google.com/webhp") ||
				strings.Contains(urlStr, "accounts.google.com/AccountChooser") {
				loggedIn = true
				fmt.Println("      LOGIN SUCCESSFUL!")
				saveSS(page, "04_logged_in")
				break
			}
		}
		page.MustWaitLoad()
		if i%10 == 0 {
			saveSS(page, fmt.Sprintf("04_wait_%ds", (i+1)/2))
		}
	}

	if !loggedIn {
		fmt.Println("FAIL: Login did not complete within 30s")
		saveSS(page, "04_timeout")
		os.Exit(1)
	}

	fmt.Println("\n[5/5] Extracting cookies ...")
	time.Sleep(2 * time.Second)
	cookies, err := page.Cookies(nil)
	if err != nil {
		fmt.Printf("FAIL: Could not get cookies: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\n=== SUCCESS! %d cookies captured ===\n", len(cookies))
	for _, c := range cookies {
		val := c.Value
		if len(val) > 60 {
			val = val[:60] + "..."
		}
		fmt.Printf("  %s = %s\n", c.Name, val)
	}
	saveSS(page, "05_success")
}

func getChromeWS() (string, error) {
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

func printURL(page *rod.Page) {
	url, err := page.Eval("window.location.href")
	if err == nil {
		fmt.Printf("      URL: %s\n", url.Value.String())
	}
}

func saveSS(page *rod.Page, name string) {
	buf, err := page.Screenshot(true, &proto.PageCaptureScreenshot{
		Format: "png",
	})
	if err == nil {
		os.WriteFile(name+".png", buf, 0644)
		fmt.Printf("      Screenshot saved: %s.png\n", name)
	}
}
