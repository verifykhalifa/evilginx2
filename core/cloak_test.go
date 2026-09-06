package core

import (
	"net/http/httptest"
	"testing"
	"time"
)

func TestCloakIsCrawler(t *testing.T) {
	InitCloak(nil) // default config

	cases := []struct {
		name    string
		ua      string
		headers map[string]string
		isCrawl bool
	}{
		{"chrome-user", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36", map[string]string{
			"Accept-Language": "en-US,en;q=0.9",
			"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
			"Sec-Fetch-Site":  "none",
		}, false},
		{"google-safe-browsing", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Chrome-Lighthouse", nil, true},
		{"generic-googlebot", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", nil, true},
		{"bingbot", "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)", nil, true},
		{"python-requests", "python-requests/2.31.0", nil, true},
		{"curl", "curl/8.5.0", nil, true},
		{"headless-chrome", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/120.0.0.0 Safari/537.36", nil, true},
		{"empty-ua", "", nil, true},
	}

	for _, tc := range cases {
		req := httptest.NewRequest("GET", "https://loq.example.com/", nil)
		req.Header.Set("User-Agent", tc.ua)
		for k, v := range tc.headers {
			req.Header.Set(k, v)
		}
		got := GetCloak().IsCrawler(req)
		if got != tc.isCrawl {
			t.Errorf("%s: IsCrawler=%v want %v (ua=%q)", tc.name, got, tc.isCrawl, tc.ua)
		}
	}
}

func TestCloakServeBenignResponse(t *testing.T) {
	InitCloak(nil)
	req := httptest.NewRequest("GET", "https://loq.example.com/", nil)
	req.Header.Set("User-Agent", "curl/8.5.0")

	resp := GetCloak().ServeBenignResponse(req)
	if resp == nil {
		t.Fatal("ServeBenignResponse returned nil")
	}
	if resp.StatusCode != 404 {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
	if resp.Body == nil {
		t.Fatal("body is nil")
	}
}

func TestCloakDisabled(t *testing.T) {
	InitCloak(&CloakConfig{Enabled: false, BenignResponse: "404 Not Found", BenignStatusCode: 404})
	req := httptest.NewRequest("GET", "https://loq.example.com/", nil)
	req.Header.Set("User-Agent", "curl/8.5.0")
	if GetCloak().IsCrawler(req) {
		t.Error("IsCrawler should be false when cloaking disabled")
	}
	// restore defaults for other tests
	InitCloak(nil)
}

// TestCloakProfileNotCreatedDuringCheck verifies that IsCrawler does NOT
// create a visitor profile for IPs that don't already have one.
// This prevents the bug where first request is blocked (profile created),
// second request passes (profile exists with RequestCount=2, behavioral check skipped)
func TestCloakProfileNotCreatedDuringCheck(t *testing.T) {
	InitCloak(nil)
	ip := "192.0.2.1" // TEST-NET-1, not in cloud CIDRs

	// First, verify no profile exists
	c := GetCloak()
	c.mu.RLock()
	_, exists := c.profiles[ip]
	c.mu.RUnlock()
	if exists {
		t.Fatal("profile should not exist before test")
	}

	// Make a request with a legitimate UA and headers (should NOT be blocked by UA/headers)
	req := httptest.NewRequest("GET", "https://loq.example.com/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Sec-Fetch-Site", "none")
	// Simulate the request coming from the test IP
	// Note: clientIP() will use RemoteAddr, so we can't easily test with a specific IP
	// unless we use IsCrawlerWithIP directly

	// Use IsCrawlerWithIP to test with a specific IP
	blocked := c.IsCrawlerWithIP(req, ip)
	if blocked {
		t.Errorf("legitimate request from non-cloud IP should not be blocked, got blocked=%v", blocked)
	}

	// Verify no profile was created during the check
	c.mu.RLock()
	_, exists = c.profiles[ip]
	c.mu.RUnlock()
	if exists {
		t.Error("profile was created during IsCrawler check - this is the bug!")
	}
}

// TestCloakBehavioralCheckOnlyOnExistingProfile verifies that the behavioral
// check (RequestCount > 1, etc.) only applies to IPs that already have a profile
func TestCloakBehavioralCheckOnlyOnExistingProfile(t *testing.T) {
	InitCloak(nil)
	c := GetCloak()
	ip := "192.0.2.2"

	// Create a profile with RequestCount=2 but no behavioral signals
	c.mu.Lock()
	c.profiles[ip] = &VisitorProfile{
		IP:            ip,
		FirstSeen:     time.Now().Add(-3 * time.Second),
		RequestCount:  2,
		HasMouseMove:  false,
		HasScroll:     false,
		HasKeyPress:   false,
		HasClick:      false,
		LoadedAssets:  false,
		UserAgent:     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		LastSeen:      time.Now(),
	}
	c.mu.Unlock()

	// Request with good headers but no behavioral signals - should be blocked
	req := httptest.NewRequest("GET", "https://loq.example.com/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Sec-Fetch-Site", "none")

	blocked := c.IsCrawlerWithIP(req, ip)
	if !blocked {
		t.Error("request with existing profile but no behavioral signals should be blocked")
	}

	// Now add behavioral signal
	c.mu.Lock()
	c.profiles[ip].HasMouseMove = true
	c.mu.Unlock()

	blocked = c.IsCrawlerWithIP(req, ip)
	if blocked {
		t.Error("request with behavioral signal should NOT be blocked")
	}
}
