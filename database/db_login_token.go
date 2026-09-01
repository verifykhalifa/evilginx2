package database

import (
	"encoding/json"
	"time"

	"github.com/tidwall/buntdb"
)

// LoginTokenTable persists dashboard login tokens in buntdb so they survive
// process restarts. Without this, every evilginx restart invalidates the token
// the browser has stored -> dashboard keeps logging the user out.
const LoginTokenTable = "login_tokens"

type LoginToken struct {
	Token      string `json:"token"`
	ExpiresAt  int64  `json:"expires_at"`
	CreateTime int64  `json:"create_time"`
}

func (d *Database) loginTokensInit() {
	d.db.CreateIndex("login_tokens_exp", LoginTokenTable+":*", buntdb.IndexJSON("expires_at"))
}

func (d *Database) loginTokenSet(token string, expiresAt int64) error {
	lt := &LoginToken{
		Token:      token,
		ExpiresAt:  expiresAt,
		CreateTime: time.Now().UTC().Unix(),
	}
	jf, err := json.Marshal(lt)
	if err != nil {
		return err
	}
	return d.db.Update(func(tx *buntdb.Tx) error {
		_, _, err := tx.Set(LoginTokenTable+":"+token, string(jf), nil)
		return err
	})
}

func (d *Database) loginTokenGet(token string) (int64, bool) {
	var expiresAt int64
	var found bool
	_ = d.db.View(func(tx *buntdb.Tx) error {
		val, err := tx.Get(LoginTokenTable + ":" + token)
		if err != nil {
			return nil
		}
		lt := &LoginToken{}
		if json.Unmarshal([]byte(val), lt) == nil {
			expiresAt = lt.ExpiresAt
			found = true
		}
		return nil
	})
	return expiresAt, found
}

func (d *Database) loginTokenDelete(token string) error {
	return d.db.Update(func(tx *buntdb.Tx) error {
		_, err := tx.Delete(LoginTokenTable + ":" + token)
		return err
	})
}

func (d *Database) loginTokensDeleteExpired(now int64) {
	_ = d.db.Update(func(tx *buntdb.Tx) error {
		tx.Ascend("login_tokens_exp", func(key, val string) bool {
			lt := &LoginToken{}
			if json.Unmarshal([]byte(val), lt) == nil && lt.ExpiresAt < now {
				tx.Delete(key)
			}
			return true
		})
		return nil
	})
}

// Exported wrappers (used by the dashboard package).

func (d *Database) SetLoginToken(token string, expiresAt int64) error {
	return d.loginTokenSet(token, expiresAt)
}

func (d *Database) GetLoginToken(token string) (int64, bool) {
	return d.loginTokenGet(token)
}

func (d *Database) DeleteLoginToken(token string) error {
	return d.loginTokenDelete(token)
}

func (d *Database) DeleteExpiredLoginTokens(now int64) {
	d.loginTokensDeleteExpired(now)
}
