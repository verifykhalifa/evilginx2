package core

import (
	"fmt"
	"testing"
)

func TestIsDatacenterIP(t *testing.T) {
	// Known datacenter/cloud/VPN ranges
	dcIPs := []string{
		"104.248.1.1",     // DigitalOcean
		"159.89.1.1",      // DigitalOcean
		"167.71.1.1",      // DigitalOcean
		"172.104.1.1",     // Linode
		"45.79.1.1",       // Linode
		"45.32.1.1",       // Vultr
		"149.28.1.1",      // Vultr
		"192.166.82.81",   // user's own VPS (datacenter)
		"3.5.1.1",         // AWS
		"52.1.1.1",        // AWS
		"34.64.1.1",       // GCP
		"35.184.1.1",      // GCP
		"13.64.1.1",       // Azure
		"20.36.1.1",       // Azure (verified in ServiceTags)
		"51.10.0.1",       // Azure
		"13.107.6.152",    // Microsoft
	}
	// Residential / mobile IPs (should NOT match)
	resIPs := []string{
		"81.202.1.1",   // residential ES
		"24.1.1.1",     // Comcast US residential
		"98.1.1.1",     // residential US
		"82.11.1.1",    // UK residential
		"217.45.1.1",    // UK residential
	}

	// Force lazy load
	InitCloak(nil)

	for _, ip := range dcIPs {
		if !IsDatacenterIP(ip) {
			t.Errorf("expected datacenter: %s", ip)
		} else {
			fmt.Printf("OK dc: %s\n", ip)
		}
	}
	for _, ip := range resIPs {
		if IsDatacenterIP(ip) {
			t.Errorf("expected NOT datacenter: %s", ip)
		} else {
			fmt.Printf("OK res: %s\n", ip)
		}
	}
}
