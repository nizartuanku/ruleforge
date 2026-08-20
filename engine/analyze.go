// Package engine orchestrates the RuleForge pipeline:
// Analyze → Map → Convert → Review, plus the two report documents.
package engine

import (
	"fmt"
	"sort"
	"strings"

	"github.com/nizartuanku/ruleforge/fwir"
)

// Analysis is the deep pre-migration inventory of one parsed source.
type Analysis struct {
	Vendor      string            `json:"vendor"`
	Hostname    string            `json:"hostname,omitempty"`
	Version     string            `json:"version,omitempty"`
	MultiTenant bool              `json:"multi_tenant"`
	TenantKind  string            `json:"tenant_kind,omitempty"` // contexts | vdoms | device-groups | packages
	Contexts    []ContextAnalysis `json:"contexts"`
	Totals      Inventory         `json:"totals"`
	Notes       []string          `json:"notes,omitempty"`
}

// Inventory counts every category.
type Inventory struct {
	Interfaces int `json:"interfaces"`
	SubIfs     int `json:"subinterfaces"`
	Bridges    int `json:"bridges"`
	Aggregates int `json:"aggregates"`
	Zones      int `json:"zones"`
	NetObjects int `json:"net_objects"`
	FQDNs      int `json:"fqdns"`
	Services   int `json:"services"`
	NetGroups  int `json:"net_groups"`
	SvcGroups  int `json:"svc_groups"`
	Rules      int `json:"rules"`
	DisabledRules int `json:"disabled_rules"`
	NATs       int `json:"nats"`
	Routes     int `json:"routes"`
	Captured   int `json:"captured"`
	Unparsed   int `json:"unparsed"`
}

// FeatureUse is one recognised feature/service and how often it appears.
type FeatureUse struct {
	Category string `json:"category"`
	Label    string `json:"label"`
	Count    int    `json:"count"`
	Convert  string `json:"convert"` // auto | partial | manual
}

// ContextAnalysis is one tenant's inventory + feature capture.
type ContextAnalysis struct {
	Name      string       `json:"name"`
	Inventory Inventory    `json:"inventory"`
	Features  []FeatureUse `json:"features"`
	Risks     []string     `json:"risks,omitempty"`
}

// Analyze builds the deep analysis for a parsed config.
func Analyze(cfg *fwir.Config) *Analysis {
	a := &Analysis{Vendor: cfg.Vendor, Hostname: cfg.Hostname, Version: cfg.Version}
	if len(cfg.Contexts) > 1 {
		a.MultiTenant = true
		switch cfg.Vendor {
		case fwir.VendorASA, fwir.VendorFTD:
			a.TenantKind = "security contexts"
		case fwir.VendorFortiGate:
			a.TenantKind = "VDOMs"
		case fwir.VendorPANOS:
			a.TenantKind = "device-groups/vsys"
		default:
			a.TenantKind = "policy packages"
		}
	}
	for i := range cfg.Contexts {
		x := &cfg.Contexts[i]
		ca := ContextAnalysis{Name: x.Name}
		inv := &ca.Inventory
		for _, ifc := range x.Interfaces {
			inv.Interfaces++
			switch ifc.Kind {
			case fwir.IfSubIf, fwir.IfVLAN:
				inv.SubIfs++
			case fwir.IfBridge:
				inv.Bridges++
			case fwir.IfAggregate:
				inv.Aggregates++
			}
		}
		inv.Zones = len(x.Zones)
		inv.NetObjects = len(x.Objects.Networks)
		for _, o := range x.Objects.Networks {
			if o.Kind == fwir.NetFQDN {
				inv.FQDNs++
			}
		}
		inv.Services = len(x.Objects.Services)
		inv.NetGroups = len(x.Objects.NetGroups)
		inv.SvcGroups = len(x.Objects.SvcGroups)
		inv.Rules = len(x.Rules)
		for _, r := range x.Rules {
			if !r.Enabled {
				inv.DisabledRules++
			}
		}
		inv.NATs = len(x.NATs)
		inv.Routes = len(x.Routes)
		inv.Captured = len(x.Captured)
		inv.Unparsed = len(x.Unparsed)

		// feature capture summary
		counts := map[string]int{}
		for _, c := range x.Captured {
			counts[c.Category]++
		}
		var cats []string
		for c := range counts {
			cats = append(cats, c)
		}
		sort.Strings(cats)
		for _, c := range cats {
			ca.Features = append(ca.Features, FeatureUse{
				Category: c, Label: capLabel(c), Count: counts[c], Convert: "manual",
			})
		}
		// auto categories
		auto := []struct {
			n     int
			label string
		}{
			{inv.Rules, "Access rules"}, {inv.NATs, "NAT rules"}, {inv.NetObjects, "Network objects"},
			{inv.Services, "Service objects"}, {inv.NetGroups + inv.SvcGroups, "Object groups"},
			{inv.Interfaces, "Interfaces"}, {inv.Zones, "Zones"}, {inv.Routes, "Static routes"},
		}
		for _, f := range auto {
			if f.n > 0 {
				ca.Features = append([]FeatureUse{{Category: "core", Label: f.label, Count: f.n, Convert: "auto"}}, ca.Features...)
			}
		}
		// risks
		appRules, urlRules := 0, 0
		for _, r := range x.Rules {
			if len(r.Apps) > 0 {
				appRules++
			}
			if len(r.URLCats) > 0 {
				urlRules++
			}
		}
		if appRules > 0 {
			ca.Risks = append(ca.Risks, fmt.Sprintf("%d rules use L7 applications (App-ID) — converting to an L4-only vendor loses application awareness; RuleForge converts them at L4 and flags each one", appRules))
		}
		if urlRules > 0 {
			ca.Risks = append(ca.Risks, fmt.Sprintf("%d rules use URL categories — recreate URL filtering profiles on the target", urlRules))
		}
		if inv.Unparsed > 0 {
			ca.Risks = append(ca.Risks, fmt.Sprintf("%d config lines were not recognised — review them in the report before cut-over", inv.Unparsed))
		}
		if counts[fwir.CapVPN] > 0 {
			ca.Risks = append(ca.Risks, fmt.Sprintf("%d VPN configuration blocks captured — site-to-site VPNs must be rebuilt on the target (v1 reports them with full source lines)", counts[fwir.CapVPN]))
		}
		if counts[fwir.CapDynRouting] > 0 {
			ca.Risks = append(ca.Risks, "dynamic routing (OSPF/BGP) present — plan routing migration separately; static routes convert automatically")
		}
		a.Contexts = append(a.Contexts, ca)
		addInv(&a.Totals, inv)
	}
	if a.MultiTenant {
		a.Notes = append(a.Notes, fmt.Sprintf("Source is multi-tenant (%d %s). Each tenant converts to its own tenant on the target (context → VDOM / device-group / instance) or to a merged policy — v1 maps 1:1.", len(a.Contexts), a.TenantKind))
	}
	return a
}

func addInv(t *Inventory, s *Inventory) {
	t.Interfaces += s.Interfaces
	t.SubIfs += s.SubIfs
	t.Bridges += s.Bridges
	t.Aggregates += s.Aggregates
	t.Zones += s.Zones
	t.NetObjects += s.NetObjects
	t.FQDNs += s.FQDNs
	t.Services += s.Services
	t.NetGroups += s.NetGroups
	t.SvcGroups += s.SvcGroups
	t.Rules += s.Rules
	t.DisabledRules += s.DisabledRules
	t.NATs += s.NATs
	t.Routes += s.Routes
	t.Captured += s.Captured
	t.Unparsed += s.Unparsed
}

func capLabel(c string) string {
	switch c {
	case fwir.CapVPN:
		return "VPN (site-to-site / remote access)"
	case fwir.CapCert:
		return "Certificates / PKI"
	case fwir.CapURLFilter:
		return "URL filtering"
	case fwir.CapAppID:
		return "Application-ID / app control"
	case fwir.CapDynRouting:
		return "Dynamic routing"
	case fwir.CapHA:
		return "High availability"
	case fwir.CapUserID:
		return "User identity / AAA"
	case fwir.CapMgmt:
		return "Management services"
	case fwir.CapInspection:
		return "Inspection policies"
	}
	return strings.Title(c)
}
