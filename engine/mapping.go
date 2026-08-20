package engine

import (
	"fmt"
	"strings"

	"github.com/nizartuanku/ruleforge/fwir"
	"github.com/nizartuanku/ruleforge/gen"
)

// MappingEntry is one editable row in the mapping view.
type MappingEntry struct {
	Kind    string `json:"kind"` // interface | zone
	Source  string `json:"source"`
	Target  string `json:"target"` // proposed; user-editable
	Context string `json:"context"`
	Note    string `json:"note,omitempty"`
}

// MapProposal is the full pre-conversion map presented for approval.
type MapProposal struct {
	Target  string         `json:"target"`
	Entries []MappingEntry `json:"entries"`
	Notes   []string       `json:"notes,omitempty"`
}

// ProposeMapping builds the default source→target map for review.
func ProposeMapping(cfg *fwir.Config, target string) *MapProposal {
	p := &MapProposal{Target: target}
	for ci := range cfg.Contexts {
		x := &cfg.Contexts[ci]
		// interfaces in stable order; physical ones get sequential target names
		physSeq := 0
		nameFor := map[string]string{}
		for _, ifc := range x.Interfaces {
			var tgt, note string
			switch ifc.Kind {
			case fwir.IfPhysical, fwir.IfMgmt:
				tgt = physName(target, physSeq)
				physSeq++
			case fwir.IfSubIf, fwir.IfVLAN:
				parent := nameFor[ifc.Parent]
				if parent == "" {
					parent = physName(target, 0)
				}
				tgt = subName(target, parent, ifc.VlanID)
			case fwir.IfAggregate:
				tgt = aggName(target, ifc.Name)
			case fwir.IfBridge:
				tgt = ifc.Name
				note = "bridge/L2 — verify target design"
			case fwir.IfLoopback:
				tgt = loopName(target)
			case fwir.IfTunnel:
				tgt = tunName(target)
			default:
				tgt = ifc.Name
			}
			nameFor[ifc.Name] = tgt
			p.Entries = append(p.Entries, MappingEntry{
				Kind: "interface", Source: ifc.Name, Target: tgt, Context: x.Name, Note: note,
			})
		}
		// zones map by name (sanitised later by the generator's namer)
		seen := map[string]bool{}
		addZone := func(z string) {
			if z == "" || seen[z] {
				return
			}
			seen[z] = true
			p.Entries = append(p.Entries, MappingEntry{Kind: "zone", Source: z, Target: z, Context: x.Name})
		}
		for _, z := range x.Zones {
			addZone(z.Name)
		}
		for _, ifc := range x.Interfaces {
			addZone(ifc.Zone)
			addZone(ifc.Alias)
		}
		for _, r := range x.Rules {
			for _, z := range r.SrcZones {
				addZone(z)
			}
			for _, z := range r.DstZones {
				addZone(z)
			}
		}
	}
	switch target {
	case fwir.VendorPANOS:
		p.Notes = append(p.Notes, "PAN-OS interface names must be ethernetSLOT/PORT or aeN — adjust the proposals to the real hardware before converting.")
	case fwir.VendorFTD:
		p.Notes = append(p.Notes, "FTD interface names follow the target appliance (e.g. GigabitEthernet0/0 on ASA-hw, Ethernet1/1 on Firepower) — adjust to the real device.")
	}
	return p
}

// BuildMappings turns approved entries into per-context gen.Mapping.
func BuildMappings(entries []MappingEntry) map[string]*gen.Mapping {
	out := map[string]*gen.Mapping{}
	for _, e := range entries {
		m, ok := out[e.Context]
		if !ok {
			m = &gen.Mapping{ZoneMap: map[string]string{}, IfaceMap: map[string]string{}}
			out[e.Context] = m
		}
		switch e.Kind {
		case "interface":
			m.IfaceMap[e.Source] = e.Target
		case "zone":
			m.ZoneMap[e.Source] = e.Target
		}
	}
	return out
}

func physName(target string, seq int) string {
	switch target {
	case fwir.VendorPANOS:
		return fmt.Sprintf("ethernet1/%d", seq+1)
	case fwir.VendorFortiGate:
		return fmt.Sprintf("port%d", seq+1)
	case fwir.VendorCheckPoint:
		return fmt.Sprintf("eth%d", seq)
	case fwir.VendorASA, fwir.VendorFTD:
		return fmt.Sprintf("GigabitEthernet0/%d", seq)
	}
	return fmt.Sprintf("eth%d", seq)
}

func subName(target, parent string, vlan int) string {
	switch target {
	case fwir.VendorFortiGate:
		return fmt.Sprintf("vlan%d", vlan)
	default:
		return fmt.Sprintf("%s.%d", parent, vlan)
	}
}

func aggName(target, src string) string {
	digits := strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, src)
	if digits == "" {
		digits = "1"
	}
	switch target {
	case fwir.VendorPANOS:
		return "ae" + digits
	case fwir.VendorFortiGate:
		return "agg" + digits
	case fwir.VendorCheckPoint:
		return "bond" + digits
	case fwir.VendorASA, fwir.VendorFTD:
		return "Port-channel" + digits
	}
	return src
}

func loopName(target string) string {
	switch target {
	case fwir.VendorPANOS:
		return "loopback.1"
	case fwir.VendorASA, fwir.VendorFTD:
		return "Loopback1"
	}
	return "loopback1"
}

func tunName(target string) string {
	switch target {
	case fwir.VendorPANOS:
		return "tunnel.1"
	case fwir.VendorASA, fwir.VendorFTD:
		return "Tunnel1"
	}
	return "tunnel1"
}
