package engine

import (
	"fmt"

	"github.com/nizartuanku/ruleforge/fwir"
	"github.com/nizartuanku/ruleforge/gen"
	"github.com/nizartuanku/ruleforge/parse"
)

// Convert runs generation for every context with its approved mapping.
func Convert(cfg *fwir.Config, target string, mappings map[string]*gen.Mapping) ([]*gen.Result, error) {
	var out []*gen.Result
	for i := range cfg.Contexts {
		x := &cfg.Contexts[i]
		m := mappings[x.Name]
		if m == nil {
			m = &gen.Mapping{}
		}
		r, err := gen.Generate(target, x, m)
		if err != nil {
			return nil, fmt.Errorf("context %s: %w", x.Name, err)
		}
		out = append(out, r)
	}
	return out, nil
}

// RoundTrip re-parses generated output with RuleForge's own parser for the
// target vendor and returns the re-parsed IR, or nil when the target has no
// text parser (FTD bundle JSON, Check Point mgmt script). Each generated
// context re-parses independently so multi-tenant sources do not collapse
// into one context.
func RoundTrip(target string, results []*gen.Result) (*fwir.Config, bool) {
	keep := func(name string) bool {
		switch target {
		case fwir.VendorASA:
			return true
		case fwir.VendorFortiGate:
			return hasSuffix(name, ".conf")
		case fwir.VendorPANOS:
			return hasPrefix(name, "panos-")
		}
		return false
	}
	switch target {
	case fwir.VendorASA, fwir.VendorFortiGate, fwir.VendorPANOS:
	default:
		return nil, false
	}
	merged := &fwir.Config{Vendor: target}
	any := false
	for _, r := range results {
		var inputs []parse.Input
		for _, f := range r.Files {
			if keep(f.Name) {
				inputs = append(inputs, parse.Input{Name: f.Name, Content: f.Content})
			}
		}
		if len(inputs) == 0 {
			continue
		}
		cfg, err := parse.Parse(target, inputs)
		if err != nil {
			return nil, false
		}
		for i := range cfg.Contexts {
			cfg.Contexts[i].Name = r.Context
			merged.Contexts = append(merged.Contexts, cfg.Contexts[i])
		}
		any = true
	}
	if !any {
		return nil, false
	}
	return merged, true
}

func hasSuffix(s, suf string) bool {
	return len(s) >= len(suf) && s[len(s)-len(suf):] == suf
}

func hasPrefix(s, pre string) bool {
	return len(s) >= len(pre) && s[:len(pre)] == pre
}
