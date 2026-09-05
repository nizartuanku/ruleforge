package parse

import (
	"fmt"
	"strings"
	"testing"

	"github.com/nizartuanku/ruleforge/fwir"
)

// PAN-OS set format spreads one rule over many lines, and the parser used to
// rescan the whole rule slice for every one of them. On a large rulebase that
// is quadratic, and it was the dominant cost of round-trip verification once
// the generator was fixed. The index has to make that O(1) without changing
// which rule a line lands on — this test asserts the second part, at a size
// where the old scan would take minutes.
func TestPanIndex_LinesLandOnTheRightRule(t *testing.T) {
	const n = 20000
	var b strings.Builder
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("rule-%05d", i)
		fmt.Fprintf(&b, "set rulebase security rules %s from zone-a\n", name)
		fmt.Fprintf(&b, "set rulebase security rules %s to zone-b\n", name)
		fmt.Fprintf(&b, "set rulebase security rules %s source addr-%05d\n", name, i)
		fmt.Fprintf(&b, "set rulebase security rules %s destination any\n", name)
		fmt.Fprintf(&b, "set rulebase security rules %s action allow\n", name)
	}
	cfg, err := Parse(fwir.VendorPANOS, []Input{{Name: "pan.txt", Content: b.String()}})
	if err != nil {
		t.Fatal(err)
	}
	var rules []fwir.Rule
	for i := range cfg.Contexts {
		rules = append(rules, cfg.Contexts[i].Rules...)
	}
	if len(rules) != n {
		t.Fatalf("got %d rules, want %d — lines were merged or duplicated", len(rules), n)
	}
	for i, r := range rules {
		wantName := fmt.Sprintf("rule-%05d", i)
		if r.Name != wantName {
			t.Fatalf("rule %d is named %q, want %q — source order was not preserved", i, r.Name, wantName)
		}
		wantSrc := fmt.Sprintf("addr-%05d", i)
		if len(r.SrcAddrs) != 1 || string(r.SrcAddrs[0]) != wantSrc {
			t.Fatalf("rule %q has sources %v, want [%s] — a field landed on the wrong rule", r.Name, r.SrcAddrs, wantSrc)
		}
	}
}

// A repeated address line must keep updating the same object, not append a
// second one.
func TestPanIndex_RepeatedObjectLinesUpdateOneObject(t *testing.T) {
	in := strings.Join([]string{
		"set address WEB ip-netmask 198.51.100.10/32",
		"set address WEB description primary web server",
		"set address DB ip-netmask 198.51.100.20/32",
		"set address WEB tag prod",
	}, "\n")
	cfg, err := Parse(fwir.VendorPANOS, []Input{{Name: "pan.txt", Content: in}})
	if err != nil {
		t.Fatal(err)
	}
	nets := cfg.Contexts[0].Objects.Networks
	if len(nets) != 2 {
		t.Fatalf("got %d objects, want 2: %+v", len(nets), nets)
	}
	web := cfg.Contexts[0].Objects.FindNet("WEB")
	if web == nil || web.Value != "198.51.100.10" || web.Desc != "primary web server" {
		t.Fatalf("WEB did not accumulate its lines: %+v", web)
	}
}
