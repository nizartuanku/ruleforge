package engine

import (
	"os"
	"strings"
	"testing"

	"github.com/nizartuanku/ruleforge/fwir"
	"github.com/nizartuanku/ruleforge/gen"
	"github.com/nizartuanku/ruleforge/parse"
)

func ifaceCfg(addr string) *fwir.Config {
	return &fwir.Config{Vendor: fwir.VendorASA, Contexts: []fwir.Context{{
		Name:       "default",
		Interfaces: []fwir.Interface{{Name: "GigabitEthernet0/0", Kind: fwir.IfPhysical, IPs: []string{addr}}},
	}}}
}

// The defect that shipped in v0.1.0: the address was masked, so exactly one
// address went in and exactly one came out and every count matched. A value
// check has to fail here or it is worth nothing.
func TestValueCheck_CatchesMaskedInterfaceAddress(t *testing.T) {
	src := ifaceCfg("198.51.100.2/28")
	rt := ifaceCfg("198.51.100.0/28") // what the buggy generator produced
	checks := buildValueChecks(src, rt)
	var addr *ValueCheck
	for i := range checks {
		if checks[i].Metric == "interface addresses" {
			addr = &checks[i]
		}
	}
	if addr == nil {
		t.Fatal("no interface address check produced")
	}
	if addr.OK {
		t.Fatal("masked interface address passed the value check")
	}
	if len(addr.Missing) != 1 || addr.Missing[0] != "198.51.100.2/28" {
		t.Fatalf("the report must name the address that went missing, got %v", addr.Missing)
	}
	if len(addr.Extra) != 1 || addr.Extra[0] != "198.51.100.0/28" {
		t.Fatalf("the report must also name what appeared instead, got %v", addr.Extra)
	}
}

// Names are rewritten on purpose by the namer and the zone mapping. A value
// check that failed on a rename would cry wolf on every job.
func TestValueCheck_RenameIsNotAFailure(t *testing.T) {
	src := &fwir.Config{Contexts: []fwir.Context{{Objects: fwir.Objects{Networks: []fwir.NetObject{
		{Name: "LAN NET", Kind: fwir.NetSubnet, Value: "10.10.0.0/16"},
	}}}}}
	rt := &fwir.Config{Contexts: []fwir.Context{{Objects: fwir.Objects{Networks: []fwir.NetObject{
		{Name: "LAN_NET", Kind: fwir.NetSubnet, Value: "10.10.0.0/16"},
	}}}}}
	for _, vc := range buildValueChecks(src, rt) {
		if !vc.OK {
			t.Fatalf("%s failed on a pure rename: missing=%v", vc.Metric, vc.Missing)
		}
	}
}

// Generators legitimately add helper objects and split tcp-udp into two.
func TestValueCheck_ExtraTargetValuesAreNotAFailure(t *testing.T) {
	src := &fwir.Config{Contexts: []fwir.Context{{Objects: fwir.Objects{
		Services: []fwir.SvcObject{{Name: "WEB", Proto: "tcp-udp", Port: "443"}},
	}}}}
	rt := &fwir.Config{Contexts: []fwir.Context{{Objects: fwir.Objects{
		Services: []fwir.SvcObject{
			{Name: "WEB-tcp", Proto: "tcp", Port: "443"},
			{Name: "WEB-udp", Proto: "udp", Port: "443"},
			{Name: "RF-helper", Proto: "tcp", Port: "8443"},
		},
	}}}}
	for _, vc := range buildValueChecks(src, rt) {
		if !vc.OK {
			t.Fatalf("%s failed: missing=%v", vc.Metric, vc.Missing)
		}
	}
}

// A dropped route must be caught by value, not only by count.
func TestValueCheck_CatchesChangedRoute(t *testing.T) {
	mk := func(gw string) *fwir.Config {
		return &fwir.Config{Contexts: []fwir.Context{{Routes: []fwir.StaticRoute{
			{Dest: "10.0.0.0/8", Gateway: gw},
		}}}}
	}
	checks := buildValueChecks(mk("192.0.2.1"), mk("192.0.2.9"))
	for _, vc := range checks {
		if vc.Metric == "static routes" {
			if vc.OK {
				t.Fatal("a changed next hop passed the value check")
			}
			return
		}
	}
	t.Fatal("no static route check produced")
}

// Every pair we can round-trip must come back clean on the shipped test
// fixtures — this is the check that found the masking bug in the generators.
func TestValueCheck_AllRoundTrippablePairsAreClean(t *testing.T) {
	srcs := map[string]string{
		fwir.VendorASA:       "../testdata/asa-multictx.cfg",
		fwir.VendorPANOS:     "../testdata/panos-fw.txt",
		fwir.VendorFortiGate: "../testdata/fortigate-vdom.conf",
	}
	for sv, path := range srcs {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		cfg, err := parse.Parse(sv, []parse.Input{{Name: "c", Content: string(b)}})
		if err != nil {
			t.Fatal(err)
		}
		for _, tv := range []string{fwir.VendorASA, fwir.VendorPANOS, fwir.VendorFortiGate} {
			if tv == sv {
				continue
			}
			var results []*gen.Result
			for i := range cfg.Contexts {
				r, err := gen.Generate(tv, &cfg.Contexts[i], nil)
				if err != nil {
					t.Fatal(err)
				}
				results = append(results, r)
			}
			rv := BuildReview(cfg, tv, results)
			if len(rv.ValueChecks) == 0 {
				t.Fatalf("%s -> %s produced no value checks", sv, tv)
			}
			for _, vc := range rv.ValueChecks {
				if !vc.OK {
					t.Errorf("%s -> %s: %s missing %v", sv, tv, vc.Metric, vc.Missing)
				}
			}
		}
	}
}

// The generated ASA config must keep the host octets of an interface address.
// 203.0.113.2/29 written as "ip address 203.0.113.0" is not a smaller mistake
// than dropping the interface: the device cannot take a network address.
func TestGen_InterfaceAddressKeepsHostOctets(t *testing.T) {
	x := &fwir.Context{Name: "default", Interfaces: []fwir.Interface{
		{Name: "GigabitEthernet0/0", Kind: fwir.IfPhysical, IPs: []string{"203.0.113.2/29"}},
		{Name: "Port-channel1", Kind: fwir.IfAggregate, Members: []string{"Gi0/2", "Gi0/3"}, IPs: []string{"10.10.0.1/16"}},
	}}
	for _, target := range []string{fwir.VendorASA, fwir.VendorFortiGate} {
		r, err := gen.Generate(target, x, nil)
		if err != nil {
			t.Fatal(err)
		}
		all := ""
		for _, f := range r.Files {
			all += f.Content + "\n"
		}
		for _, want := range []string{"203.0.113.2", "10.10.0.1"} {
			if !strings.Contains(all, want) {
				t.Errorf("%s: generated config lost the host octets of %s", target, want)
			}
		}
		for _, bad := range []string{"203.0.113.0 255.255.255.248", "10.10.0.0 255.255.0.0"} {
			if strings.Contains(all, bad) {
				t.Errorf("%s: generated config wrote the network address %q as an interface address", target, bad)
			}
		}
	}
}

// "!" ends sub-mode on an ASA. A comment between "interface X" and its
// "ip address" line silently detaches the address from the interface.
func TestGenASA_NoCommentInsideInterfaceBlock(t *testing.T) {
	x := &fwir.Context{Name: "default", Interfaces: []fwir.Interface{
		{Name: "Port-channel1", Kind: fwir.IfAggregate, Members: []string{"Gi0/2"}, IPs: []string{"10.10.0.1/16"}},
	}}
	r, err := gen.Generate(fwir.VendorASA, x, nil)
	if err != nil {
		t.Fatal(err)
	}
	// A bare "!" after a block is the normal ASA separator. What must never
	// happen is an indented sub-command AFTER a "!" that follows "interface X":
	// by then the device has already left interface configuration mode.
	for _, f := range r.Files {
		inBlock, sawBang := false, false
		for _, ln := range strings.Split(f.Content, "\n") {
			switch {
			case strings.HasPrefix(ln, "interface "):
				inBlock, sawBang = true, false
			case inBlock && strings.HasPrefix(ln, "!"):
				sawBang = true
			case inBlock && sawBang && strings.HasPrefix(ln, " "):
				t.Fatalf("%q comes after a %q inside the interface block, so the device never applies it", ln, "!")
			case ln != "" && !strings.HasPrefix(ln, " ") && !strings.HasPrefix(ln, "!"):
				inBlock, sawBang = false, false
			}
		}
	}
}
