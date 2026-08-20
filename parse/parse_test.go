package parse

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nizartuanku/ruleforge/fwir"
)

func load(t *testing.T, name string) Input {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "testdata", name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return Input{Name: name, Content: string(b)}
}

func TestASAMultiContext(t *testing.T) {
	cfg, err := Parse(fwir.VendorASA, []Input{load(t, "asa-multictx.cfg")})
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Contexts) != 2 {
		t.Fatalf("want 2 contexts, got %d (%v)", len(cfg.Contexts), names(cfg))
	}
	dmz := cfg.Ctx("CTX-DMZ")
	if dmz == nil {
		t.Fatal("missing CTX-DMZ")
	}
	// interfaces: gi0/0, gi0/1.100 (subif), gi0/2, gi0/3, Port-channel1
	if got := len(dmz.Interfaces); got != 5 {
		t.Fatalf("CTX-DMZ interfaces = %d, want 5", got)
	}
	var pc *fwir.Interface
	for i := range dmz.Interfaces {
		if dmz.Interfaces[i].Name == "Port-channel1" {
			pc = &dmz.Interfaces[i]
		}
	}
	if pc == nil || pc.Kind != fwir.IfAggregate || len(pc.Members) != 2 {
		t.Fatalf("Port-channel1 wrong: %+v", pc)
	}
	sub := dmz.Interfaces[1]
	if sub.Kind != fwir.IfSubIf || sub.VlanID != 100 || sub.Parent != "GigabitEthernet0/1" {
		t.Fatalf("subif wrong: %+v", sub)
	}
	// objects
	if len(dmz.Objects.Networks) != 4 {
		t.Fatalf("networks = %d, want 4", len(dmz.Objects.Networks))
	}
	if o := dmz.Objects.FindNet("CDN-FQDN"); o == nil || o.Kind != fwir.NetFQDN || o.Value != "cdn.example.com" {
		t.Fatalf("fqdn object wrong: %+v", o)
	}
	if g := dmz.Objects.FindSvcGroup("WEB-PORTS"); g == nil || len(g.Members) != 3 {
		t.Fatalf("WEB-PORTS wrong: %+v", g)
	}
	// rules: 3 + 3
	if len(dmz.Rules) != 6 {
		t.Fatalf("rules = %d, want 6", len(dmz.Rules))
	}
	if dmz.Rules[0].Desc == "" || !dmz.Rules[0].Log || dmz.Rules[0].Action != "allow" {
		t.Fatalf("rule1 wrong: %+v", dmz.Rules[0])
	}
	if dmz.Rules[0].SrcZones[0] != "outside" {
		t.Fatalf("acl binding missing: %+v", dmz.Rules[0])
	}
	// NAT: object NAT ×2 + manual ×1
	if len(dmz.NATs) != 3 {
		t.Fatalf("nats = %d, want 3", len(dmz.NATs))
	}
	kinds := map[string]int{}
	for _, n := range dmz.NATs {
		kinds[n.Kind]++
	}
	if kinds[fwir.NATStatic] != 1 || kinds[fwir.NATDynamicPAT] != 1 || kinds[fwir.NATTwice] != 1 {
		t.Fatalf("nat kinds wrong: %v", kinds)
	}
	if len(dmz.Routes) != 2 {
		t.Fatalf("routes = %d, want 2", len(dmz.Routes))
	}
	// captured features: crypto, tunnel-group ×2, router ospf, snmp
	caps := map[string]bool{}
	for _, c := range dmz.Captured {
		caps[c.Category] = true
	}
	for _, want := range []string{fwir.CapVPN, fwir.CapDynRouting, fwir.CapMgmt} {
		if !caps[want] {
			t.Fatalf("captured missing %s: %+v", want, caps)
		}
	}
	corp := cfg.Ctx("CTX-CORP")
	if corp == nil || len(corp.Rules) != 1 || len(corp.Routes) != 1 {
		t.Fatalf("CTX-CORP wrong: %+v", corp)
	}
}

func TestPANOS(t *testing.T) {
	cfg, err := Parse(fwir.VendorPANOS, []Input{load(t, "panos-fw.txt")})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Hostname != "pan-edge" {
		t.Fatalf("hostname = %q", cfg.Hostname)
	}
	if len(cfg.Contexts) != 1 {
		t.Fatalf("contexts = %d, want 1", len(cfg.Contexts))
	}
	x := &cfg.Contexts[0]
	// interfaces: eth1/1, eth1/2, eth1/2.200, ae1, eth1/3, eth1/4
	if len(x.Interfaces) != 6 {
		t.Fatalf("interfaces = %d, want 6: %+v", len(x.Interfaces), ifNames(x))
	}
	var ae *fwir.Interface
	for i := range x.Interfaces {
		if x.Interfaces[i].Name == "ae1" {
			ae = &x.Interfaces[i]
		}
	}
	if ae == nil || ae.Kind != fwir.IfAggregate || len(ae.Members) != 2 {
		t.Fatalf("ae1 wrong: %+v", ae)
	}
	if len(x.Zones) != 3 {
		t.Fatalf("zones = %d, want 3", len(x.Zones))
	}
	if len(x.Objects.Networks) != 4 || len(x.Objects.NetGroups) != 1 {
		t.Fatalf("objects wrong: %d nets %d groups", len(x.Objects.Networks), len(x.Objects.NetGroups))
	}
	if len(x.Rules) != 3 {
		t.Fatalf("rules = %d, want 3", len(x.Rules))
	}
	web := x.Rules[0]
	if web.Name != "Allow-Web" || len(web.Apps) != 2 || web.Action != "allow" || !web.Log {
		t.Fatalf("Allow-Web wrong: %+v", web)
	}
	if x.Rules[2].Action != "deny" {
		t.Fatalf("Block-All wrong: %+v", x.Rules[2])
	}
	if len(x.NATs) != 2 {
		t.Fatalf("nats = %d, want 2", len(x.NATs))
	}
	if x.NATs[0].Kind != fwir.NATDynamicPAT || x.NATs[0].TransSrc != "interface" {
		t.Fatalf("SNAT wrong: %+v", x.NATs[0])
	}
	if x.NATs[1].TransDst != "SRV-APP" {
		t.Fatalf("DNAT wrong: %+v", x.NATs[1])
	}
	if len(x.Routes) != 2 {
		t.Fatalf("routes = %d, want 2 (%+v)", len(x.Routes), x.Routes)
	}
	caps := map[string]bool{}
	for _, c := range x.Captured {
		caps[c.Category] = true
	}
	if !caps[fwir.CapVPN] || !caps[fwir.CapHA] || !caps[fwir.CapCert] {
		t.Fatalf("captured missing: %v", caps)
	}
}

func TestFortiGateVDOM(t *testing.T) {
	cfg, err := Parse(fwir.VendorFortiGate, []Input{load(t, "fortigate-vdom.conf")})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Hostname != "fgt-core" {
		t.Fatalf("hostname = %q", cfg.Hostname)
	}
	if len(cfg.Contexts) != 2 {
		t.Fatalf("contexts = %d, want 2 (%v)", len(cfg.Contexts), names(cfg))
	}
	root := cfg.Ctx("root")
	if root == nil {
		t.Fatal("missing root vdom")
	}
	// root interfaces: port1, port2, agg1
	if len(root.Interfaces) != 3 {
		t.Fatalf("root interfaces = %d, want 3: %v", len(root.Interfaces), ifNames(root))
	}
	dmzvd := cfg.Ctx("DMZ-VD")
	if dmzvd == nil || len(dmzvd.Interfaces) != 1 || dmzvd.Interfaces[0].Kind != fwir.IfSubIf {
		t.Fatalf("DMZ-VD wrong: %+v", dmzvd)
	}
	if len(root.Zones) != 2 {
		t.Fatalf("zones = %d, want 2", len(root.Zones))
	}
	// networks: 4 + VIP alias object + SNAT pool object
	if len(root.Objects.Networks) != 6 {
		t.Fatalf("networks = %d, want 6: %+v", len(root.Objects.Networks), root.Objects.Networks)
	}
	if len(root.Rules) != 3 {
		t.Fatalf("rules = %d, want 3", len(root.Rules))
	}
	if root.Rules[2].Action != "deny" || !root.Rules[2].Log {
		t.Fatalf("deny-any wrong: %+v", root.Rules[2])
	}
	// NATs: VIP static + policy-2 pool SNAT
	if len(root.NATs) != 2 {
		t.Fatalf("nats = %d, want 2: %+v", len(root.NATs), root.NATs)
	}
	var vip, snat *fwir.NAT
	for i := range root.NATs {
		if root.NATs[i].Kind == fwir.NATStatic {
			vip = &root.NATs[i]
		}
		if root.NATs[i].Kind == fwir.NATDynamic {
			snat = &root.NATs[i]
		}
	}
	if vip == nil || vip.OrigDst != "198.18.0.25" || vip.TransDst != "10.70.5.25" {
		t.Fatalf("vip wrong: %+v", vip)
	}
	if snat == nil || snat.TransSrc != "SNAT-POOL" {
		t.Fatalf("snat wrong: %+v", snat)
	}
	if len(root.Routes) != 2 {
		t.Fatalf("routes = %d, want 2", len(root.Routes))
	}
	if root.Routes[0].Dest != "0.0.0.0/0" {
		t.Fatalf("default route wrong: %+v", root.Routes[0])
	}
	caps := map[string]bool{}
	for _, c := range root.Captured {
		caps[c.Category] = true
	}
	if !caps[fwir.CapVPN] {
		t.Fatalf("vpn phase1 not captured: %v", caps)
	}
	hasHA := false
	for _, c := range cfg.Contexts {
		for _, cc := range c.Captured {
			if cc.Category == fwir.CapHA {
				hasHA = true
			}
		}
	}
	if !hasHA {
		t.Fatal("HA not captured")
	}
}

func TestCheckPoint(t *testing.T) {
	cfg, err := Parse(fwir.VendorCheckPoint, []Input{
		load(t, "checkpoint-gaia.txt"),
		load(t, "checkpoint-access.json"),
		load(t, "checkpoint-nat.json"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Hostname != "cp-gw1" {
		t.Fatalf("hostname = %q", cfg.Hostname)
	}
	x := &cfg.Contexts[0]
	// interfaces: eth0, eth1, eth1.400, bond2 (eth2, eth3 created as members? bond only) —
	// gaia parse creates eth0, eth1, eth1.400, bond2
	if len(x.Interfaces) < 4 {
		t.Fatalf("interfaces = %d, want >= 4: %v", len(x.Interfaces), ifNames(x))
	}
	var bond *fwir.Interface
	for i := range x.Interfaces {
		if x.Interfaces[i].Name == "bond2" {
			bond = &x.Interfaces[i]
		}
	}
	if bond == nil || bond.Kind != fwir.IfAggregate || len(bond.Members) != 2 {
		t.Fatalf("bond2 wrong: %+v", bond)
	}
	if len(x.Routes) != 2 {
		t.Fatalf("routes = %d, want 2", len(x.Routes))
	}
	// rules from JSON (section flattened): 3
	if len(x.Rules) != 3 {
		t.Fatalf("rules = %d, want 3: %+v", len(x.Rules), x.Rules)
	}
	if x.Rules[0].Name != "Web to App" || x.Rules[0].Action != "allow" || !x.Rules[0].Log {
		t.Fatalf("rule1 wrong: %+v", x.Rules[0])
	}
	if len(x.Rules[0].DstAddrs) != 1 || x.Rules[0].DstAddrs[0] != "grp-app" {
		t.Fatalf("rule1 dst wrong: %+v", x.Rules[0].DstAddrs)
	}
	if x.Rules[2].Action != "deny" {
		t.Fatalf("cleanup wrong: %+v", x.Rules[2])
	}
	// objects
	if x.Objects.FindNet("srv-app-1") == nil || x.Objects.FindNetGroup("grp-app") == nil {
		t.Fatal("objects missing")
	}
	if s := x.Objects.FindSvc("https"); s == nil || s.Proto != "tcp" || s.Port != "443" {
		t.Fatalf("https svc wrong: %+v", s)
	}
	// NAT
	if len(x.NATs) != 2 {
		t.Fatalf("nats = %d, want 2", len(x.NATs))
	}
	if x.NATs[0].Kind != fwir.NATDynamicPAT || x.NATs[0].OrigSrc != "net-lan" {
		t.Fatalf("hide nat wrong: %+v", x.NATs[0])
	}
	if x.NATs[1].Kind != fwir.NATStatic || x.NATs[1].TransDst != "srv-app-1" {
		t.Fatalf("static nat wrong: %+v", x.NATs[1])
	}
	// VPN community captured
	found := false
	for _, c := range x.Captured {
		if c.Category == fwir.CapVPN {
			found = true
		}
	}
	if !found {
		t.Fatal("vpn community not captured")
	}
}

func TestDetectVendor(t *testing.T) {
	cases := map[string]string{
		"fortigate-vdom.conf": fwir.VendorFortiGate,
		"panos-fw.txt":        fwir.VendorPANOS,
		"asa-multictx.cfg":    fwir.VendorASA,
	}
	for f, want := range cases {
		if got := DetectVendor(load(t, f).Content); got != want {
			t.Errorf("%s detected as %q, want %q", f, got, want)
		}
	}
}

func names(cfg *fwir.Config) []string {
	var out []string
	for _, c := range cfg.Contexts {
		out = append(out, c.Name)
	}
	return out
}

func ifNames(x *fwir.Context) []string {
	var out []string
	for _, i := range x.Interfaces {
		out = append(out, i.Name)
	}
	return out
}
