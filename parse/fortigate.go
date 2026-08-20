package parse

import (
	"strings"

	"github.com/nizartuanku/ruleforge/fwir"
)

// ---- generic FortiOS block tree ----

type ftBlock struct {
	name     string              // "system interface", or edit key
	sets     map[string][]string // set key → values (quoted values unwrapped)
	children []*ftBlock          // config/edit blocks in order
	raw      []string
}

func (b *ftBlock) get(key string) string {
	if v, ok := b.sets[key]; ok && len(v) > 0 {
		return v[0]
	}
	return ""
}
func (b *ftBlock) getAll(key string) []string { return b.sets[key] }

func (b *ftBlock) child(name string) *ftBlock {
	for _, c := range b.children {
		if c.name == name {
			return c
		}
	}
	return nil
}

// parseFortiTree parses FortiOS config text into a block tree.
func parseFortiTree(text string) (*ftBlock, []string) {
	root := &ftBlock{name: "", sets: map[string][]string{}}
	stack := []*ftBlock{root}
	var unparsed []string
	for _, rawLine := range strings.Split(text, "\n") {
		line := strings.TrimSpace(strings.TrimRight(rawLine, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		top := stack[len(stack)-1]
		toks := ftTokens(line)
		if len(toks) == 0 {
			continue
		}
		switch toks[0] {
		case "config":
			nb := &ftBlock{name: strings.Join(toks[1:], " "), sets: map[string][]string{}}
			top.children = append(top.children, nb)
			stack = append(stack, nb)
		case "edit":
			nb := &ftBlock{name: strings.Join(toks[1:], " "), sets: map[string][]string{}}
			top.children = append(top.children, nb)
			stack = append(stack, nb)
		case "next", "end":
			if len(stack) > 1 {
				stack = stack[:len(stack)-1]
			}
		case "set":
			if len(toks) >= 2 {
				top.sets[toks[1]] = append(top.sets[toks[1]], toks[2:]...)
				top.raw = append(top.raw, line)
			}
		case "unset", "append":
			top.raw = append(top.raw, line)
		default:
			unparsed = append(unparsed, line)
		}
	}
	return root, unparsed
}

// ftTokens splits a FortiOS line honoring double quotes.
func ftTokens(line string) []string {
	var toks []string
	var cur strings.Builder
	inQuote := false
	for _, r := range line {
		switch {
		case r == '"':
			inQuote = !inQuote
			if !inQuote { // closing quote: emit even if empty
				toks = append(toks, cur.String())
				cur.Reset()
			}
		case !inQuote && (r == ' ' || r == '\t'):
			if cur.Len() > 0 {
				toks = append(toks, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 {
		toks = append(toks, cur.String())
	}
	return toks
}

// ---- FortiGate → IR ----

func parseFortiGateInputs(inputs []Input) (*fwir.Config, error) {
	cfg := &fwir.Config{Vendor: fwir.VendorFortiGate}
	for _, in := range inputs {
		root, unparsed := parseFortiTree(in.Content)
		hostname := parseFortiGlobalMeta(root)
		if hostname != "" && cfg.Hostname == "" {
			cfg.Hostname = hostname
		}
		vdomDecl := hasVDOMs(root)
		if vdomDecl {
			parseFortiVDOMs(cfg, root, unparsed)
		} else {
			x := &fwir.Context{Name: "default", Unparsed: unparsed}
			parseFortiSections(x, root)
			cfg.Contexts = append(cfg.Contexts, *x)
		}
	}
	for ci := range cfg.Contexts {
		x := &cfg.Contexts[ci]
		for j := range x.Rules {
			x.Rules[j].Index = j + 1
		}
		for j := range x.NATs {
			x.NATs[j].Index = j + 1
		}
	}
	return cfg, nil
}

func parseFortiGlobalMeta(root *ftBlock) string {
	// hostname lives in `config system global` → set hostname
	for _, c := range root.children {
		if c.name == "system global" {
			return c.get("hostname")
		}
		if c.name == "global" { // vdom-mode wrapper
			if g := c.child("system global"); g != nil {
				return g.get("hostname")
			}
		}
	}
	return ""
}

func hasVDOMs(root *ftBlock) bool {
	for _, c := range root.children {
		if c.name == "vdom" {
			return true
		}
	}
	return false
}

// parseFortiVDOMs handles multi-VDOM config: `config vdom / edit NAME /
// (sections…)` blocks plus a `config global` section whose interfaces carry
// `set vdom`.
func parseFortiVDOMs(cfg *fwir.Config, root *ftBlock, unparsed []string) {
	ctxByName := map[string]*fwir.Context{}
	var order []string
	getCtx := func(name string) *fwir.Context {
		if c, ok := ctxByName[name]; ok {
			return c
		}
		c := &fwir.Context{Name: name}
		ctxByName[name] = c
		order = append(order, name)
		return c
	}
	// interfaces from config global, assigned per `set vdom`
	for _, c := range root.children {
		if c.name != "global" {
			continue
		}
		if ifs := c.child("system interface"); ifs != nil {
			for _, e := range ifs.children {
				vd := e.get("vdom")
				if vd == "" {
					vd = "root"
				}
				parseFortiInterface(getCtx(vd), e)
			}
		}
		if ha := c.child("system ha"); ha != nil {
			getCtx("root").AddCaptured(fwir.CapHA, "system ha", "HA configuration", ha.raw...)
		}
	}
	for _, c := range root.children {
		if c.name != "vdom" {
			continue
		}
		for _, vd := range c.children {
			x := getCtx(vd.name)
			parseFortiSections(x, vd)
		}
	}
	if len(order) == 0 {
		x := &fwir.Context{Name: "default", Unparsed: unparsed}
		parseFortiSections(x, root)
		cfg.Contexts = append(cfg.Contexts, *x)
		return
	}
	ctxByName[order[0]].Unparsed = append(ctxByName[order[0]].Unparsed, unparsed...)
	for _, name := range order {
		cfg.Contexts = append(cfg.Contexts, *ctxByName[name])
	}
}

// parseFortiSections walks one scope (device or VDOM) and fills the context.
func parseFortiSections(x *fwir.Context, scope *ftBlock) {
	for _, sec := range scope.children {
		switch sec.name {
		case "system interface":
			for _, e := range sec.children {
				parseFortiInterface(x, e)
			}
		case "system zone":
			for _, e := range sec.children {
				x.Zones = append(x.Zones, fwir.Zone{Name: e.name, Interfaces: e.getAll("interface")})
			}
		case "firewall address":
			for _, e := range sec.children {
				parseFortiAddress(x, e)
			}
		case "firewall addrgrp":
			for _, e := range sec.children {
				x.Objects.NetGroups = append(x.Objects.NetGroups, fwir.Group{
					Name: e.name, Members: e.getAll("member"), Desc: e.get("comment"),
				})
			}
		case "firewall service custom":
			for _, e := range sec.children {
				parseFortiService(x, e)
			}
		case "firewall service group":
			for _, e := range sec.children {
				x.Objects.SvcGroups = append(x.Objects.SvcGroups, fwir.Group{
					Name: e.name, Members: e.getAll("member"), Desc: e.get("comment"),
				})
			}
		case "firewall policy":
			for _, e := range sec.children {
				parseFortiPolicy(x, e)
			}
		case "firewall vip":
			for _, e := range sec.children {
				parseFortiVIP(x, e)
			}
		case "firewall ippool":
			for _, e := range sec.children {
				parseFortiIPPool(x, e)
			}
		case "firewall central-snat-map":
			for _, e := range sec.children {
				parseFortiCentralSNAT(x, e)
			}
		case "router static":
			for _, e := range sec.children {
				parseFortiRoute(x, e)
			}
		case "router bgp", "router ospf", "router rip", "router isis":
			x.AddCaptured(fwir.CapDynRouting, sec.name, "dynamic routing ("+strings.TrimPrefix(sec.name, "router ")+")", flattenRaw(sec)...)
		case "vpn ipsec phase1-interface", "vpn ipsec phase2-interface", "vpn ipsec phase1", "vpn ipsec phase2":
			for _, e := range sec.children {
				x.AddCaptured(fwir.CapVPN, e.name, sec.name, e.raw...)
			}
		case "vpn ssl settings", "vpn ssl web portal":
			x.AddCaptured(fwir.CapVPN, sec.name, "SSL VPN", flattenRaw(sec)...)
		case "vpn certificate local", "vpn certificate ca", "certificate local":
			for _, e := range sec.children {
				x.AddCaptured(fwir.CapCert, e.name, "certificate", e.raw...)
			}
		case "system ha":
			x.AddCaptured(fwir.CapHA, "system ha", "HA configuration", sec.raw...)
		case "webfilter profile", "webfilter urlfilter":
			for _, e := range sec.children {
				x.AddCaptured(fwir.CapURLFilter, e.name, sec.name, e.raw...)
			}
		case "application list":
			for _, e := range sec.children {
				x.AddCaptured(fwir.CapAppID, e.name, "application control profile", e.raw...)
			}
		case "user local", "user group", "user ldap", "user radius":
			for _, e := range sec.children {
				x.AddCaptured(fwir.CapUserID, e.name, sec.name, e.raw...)
			}
		case "system global", "system settings", "system dns", "system ntp", "system snmp sysinfo", "log syslogd setting", "system admin":
			x.AddCaptured(fwir.CapMgmt, sec.name, "management/system setting", sec.raw...)
		case "system vdom-link", "system virtual-switch", "system switch-interface":
			x.AddCaptured(fwir.CapOther, sec.name, sec.name+" — review target L2 design", flattenRaw(sec)...)
		case "firewall schedule recurring", "firewall schedule onetime":
			for _, e := range sec.children {
				x.AddCaptured(fwir.CapOther, e.name, "schedule", e.raw...)
			}
		default:
			// keep whole unknown section as one captured item (recognised
			// syntax, unknown semantics) rather than line-noise.
			if len(sec.children) > 0 || len(sec.raw) > 0 {
				x.AddCaptured(fwir.CapOther, sec.name, "unmapped section", flattenRaw(sec)...)
			}
		}
	}
}

func flattenRaw(b *ftBlock) []string {
	out := append([]string{}, b.raw...)
	for _, c := range b.children {
		out = append(out, "edit "+c.name)
		out = append(out, flattenRaw(c)...)
	}
	if len(out) > 40 {
		out = append(out[:40], "… ("+itoa(len(out)-40)+" more lines)")
	}
	return out
}

func itoa(n int) string { return strings.TrimSpace(strings.ReplaceAll(strings.Repeat("", 0)+fmtInt(n), "", "")) }

func fmtInt(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

func parseFortiInterface(x *fwir.Context, e *ftBlock) {
	ifc := ensureIface(x, e.name)
	ifc.Raw = e.raw
	switch e.get("type") {
	case "aggregate":
		ifc.Kind = fwir.IfAggregate
		ifc.Members = e.getAll("member")
	case "vlan":
		ifc.Kind = fwir.IfSubIf
		ifc.Parent = e.get("interface")
		ifc.VlanID = atoi(e.get("vlanid"))
	case "loopback":
		ifc.Kind = fwir.IfLoopback
	case "tunnel":
		ifc.Kind = fwir.IfTunnel
	case "switch", "hard-switch", "software-switch":
		ifc.Kind = fwir.IfBridge
		ifc.Members = e.getAll("member")
	default:
		if ifc.Kind == "" {
			ifc.Kind = fwir.IfPhysical
		}
		if e.get("vlanid") != "" {
			ifc.Kind = fwir.IfSubIf
			ifc.Parent = e.get("interface")
			ifc.VlanID = atoi(e.get("vlanid"))
		}
	}
	if ipToks := e.getAll("ip"); len(ipToks) >= 2 {
		if cidr, err := fwir.CIDRFromIPMask(ipToks[0], ipToks[1]); err == nil {
			ifc.IPs = appendUnique(ifc.IPs, cidr)
		}
	}
	if a := e.get("alias"); a != "" {
		ifc.Alias = a
	}
	if d := e.get("description"); d != "" {
		ifc.Desc = d
	}
	if e.get("status") == "down" {
		ifc.Shutdown = true
	}
	ifc.MTU = atoi(e.get("mtu"))
}

func parseFortiAddress(x *fwir.Context, e *ftBlock) {
	obj := fwir.NetObject{Name: e.name, Desc: e.get("comment")}
	switch e.get("type") {
	case "iprange":
		obj.Kind, obj.Value, obj.Value2 = fwir.NetRange, e.get("start-ip"), e.get("end-ip")
	case "fqdn":
		obj.Kind, obj.Value = fwir.NetFQDN, e.get("fqdn")
	case "dynamic", "interface-subnet", "mac":
		x.AddCaptured(fwir.CapOther, e.name, "address type "+e.get("type")+" — resolve manually", e.raw...)
		return
	default: // ipmask (default type)
		toks := e.getAll("subnet")
		if len(toks) >= 2 {
			if cidr, err := fwir.CIDRFromIPMask(toks[0], toks[1]); err == nil {
				if fwir.IsHostCIDR(cidr) {
					obj.Kind, obj.Value = fwir.NetHost, fwir.HostPart(cidr)
				} else {
					obj.Kind, obj.Value = fwir.NetSubnet, cidr
				}
			}
		} else if len(toks) == 1 { // "10.0.0.0/24" single-token form
			if fwir.IsHostCIDR(toks[0]) {
				obj.Kind, obj.Value = fwir.NetHost, fwir.HostPart(toks[0])
			} else {
				obj.Kind, obj.Value = fwir.NetSubnet, toks[0]
			}
		}
	}
	if obj.Kind == "" {
		if e.name == "all" {
			return // implicit
		}
		x.Unparsed = append(x.Unparsed, "firewall address "+e.name)
		return
	}
	x.Objects.Networks = append(x.Objects.Networks, obj)
}

func parseFortiService(x *fwir.Context, e *ftBlock) {
	obj := fwir.SvcObject{Name: e.name, Desc: e.get("comment")}
	if v := e.get("tcp-portrange"); v != "" {
		obj.Proto, obj.Port = "tcp", normalizeFortiPort(v)
		if u := e.get("udp-portrange"); u != "" {
			obj.Proto = "tcp-udp"
			// when both differ the object is split by the generator; record udp port too
			if normalizeFortiPort(u) != obj.Port {
				obj.Desc = strings.TrimSpace(obj.Desc + " [udp:" + normalizeFortiPort(u) + "]")
			}
		}
	} else if v := e.get("udp-portrange"); v != "" {
		obj.Proto, obj.Port = "udp", normalizeFortiPort(v)
	} else if v := e.get("sctp-portrange"); v != "" {
		obj.Proto, obj.Port = "sctp", normalizeFortiPort(v)
	} else {
		switch strings.ToUpper(e.get("protocol")) {
		case "ICMP", "ICMP6":
			obj.Proto = "icmp"
			obj.ICMPType = e.get("icmptype")
		case "IP":
			obj.Proto = "ip"
			if n := e.get("protocol-number"); n != "" && n != "0" {
				obj.Proto = n
			}
		default:
			if e.name == "ALL" {
				return // implicit any
			}
			x.AddCaptured(fwir.CapOther, e.name, "service protocol "+e.get("protocol")+" — review", e.raw...)
			return
		}
	}
	x.Objects.Services = append(x.Objects.Services, obj)
}

// normalizeFortiPort turns "443" or "8080-8090" or "443:1024-65535" (dst:src)
// into the destination part; multiple space-separated ranges keep the first
// and note the rest via return (callers store only dst).
func normalizeFortiPort(v string) string {
	first := strings.Fields(v)[0]
	if i := strings.IndexByte(first, ':'); i > 0 {
		first = first[:i]
	}
	return first
}

func parseFortiPolicy(x *fwir.Context, e *ftBlock) {
	r := fwir.Rule{
		Name:    e.get("name"),
		Enabled: e.get("status") != "disable",
		Action:  "deny",
		Desc:    e.get("comments"),
		Raw:     "firewall policy " + e.name,
	}
	if r.Name == "" {
		r.Name = "policy-" + e.name
	}
	if e.get("action") == "accept" {
		r.Action = "allow"
	}
	for _, z := range e.getAll("srcintf") {
		if z != "any" {
			r.SrcZones = append(r.SrcZones, z)
		}
	}
	for _, z := range e.getAll("dstintf") {
		if z != "any" {
			r.DstZones = append(r.DstZones, z)
		}
	}
	for _, a := range e.getAll("srcaddr") {
		if a != "all" {
			r.SrcAddrs = append(r.SrcAddrs, fwir.Ref(a))
		}
	}
	for _, a := range e.getAll("dstaddr") {
		if a != "all" {
			r.DstAddrs = append(r.DstAddrs, fwir.Ref(a))
		}
	}
	for _, s := range e.getAll("service") {
		if s != "ALL" {
			r.Services = append(r.Services, fwir.SvcRef(s))
		}
	}
	switch e.get("logtraffic") {
	case "all", "utm":
		r.Log = true
	}
	if al := e.get("application-list"); al != "" {
		x.AddCaptured(fwir.CapAppID, r.Name, "application-list "+al+" attached to policy", "firewall policy "+e.name)
	}
	if wf := e.get("webfilter-profile"); wf != "" {
		x.AddCaptured(fwir.CapURLFilter, r.Name, "webfilter-profile "+wf+" attached to policy", "firewall policy "+e.name)
	}
	x.Rules = append(x.Rules, r)

	// Policy-embedded NAT: `set nat enable` = source PAT to egress interface,
	// optionally via ippool.
	if e.get("nat") == "enable" {
		n := fwir.NAT{
			Name: "policy-" + e.name + "-snat", Enabled: r.Enabled, Kind: fwir.NATDynamicPAT,
			SrcIface: strings.Join(r.SrcZones, ","), DstIface: strings.Join(r.DstZones, ","),
			TransSrc: "interface",
			Raw:      "firewall policy " + e.name + " (set nat enable)",
		}
		if len(r.SrcAddrs) == 1 {
			n.OrigSrc = r.SrcAddrs[0]
		}
		if e.get("ippool") == "enable" {
			if pn := e.get("poolname"); pn != "" {
				n.Kind = fwir.NATDynamic
				n.TransSrc = fwir.Ref(pn)
			}
		}
		x.NATs = append(x.NATs, n)
	}
}

func parseFortiVIP(x *fwir.Context, e *ftBlock) {
	// VIP = destination NAT object; also usable as address in policies.
	ext := e.get("extip")
	mapped := e.get("mappedip")
	n := fwir.NAT{
		Name: e.name, Enabled: true, Kind: fwir.NATStatic,
		DstIface: e.get("extintf"),
		OrigDst:  fwir.Ref(ext),
		TransDst: fwir.Ref(strings.SplitN(mapped, "-", 2)[0]),
		Raw:      "firewall vip " + e.name,
		Desc:     e.get("comment"),
	}
	if e.get("portforward") == "enable" {
		proto := e.get("protocol")
		if proto == "" {
			proto = "tcp"
		}
		n.OrigSvc = fwir.SvcLiteral(proto, e.get("extport"))
		n.TransSvc = fwir.SvcLiteral(proto, e.get("mappedport"))
	}
	// register the VIP name as a host object so policies referencing it resolve
	if mapped != "" {
		x.Objects.Networks = append(x.Objects.Networks, fwir.NetObject{
			Name: e.name, Kind: fwir.NetHost, Value: strings.SplitN(mapped, "-", 2)[0],
			Desc: "VIP (dst-NAT) external " + ext,
		})
	}
	x.NATs = append(x.NATs, n)
}

func parseFortiIPPool(x *fwir.Context, e *ftBlock) {
	// ippool defines a pool; referenced from policies. Store as range object;
	// central-snat/policy nat reference it by name.
	x.Objects.Networks = append(x.Objects.Networks, fwir.NetObject{
		Name: e.name, Kind: fwir.NetRange, Value: e.get("startip"), Value2: e.get("endip"),
		Desc: "NAT ippool",
	})
}

func parseFortiCentralSNAT(x *fwir.Context, e *ftBlock) {
	n := fwir.NAT{
		Name: "central-snat-" + e.name, Enabled: e.get("status") != "disable",
		Kind:     fwir.NATDynamicPAT,
		SrcIface: strings.Join(e.getAll("srcintf"), ","),
		DstIface: strings.Join(e.getAll("dstintf"), ","),
		Raw:      "firewall central-snat-map " + e.name,
	}
	if v := e.getAll("orig-addr"); len(v) > 0 && v[0] != "all" {
		n.OrigSrc = fwir.Ref(v[0])
	}
	if e.get("nat-ippool") != "" {
		n.Kind = fwir.NATDynamic
		n.TransSrc = fwir.Ref(e.get("nat-ippool"))
	} else {
		n.TransSrc = "interface"
	}
	x.NATs = append(x.NATs, n)
}

func parseFortiRoute(x *fwir.Context, e *ftBlock) {
	r := fwir.StaticRoute{Iface: e.get("device"), Gateway: e.get("gateway"), Metric: atoi(e.get("distance")), Raw: "router static " + e.name}
	toks := e.getAll("dst")
	switch {
	case len(toks) >= 2:
		if cidr, err := fwir.CIDRFromIPMask(toks[0], toks[1]); err == nil {
			r.Dest = cidr
		}
	case len(toks) == 1:
		r.Dest = toks[0]
	default:
		r.Dest = "0.0.0.0/0"
	}
	if r.Dest == "" {
		x.Unparsed = append(x.Unparsed, "router static edit "+e.name)
		return
	}
	x.Routes = append(x.Routes, r)
}
