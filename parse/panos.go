package parse

import (
	"strconv"
	"strings"

	"github.com/nizartuanku/ruleforge/fwir"
)

// parsePANOSInputs parses PAN-OS "set" format configuration — firewall
// (with or without vsys) and Panorama (device-groups + shared + templates).
func parsePANOSInputs(inputs []Input) (*fwir.Config, error) {
	cfg := &fwir.Config{Vendor: fwir.VendorPANOS}
	p := &panParser{
		contexts: map[string]*fwir.Context{},
		order:    []string{},
	}
	for _, in := range inputs {
		for _, raw := range strings.Split(in.Content, "\n") {
			line := strings.TrimSpace(strings.TrimRight(raw, "\r"))
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			p.line(cfg, line)
		}
	}
	// shared objects merge into every device-group context.
	if shared, ok := p.contexts["shared"]; ok && len(p.order) > 1 {
		for _, name := range p.order {
			if name == "shared" {
				continue
			}
			c := p.contexts[name]
			c.Objects.Networks = append(dupNets(shared.Objects.Networks), c.Objects.Networks...)
			c.Objects.Services = append(dupSvcs(shared.Objects.Services), c.Objects.Services...)
			c.Objects.NetGroups = append(dupGroups(shared.Objects.NetGroups), c.Objects.NetGroups...)
			c.Objects.SvcGroups = append(dupGroups(shared.Objects.SvcGroups), c.Objects.SvcGroups...)
		}
		if emptyPolicy(shared) {
			// shared carries no policy of its own — fold its captured
			// features and unparsed lines into the first real context so
			// nothing is lost, then drop it.
			first := p.contexts[firstNonShared(p.order)]
			if first != nil {
				first.Captured = append(first.Captured, shared.Captured...)
				first.Unparsed = append(first.Unparsed, shared.Unparsed...)
			}
			delete(p.contexts, "shared")
			p.order = remove(p.order, "shared")
		}
	}
	for _, name := range p.order {
		c := p.contexts[name]
		for j := range c.Rules {
			c.Rules[j].Index = j + 1
		}
		for j := range c.NATs {
			c.NATs[j].Index = j + 1
		}
		cfg.Contexts = append(cfg.Contexts, *c)
	}
	if len(cfg.Contexts) == 0 {
		cfg.Contexts = []fwir.Context{{Name: "default"}}
	}
	return cfg, nil
}

func dupNets(in []fwir.NetObject) []fwir.NetObject { out := make([]fwir.NetObject, len(in)); copy(out, in); return out }
func dupSvcs(in []fwir.SvcObject) []fwir.SvcObject { out := make([]fwir.SvcObject, len(in)); copy(out, in); return out }
func dupGroups(in []fwir.Group) []fwir.Group       { out := make([]fwir.Group, len(in)); copy(out, in); return out }

func emptyPolicy(c *fwir.Context) bool {
	return len(c.Rules) == 0 && len(c.NATs) == 0 && len(c.Interfaces) == 0 && len(c.Routes) == 0
}

func firstNonShared(order []string) string {
	for _, n := range order {
		if n != "shared" {
			return n
		}
	}
	return ""
}

func remove(ss []string, v string) []string {
	var out []string
	for _, s := range ss {
		if s != v {
			out = append(out, s)
		}
	}
	return out
}

type panParser struct {
	contexts map[string]*fwir.Context
	order    []string
}

func (p *panParser) ctx(name string) *fwir.Context {
	if c, ok := p.contexts[name]; ok {
		return c
	}
	c := &fwir.Context{Name: name}
	p.contexts[name] = c
	p.order = append(p.order, name)
	return c
}

// line routes one `set …` line to the right context and section.
func (p *panParser) line(cfg *fwir.Config, line string) {
	toks := panTokens(line)
	if len(toks) < 2 || toks[0] != "set" {
		if len(toks) > 0 && (toks[0] == "delete" || toks[0] == "edit" || toks[0] == "quit" || toks[0] == "exit" || toks[0] == "top") {
			return
		}
		p.ctx("default").Unparsed = append(p.ctx("default").Unparsed, line)
		return
	}
	rest := toks[1:]
	ctxName := "default"
	switch rest[0] {
	case "device-group":
		if len(rest) < 3 {
			return
		}
		ctxName = rest[1]
		rest = rest[2:]
	case "shared":
		ctxName = "shared"
		rest = rest[1:]
	case "vsys":
		if len(rest) < 3 {
			return
		}
		ctxName = rest[1]
		rest = rest[2:]
	case "template":
		if len(rest) < 3 {
			return
		}
		ctxName = "template:" + rest[1]
		rest = rest[2:]
		// template lines wrap a nested `config … devices …/vsys …` path; strip it.
		rest = stripTemplateWrapper(rest)
		if len(rest) == 0 {
			return
		}
	}
	x := p.ctx(ctxName)
	p.section(cfg, x, rest, line)
}

// stripTemplateWrapper removes `config devices <id> [vsys <name>]` prefixes
// found in Panorama template set-lines.
func stripTemplateWrapper(rest []string) []string {
	if len(rest) > 0 && rest[0] == "config" {
		rest = rest[1:]
	}
	if len(rest) >= 2 && rest[0] == "devices" {
		rest = rest[2:]
	}
	if len(rest) >= 2 && rest[0] == "vsys" {
		rest = rest[2:]
	}
	return rest
}

func (p *panParser) section(cfg *fwir.Config, x *fwir.Context, rest []string, raw string) {
	if len(rest) == 0 {
		return
	}
	switch rest[0] {
	case "deviceconfig":
		if len(rest) >= 4 && rest[1] == "system" && rest[2] == "hostname" {
			cfg.Hostname = rest[3]
			return
		}
		if len(rest) >= 2 && rest[1] == "high-availability" {
			x.AddCaptured(fwir.CapHA, "high-availability", "HA configuration", raw)
			return
		}
		x.AddCaptured(fwir.CapMgmt, "deviceconfig", "device/system setting", raw)
	case "address":
		p.address(x, rest[1:], raw)
	case "address-group":
		p.addressGroup(x, rest[1:], raw)
	case "service":
		p.service(x, rest[1:], raw)
	case "service-group":
		p.serviceGroup(x, rest[1:], raw)
	case "zone":
		p.zone(x, rest[1:], raw)
	case "network":
		p.network(x, rest[1:], raw)
	case "rulebase", "pre-rulebase", "post-rulebase":
		p.rulebase(x, rest, raw)
	case "profiles":
		cat := fwir.CapOther
		det := "security profile"
		if len(rest) >= 2 && rest[1] == "url-filtering" {
			cat, det = fwir.CapURLFilter, "URL filtering profile"
		}
		x.AddCaptured(cat, tokAt(rest, 2), det, raw)
	case "certificate", "certificate-profile", "ssl-tls-service-profile":
		x.AddCaptured(fwir.CapCert, tokAt(rest, 1), "certificate configuration", raw)
	case "user-id-agent", "user-id-collector":
		x.AddCaptured(fwir.CapUserID, tokAt(rest, 1), "User-ID", raw)
	case "application", "application-group", "application-filter":
		x.AddCaptured(fwir.CapAppID, tokAt(rest, 1), "custom application object", raw)
	case "tag", "log-settings", "schedule":
		x.AddCaptured(fwir.CapOther, rest[0], rest[0]+" configuration", raw)
	case "mgt-config", "devices", "readonly":
		// panorama admin scaffolding
		return
	default:
		x.Unparsed = append(x.Unparsed, raw)
	}
}

func (p *panParser) address(x *fwir.Context, t []string, raw string) {
	if len(t) < 2 {
		x.Unparsed = append(x.Unparsed, raw)
		return
	}
	name := t[0]
	obj := ensureNet(x, name)
	switch t[1] {
	case "ip-netmask":
		v := tokAt(t, 2)
		if fwir.IsHostCIDR(v) {
			obj.Kind, obj.Value = fwir.NetHost, fwir.HostPart(v)
		} else {
			obj.Kind, obj.Value = fwir.NetSubnet, v
		}
	case "ip-range":
		parts := strings.SplitN(tokAt(t, 2), "-", 2)
		obj.Kind = fwir.NetRange
		obj.Value = parts[0]
		if len(parts) == 2 {
			obj.Value2 = parts[1]
		}
	case "fqdn":
		obj.Kind, obj.Value = fwir.NetFQDN, tokAt(t, 2)
	case "description":
		obj.Desc = strings.Join(t[2:], " ")
	case "tag":
		// ignore
	default:
		x.Unparsed = append(x.Unparsed, raw)
	}
}

func ensureNet(x *fwir.Context, name string) *fwir.NetObject {
	if o := x.Objects.FindNet(name); o != nil {
		return o
	}
	x.Objects.Networks = append(x.Objects.Networks, fwir.NetObject{Name: name})
	return &x.Objects.Networks[len(x.Objects.Networks)-1]
}

func (p *panParser) addressGroup(x *fwir.Context, t []string, raw string) {
	if len(t) < 2 {
		return
	}
	name := t[0]
	g := x.Objects.FindNetGroup(name)
	if g == nil {
		x.Objects.NetGroups = append(x.Objects.NetGroups, fwir.Group{Name: name})
		g = &x.Objects.NetGroups[len(x.Objects.NetGroups)-1]
	}
	switch t[1] {
	case "static":
		g.Members = append(g.Members, t[2:]...)
	case "description":
		g.Desc = strings.Join(t[2:], " ")
	case "dynamic":
		x.AddCaptured(fwir.CapOther, name, "dynamic address group (tag-based) — resolve membership manually", raw)
	}
}

func (p *panParser) service(x *fwir.Context, t []string, raw string) {
	if len(t) < 2 {
		return
	}
	name := t[0]
	var obj *fwir.SvcObject
	if o := x.Objects.FindSvc(name); o != nil {
		obj = o
	} else {
		x.Objects.Services = append(x.Objects.Services, fwir.SvcObject{Name: name})
		obj = &x.Objects.Services[len(x.Objects.Services)-1]
	}
	// set service NAME protocol tcp port 443 [source-port N]
	for i := 1; i < len(t); i++ {
		switch t[i] {
		case "protocol":
			if i+1 < len(t) {
				obj.Proto = t[i+1]
			}
		case "port":
			obj.Port = tokAt(t, i+1)
		case "source-port":
			obj.SrcPort = tokAt(t, i+1)
		case "description":
			obj.Desc = strings.Join(t[i+1:], " ")
			return
		}
	}
}

func (p *panParser) serviceGroup(x *fwir.Context, t []string, raw string) {
	if len(t) < 2 {
		return
	}
	name := t[0]
	g := x.Objects.FindSvcGroup(name)
	if g == nil {
		x.Objects.SvcGroups = append(x.Objects.SvcGroups, fwir.Group{Name: name})
		g = &x.Objects.SvcGroups[len(x.Objects.SvcGroups)-1]
	}
	if t[1] == "members" {
		g.Members = append(g.Members, t[2:]...)
	}
}

func (p *panParser) zone(x *fwir.Context, t []string, raw string) {
	if len(t) < 1 {
		return
	}
	name := t[0]
	var z *fwir.Zone
	for i := range x.Zones {
		if x.Zones[i].Name == name {
			z = &x.Zones[i]
			break
		}
	}
	if z == nil {
		x.Zones = append(x.Zones, fwir.Zone{Name: name})
		z = &x.Zones[len(x.Zones)-1]
	}
	// set zone Z network layer3 [ eth1/1 eth1/2 ]
	for i := 1; i < len(t); i++ {
		if t[i] == "layer3" || t[i] == "layer2" || t[i] == "virtual-wire" {
			z.Interfaces = append(z.Interfaces, t[i+1:]...)
			return
		}
	}
}

func (p *panParser) network(x *fwir.Context, t []string, raw string) {
	if len(t) == 0 {
		return
	}
	switch t[0] {
	case "interface":
		p.netInterface(x, t[1:], raw)
	case "virtual-router":
		// set network virtual-router default routing-table ip static-route NAME destination D nexthop ip-address G / interface I / metric M
		if contains(t, "static-route") {
			p.staticRoute(x, t, raw)
			return
		}
		if contains(t, "bgp") || contains(t, "ospf") || contains(t, "rip") {
			x.AddCaptured(fwir.CapDynRouting, tokAt(t, 1), "dynamic routing on virtual-router", raw)
			return
		}
		x.AddCaptured(fwir.CapOther, tokAt(t, 1), "virtual-router setting", raw)
	case "ike", "tunnel":
		x.AddCaptured(fwir.CapVPN, strings.Join(t[:min(3, len(t))], " "), "IPsec/IKE VPN", raw)
	case "vlan":
		x.AddCaptured(fwir.CapOther, tokAt(t, 1), "L2 vlan bridging", raw)
	case "dns-proxy", "dhcp", "qos":
		x.AddCaptured(fwir.CapMgmt, t[0], t[0]+" configuration", raw)
	case "profiles":
		x.AddCaptured(fwir.CapOther, tokAt(t, 1), "network profile (zone-protection/mgmt)", raw)
	default:
		x.Unparsed = append(x.Unparsed, raw)
	}
}

func (p *panParser) netInterface(x *fwir.Context, t []string, raw string) {
	if len(t) < 2 {
		return
	}
	kindTok := t[0] // ethernet | aggregate-ethernet | loopback | tunnel | vlan
	name := t[1]
	rest := t[2:]
	ifc := ensureIface(x, name)
	switch kindTok {
	case "ethernet":
		if ifc.Kind == "" {
			ifc.Kind = fwir.IfPhysical
		}
	case "aggregate-ethernet":
		ifc.Kind = fwir.IfAggregate
	case "loopback":
		ifc.Kind = fwir.IfLoopback
	case "tunnel":
		ifc.Kind = fwir.IfTunnel
	case "vlan":
		ifc.Kind = fwir.IfVLAN
	}
	for i := 0; i < len(rest); i++ {
		switch rest[i] {
		case "layer3":
			// possibly followed by units / ip / etc.
		case "units":
			// sub-interface: set … units ethX.Y tag N / ip A
			if i+1 < len(rest) {
				sub := ensureIface(x, rest[i+1])
				sub.Kind = fwir.IfSubIf
				sub.Parent = name
				for j := i + 2; j < len(rest); j++ {
					switch rest[j] {
					case "tag":
						sub.VlanID = atoi(tokAt(rest, j+1))
					case "ip":
						if v := tokAt(rest, j+1); v != "" {
							sub.IPs = appendUnique(sub.IPs, v)
						}
					case "comment":
						sub.Desc = strings.Join(rest[j+1:], " ")
					}
				}
			}
			return
		case "ip":
			if v := tokAt(rest, i+1); v != "" && v != "address" {
				ifc.IPs = appendUnique(ifc.IPs, v)
			}
		case "aggregate-group":
			ag := tokAt(rest, i+1)
			agg := ensureIface(x, ag)
			agg.Kind = fwir.IfAggregate
			agg.Members = appendUnique(agg.Members, name)
		case "comment":
			ifc.Desc = strings.Join(rest[i+1:], " ")
			return
		case "mtu":
			ifc.MTU = atoi(tokAt(rest, i+1))
		case "link-state":
			if tokAt(rest, i+1) == "down" {
				ifc.Shutdown = true
			}
		}
	}
}

func (p *panParser) staticRoute(x *fwir.Context, t []string, raw string) {
	r := fwir.StaticRoute{Raw: raw}
	for i := 0; i < len(t); i++ {
		switch t[i] {
		case "static-route":
			r.Desc = tokAt(t, i+1) // route name
		case "destination":
			r.Dest = tokAt(t, i+1)
		case "ip-address":
			r.Gateway = tokAt(t, i+1)
		case "interface":
			r.Iface = tokAt(t, i+1)
		case "metric":
			r.Metric = atoi(tokAt(t, i+1))
		}
	}
	if r.Dest == "" {
		x.Unparsed = append(x.Unparsed, raw)
		return
	}
	// merge fragments of the same route (set-format spreads one route over lines)
	for i := range x.Routes {
		if x.Routes[i].Desc == r.Desc && x.Routes[i].Dest == r.Dest || (x.Routes[i].Desc == r.Desc && r.Dest == "") {
			if r.Gateway != "" {
				x.Routes[i].Gateway = r.Gateway
			}
			if r.Iface != "" {
				x.Routes[i].Iface = r.Iface
			}
			if r.Metric != 0 {
				x.Routes[i].Metric = r.Metric
			}
			return
		}
	}
	x.Routes = append(x.Routes, r)
}

func (p *panParser) rulebase(x *fwir.Context, t []string, raw string) {
	// [pre-|post-]rulebase security rules NAME field values…
	// [pre-|post-]rulebase nat rules NAME field values…
	if len(t) < 4 {
		x.Unparsed = append(x.Unparsed, raw)
		return
	}
	kind := t[1] // security | nat | …
	if t[2] != "rules" {
		if kind == "default-security-rules" {
			return
		}
		x.AddCaptured(fwir.CapOther, kind, "rulebase section "+kind, raw)
		return
	}
	name := t[3]
	rest := t[4:]
	switch kind {
	case "security":
		r := ensureRule(x, name)
		p.secRuleFields(x, r, rest, raw)
	case "nat":
		n := ensureNAT(x, name)
		p.natRuleFields(n, rest)
	default:
		x.AddCaptured(fwir.CapOther, name, "rulebase "+kind+" rule", raw)
	}
}

func ensureIface(x *fwir.Context, name string) *fwir.Interface {
	for i := range x.Interfaces {
		if x.Interfaces[i].Name == name {
			return &x.Interfaces[i]
		}
	}
	x.Interfaces = append(x.Interfaces, fwir.Interface{Name: name, SecLevel: -1})
	return &x.Interfaces[len(x.Interfaces)-1]
}

func ensureRule(x *fwir.Context, name string) *fwir.Rule {
	for i := range x.Rules {
		if x.Rules[i].Name == name {
			return &x.Rules[i]
		}
	}
	x.Rules = append(x.Rules, fwir.Rule{Name: name, Enabled: true, Action: "allow"})
	return &x.Rules[len(x.Rules)-1]
}

func ensureNAT(x *fwir.Context, name string) *fwir.NAT {
	for i := range x.NATs {
		if x.NATs[i].Name == name {
			return &x.NATs[i]
		}
	}
	x.NATs = append(x.NATs, fwir.NAT{Name: name, Enabled: true, Kind: fwir.NATTwice})
	return &x.NATs[len(x.NATs)-1]
}

// panSecKeywords are the security-rule field names; a single set-line may
// carry several fields back to back ("… from A to B source X action allow"),
// so fields are chunked at keyword boundaries.
var panSecKeywords = map[string]bool{
	"from": true, "to": true, "source": true, "destination": true, "service": true,
	"application": true, "category": true, "action": true, "log-end": true, "log-start": true,
	"disabled": true, "description": true, "profile-setting": true, "source-user": true,
	"tag": true, "group-tag": true, "rule-type": true, "negate-source": true,
	"negate-destination": true, "log-setting": true, "source-hip": true, "destination-hip": true,
}

var panNATKeywords = map[string]bool{
	"from": true, "to": true, "source": true, "destination": true, "service": true,
	"source-translation": true, "destination-translation": true, "disabled": true,
	"description": true, "to-interface": true, "nat-type": true, "tag": true,
}

// chunkFields splits a token tail into (keyword, values…) groups. description
// greedily consumes the rest of the line.
func chunkFields(t []string, keywords map[string]bool) [][]string {
	var out [][]string
	i := 0
	for i < len(t) {
		if !keywords[t[i]] {
			i++ // stray token: skip (kept in raw)
			continue
		}
		key := t[i]
		j := i + 1
		if key == "description" {
			out = append(out, t[i:])
			break
		}
		for j < len(t) && !keywords[t[j]] {
			j++
		}
		out = append(out, t[i:j])
		i = j
	}
	return out
}

func (p *panParser) secRuleFields(x *fwir.Context, r *fwir.Rule, t []string, raw string) {
	for _, chunk := range chunkFields(t, panSecKeywords) {
		p.secRuleField(x, r, chunk, raw)
	}
	r.Raw = strings.TrimSpace(r.Raw + "\n" + raw)
}

func (p *panParser) secRuleField(x *fwir.Context, r *fwir.Rule, t []string, raw string) {
	if len(t) == 0 {
		return
	}
	vals := t[1:]
	switch t[0] {
	case "from":
		r.SrcZones = appendVals(r.SrcZones, vals)
	case "to":
		r.DstZones = appendVals(r.DstZones, vals)
	case "source":
		for _, v := range dropAny(vals) {
			r.SrcAddrs = append(r.SrcAddrs, fwir.Ref(v))
		}
	case "destination":
		for _, v := range dropAny(vals) {
			r.DstAddrs = append(r.DstAddrs, fwir.Ref(v))
		}
	case "service":
		for _, v := range vals {
			switch v {
			case "any":
			case "application-default":
				r.Desc = strings.TrimSpace(r.Desc + " [service application-default]")
			default:
				r.Services = append(r.Services, fwir.SvcRef(v))
			}
		}
	case "application":
		for _, v := range dropAny(vals) {
			r.Apps = append(r.Apps, v)
		}
	case "category":
		for _, v := range dropAny(vals) {
			r.URLCats = append(r.URLCats, v)
		}
	case "action":
		switch tokAt(vals, 0) {
		case "allow":
			r.Action = "allow"
		default: // deny, drop, reset-*
			r.Action = "deny"
		}
	case "log-end", "log-start":
		if tokAt(vals, 0) == "yes" {
			r.Log = true
		}
	case "disabled":
		if tokAt(vals, 0) == "yes" {
			r.Enabled = false
		}
	case "description":
		r.Desc = strings.TrimSpace(strings.Join(vals, " ") + " " + r.Desc)
	case "profile-setting":
		x.AddCaptured(fwir.CapOther, r.Name, "security-profile attached to rule "+r.Name, raw)
	case "source-user":
		if tokAt(vals, 0) != "any" {
			x.AddCaptured(fwir.CapUserID, r.Name, "User-ID condition on rule "+r.Name, raw)
		}
	case "tag", "group-tag", "rule-type", "negate-source", "negate-destination", "log-setting":
		// cosmetic / advanced; negate flagged:
		if strings.HasPrefix(t[0], "negate") && tokAt(vals, 0) == "yes" {
			x.AddCaptured(fwir.CapOther, r.Name, t[0]+" on rule — verify manually", raw)
		}
	}
}

func (p *panParser) natRuleFields(n *fwir.NAT, t []string) {
	for _, chunk := range chunkFields(t, panNATKeywords) {
		p.natRuleField(n, chunk)
	}
}

func (p *panParser) natRuleField(n *fwir.NAT, t []string) {
	if len(t) == 0 {
		return
	}
	vals := t[1:]
	switch t[0] {
	case "from":
		n.SrcIface = tokAt(vals, 0)
	case "to":
		n.DstIface = tokAt(vals, 0)
	case "source":
		if v := tokAt(vals, 0); v != "any" {
			n.OrigSrc = fwir.Ref(v)
		}
	case "destination":
		if v := tokAt(vals, 0); v != "any" {
			n.OrigDst = fwir.Ref(v)
		}
	case "service":
		if v := tokAt(vals, 0); v != "any" {
			n.OrigSvc = fwir.SvcRef(v)
		}
	case "source-translation":
		switch tokAt(vals, 0) {
		case "dynamic-ip-and-port":
			n.Kind = fwir.NATDynamicPAT
			if tokAt(vals, 1) == "interface-address" {
				n.TransSrc = "interface"
			} else if tokAt(vals, 1) == "translated-address" {
				n.TransSrc = fwir.Ref(tokAt(vals, 2))
			}
		case "dynamic-ip":
			n.Kind = fwir.NATDynamic
			if tokAt(vals, 1) == "translated-address" {
				n.TransSrc = fwir.Ref(tokAt(vals, 2))
			}
		case "static-ip":
			n.Kind = fwir.NATStatic
			for i := 1; i < len(vals); i++ {
				switch vals[i] {
				case "translated-address":
					n.TransSrc = fwir.Ref(tokAt(vals, i+1))
				case "bi-directional":
					n.Bidir = tokAt(vals, i+1) == "yes"
				}
			}
		}
	case "destination-translation":
		if n.Kind == "" || n.Kind == fwir.NATTwice {
			n.Kind = fwir.NATStatic
		}
		for i := 0; i < len(vals); i++ {
			switch vals[i] {
			case "translated-address":
				n.TransDst = fwir.Ref(tokAt(vals, i+1))
			case "translated-port":
				n.TransSvc = fwir.SvcLiteral("tcp", tokAt(vals, i+1))
			}
		}
	case "disabled":
		if tokAt(vals, 0) == "yes" {
			n.Enabled = false
		}
	case "description":
		n.Desc = strings.Join(vals, " ")
	}
}

func appendVals(dst []string, vals []string) []string {
	for _, v := range dropAny(vals) {
		dst = appendUnique(dst, v)
	}
	return dst
}

func dropAny(vals []string) []string {
	var out []string
	for _, v := range vals {
		if v != "any" && v != "" {
			out = append(out, v)
		}
	}
	return out
}

func appendUnique(dst []string, v string) []string {
	for _, d := range dst {
		if d == v {
			return dst
		}
	}
	return append(dst, v)
}

func contains(ss []string, v string) bool {
	for _, s := range ss {
		if s == v {
			return true
		}
	}
	return false
}

func tokAt(ss []string, i int) string {
	if i >= 0 && i < len(ss) {
		return ss[i]
	}
	return ""
}

func atoi(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}

// panTokens tokenizes a set-line: whitespace-separated, honoring "quoted
// strings" and flattening [ bracketed lists ] into plain tokens.
func panTokens(line string) []string {
	var toks []string
	var cur strings.Builder
	inQuote := false
	flush := func() {
		if cur.Len() > 0 {
			toks = append(toks, cur.String())
			cur.Reset()
		}
	}
	for _, r := range line {
		switch {
		case r == '"':
			inQuote = !inQuote
		case !inQuote && (r == ' ' || r == '\t'):
			flush()
		case !inQuote && (r == '[' || r == ']'):
			flush()
		default:
			cur.WriteRune(r)
		}
	}
	flush()
	return toks
}
