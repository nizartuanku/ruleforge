package gen

import (
	"fmt"
	"strings"

	"github.com/nizartuanku/ruleforge/fwir"
)

// genASA renders one context as Cisco ASA CLI.
func genASA(x *fwir.Context, m *Mapping) *Result {
	res := &Result{Context: x.Name}
	nm := newNamer(fwir.VendorASA)
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format+"\n", a...) }

	w("! RuleForge — generated Cisco ASA configuration")
	w("! Context: %s", x.Name)
	w("!")

	// helper objects created on demand (literals inside rules/NAT)
	helperObjs := map[string]string{} // helper name → definition lines
	helperOrder := []string{}
	ensureHelperNet := func(lit string) string {
		name := "RF-" + strings.NewReplacer("/", "-", ".", "_", ":", "_", "-", "_").Replace(lit)
		name = nm.name(name)
		if _, ok := helperObjs[name]; !ok {
			var def string
			if strings.Contains(lit, "-") && !strings.Contains(lit, "/") {
				parts := strings.SplitN(lit, "-", 2)
				def = fmt.Sprintf("object network %s\n range %s %s", name, parts[0], parts[1])
			} else if fwir.IsHostCIDR(lit) {
				def = fmt.Sprintf("object network %s\n host %s", name, fwir.HostPart(lit))
			} else {
				ip, mask, err := fwir.SplitCIDR(lit)
				if err != nil {
					return ""
				}
				def = fmt.Sprintf("object network %s\n subnet %s %s", name, ip, mask)
			}
			helperObjs[name] = def
			helperOrder = append(helperOrder, name)
		}
		return name
	}

	// ---- interfaces ----
	zoneNameif := map[string]string{} // zone → nameif chosen
	for _, z := range x.Zones {
		zoneNameif[z.Name] = m.MapZone(z.Name)
	}
	secLevel := func(ifc fwir.Interface) int {
		if ifc.SecLevel >= 0 {
			return ifc.SecLevel
		}
		l := strings.ToLower(firstNonEmpty(ifc.Zone, ifc.Alias))
		switch {
		case strings.Contains(l, "outside") || strings.Contains(l, "untrust") || strings.Contains(l, "wan") || strings.Contains(l, "internet"):
			return 0
		case strings.Contains(l, "dmz"):
			return 50
		}
		return 100
	}
	for _, ifc := range x.Interfaces {
		tgtName := m.MapIface(ifc.Name)
		status := StConverted
		detail := ""
		var lines []string
		lines = append(lines, "interface "+tgtName)
		switch ifc.Kind {
		case fwir.IfSubIf:
			if ifc.VlanID > 0 {
				lines = append(lines, fmt.Sprintf(" vlan %d", ifc.VlanID))
			}
		case fwir.IfAggregate:
			// Port-channel itself; members carry channel-group
			for _, mem := range ifc.Members {
				lines = append(lines, fmt.Sprintf("! member %s → interface %s / channel-group %s mode active",
					mem, m.MapIface(mem), strings.TrimPrefix(strings.ToLower(tgtName), "port-channel")))
			}
			detail = "verify channel-group numbering on member interfaces"
			if len(ifc.Members) > 0 {
				status = StPartial
			}
		case fwir.IfBridge:
			detail = "bridge: members must carry `bridge-group N`; BVI holds the IP"
			status = StPartial
		}
		alias := firstNonEmpty(ifc.Zone, ifc.Alias)
		if alias != "" {
			lines = append(lines, " nameif "+m.MapZone(alias))
			lines = append(lines, fmt.Sprintf(" security-level %d", secLevel(ifc)))
		}
		for _, ip := range ifc.IPs {
			ipAddr, mask, err := fwir.SplitCIDR(ip)
			if err == nil {
				lines = append(lines, fmt.Sprintf(" ip address %s %s", ipAddr, mask))
			}
		}
		if ifc.Desc != "" {
			lines = append(lines, " description "+ifc.Desc)
		}
		if ifc.Shutdown {
			lines = append(lines, " shutdown")
		} else {
			lines = append(lines, " no shutdown")
		}
		out := strings.Join(lines, "\n")
		w("%s\n!", out)
		res.Items = append(res.Items, Item{Category: "interface", Name: ifc.Name, Status: status, Detail: detail, Output: out})
	}

	// zones → nameif note (ASA has no separate zone object)
	for _, z := range x.Zones {
		res.Items = append(res.Items, Item{
			Category: "zone", Name: z.Name, Status: StConverted,
			Detail: "ASA models zones as interface nameif — mapped to nameif " + m.MapZone(z.Name),
		})
	}

	// ---- objects ----
	for _, o := range x.Objects.Networks {
		name := nm.name(o.Name)
		var def string
		switch o.Kind {
		case fwir.NetHost:
			def = " host " + o.Value
		case fwir.NetSubnet:
			ip, mask, err := fwir.SplitCIDR(o.Value)
			if err != nil {
				res.Items = append(res.Items, Item{Category: "object", Name: o.Name, Status: StFailed, Detail: "bad subnet " + o.Value})
				continue
			}
			def = fmt.Sprintf(" subnet %s %s", ip, mask)
		case fwir.NetRange:
			def = fmt.Sprintf(" range %s %s", o.Value, o.Value2)
		case fwir.NetFQDN:
			def = " fqdn v4 " + o.Value
		}
		out := "object network " + name + "\n" + def
		if o.Desc != "" {
			out += "\n description " + o.Desc
		}
		w("%s\n!", out)
		res.Items = append(res.Items, Item{Category: "object", Name: o.Name, Status: StConverted, Output: out})
	}
	for _, s := range x.Objects.Services {
		name := nm.name(s.Name)
		proto := s.Proto
		if proto == "tcp-udp" {
			proto = "tcp-udp"
		}
		var def string
		switch proto {
		case "icmp":
			def = " service icmp"
			if s.ICMPType != "" {
				def += " " + s.ICMPType
			}
		default:
			def = " service " + proto
			if s.SrcPort != "" {
				def += " source " + asaPortClause(s.SrcPort)
			}
			if s.Port != "" {
				def += " destination " + asaPortClause(s.Port)
			}
		}
		out := "object service " + name + "\n" + def
		w("%s\n!", out)
		res.Items = append(res.Items, Item{Category: "service", Name: s.Name, Status: StConverted, Output: out})
	}
	for _, g := range x.Objects.NetGroups {
		name := nm.name(g.Name)
		var lines []string
		lines = append(lines, "object-group network "+name)
		status := StConverted
		detail := ""
		for _, mem := range g.Members {
			switch {
			case x.Objects.FindNet(mem) != nil || x.Objects.FindNetGroup(mem) != nil:
				if x.Objects.FindNetGroup(mem) != nil {
					lines = append(lines, " group-object "+nm.lookup(mem))
				} else {
					lines = append(lines, " network-object object "+nm.lookup(mem))
				}
			case fwir.Ref(mem).IsLiteral():
				if fwir.IsHostCIDR(mem) {
					lines = append(lines, " network-object host "+fwir.HostPart(mem))
				} else if ip, mask, err := fwir.SplitCIDR(mem); err == nil {
					lines = append(lines, fmt.Sprintf(" network-object %s %s", ip, mask))
				} else {
					status, detail = StPartial, "member "+mem+" could not be rendered"
				}
			default:
				status, detail = StPartial, "member "+mem+" is not a defined object — verify"
				lines = append(lines, " ! unresolved member: "+mem)
			}
		}
		out := strings.Join(lines, "\n")
		w("%s\n!", out)
		res.Items = append(res.Items, Item{Category: "group", Name: g.Name, Status: status, Detail: detail, Output: out})
	}
	for _, g := range x.Objects.SvcGroups {
		name := nm.name(g.Name)
		var lines []string
		lines = append(lines, "object-group service "+name)
		status := StConverted
		detail := ""
		for _, mem := range g.Members {
			if x.Objects.FindSvc(mem) != nil {
				lines = append(lines, " service-object object "+nm.lookup(mem))
				continue
			}
			if x.Objects.FindSvcGroup(mem) != nil {
				lines = append(lines, " group-object "+nm.lookup(mem))
				continue
			}
			if proto, port, ok := fwir.SvcRef(mem).SplitSvcLiteral(); ok {
				if port != "" {
					lines = append(lines, fmt.Sprintf(" service-object %s destination %s", protoSplitFirst(proto), asaPortClause(port)))
				} else {
					lines = append(lines, " service-object "+protoSplitFirst(proto))
				}
				continue
			}
			status, detail = StPartial, "member "+mem+" unresolved — verify"
			lines = append(lines, " ! unresolved member: "+mem)
		}
		out := strings.Join(lines, "\n")
		w("%s\n!", out)
		res.Items = append(res.Items, Item{Category: "group", Name: g.Name, Status: status, Detail: detail, Output: out})
	}

	// ---- access rules ----
	// Group rules by source zone → one ACL per zone, bound "in".
	aclOf := func(r fwir.Rule) string {
		if len(r.SrcZones) > 0 {
			return m.MapZone(r.SrcZones[0]) + "_in"
		}
		return "global_acl"
	}
	addrClause := func(refs []fwir.Ref, ruleName, side string) (string, string, string) {
		// returns clause, status, detail
		if len(refs) == 0 {
			return "any", StConverted, ""
		}
		if len(refs) == 1 {
			r := refs[0]
			switch classifyRef(x, r) {
			case refAny:
				return "any", StConverted, ""
			case refNetObj:
				return "object " + nm.lookup(string(r)), StConverted, ""
			case refNetGroup:
				return "object-group " + nm.lookup(string(r)), StConverted, ""
			case refLiteralCIDR:
				if fwir.IsHostCIDR(string(r)) {
					return "host " + fwir.HostPart(string(r)), StConverted, ""
				}
				ip, mask, err := fwir.SplitCIDR(string(r))
				if err != nil {
					return "any", StFailed, "bad address " + string(r)
				}
				return ip + " " + mask, StConverted, ""
			case refLiteralRange:
				h := ensureHelperNet(string(r))
				return "object " + h, StConverted, "range literal wrapped in object " + h
			case refInterface:
				return "any", StPartial, "interface-address reference " + string(r) + " widened to any — verify"
			default:
				return "any", StPartial, side + " reference " + string(r) + " unresolved — widened to any, VERIFY"
			}
		}
		// multiple refs → ad-hoc group
		gname := nm.name("RF-" + ruleName + "-" + side)
		var lines []string
		lines = append(lines, "object-group network "+gname)
		st, det := StConverted, ""
		for _, r := range refs {
			switch classifyRef(x, r) {
			case refNetObj:
				lines = append(lines, " network-object object "+nm.lookup(string(r)))
			case refNetGroup:
				lines = append(lines, " group-object "+nm.lookup(string(r)))
			case refLiteralCIDR:
				if fwir.IsHostCIDR(string(r)) {
					lines = append(lines, " network-object host "+fwir.HostPart(string(r)))
				} else if ip, mask, err := fwir.SplitCIDR(string(r)); err == nil {
					lines = append(lines, fmt.Sprintf(" network-object %s %s", ip, mask))
				}
			default:
				st, det = StPartial, "member "+string(r)+" unresolved"
				lines = append(lines, " ! unresolved member: "+string(r))
			}
		}
		helperObjs[gname] = strings.Join(lines, "\n")
		helperOrder = append(helperOrder, gname)
		return "object-group " + gname, st, det
	}

	var aclLines []string
	for _, r := range x.Rules {
		action := "permit"
		if r.Action == "deny" {
			action = "deny"
		}
		acl := aclOf(r)
		srcClause, st1, d1 := addrClause(r.SrcAddrs, firstNonEmpty(r.Name, fmt.Sprintf("r%d", r.Index)), "src")
		dstClause, st2, d2 := addrClause(r.DstAddrs, firstNonEmpty(r.Name, fmt.Sprintf("r%d", r.Index)), "dst")
		status := worst(st1, st2)
		details := []string{}
		if d1 != "" {
			details = append(details, d1)
		}
		if d2 != "" {
			details = append(details, d2)
		}
		if len(r.Apps) > 0 {
			status = worst(status, StPartial)
			details = append(details, fmt.Sprintf("L7 applications (%s) have no ASA equivalent — rule converted at L4 only", strings.Join(r.Apps, ", ")))
		}
		if len(r.URLCats) > 0 {
			status = worst(status, StPartial)
			details = append(details, "URL categories dropped (no ASA equivalent) — consider FTD/URL filtering")
		}
		// service handling: may expand to several lines
		var svcParts []struct {
			proto  string
			port   string
			objRef string // "object X" / "object-group X"
		}
		if len(r.Services) == 0 {
			svcParts = append(svcParts, struct{ proto, port, objRef string }{"ip", "", ""})
		}
		for _, s := range r.Services {
			switch classifySvc(x, s) {
			case svcAny:
				svcParts = append(svcParts, struct{ proto, port, objRef string }{"ip", "", ""})
			case svcObj:
				svcParts = append(svcParts, struct{ proto, port, objRef string }{"", "", "object " + nm.lookup(string(s))})
			case svcGroup:
				svcParts = append(svcParts, struct{ proto, port, objRef string }{"", "", "object-group " + nm.lookup(string(s))})
			case svcLiteral:
				proto, port, _ := s.SplitSvcLiteral()
				svcParts = append(svcParts, struct{ proto, port, objRef string }{protoSplitFirst(proto), port, ""})
			default:
				status = worst(status, StPartial)
				details = append(details, "service "+string(s)+" unresolved — widened to ip, VERIFY")
				svcParts = append(svcParts, struct{ proto, port, objRef string }{"ip", "", ""})
			}
		}
		var ruleOut []string
		if r.Desc != "" || r.Name != "" {
			ruleOut = append(ruleOut, fmt.Sprintf("access-list %s remark %s", acl, firstNonEmpty(r.Desc, r.Name)))
		}
		for _, sp := range svcParts {
			var l string
			if sp.objRef != "" {
				l = fmt.Sprintf("access-list %s extended %s %s %s %s", acl, action, sp.objRef, srcClause, dstClause)
			} else {
				l = fmt.Sprintf("access-list %s extended %s %s %s %s", acl, action, sp.proto, srcClause, dstClause)
				if sp.port != "" {
					l += " " + asaPortClause(sp.port)
				}
			}
			if r.Log {
				l += " log"
			}
			if !r.Enabled {
				l += " inactive"
			}
			ruleOut = append(ruleOut, l)
		}
		aclLines = append(aclLines, ruleOut...)
		res.Items = append(res.Items, Item{
			Category: "rule", Name: firstNonEmpty(r.Name, fmt.Sprintf("rule %d", r.Index)),
			Status: status, Detail: strings.Join(details, "; "), Output: strings.Join(ruleOut, "\n"),
		})
	}

	// helper objects before ACLs
	if len(helperOrder) > 0 {
		w("! --- helper objects created by RuleForge for literals/multi-value fields ---")
		for _, hn := range helperOrder {
			w("%s\n!", helperObjs[hn])
		}
	}
	for _, l := range aclLines {
		w("%s", l)
	}
	// bindings
	bound := map[string]bool{}
	for _, r := range x.Rules {
		acl := aclOf(r)
		if bound[acl] {
			continue
		}
		bound[acl] = true
		if acl == "global_acl" {
			w("access-group global_acl global")
		} else {
			w("access-group %s in interface %s", acl, strings.TrimSuffix(acl, "_in"))
		}
	}
	w("!")

	// ---- NAT ----
	natRef := func(r fwir.Ref) string {
		switch classifyRef(x, r) {
		case refAny:
			return "any"
		case refNetObj, refNetGroup:
			return nm.lookup(string(r))
		case refLiteralCIDR, refLiteralRange:
			return ensureHelperNet(string(r))
		}
		if r == "interface" {
			return "interface"
		}
		return string(r)
	}
	for _, n := range x.NATs {
		pair := fmt.Sprintf("(%s,%s)", ifOrAny(m.MapZone(n.SrcIface)), ifOrAny(m.MapZone(n.DstIface)))
		var l string
		status := StConverted
		detail := ""
		switch n.Kind {
		case fwir.NATStatic:
			if n.OrigDst != "" || n.TransDst != "" {
				// destination-side static (e.g. VIP): render as twice NAT
				l = fmt.Sprintf("nat %s source static %s %s destination static %s %s", pair,
					orAny(natRef(n.OrigSrc)), orSame(natRef(n.TransSrc), natRef(n.OrigSrc)),
					orAny(natRef(n.OrigDst)), orSame(natRef(n.TransDst), natRef(n.OrigDst)))
			} else {
				l = fmt.Sprintf("nat %s source static %s %s", pair, orAny(natRef(n.OrigSrc)), orSame(natRef(n.TransSrc), natRef(n.OrigSrc)))
			}
		case fwir.NATDynamicPAT:
			l = fmt.Sprintf("nat %s source dynamic %s interface", pair, orAny(natRef(n.OrigSrc)))
			if n.TransSrc != "" && n.TransSrc != "interface" {
				l = fmt.Sprintf("nat %s source dynamic %s pat-pool %s", pair, orAny(natRef(n.OrigSrc)), natRef(n.TransSrc))
			}
		case fwir.NATDynamic:
			l = fmt.Sprintf("nat %s source dynamic %s %s", pair, orAny(natRef(n.OrigSrc)), natRef(n.TransSrc))
		default: // twice
			l = fmt.Sprintf("nat %s source static %s %s", pair, orAny(natRef(n.OrigSrc)), orSame(natRef(n.TransSrc), natRef(n.OrigSrc)))
			if n.OrigDst != "" || n.TransDst != "" {
				l += fmt.Sprintf(" destination static %s %s", orAny(natRef(n.TransDst)), orAny(natRef(n.OrigDst)))
			}
		}
		if n.OrigSvc != "" && n.TransSvc != "" {
			op, opok := svcToASAService(x, n.OrigSvc)
			tp, tpok := svcToASAService(x, n.TransSvc)
			if opok && tpok {
				l += fmt.Sprintf(" service %s %s", op, tp)
			} else {
				status = worst(status, StPartial)
				detail = "service translation could not be rendered — add `service` clause manually"
			}
		}
		if !n.Enabled {
			l += " inactive"
		}
		if n.Desc != "" {
			l += " description " + n.Desc
		}
		w("%s", l)
		res.Items = append(res.Items, Item{Category: "nat", Name: firstNonEmpty(n.Name, fmt.Sprintf("nat %d", n.Index)), Status: status, Detail: detail, Output: l})
	}
	w("!")

	// ---- routes ----
	for _, r := range x.Routes {
		ip, mask, err := fwir.SplitCIDR(r.Dest)
		if err != nil {
			res.Items = append(res.Items, Item{Category: "route", Name: r.Dest, Status: StFailed, Detail: err.Error()})
			continue
		}
		metric := r.Metric
		if metric == 0 {
			metric = 1
		}
		l := fmt.Sprintf("route %s %s %s %s %d", firstNonEmpty(m.MapZone(m.MapIface(r.Iface)), "outside"), ip, mask, r.Gateway, metric)
		w("%s", l)
		res.Items = append(res.Items, Item{Category: "route", Name: r.Dest, Status: StConverted, Output: l})
	}

	captureItems(x, res)
	res.Files = append(res.Files, File{Name: "asa-" + safeFile(x.Name) + ".cfg", Content: b.String()})
	res.Renames = nm.Renames
	return res
}

func asaPortClause(port string) string {
	if strings.Contains(port, "-") {
		parts := strings.SplitN(port, "-", 2)
		return "range " + parts[0] + " " + parts[1]
	}
	return "eq " + port
}

// svcToASAService renders a SvcRef as an ASA nat service literal "tcp 80 80"
// operand (proto port). Named objects resolve to their proto/port.
func svcToASAService(x *fwir.Context, s fwir.SvcRef) (string, bool) {
	if proto, port, ok := s.SplitSvcLiteral(); ok && port != "" {
		return protoSplitFirst(proto) + " " + port, true
	}
	if o := x.Objects.FindSvc(string(s)); o != nil && o.Port != "" {
		return protoSplitFirst(o.Proto) + " " + o.Port, true
	}
	return "", false
}

func protoSplitFirst(proto string) string {
	if proto == "tcp-udp" {
		return "tcp" // ASA cannot express both in one clause; second line handled by caller when needed
	}
	return proto
}

func worst(a, b string) string {
	rank := map[string]int{StConverted: 0, StInfo: 0, StPartial: 1, StManual: 2, StFailed: 3}
	if rank[b] > rank[a] {
		return b
	}
	return a
}

func ifOrAny(s string) string {
	if s == "" {
		return "any"
	}
	return s
}

func orAny(s string) string {
	if s == "" {
		return "any"
	}
	return s
}

func orSame(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

func safeFile(s string) string {
	s = strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' {
			return r
		}
		return '-'
	}, s)
	if s == "" {
		return "default"
	}
	return s
}
