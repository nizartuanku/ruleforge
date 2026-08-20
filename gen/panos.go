package gen

import (
	"fmt"
	"strings"

	"github.com/nizartuanku/ruleforge/fwir"
)

// genPANOS renders one context as PAN-OS set commands. Two files ship: the
// firewall-local form, and a Panorama form (objects+policies under a
// device-group named after the context, network config annotated for a
// template).
func genPANOS(x *fwir.Context, m *Mapping) *Result {
	res := &Result{Context: x.Name}
	nm := newNamer(fwir.VendorPANOS)
	var fw strings.Builder // firewall-local lines
	var netLines, objLines, polLines []string
	addNet := func(format string, a ...any) { netLines = append(netLines, fmt.Sprintf(format, a...)) }
	addObj := func(format string, a ...any) { objLines = append(objLines, fmt.Sprintf(format, a...)) }
	addPol := func(format string, a ...any) { polLines = append(polLines, fmt.Sprintf(format, a...)) }

	helperSvcs := map[string]bool{}
	ensureSvc := func(s fwir.SvcRef) (string, bool) {
		proto, port, ok := s.SplitSvcLiteral()
		if !ok || port == "" {
			return "", false
		}
		if proto == "tcp-udp" {
			proto = "tcp" // second proto noted by caller
		}
		name := nm.name(fmt.Sprintf("RF-%s-%s", proto, strings.ReplaceAll(port, "-", "_")))
		if !helperSvcs[name] {
			helperSvcs[name] = true
			addObj("set service %s protocol %s port %s", panQ(name), proto, port)
		}
		return name, true
	}
	helperAddrs := map[string]bool{}
	ensureAddr := func(lit string) string {
		name := nm.name("RF-" + strings.NewReplacer("/", "-", ":", "_").Replace(lit))
		if !helperAddrs[name] {
			helperAddrs[name] = true
			if strings.Contains(lit, "-") && !strings.Contains(lit, "/") {
				addObj("set address %s ip-range %s", panQ(name), lit)
			} else {
				addObj("set address %s ip-netmask %s", panQ(name), lit)
			}
		}
		return name
	}

	// ---- interfaces ----
	panIface := func(name string) string { return m.MapIface(name) }
	for _, ifc := range x.Interfaces {
		tgt := panIface(ifc.Name)
		status := StConverted
		detail := ""
		var out []string
		isPANName := strings.HasPrefix(tgt, "ethernet") || strings.HasPrefix(tgt, "ae") ||
			strings.HasPrefix(tgt, "loopback") || strings.HasPrefix(tgt, "tunnel") || strings.HasPrefix(tgt, "vlan")
		if !isPANName {
			status = StPartial
			detail = "map to a real PAN-OS interface name (ethernetX/Y, aeN) in the mapping step"
		}
		switch ifc.Kind {
		case fwir.IfSubIf:
			parent := panIface(ifc.Parent)
			sub := tgt
			if !strings.Contains(sub, ".") && ifc.VlanID > 0 {
				sub = fmt.Sprintf("%s.%d", parent, ifc.VlanID)
			}
			out = append(out, fmt.Sprintf("set network interface ethernet %s layer3 units %s tag %d", parent, sub, ifc.VlanID))
			for _, ip := range ifc.IPs {
				out = append(out, fmt.Sprintf("set network interface ethernet %s layer3 units %s ip %s", parent, sub, ip))
			}
			if ifc.Desc != "" {
				out = append(out, fmt.Sprintf("set network interface ethernet %s layer3 units %s comment %s", parent, sub, panQ(ifc.Desc)))
			}
		case fwir.IfAggregate:
			out = append(out, fmt.Sprintf("set network interface aggregate-ethernet %s layer3", tgt))
			for _, ip := range ifc.IPs {
				out = append(out, fmt.Sprintf("set network interface aggregate-ethernet %s layer3 ip %s", tgt, ip))
			}
			for _, mem := range ifc.Members {
				out = append(out, fmt.Sprintf("set network interface ethernet %s aggregate-group %s", panIface(mem), tgt))
			}
		case fwir.IfBridge:
			status = worst(status, StPartial)
			detail = strings.TrimSpace(detail + " bridge/L2 — recreate as PAN-OS vlan/virtual-wire manually; members: " + strings.Join(ifc.Members, ", "))
			out = append(out, fmt.Sprintf("# bridge %s (members %s): configure `set network vlan` + vlan interface manually", tgt, strings.Join(ifc.Members, ",")))
		case fwir.IfLoopback:
			for _, ip := range ifc.IPs {
				out = append(out, fmt.Sprintf("set network interface loopback units %s ip %s", tgt, ip))
			}
		case fwir.IfTunnel:
			out = append(out, fmt.Sprintf("set network interface tunnel units %s", tgt))
		default:
			out = append(out, fmt.Sprintf("set network interface ethernet %s layer3", tgt))
			for _, ip := range ifc.IPs {
				out = append(out, fmt.Sprintf("set network interface ethernet %s layer3 ip %s", tgt, ip))
			}
			if ifc.Desc != "" {
				out = append(out, fmt.Sprintf("set network interface ethernet %s comment %s", tgt, panQ(ifc.Desc)))
			}
			if ifc.MTU > 0 {
				out = append(out, fmt.Sprintf("set network interface ethernet %s layer3 mtu %d", tgt, ifc.MTU))
			}
		}
		for _, l := range out {
			addNet("%s", l)
		}
		// attach to virtual router
		if len(ifc.IPs) > 0 && status != StPartial {
			addNet("set network virtual-router default interface %s", tgt)
		}
		res.Items = append(res.Items, Item{Category: "interface", Name: ifc.Name, Status: status, Detail: detail, Output: strings.Join(out, "\n")})
	}

	// ---- zones ----
	zoneIfaces := map[string][]string{}
	for _, z := range x.Zones {
		tz := m.MapZone(z.Name)
		for _, ifn := range z.Interfaces {
			zoneIfaces[tz] = append(zoneIfaces[tz], panIface(ifn))
		}
	}
	// interfaces that carry Zone directly
	for _, ifc := range x.Interfaces {
		if ifc.Zone != "" {
			tz := m.MapZone(ifc.Zone)
			zoneIfaces[tz] = appendUniqueStr(zoneIfaces[tz], panIface(ifc.Name))
		} else if ifc.Alias != "" {
			tz := m.MapZone(ifc.Alias)
			zoneIfaces[tz] = appendUniqueStr(zoneIfaces[tz], panIface(ifc.Name))
		}
	}
	for _, z := range x.Zones {
		tz := m.MapZone(z.Name)
		ifs := zoneIfaces[tz]
		if len(ifs) == 0 {
			addNet("set zone %s network layer3", panQ(tz))
		} else {
			addNet("set zone %s network layer3 [ %s ]", panQ(tz), strings.Join(ifs, " "))
		}
		res.Items = append(res.Items, Item{Category: "zone", Name: z.Name, Status: StConverted, Output: "set zone " + tz})
	}

	// ---- objects ----
	for _, o := range x.Objects.Networks {
		name := nm.name(o.Name)
		var l string
		switch o.Kind {
		case fwir.NetHost:
			l = fmt.Sprintf("set address %s ip-netmask %s/32", panQ(name), o.Value)
		case fwir.NetSubnet:
			l = fmt.Sprintf("set address %s ip-netmask %s", panQ(name), o.Value)
		case fwir.NetRange:
			l = fmt.Sprintf("set address %s ip-range %s-%s", panQ(name), o.Value, o.Value2)
		case fwir.NetFQDN:
			l = fmt.Sprintf("set address %s fqdn %s", panQ(name), o.Value)
		}
		addObj("%s", l)
		if o.Desc != "" {
			addObj("set address %s description %s", panQ(name), panQ(o.Desc))
		}
		res.Items = append(res.Items, Item{Category: "object", Name: o.Name, Status: StConverted, Output: l})
	}
	for _, s := range x.Objects.Services {
		name := nm.name(s.Name)
		status := StConverted
		detail := ""
		var l string
		switch s.Proto {
		case "tcp", "udp", "sctp":
			port := s.Port
			if port == "" {
				port = "0-65535"
			}
			l = fmt.Sprintf("set service %s protocol %s port %s", panQ(name), s.Proto, port)
			if s.SrcPort != "" {
				l += " source-port " + s.SrcPort
			}
		case "tcp-udp":
			l = fmt.Sprintf("set service %s protocol tcp port %s", panQ(name), orDef(s.Port, "0-65535"))
			addObj("%s", l)
			l2 := fmt.Sprintf("set service %s protocol udp port %s", panQ(nm.name(s.Name+"-udp")), orDef(s.Port, "0-65535"))
			addObj("%s", l2)
			status = StPartial
			detail = "tcp-udp split into two PAN-OS services (tcp + udp) — reference both where used"
			res.Items = append(res.Items, Item{Category: "service", Name: s.Name, Status: status, Detail: detail, Output: l + "\n" + l2})
			continue
		case "icmp":
			status = StPartial
			detail = "ICMP service → use application ping/icmp in PAN-OS; rules referencing it use application icmp"
			l = "# " + name + ": icmp — PAN-OS uses App-ID (ping/icmp) instead of an L4 service"
		default:
			status = StPartial
			detail = "IP-protocol service (" + s.Proto + ") — PAN-OS needs a custom application; review"
			l = "# " + name + ": ip-proto " + s.Proto + " — create custom application manually"
		}
		addObj("%s", l)
		res.Items = append(res.Items, Item{Category: "service", Name: s.Name, Status: status, Detail: detail, Output: l})
	}
	for _, g := range x.Objects.NetGroups {
		name := nm.name(g.Name)
		var mems []string
		status := StConverted
		detail := ""
		for _, mem := range g.Members {
			switch {
			case x.Objects.FindNet(mem) != nil || x.Objects.FindNetGroup(mem) != nil:
				mems = append(mems, panQ(nm.lookup(mem)))
			case fwir.Ref(mem).IsLiteral():
				mems = append(mems, panQ(ensureAddr(mem)))
			default:
				status, detail = StPartial, "member "+mem+" unresolved"
			}
		}
		l := fmt.Sprintf("set address-group %s static [ %s ]", panQ(name), strings.Join(mems, " "))
		addObj("%s", l)
		res.Items = append(res.Items, Item{Category: "group", Name: g.Name, Status: status, Detail: detail, Output: l})
	}
	for _, g := range x.Objects.SvcGroups {
		name := nm.name(g.Name)
		var mems []string
		status := StConverted
		detail := ""
		for _, mem := range g.Members {
			if x.Objects.FindSvc(mem) != nil || x.Objects.FindSvcGroup(mem) != nil {
				mems = append(mems, panQ(nm.lookup(mem)))
				continue
			}
			if hn, ok := ensureSvc(fwir.SvcRef(mem)); ok {
				mems = append(mems, panQ(hn))
				continue
			}
			status, detail = StPartial, "member "+mem+" unresolved"
		}
		l := fmt.Sprintf("set service-group %s members [ %s ]", panQ(name), strings.Join(mems, " "))
		addObj("%s", l)
		res.Items = append(res.Items, Item{Category: "group", Name: g.Name, Status: status, Detail: detail, Output: l})
	}

	// ---- security rules ----
	for _, r := range x.Rules {
		rname := nm.unique(firstNonEmpty(r.Name, fmt.Sprintf("rule-%d", r.Index)))
		status := StConverted
		var details []string
		from := listOrAny(mapZones(m, r.SrcZones))
		to := listOrAny(mapZones(m, r.DstZones))
		src, st1, d1 := panAddrList(x, nm, ensureAddr, r.SrcAddrs)
		dst, st2, d2 := panAddrList(x, nm, ensureAddr, r.DstAddrs)
		status = worst(worst(status, st1), st2)
		if d1 != "" {
			details = append(details, d1)
		}
		if d2 != "" {
			details = append(details, d2)
		}
		apps := "any"
		if len(r.Apps) > 0 {
			apps = "[ " + strings.Join(r.Apps, " ") + " ]"
		}
		var svcs []string
		icmpApp := false
		for _, s := range r.Services {
			switch classifySvc(x, s) {
			case svcAny:
			case svcObj, svcGroup:
				o := x.Objects.FindSvc(string(s))
				if o != nil && o.Proto == "icmp" {
					icmpApp = true
					continue
				}
				svcs = append(svcs, panQ(nm.lookup(string(s))))
			case svcLiteral:
				proto, _, _ := s.SplitSvcLiteral()
				if proto == "icmp" {
					icmpApp = true
					continue
				}
				if hn, ok := ensureSvc(s); ok {
					svcs = append(svcs, panQ(hn))
				}
			default:
				status = worst(status, StPartial)
				details = append(details, "service "+string(s)+" unresolved — left as any, VERIFY")
			}
		}
		svc := "any"
		if len(svcs) > 0 {
			svc = "[ " + strings.Join(svcs, " ") + " ]"
		} else if apps != "any" {
			svc = "application-default"
		}
		if icmpApp {
			if apps == "any" {
				apps = "[ ping icmp ]"
			}
			status = worst(status, StPartial)
			details = append(details, "ICMP service expressed as App-ID ping/icmp")
		}
		action := "allow"
		if r.Action == "deny" {
			action = "deny"
		}
		base := fmt.Sprintf("set rulebase security rules %s", panQ(rname))
		var out []string
		out = append(out, fmt.Sprintf("%s from %s", base, from))
		out = append(out, fmt.Sprintf("%s to %s", base, to))
		out = append(out, fmt.Sprintf("%s source %s", base, src))
		out = append(out, fmt.Sprintf("%s destination %s", base, dst))
		out = append(out, fmt.Sprintf("%s application %s", base, apps))
		out = append(out, fmt.Sprintf("%s service %s", base, svc))
		out = append(out, fmt.Sprintf("%s action %s", base, action))
		if r.Log {
			out = append(out, fmt.Sprintf("%s log-end yes", base))
		}
		if !r.Enabled {
			out = append(out, fmt.Sprintf("%s disabled yes", base))
		}
		if r.Desc != "" {
			out = append(out, fmt.Sprintf("%s description %s", base, panQ(r.Desc)))
		}
		if len(r.URLCats) > 0 {
			status = worst(status, StPartial)
			details = append(details, "URL categories ("+strings.Join(r.URLCats, ", ")+") need a URL-filtering profile — attach manually")
		}
		for _, l := range out {
			addPol("%s", l)
		}
		res.Items = append(res.Items, Item{Category: "rule", Name: firstNonEmpty(r.Name, rname), Status: status, Detail: strings.Join(details, "; "), Output: strings.Join(out, "\n")})
	}

	// ---- NAT ----
	for _, n := range x.NATs {
		rname := nm.unique(firstNonEmpty(n.Name, fmt.Sprintf("nat-%d", n.Index)))
		base := fmt.Sprintf("set rulebase nat rules %s", panQ(rname))
		status := StConverted
		var details []string
		from := orDef(m.MapZone(n.SrcIface), "any")
		to := orDef(m.MapZone(n.DstIface), "any")
		var out []string
		out = append(out, fmt.Sprintf("%s from %s", base, panQ(from)))
		out = append(out, fmt.Sprintf("%s to %s", base, panQ(to)))
		src := "any"
		if n.OrigSrc != "" && !n.OrigSrc.IsAny() {
			src = panQ(panRefName(x, nm, ensureAddr, n.OrigSrc))
		}
		dstA := "any"
		if n.OrigDst != "" && !n.OrigDst.IsAny() {
			dstA = panQ(panRefName(x, nm, ensureAddr, n.OrigDst))
		}
		out = append(out, fmt.Sprintf("%s source %s", base, src))
		out = append(out, fmt.Sprintf("%s destination %s", base, dstA))
		if n.OrigSvc != "" && !n.OrigSvc.IsAny() {
			if hn, ok := ensureSvc(n.OrigSvc); ok {
				out = append(out, fmt.Sprintf("%s service %s", base, panQ(hn)))
			} else if x.Objects.FindSvc(string(n.OrigSvc)) != nil {
				out = append(out, fmt.Sprintf("%s service %s", base, panQ(nm.lookup(string(n.OrigSvc)))))
			}
		}
		switch n.Kind {
		case fwir.NATDynamicPAT:
			if n.TransSrc == "interface" || n.TransSrc == "" {
				out = append(out, fmt.Sprintf("%s source-translation dynamic-ip-and-port interface-address interface %s", base, "<egress-interface>"))
				status = worst(status, StPartial)
				details = append(details, "set the egress interface for interface-address PAT (mapping step does not know the target port name)")
			} else {
				out = append(out, fmt.Sprintf("%s source-translation dynamic-ip-and-port translated-address %s", base, panQ(panRefName(x, nm, ensureAddr, n.TransSrc))))
			}
		case fwir.NATDynamic:
			out = append(out, fmt.Sprintf("%s source-translation dynamic-ip translated-address %s", base, panQ(panRefName(x, nm, ensureAddr, n.TransSrc))))
		case fwir.NATStatic:
			if n.TransSrc != "" && n.TransSrc != n.OrigSrc {
				bidir := "no"
				if n.Bidir {
					bidir = "yes"
				}
				out = append(out, fmt.Sprintf("%s source-translation static-ip translated-address %s bi-directional %s", base, panQ(panRefName(x, nm, ensureAddr, n.TransSrc)), bidir))
			}
			if n.TransDst != "" {
				out = append(out, fmt.Sprintf("%s destination-translation translated-address %s", base, panQ(panRefName(x, nm, ensureAddr, n.TransDst))))
				if _, port, ok := n.TransSvc.SplitSvcLiteral(); ok && port != "" {
					out = append(out, fmt.Sprintf("%s destination-translation translated-port %s", base, port))
				}
			}
		default: // twice
			if n.TransSrc != "" && n.TransSrc != n.OrigSrc {
				out = append(out, fmt.Sprintf("%s source-translation static-ip translated-address %s bi-directional no", base, panQ(panRefName(x, nm, ensureAddr, n.TransSrc))))
			}
			if n.TransDst != "" {
				out = append(out, fmt.Sprintf("%s destination-translation translated-address %s", base, panQ(panRefName(x, nm, ensureAddr, n.TransDst))))
			}
		}
		if !n.Enabled {
			out = append(out, fmt.Sprintf("%s disabled yes", base))
		}
		if n.Desc != "" {
			out = append(out, fmt.Sprintf("%s description %s", base, panQ(n.Desc)))
		}
		for _, l := range out {
			addPol("%s", l)
		}
		res.Items = append(res.Items, Item{Category: "nat", Name: firstNonEmpty(n.Name, rname), Status: status, Detail: strings.Join(details, "; "), Output: strings.Join(out, "\n")})
	}

	// ---- routes ----
	for i, r := range x.Routes {
		rn := fmt.Sprintf("rf-route-%d", i+1)
		l := fmt.Sprintf("set network virtual-router default routing-table ip static-route %s destination %s", rn, r.Dest)
		if r.Gateway != "" {
			l += " nexthop ip-address " + r.Gateway
		}
		if r.Iface != "" {
			l += " interface " + m.MapIface(r.Iface)
		}
		if r.Metric > 0 {
			l += fmt.Sprintf(" metric %d", r.Metric)
		}
		addNet("%s", l)
		res.Items = append(res.Items, Item{Category: "route", Name: r.Dest, Status: StConverted, Output: l})
	}

	captureItems(x, res)

	// firewall-local file
	fw.WriteString("# RuleForge — generated PAN-OS set commands (firewall-local)\n# Context: " + x.Name + "\n# Paste in configure mode. Review the conversion report first.\n\n")
	for _, l := range netLines {
		fw.WriteString(l + "\n")
	}
	fw.WriteString("\n")
	for _, l := range objLines {
		fw.WriteString(l + "\n")
	}
	fw.WriteString("\n")
	for _, l := range polLines {
		fw.WriteString(l + "\n")
	}
	res.Files = append(res.Files, File{Name: "panos-" + safeFile(x.Name) + "-set.txt", Content: fw.String()})

	// Panorama variant: objects+policies under device-group; network via template note
	var pn strings.Builder
	dg := safeFile(x.Name)
	if dg == "default" {
		dg = "DG-migrated"
	}
	pn.WriteString("# RuleForge — Panorama variant\n# Objects & policies land in device-group \"" + dg + "\" (pre-rulebase).\n# Network config (interfaces/zones/routes) belongs in a template — lines kept firewall-local below for reference.\n\n")
	for _, l := range objLines {
		pn.WriteString("set device-group " + dg + " " + strings.TrimPrefix(l, "set ") + "\n")
	}
	for _, l := range polLines {
		pl := strings.TrimPrefix(l, "set ")
		pl = strings.Replace(pl, "rulebase ", "pre-rulebase ", 1)
		pn.WriteString("set device-group " + dg + " " + pl + "\n")
	}
	pn.WriteString("\n# --- template (network) reference ---\n")
	for _, l := range netLines {
		pn.WriteString("# " + l + "\n")
	}
	res.Files = append(res.Files, File{Name: "panorama-" + safeFile(x.Name) + "-set.txt", Content: pn.String()})
	res.Renames = nm.Renames
	return res
}

func panAddrList(x *fwir.Context, nm *namer, ensureAddr func(string) string, refs []fwir.Ref) (string, string, string) {
	if len(refs) == 0 {
		return "any", StConverted, ""
	}
	var mems []string
	status, detail := StConverted, ""
	for _, r := range refs {
		switch classifyRef(x, r) {
		case refAny:
			return "any", StConverted, ""
		case refNetObj, refNetGroup:
			mems = append(mems, panQ(nm.lookup(string(r))))
		case refLiteralCIDR, refLiteralRange:
			mems = append(mems, panQ(ensureAddr(string(r))))
		default:
			status, detail = StPartial, "reference "+string(r)+" unresolved — omitted, VERIFY"
		}
	}
	if len(mems) == 0 {
		return "any", worst(status, StPartial), detail
	}
	if len(mems) == 1 {
		return mems[0], status, detail
	}
	return "[ " + strings.Join(mems, " ") + " ]", status, detail
}

func panRefName(x *fwir.Context, nm *namer, ensureAddr func(string) string, r fwir.Ref) string {
	switch classifyRef(x, r) {
	case refNetObj, refNetGroup:
		return nm.lookup(string(r))
	case refLiteralCIDR, refLiteralRange:
		return ensureAddr(string(r))
	}
	return string(r)
}

// panQ quotes a value for set-command output when it contains spaces.
func panQ(s string) string {
	if strings.ContainsAny(s, " \t") {
		return "\"" + s + "\""
	}
	return s
}

func listOrAny(zs []string) string {
	if len(zs) == 0 {
		return "any"
	}
	var q []string
	for _, z := range zs {
		q = append(q, panQ(z))
	}
	if len(q) == 1 {
		return q[0]
	}
	return "[ " + strings.Join(q, " ") + " ]"
}

func orDef(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func appendUniqueStr(dst []string, v string) []string {
	for _, d := range dst {
		if d == v {
			return dst
		}
	}
	return append(dst, v)
}
