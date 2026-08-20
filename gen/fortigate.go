package gen

import (
	"fmt"
	"strings"

	"github.com/nizartuanku/ruleforge/fwir"
)

// genFortiGate renders one context as FortiOS CLI.
func genFortiGate(x *fwir.Context, m *Mapping) *Result {
	res := &Result{Context: x.Name}
	nm := newNamer(fwir.VendorFortiGate)
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format+"\n", a...) }

	w("# RuleForge — generated FortiOS configuration")
	w("# Context: %s", x.Name)
	w("# NAT model: central NAT (enable with: config system settings / set central-nat enable)")
	w("")

	// ---- interfaces ----
	w("config system interface")
	for _, ifc := range x.Interfaces {
		tgt := m.MapIface(ifc.Name)
		status := StConverted
		detail := ""
		var lines []string
		lines = append(lines, fmt.Sprintf("    edit %q", tgt))
		switch ifc.Kind {
		case fwir.IfAggregate:
			lines = append(lines, "        set type aggregate")
			if len(ifc.Members) > 0 {
				var mem []string
				for _, mm := range ifc.Members {
					mem = append(mem, fmt.Sprintf("%q", m.MapIface(mm)))
				}
				lines = append(lines, "        set member "+strings.Join(mem, " "))
			}
		case fwir.IfSubIf:
			lines = append(lines, fmt.Sprintf("        set interface %q", m.MapIface(ifc.Parent)))
			lines = append(lines, fmt.Sprintf("        set vlanid %d", ifc.VlanID))
		case fwir.IfBridge:
			lines = append(lines, "        set type software-switch")
			if len(ifc.Members) > 0 {
				var mem []string
				for _, mm := range ifc.Members {
					mem = append(mem, fmt.Sprintf("%q", m.MapIface(mm)))
				}
				lines = append(lines, "        set member "+strings.Join(mem, " "))
			}
			status, detail = StPartial, "bridge mapped to software-switch — verify L2 design"
		case fwir.IfLoopback:
			lines = append(lines, "        set type loopback")
		case fwir.IfTunnel:
			lines = append(lines, "        set type tunnel")
			status, detail = StPartial, "tunnel interface — tie to VPN phase1-interface manually"
		}
		for _, ip := range ifc.IPs {
			ipAddr, mask, err := fwir.SplitCIDR(ip)
			if err == nil {
				lines = append(lines, fmt.Sprintf("        set ip %s %s", ipAddr, mask))
				lines = append(lines, "        set allowaccess ping")
			}
		}
		if ifc.Desc != "" {
			lines = append(lines, fmt.Sprintf("        set description %q", ifc.Desc))
		}
		if alias := firstNonEmpty(ifc.Alias, ifc.Zone); alias != "" {
			lines = append(lines, fmt.Sprintf("        set alias %q", truncate(alias, 25)))
		}
		if ifc.Shutdown {
			lines = append(lines, "        set status down")
		}
		if ifc.MTU > 0 {
			lines = append(lines, "        set mtu-override enable")
			lines = append(lines, fmt.Sprintf("        set mtu %d", ifc.MTU))
		}
		lines = append(lines, "    next")
		out := strings.Join(lines, "\n")
		w("%s", out)
		res.Items = append(res.Items, Item{Category: "interface", Name: ifc.Name, Status: status, Detail: detail, Output: out})
	}
	w("end")
	w("")

	// ---- zones ----
	zoneOfIface := map[string]string{}
	w("config system zone")
	for _, z := range x.Zones {
		tz := m.MapZone(z.Name)
		var mem []string
		for _, ifn := range z.Interfaces {
			mem = append(mem, fmt.Sprintf("%q", m.MapIface(ifn)))
			zoneOfIface[ifn] = tz
		}
		out := fmt.Sprintf("    edit %q\n        set interface %s\n    next", tz, strings.Join(mem, " "))
		w("%s", out)
		res.Items = append(res.Items, Item{Category: "zone", Name: z.Name, Status: StConverted, Output: out})
	}
	w("end")
	w("")

	// ---- address objects ----
	w("config firewall address")
	for _, o := range x.Objects.Networks {
		name := nm.name(o.Name)
		var lines []string
		lines = append(lines, fmt.Sprintf("    edit %q", name))
		switch o.Kind {
		case fwir.NetHost:
			lines = append(lines, fmt.Sprintf("        set subnet %s 255.255.255.255", o.Value))
		case fwir.NetSubnet:
			ip, mask, err := fwir.SplitCIDR(o.Value)
			if err != nil {
				res.Items = append(res.Items, Item{Category: "object", Name: o.Name, Status: StFailed, Detail: "bad subnet " + o.Value})
				continue
			}
			lines = append(lines, fmt.Sprintf("        set subnet %s %s", ip, mask))
		case fwir.NetRange:
			lines = append(lines, "        set type iprange")
			lines = append(lines, fmt.Sprintf("        set start-ip %s", o.Value))
			lines = append(lines, fmt.Sprintf("        set end-ip %s", o.Value2))
		case fwir.NetFQDN:
			lines = append(lines, "        set type fqdn")
			lines = append(lines, fmt.Sprintf("        set fqdn %q", o.Value))
		}
		if o.Desc != "" {
			lines = append(lines, fmt.Sprintf("        set comment %q", o.Desc))
		}
		lines = append(lines, "    next")
		out := strings.Join(lines, "\n")
		w("%s", out)
		res.Items = append(res.Items, Item{Category: "object", Name: o.Name, Status: StConverted, Output: out})
	}
	// helper addresses for literals
	litAddrs := map[string]string{}
	ensureAddr := func(lit string) string {
		if n, ok := litAddrs[lit]; ok {
			return n
		}
		name := nm.name("RF-" + strings.NewReplacer("/", "-", ":", "_").Replace(lit))
		litAddrs[lit] = name
		return name
	}
	collectLits := func(refs []fwir.Ref) {
		for _, r := range refs {
			k := classifyRef(x, r)
			if k == refLiteralCIDR || k == refLiteralRange {
				ensureAddr(string(r))
			}
		}
	}
	for _, r := range x.Rules {
		collectLits(r.SrcAddrs)
		collectLits(r.DstAddrs)
	}
	for _, n := range x.NATs {
		for _, r := range []fwir.Ref{n.OrigSrc, n.OrigDst, n.TransSrc, n.TransDst} {
			if r != "" && r != "interface" {
				k := classifyRef(x, r)
				if k == refLiteralCIDR || k == refLiteralRange {
					ensureAddr(string(r))
				}
			}
		}
	}
	for lit, name := range litAddrs {
		var def string
		if strings.Contains(lit, "-") && !strings.Contains(lit, "/") {
			parts := strings.SplitN(lit, "-", 2)
			def = fmt.Sprintf("    edit %q\n        set type iprange\n        set start-ip %s\n        set end-ip %s\n    next", name, parts[0], parts[1])
		} else if ip, mask, err := fwir.SplitCIDR(lit); err == nil {
			def = fmt.Sprintf("    edit %q\n        set subnet %s %s\n    next", name, ip, mask)
		} else {
			continue
		}
		w("%s", def)
	}
	w("end")
	w("")

	// ---- address groups ----
	if len(x.Objects.NetGroups) > 0 {
		w("config firewall addrgrp")
		for _, g := range x.Objects.NetGroups {
			name := nm.name(g.Name)
			var mem []string
			status, detail := StConverted, ""
			for _, mm := range g.Members {
				switch {
				case x.Objects.FindNet(mm) != nil || x.Objects.FindNetGroup(mm) != nil:
					mem = append(mem, fmt.Sprintf("%q", nm.lookup(mm)))
				case fwir.Ref(mm).IsLiteral():
					mem = append(mem, fmt.Sprintf("%q", ensureAddr(mm)))
					status, detail = StPartial, "literal members wrapped in helper address objects — ensure they were emitted"
				default:
					status, detail = StPartial, "member "+mm+" unresolved"
				}
			}
			out := fmt.Sprintf("    edit %q\n        set member %s\n    next", name, strings.Join(mem, " "))
			w("%s", out)
			res.Items = append(res.Items, Item{Category: "group", Name: g.Name, Status: status, Detail: detail, Output: out})
		}
		w("end")
		w("")
	}

	// ---- services ----
	w("config firewall service custom")
	for _, s := range x.Objects.Services {
		name := nm.name(s.Name)
		var lines []string
		lines = append(lines, fmt.Sprintf("    edit %q", name))
		status, detail := StConverted, ""
		switch s.Proto {
		case "tcp":
			lines = append(lines, "        set tcp-portrange "+orDef(s.Port, "1-65535"))
		case "udp":
			lines = append(lines, "        set udp-portrange "+orDef(s.Port, "1-65535"))
		case "tcp-udp":
			lines = append(lines, "        set tcp-portrange "+orDef(s.Port, "1-65535"))
			lines = append(lines, "        set udp-portrange "+orDef(s.Port, "1-65535"))
		case "sctp":
			lines = append(lines, "        set sctp-portrange "+orDef(s.Port, "1-65535"))
		case "icmp":
			lines = append(lines, "        set protocol ICMP")
			if s.ICMPType != "" {
				lines = append(lines, "        set icmptype "+s.ICMPType)
			}
		case "ip", "":
			lines = append(lines, "        set protocol IP")
		default:
			lines = append(lines, "        set protocol IP")
			lines = append(lines, "        set protocol-number "+s.Proto)
			detail = "protocol " + s.Proto + " mapped by number — verify"
		}
		if s.SrcPort != "" {
			status = worst(status, StPartial)
			detail = strings.TrimSpace(detail + " source-port constraint (" + s.SrcPort + ") appended to portrange")
			// FortiOS: portrange dst:src
			for i, l := range lines {
				if strings.Contains(l, "-portrange ") {
					lines[i] = l + ":" + s.SrcPort
				}
			}
		}
		if s.Desc != "" {
			lines = append(lines, fmt.Sprintf("        set comment %q", s.Desc))
		}
		lines = append(lines, "    next")
		out := strings.Join(lines, "\n")
		w("%s", out)
		res.Items = append(res.Items, Item{Category: "service", Name: s.Name, Status: status, Detail: detail, Output: out})
	}
	// helper services for literals in rules
	litSvcs := map[string]string{}
	ensureSvc := func(s fwir.SvcRef) (string, bool) {
		proto, port, ok := s.SplitSvcLiteral()
		if !ok {
			return "", false
		}
		key := proto + "/" + port
		if n, ok := litSvcs[key]; ok {
			return n, true
		}
		name := nm.name("RF-" + proto + "-" + strings.ReplaceAll(orDef(port, "all"), "-", "_"))
		litSvcs[key] = name
		var def string
		switch proto {
		case "tcp":
			def = fmt.Sprintf("    edit %q\n        set tcp-portrange %s\n    next", name, orDef(port, "1-65535"))
		case "udp":
			def = fmt.Sprintf("    edit %q\n        set udp-portrange %s\n    next", name, orDef(port, "1-65535"))
		case "tcp-udp":
			def = fmt.Sprintf("    edit %q\n        set tcp-portrange %s\n        set udp-portrange %s\n    next", name, orDef(port, "1-65535"), orDef(port, "1-65535"))
		case "icmp":
			def = fmt.Sprintf("    edit %q\n        set protocol ICMP\n    next", name)
		default:
			def = fmt.Sprintf("    edit %q\n        set protocol IP\n    next", name)
		}
		w("%s", def)
		return name, true
	}
	// pre-walk rules so helper services are inside this config block
	for _, r := range x.Rules {
		for _, s := range r.Services {
			if classifySvc(x, s) == svcLiteral {
				ensureSvc(s)
			}
		}
	}
	w("end")
	w("")

	if len(x.Objects.SvcGroups) > 0 {
		w("config firewall service group")
		for _, g := range x.Objects.SvcGroups {
			name := nm.name(g.Name)
			var mem []string
			status, detail := StConverted, ""
			for _, mm := range g.Members {
				if x.Objects.FindSvc(mm) != nil || x.Objects.FindSvcGroup(mm) != nil {
					mem = append(mem, fmt.Sprintf("%q", nm.lookup(mm)))
					continue
				}
				if hn, ok := litSvcs[strings.ReplaceAll(mm, "//", "/")]; ok {
					mem = append(mem, fmt.Sprintf("%q", hn))
					continue
				}
				if _, _, ok := fwir.SvcRef(mm).SplitSvcLiteral(); ok {
					// helper emitted in custom block already? if not, mark
					if hn, ok2 := litSvcs[mm]; ok2 {
						mem = append(mem, fmt.Sprintf("%q", hn))
						continue
					}
					status, detail = StPartial, "literal member "+mm+" — helper service missing, add manually"
					continue
				}
				status, detail = StPartial, "member "+mm+" unresolved"
			}
			out := fmt.Sprintf("    edit %q\n        set member %s\n    next", name, strings.Join(mem, " "))
			w("%s", out)
			res.Items = append(res.Items, Item{Category: "group", Name: g.Name, Status: status, Detail: detail, Output: out})
		}
		w("end")
		w("")
	}

	// ---- VIPs (static destination NAT) & ippools ----
	var vipNATs []int
	var snatNATs []int
	for i, n := range x.NATs {
		if (n.Kind == fwir.NATStatic || n.Kind == fwir.NATTwice) && n.TransDst != "" {
			vipNATs = append(vipNATs, i)
		} else {
			snatNATs = append(snatNATs, i)
		}
	}
	resolveIP := func(r fwir.Ref) string {
		s := string(r)
		if o := x.Objects.FindNet(s); o != nil {
			return o.Value
		}
		return fwir.HostPart(s)
	}
	if len(vipNATs) > 0 {
		w("config firewall vip")
		for _, i := range vipNATs {
			n := x.NATs[i]
			name := nm.name(firstNonEmpty(n.Name, fmt.Sprintf("nat-%d-vip", n.Index)))
			var lines []string
			lines = append(lines, fmt.Sprintf("    edit %q", name))
			// For dst-NAT: external = original dst, mapped = translated dst
			lines = append(lines, "        set extip "+resolveIP(n.OrigDst))
			lines = append(lines, "        set mappedip "+resolveIP(n.TransDst))
			if n.DstIface != "" && n.DstIface != "any" {
				lines = append(lines, fmt.Sprintf("        set extintf %q", m.MapIface(m.MapZone(n.DstIface))))
			} else {
				lines = append(lines, "        set extintf \"any\"")
			}
			status, detail := StConverted, ""
			if p1, port1, ok1 := n.OrigSvc.SplitSvcLiteral(); ok1 && port1 != "" {
				_, port2, _ := n.TransSvc.SplitSvcLiteral()
				lines = append(lines, "        set portforward enable")
				lines = append(lines, "        set protocol "+p1)
				lines = append(lines, "        set extport "+port1)
				lines = append(lines, "        set mappedport "+orDef(port2, port1))
			}
			if n.OrigSrc != "" && !n.OrigSrc.IsAny() {
				status, detail = StPartial, "original-source restriction on dst-NAT — apply via matching policy"
			}
			lines = append(lines, "    next")
			out := strings.Join(lines, "\n")
			w("%s", out)
			res.Items = append(res.Items, Item{Category: "nat", Name: firstNonEmpty(n.Name, fmt.Sprintf("nat %d", n.Index)), Status: status, Detail: detail, Output: out})
		}
		w("end")
		w("")
	}
	// ippools for dynamic pools
	poolName := map[int]string{}
	var poolDefs []string
	for _, i := range snatNATs {
		n := x.NATs[i]
		if n.Kind == fwir.NATDynamic && n.TransSrc != "" && n.TransSrc != "interface" {
			pname := nm.name(firstNonEmpty(string(n.TransSrc), fmt.Sprintf("pool-%d", n.Index)) + "-pool")
			poolName[i] = pname
			start, end := resolveIP(n.TransSrc), resolveIP(n.TransSrc)
			if o := x.Objects.FindNet(string(n.TransSrc)); o != nil && o.Kind == fwir.NetRange {
				start, end = o.Value, o.Value2
			}
			poolDefs = append(poolDefs, fmt.Sprintf("    edit %q\n        set startip %s\n        set endip %s\n    next", pname, start, end))
		}
	}
	if len(poolDefs) > 0 {
		w("config firewall ippool")
		for _, d := range poolDefs {
			w("%s", d)
		}
		w("end")
		w("")
	}
	// central SNAT
	if len(snatNATs) > 0 {
		w("config firewall central-snat-map")
		id := 0
		for _, i := range snatNATs {
			n := x.NATs[i]
			id++
			var lines []string
			lines = append(lines, fmt.Sprintf("    edit %d", id))
			srcIntf := orDef(m.MapZone(n.SrcIface), "any")
			dstIntf := orDef(m.MapZone(n.DstIface), "any")
			lines = append(lines, fmt.Sprintf("        set srcintf %q", srcIntf))
			lines = append(lines, fmt.Sprintf("        set dstintf %q", dstIntf))
			orig := "all"
			if n.OrigSrc != "" && !n.OrigSrc.IsAny() {
				orig = fortiRefName(x, nm, litAddrs, n.OrigSrc)
			}
			lines = append(lines, fmt.Sprintf("        set orig-addr %q", orig))
			dst := "all"
			if n.OrigDst != "" && !n.OrigDst.IsAny() {
				dst = fortiRefName(x, nm, litAddrs, n.OrigDst)
			}
			lines = append(lines, fmt.Sprintf("        set dst-addr %q", dst))
			status, detail := StConverted, ""
			switch n.Kind {
			case fwir.NATDynamic:
				if pn, ok := poolName[i]; ok {
					lines = append(lines, "        set nat-ippool "+fmt.Sprintf("%q", pn))
				}
			case fwir.NATStatic:
				status, detail = StPartial, "1:1 source static NAT expressed as SNAT map — verify port behaviour (FortiOS hides by default)"
				if n.TransSrc != "" && n.TransSrc != "interface" {
					lines = append(lines, "        set nat-ippool "+fmt.Sprintf("%q", nm.lookup(string(n.TransSrc))))
					detail += "; consider an ippool type one-to-one"
				}
			}
			if !n.Enabled {
				lines = append(lines, "        set status disable")
			}
			lines = append(lines, "        set nat enable")
			lines = append(lines, "    next")
			out := strings.Join(lines, "\n")
			w("%s", out)
			res.Items = append(res.Items, Item{Category: "nat", Name: firstNonEmpty(n.Name, fmt.Sprintf("nat %d", n.Index)), Status: status, Detail: detail, Output: out})
		}
		w("end")
		w("")
	}

	// ---- policies ----
	w("config firewall policy")
	pid := 0
	for _, r := range x.Rules {
		pid++
		status := StConverted
		var details []string
		var lines []string
		lines = append(lines, fmt.Sprintf("    edit %d", pid))
		if r.Name != "" {
			lines = append(lines, fmt.Sprintf("        set name %q", truncate(nm.unique(r.Name), 35)))
		}
		src := zoneList(mapZones(m, r.SrcZones))
		dst := zoneList(mapZones(m, r.DstZones))
		lines = append(lines, "        set srcintf "+src)
		lines = append(lines, "        set dstintf "+dst)
		lines = append(lines, "        set srcaddr "+fortiAddrList(x, nm, litAddrs, r.SrcAddrs, &status, &details))
		lines = append(lines, "        set dstaddr "+fortiAddrList(x, nm, litAddrs, r.DstAddrs, &status, &details))
		var svcs []string
		for _, s := range r.Services {
			switch classifySvc(x, s) {
			case svcAny:
			case svcObj, svcGroup:
				svcs = append(svcs, fmt.Sprintf("%q", nm.lookup(string(s))))
			case svcLiteral:
				proto, port, _ := s.SplitSvcLiteral()
				if hn, ok := litSvcs[proto+"/"+port]; ok {
					svcs = append(svcs, fmt.Sprintf("%q", hn))
				}
			default:
				status = worst(status, StPartial)
				details = append(details, "service "+string(s)+" unresolved — set to ALL, VERIFY")
			}
		}
		if len(svcs) == 0 {
			lines = append(lines, "        set service \"ALL\"")
		} else {
			lines = append(lines, "        set service "+strings.Join(svcs, " "))
		}
		action := "accept"
		if r.Action == "deny" {
			action = "deny"
		}
		lines = append(lines, "        set action "+action)
		lines = append(lines, "        set schedule \"always\"")
		if r.Log {
			lines = append(lines, "        set logtraffic all")
		}
		if !r.Enabled {
			lines = append(lines, "        set status disable")
		}
		if r.Desc != "" {
			lines = append(lines, fmt.Sprintf("        set comments %q", truncate(r.Desc, 250)))
		}
		if len(r.Apps) > 0 {
			status = worst(status, StPartial)
			details = append(details, "L7 applications ("+strings.Join(r.Apps, ", ")+") need an application-list profile — attach manually")
		}
		if len(r.URLCats) > 0 {
			status = worst(status, StPartial)
			details = append(details, "URL categories need a webfilter profile — attach manually")
		}
		lines = append(lines, "    next")
		out := strings.Join(lines, "\n")
		w("%s", out)
		res.Items = append(res.Items, Item{Category: "rule", Name: firstNonEmpty(r.Name, fmt.Sprintf("rule %d", r.Index)), Status: status, Detail: strings.Join(details, "; "), Output: out})
	}
	w("end")
	w("")

	// ---- routes ----
	if len(x.Routes) > 0 {
		w("config router static")
		for i, r := range x.Routes {
			ip, mask, err := fwir.SplitCIDR(r.Dest)
			if err != nil {
				res.Items = append(res.Items, Item{Category: "route", Name: r.Dest, Status: StFailed, Detail: err.Error()})
				continue
			}
			var lines []string
			lines = append(lines, fmt.Sprintf("    edit %d", i+1))
			lines = append(lines, fmt.Sprintf("        set dst %s %s", ip, mask))
			if r.Gateway != "" {
				lines = append(lines, "        set gateway "+r.Gateway)
			}
			if r.Iface != "" {
				lines = append(lines, fmt.Sprintf("        set device %q", m.MapIface(r.Iface)))
			}
			if r.Metric > 0 {
				lines = append(lines, fmt.Sprintf("        set distance %d", r.Metric))
			}
			lines = append(lines, "    next")
			out := strings.Join(lines, "\n")
			w("%s", out)
			res.Items = append(res.Items, Item{Category: "route", Name: r.Dest, Status: StConverted, Output: out})
		}
		w("end")
	}

	captureItems(x, res)
	res.Files = append(res.Files, File{Name: "fortigate-" + safeFile(x.Name) + ".conf", Content: b.String()})
	res.Renames = nm.Renames
	return res
}

func zoneList(zs []string) string {
	if len(zs) == 0 {
		return "\"any\""
	}
	var q []string
	for _, z := range zs {
		q = append(q, fmt.Sprintf("%q", z))
	}
	return strings.Join(q, " ")
}

func fortiRefName(x *fwir.Context, nm *namer, litAddrs map[string]string, r fwir.Ref) string {
	switch classifyRef(x, r) {
	case refNetObj, refNetGroup:
		return nm.lookup(string(r))
	case refLiteralCIDR, refLiteralRange:
		if n, ok := litAddrs[string(r)]; ok {
			return n
		}
	}
	return string(r)
}

func fortiAddrList(x *fwir.Context, nm *namer, litAddrs map[string]string, refs []fwir.Ref, status *string, details *[]string) string {
	if len(refs) == 0 {
		return "\"all\""
	}
	var mems []string
	for _, r := range refs {
		switch classifyRef(x, r) {
		case refAny:
			return "\"all\""
		case refNetObj, refNetGroup:
			mems = append(mems, fmt.Sprintf("%q", nm.lookup(string(r))))
		case refLiteralCIDR, refLiteralRange:
			if n, ok := litAddrs[string(r)]; ok {
				mems = append(mems, fmt.Sprintf("%q", n))
			}
		default:
			*status = worst(*status, StPartial)
			*details = append(*details, "reference "+string(r)+" unresolved — omitted, VERIFY")
		}
	}
	if len(mems) == 0 {
		return "\"all\""
	}
	return strings.Join(mems, " ")
}
