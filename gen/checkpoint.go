package gen

import (
	"fmt"
	"strings"

	"github.com/nizartuanku/ruleforge/fwir"
)

// genCheckPoint renders one context as (a) an mgmt_cli script for objects,
// access rules and NAT, and (b) a Gaia clish script for interfaces/routes.
func genCheckPoint(x *fwir.Context, m *Mapping) *Result {
	res := &Result{Context: x.Name}
	nm := newNamer(fwir.VendorCheckPoint)
	var mg strings.Builder // mgmt_cli
	var gc strings.Builder // gaia clish
	wm := func(format string, a ...any) { fmt.Fprintf(&mg, format+"\n", a...) }
	wg := func(format string, a ...any) { fmt.Fprintf(&gc, format+"\n", a...) }

	layer := safeFile(x.Name)
	if layer == "default" {
		layer = "RuleForge"
	}
	layer += " Network"

	wm("#!/bin/bash")
	wm("# RuleForge — generated Check Point mgmt_cli script")
	wm("# Context: %s — access layer: %q", x.Name, layer)
	wm("# Run: mgmt_cli login > id.txt   then   bash this-script.sh   then   mgmt_cli publish -s id.txt")
	wm("S=\"-s id.txt\"")
	wm("")

	// ---- Gaia: interfaces & routes ----
	wg("# RuleForge — generated Gaia clish script (interfaces & routes)")
	wg("# Context: %s — run in clish, then `save config`", x.Name)
	for _, ifc := range x.Interfaces {
		tgt := m.MapIface(ifc.Name)
		status := StConverted
		detail := ""
		var lines []string
		switch ifc.Kind {
		case fwir.IfAggregate:
			bondID := strings.TrimLeft(tgt, "bond")
			if bondID == tgt || bondID == "" {
				bondID = "1"
				detail = "aggregate mapped to bonding group 1 — adjust id"
				status = StPartial
			}
			lines = append(lines, fmt.Sprintf("add bonding group %s", bondID))
			for _, mem := range ifc.Members {
				lines = append(lines, fmt.Sprintf("add bonding group %s interface %s", bondID, m.MapIface(mem)))
			}
			tgt = "bond" + bondID
		case fwir.IfSubIf:
			lines = append(lines, fmt.Sprintf("add interface %s vlan %d", m.MapIface(ifc.Parent), ifc.VlanID))
			tgt = fmt.Sprintf("%s.%d", m.MapIface(ifc.Parent), ifc.VlanID)
		case fwir.IfBridge:
			status, detail = StPartial, "bridge — create bridging group in Gaia manually; members: "+strings.Join(ifc.Members, ", ")
		}
		for _, ip := range ifc.IPs {
			parts := strings.SplitN(ip, "/", 2)
			if len(parts) == 2 {
				lines = append(lines, fmt.Sprintf("set interface %s ipv4-address %s mask-length %s", tgt, parts[0], parts[1]))
			}
		}
		if ifc.Desc != "" {
			lines = append(lines, fmt.Sprintf("set interface %s comments %q", tgt, ifc.Desc))
		}
		if !ifc.Shutdown {
			lines = append(lines, fmt.Sprintf("set interface %s state on", tgt))
		} else {
			lines = append(lines, fmt.Sprintf("set interface %s state off", tgt))
		}
		if ifc.MTU > 0 {
			lines = append(lines, fmt.Sprintf("set interface %s mtu %d", tgt, ifc.MTU))
		}
		out := strings.Join(lines, "\n")
		wg("%s", out)
		res.Items = append(res.Items, Item{Category: "interface", Name: ifc.Name, Status: status, Detail: detail, Output: out})
	}
	for _, r := range x.Routes {
		dest := r.Dest
		if dest == "0.0.0.0/0" {
			dest = "default"
		}
		l := fmt.Sprintf("set static-route %s nexthop gateway address %s on", dest, r.Gateway)
		wg("%s", l)
		res.Items = append(res.Items, Item{Category: "route", Name: r.Dest, Status: StConverted, Output: l})
	}
	wg("save config")

	// ---- zones ----
	for _, z := range x.Zones {
		tz := nm.name(m.MapZone(z.Name))
		l := fmt.Sprintf("mgmt_cli add security-zone name %q $S", tz)
		wm("%s", l)
		res.Items = append(res.Items, Item{
			Category: "zone", Name: z.Name, Status: StPartial,
			Detail: "security-zone object created — bind it to the gateway interface (" + strings.Join(z.Interfaces, ", ") + ") in the gateway topology editor",
			Output: l,
		})
	}
	wm("")

	// ---- objects ----
	for _, o := range x.Objects.Networks {
		name := nm.name(o.Name)
		var l string
		switch o.Kind {
		case fwir.NetHost:
			l = fmt.Sprintf("mgmt_cli add host name %q ip-address %s $S", name, o.Value)
		case fwir.NetSubnet:
			parts := strings.SplitN(o.Value, "/", 2)
			if len(parts) != 2 {
				res.Items = append(res.Items, Item{Category: "object", Name: o.Name, Status: StFailed, Detail: "bad subnet " + o.Value})
				continue
			}
			l = fmt.Sprintf("mgmt_cli add network name %q subnet %s mask-length %s $S", name, parts[0], parts[1])
		case fwir.NetRange:
			l = fmt.Sprintf("mgmt_cli add address-range name %q ip-address-first %s ip-address-last %s $S", name, o.Value, o.Value2)
		case fwir.NetFQDN:
			l = fmt.Sprintf("mgmt_cli add dns-domain name %q is-sub-domain false $S", "."+strings.TrimPrefix(o.Value, "."))
			res.Items = append(res.Items, Item{Category: "object", Name: o.Name, Status: StPartial,
				Detail: "FQDN object becomes dns-domain ." + o.Value + " (Check Point matches by DNS suffix)", Output: l})
			wm("%s", l)
			continue
		}
		if o.Desc != "" {
			l += fmt.Sprintf(" comments %q", o.Desc)
		}
		wm("%s", l)
		res.Items = append(res.Items, Item{Category: "object", Name: o.Name, Status: StConverted, Output: l})
	}
	helper := map[string]string{}
	ensureNet := func(lit string) string {
		if n, ok := helper[lit]; ok {
			return n
		}
		name := nm.name("RF_" + strings.NewReplacer("/", "-", ".", "_", ":", "_").Replace(lit))
		helper[lit] = name
		if strings.Contains(lit, "-") && !strings.Contains(lit, "/") {
			parts := strings.SplitN(lit, "-", 2)
			wm("mgmt_cli add address-range name %q ip-address-first %s ip-address-last %s $S", name, parts[0], parts[1])
		} else if fwir.IsHostCIDR(lit) {
			wm("mgmt_cli add host name %q ip-address %s $S", name, fwir.HostPart(lit))
		} else {
			parts := strings.SplitN(lit, "/", 2)
			wm("mgmt_cli add network name %q subnet %s mask-length %s $S", name, parts[0], parts[1])
		}
		return name
	}
	for _, s := range x.Objects.Services {
		name := nm.name(s.Name)
		var l string
		status, detail := StConverted, ""
		switch s.Proto {
		case "tcp":
			l = fmt.Sprintf("mgmt_cli add service-tcp name %q port %s $S", name, orDef(s.Port, "1-65535"))
		case "udp":
			l = fmt.Sprintf("mgmt_cli add service-udp name %q port %s $S", name, orDef(s.Port, "1-65535"))
		case "tcp-udp":
			l1 := fmt.Sprintf("mgmt_cli add service-tcp name %q port %s $S", nm.name(s.Name+"-tcp"), orDef(s.Port, "1-65535"))
			l2 := fmt.Sprintf("mgmt_cli add service-udp name %q port %s $S", nm.name(s.Name+"-udp"), orDef(s.Port, "1-65535"))
			wm("%s", l1)
			wm("%s", l2)
			res.Items = append(res.Items, Item{Category: "service", Name: s.Name, Status: StPartial,
				Detail: "tcp-udp split into two services", Output: l1 + "\n" + l2})
			continue
		case "icmp":
			l = fmt.Sprintf("mgmt_cli add service-icmp name %q $S", name)
			if s.ICMPType != "" {
				l = fmt.Sprintf("mgmt_cli add service-icmp name %q icmp-type %s $S", name, s.ICMPType)
			}
		default:
			l = fmt.Sprintf("mgmt_cli add service-other name %q ip-protocol %s $S", name, s.Proto)
			status, detail = StPartial, "IP-protocol service — verify protocol number"
		}
		wm("%s", l)
		res.Items = append(res.Items, Item{Category: "service", Name: s.Name, Status: status, Detail: detail, Output: l})
	}
	ensureSvc := func(s fwir.SvcRef) (string, bool) {
		proto, port, ok := s.SplitSvcLiteral()
		if !ok {
			return "", false
		}
		key := "svc:" + proto + "/" + port
		if n, ok := helper[key]; ok {
			return n, true
		}
		name := nm.name("RF_" + proto + "_" + strings.ReplaceAll(orDef(port, "all"), "-", "_"))
		helper[key] = name
		switch proto {
		case "tcp", "tcp-udp":
			wm("mgmt_cli add service-tcp name %q port %s $S", name, orDef(port, "1-65535"))
		case "udp":
			wm("mgmt_cli add service-udp name %q port %s $S", name, orDef(port, "1-65535"))
		case "icmp":
			wm("mgmt_cli add service-icmp name %q $S", name)
		default:
			wm("mgmt_cli add service-other name %q ip-protocol %s $S", name, proto)
		}
		return name, true
	}
	for _, g := range x.Objects.NetGroups {
		name := nm.name(g.Name)
		parts := []string{fmt.Sprintf("mgmt_cli add group name %q", name)}
		status, detail := StConverted, ""
		i := 0
		for _, mm := range g.Members {
			var ref string
			switch {
			case x.Objects.FindNet(mm) != nil || x.Objects.FindNetGroup(mm) != nil:
				ref = nm.lookup(mm)
			case fwir.Ref(mm).IsLiteral():
				ref = ensureNet(mm)
			default:
				status, detail = StPartial, "member "+mm+" unresolved"
				continue
			}
			i++
			parts = append(parts, fmt.Sprintf("members.%d %q", i, ref))
		}
		l := strings.Join(parts, " ") + " $S"
		wm("%s", l)
		res.Items = append(res.Items, Item{Category: "group", Name: g.Name, Status: status, Detail: detail, Output: l})
	}
	for _, g := range x.Objects.SvcGroups {
		name := nm.name(g.Name)
		parts := []string{fmt.Sprintf("mgmt_cli add service-group name %q", name)}
		status, detail := StConverted, ""
		i := 0
		for _, mm := range g.Members {
			var ref string
			if x.Objects.FindSvc(mm) != nil || x.Objects.FindSvcGroup(mm) != nil {
				ref = nm.lookup(mm)
			} else if hn, ok := ensureSvc(fwir.SvcRef(mm)); ok {
				ref = hn
			} else {
				status, detail = StPartial, "member "+mm+" unresolved"
				continue
			}
			i++
			parts = append(parts, fmt.Sprintf("members.%d %q", i, ref))
		}
		l := strings.Join(parts, " ") + " $S"
		wm("%s", l)
		res.Items = append(res.Items, Item{Category: "group", Name: g.Name, Status: status, Detail: detail, Output: l})
	}
	wm("")

	// ---- access rules ----
	wm("# Access layer %q must exist (add access-layer name %q) or use your package's Network layer.", layer, layer)
	for _, r := range x.Rules {
		status := StConverted
		var details []string
		parts := []string{fmt.Sprintf("mgmt_cli add access-rule layer %q position bottom", layer)}
		rname := firstNonEmpty(r.Name, fmt.Sprintf("rule-%d", r.Index))
		parts = append(parts, fmt.Sprintf("name %q", rname))
		addRefs := func(field string, refs []fwir.Ref) {
			if len(refs) == 0 {
				return
			}
			i := 0
			for _, rr := range refs {
				var ref string
				switch classifyRef(x, rr) {
				case refAny:
					continue
				case refNetObj, refNetGroup:
					ref = nm.lookup(string(rr))
				case refLiteralCIDR, refLiteralRange:
					ref = ensureNet(string(rr))
				default:
					status = worst(status, StPartial)
					details = append(details, field+" reference "+string(rr)+" unresolved — omitted, VERIFY")
					continue
				}
				i++
				parts = append(parts, fmt.Sprintf("%s.%d %q", field, i, ref))
			}
		}
		addRefs("source", r.SrcAddrs)
		addRefs("destination", r.DstAddrs)
		i := 0
		for _, s := range r.Services {
			var ref string
			switch classifySvc(x, s) {
			case svcAny:
				continue
			case svcObj, svcGroup:
				ref = nm.lookup(string(s))
			case svcLiteral:
				if hn, ok := ensureSvc(s); ok {
					ref = hn
				} else {
					continue
				}
			default:
				status = worst(status, StPartial)
				details = append(details, "service "+string(s)+" unresolved — omitted, VERIFY")
				continue
			}
			i++
			parts = append(parts, fmt.Sprintf("service.%d %q", i, ref))
		}
		action := "Accept"
		if r.Action == "deny" {
			action = "Drop"
		}
		parts = append(parts, fmt.Sprintf("action %q", action))
		if r.Log {
			parts = append(parts, "track.type \"Log\"")
		}
		if !r.Enabled {
			parts = append(parts, "enabled false")
		}
		comment := r.Desc
		if len(r.SrcZones)+len(r.DstZones) > 0 {
			zinfo := "zones: " + strings.Join(mapZones(m, r.SrcZones), ",") + " -> " + strings.Join(mapZones(m, r.DstZones), ",")
			comment = strings.TrimSpace(comment + " [" + zinfo + "]")
			details = append(details, "zone match recorded in comment — Check Point applies zones via gateway topology")
			status = worst(status, StPartial)
		}
		if len(r.Apps) > 0 {
			status = worst(status, StPartial)
			details = append(details, "applications ("+strings.Join(r.Apps, ", ")+") — recreate with Application Control layer")
		}
		if len(r.URLCats) > 0 {
			status = worst(status, StPartial)
			details = append(details, "URL categories — recreate with URL Filtering")
		}
		if comment != "" {
			parts = append(parts, fmt.Sprintf("comments %q", truncate(comment, 150)))
		}
		l := strings.Join(parts, " ") + " $S"
		wm("%s", l)
		res.Items = append(res.Items, Item{Category: "rule", Name: rname, Status: status, Detail: strings.Join(details, "; "), Output: l})
	}
	wm("")

	// ---- NAT ----
	wm("# NAT rules target package \"standard\" — change to your policy package name.")
	for _, n := range x.NATs {
		status := StConverted
		var details []string
		parts := []string{"mgmt_cli add nat-rule package \"standard\" position bottom"}
		method := "static"
		switch n.Kind {
		case fwir.NATDynamicPAT, fwir.NATDynamic:
			method = "hide"
			if n.Kind == fwir.NATDynamic {
				details = append(details, "dynamic pool NAT expressed as hide NAT behind the pool object — verify")
				status = StPartial
			}
		}
		parts = append(parts, fmt.Sprintf("method %q", method))
		cpRef := func(r fwir.Ref) (string, bool) {
			switch classifyRef(x, r) {
			case refNetObj, refNetGroup:
				return nm.lookup(string(r)), true
			case refLiteralCIDR, refLiteralRange:
				return ensureNet(string(r)), true
			}
			return "", false
		}
		if n.OrigSrc != "" && !n.OrigSrc.IsAny() {
			if ref, ok := cpRef(n.OrigSrc); ok {
				parts = append(parts, fmt.Sprintf("original-source %q", ref))
			}
		}
		if n.OrigDst != "" && !n.OrigDst.IsAny() {
			if ref, ok := cpRef(n.OrigDst); ok {
				parts = append(parts, fmt.Sprintf("original-destination %q", ref))
			}
		}
		if n.TransSrc != "" && n.TransSrc != "interface" {
			if ref, ok := cpRef(n.TransSrc); ok {
				parts = append(parts, fmt.Sprintf("translated-source %q", ref))
			}
		} else if n.TransSrc == "interface" {
			status = worst(status, StPartial)
			details = append(details, "PAT to egress-interface address → configure hide-behind-gateway on the object or gateway")
		}
		if n.TransDst != "" {
			if ref, ok := cpRef(n.TransDst); ok {
				parts = append(parts, fmt.Sprintf("translated-destination %q", ref))
			}
		}
		if n.OrigSvc != "" && !n.OrigSvc.IsAny() {
			if hn, ok := ensureSvc(n.OrigSvc); ok {
				parts = append(parts, fmt.Sprintf("original-service %q", hn))
			} else if x.Objects.FindSvc(string(n.OrigSvc)) != nil {
				parts = append(parts, fmt.Sprintf("original-service %q", nm.lookup(string(n.OrigSvc))))
			}
		}
		if n.TransSvc != "" && !n.TransSvc.IsAny() {
			if hn, ok := ensureSvc(n.TransSvc); ok {
				parts = append(parts, fmt.Sprintf("translated-service %q", hn))
			}
		}
		if !n.Enabled {
			parts = append(parts, "enabled false")
		}
		l := strings.Join(parts, " ") + " $S"
		wm("%s", l)
		res.Items = append(res.Items, Item{Category: "nat", Name: firstNonEmpty(n.Name, fmt.Sprintf("nat %d", n.Index)), Status: status, Detail: strings.Join(details, "; "), Output: l})
	}
	wm("")
	wm("# mgmt_cli publish -s id.txt")

	captureItems(x, res)
	res.Files = append(res.Files,
		File{Name: "checkpoint-" + safeFile(x.Name) + "-mgmt.sh", Content: mg.String()},
		File{Name: "checkpoint-" + safeFile(x.Name) + "-gaia.txt", Content: gc.String()},
	)
	res.Renames = nm.Renames
	return res
}
