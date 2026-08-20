package gen

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/nizartuanku/ruleforge/fwir"
)

// genFTD renders one context as an FMC-ready bundle: a JSON file whose shape
// follows the FMC REST API object models (networks, ports, groups, security
// zones, access policy, NAT policy) plus a README describing the import
// order, and an interface/route worksheet (FMC configures device interfaces
// per-device, so those ship as a reviewed worksheet rather than blind JSON).
func genFTD(x *fwir.Context, m *Mapping) *Result {
	res := &Result{Context: x.Name}
	nm := newNamer(fwir.VendorFTD)

	type obj = map[string]any
	bundle := obj{
		"$schema":   "ruleforge-fmc-bundle-v1",
		"context":   x.Name,
		"generator": "RuleForge",
	}

	// ---- security zones ----
	var zones []obj
	zoneSet := map[string]bool{}
	addZone := func(name string) {
		if name == "" || zoneSet[name] {
			return
		}
		zoneSet[name] = true
		zones = append(zones, obj{"type": "SecurityZone", "name": name, "interfaceMode": "ROUTED"})
	}
	for _, z := range x.Zones {
		addZone(m.MapZone(z.Name))
	}
	for _, ifc := range x.Interfaces {
		if a := firstNonEmpty(ifc.Zone, ifc.Alias); a != "" {
			addZone(m.MapZone(a))
		}
	}
	for _, z := range x.Zones {
		res.Items = append(res.Items, Item{Category: "zone", Name: z.Name, Status: StConverted,
			Detail: "SecurityZone object; assign interfaces in FMC device management"})
	}

	// ---- network objects ----
	var nets, netGroups []obj
	for _, o := range x.Objects.Networks {
		name := nm.name(o.Name)
		switch o.Kind {
		case fwir.NetHost:
			nets = append(nets, obj{"type": "Host", "name": name, "value": o.Value, "description": o.Desc})
		case fwir.NetSubnet:
			nets = append(nets, obj{"type": "Network", "name": name, "value": o.Value, "description": o.Desc})
		case fwir.NetRange:
			nets = append(nets, obj{"type": "Range", "name": name, "value": o.Value + "-" + o.Value2, "description": o.Desc})
		case fwir.NetFQDN:
			nets = append(nets, obj{"type": "FQDN", "name": name, "value": o.Value, "dnsResolution": "IPV4_ONLY", "description": o.Desc})
		}
		res.Items = append(res.Items, Item{Category: "object", Name: o.Name, Status: StConverted})
	}
	litNet := map[string]string{}
	ensureNet := func(lit string) string {
		if n, ok := litNet[lit]; ok {
			return n
		}
		name := nm.name("RF-" + strings.NewReplacer("/", "-", ":", "_").Replace(lit))
		litNet[lit] = name
		typ := "Network"
		val := lit
		if strings.Contains(lit, "-") && !strings.Contains(lit, "/") {
			typ = "Range"
		} else if fwir.IsHostCIDR(lit) {
			typ, val = "Host", fwir.HostPart(lit)
		}
		nets = append(nets, obj{"type": typ, "name": name, "value": val})
		return name
	}
	for _, g := range x.Objects.NetGroups {
		name := nm.name(g.Name)
		var members, literals []obj
		status, detail := StConverted, ""
		for _, mm := range g.Members {
			switch {
			case x.Objects.FindNet(mm) != nil:
				members = append(members, obj{"type": "objectRef", "name": nm.lookup(mm)})
			case x.Objects.FindNetGroup(mm) != nil:
				members = append(members, obj{"type": "groupRef", "name": nm.lookup(mm)})
			case fwir.Ref(mm).IsLiteral():
				literals = append(literals, obj{"type": "Network", "value": mm})
			default:
				status, detail = StPartial, "member "+mm+" unresolved"
			}
		}
		netGroups = append(netGroups, obj{"type": "NetworkGroup", "name": name, "objects": members, "literals": literals, "description": g.Desc})
		res.Items = append(res.Items, Item{Category: "group", Name: g.Name, Status: status, Detail: detail})
	}

	// ---- port objects ----
	var ports, portGroups []obj
	for _, s := range x.Objects.Services {
		name := nm.name(s.Name)
		status, detail := StConverted, ""
		switch s.Proto {
		case "tcp", "udp", "sctp":
			p := obj{"type": "ProtocolPortObject", "name": name, "protocol": strings.ToUpper(s.Proto)}
			if s.Port != "" {
				p["port"] = s.Port
			}
			ports = append(ports, p)
		case "tcp-udp":
			ports = append(ports,
				obj{"type": "ProtocolPortObject", "name": name, "protocol": "TCP", "port": s.Port},
				obj{"type": "ProtocolPortObject", "name": nm.name(s.Name + "-udp"), "protocol": "UDP", "port": s.Port})
			status, detail = StPartial, "tcp-udp split into TCP + UDP port objects"
		case "icmp":
			p := obj{"type": "ICMPV4Object", "name": name}
			if s.ICMPType != "" {
				p["icmpType"] = s.ICMPType
			}
			ports = append(ports, p)
		default:
			ports = append(ports, obj{"type": "ProtocolPortObject", "name": name, "protocol": strings.ToUpper(s.Proto)})
			detail = "IP-protocol service — verify protocol mapping in FMC"
			status = StPartial
		}
		res.Items = append(res.Items, Item{Category: "service", Name: s.Name, Status: status, Detail: detail})
	}
	litPort := map[string]string{}
	ensurePort := func(s fwir.SvcRef) (string, bool) {
		proto, port, ok := s.SplitSvcLiteral()
		if !ok || proto == "ip" || proto == "any" {
			return "", false
		}
		key := proto + "/" + port
		if n, ok := litPort[key]; ok {
			return n, true
		}
		name := nm.name("RF-" + proto + "-" + strings.ReplaceAll(orDef(port, "all"), "-", "_"))
		litPort[key] = name
		if proto == "icmp" {
			ports = append(ports, obj{"type": "ICMPV4Object", "name": name})
		} else {
			p := obj{"type": "ProtocolPortObject", "name": name, "protocol": strings.ToUpper(protoSplitFirst(proto))}
			if port != "" {
				p["port"] = port
			}
			ports = append(ports, p)
		}
		return name, true
	}
	for _, g := range x.Objects.SvcGroups {
		name := nm.name(g.Name)
		var members []obj
		status, detail := StConverted, ""
		for _, mm := range g.Members {
			if x.Objects.FindSvc(mm) != nil || x.Objects.FindSvcGroup(mm) != nil {
				members = append(members, obj{"type": "objectRef", "name": nm.lookup(mm)})
				continue
			}
			if hn, ok := ensurePort(fwir.SvcRef(mm)); ok {
				members = append(members, obj{"type": "objectRef", "name": hn})
				continue
			}
			status, detail = StPartial, "member "+mm+" unresolved"
		}
		portGroups = append(portGroups, obj{"type": "PortObjectGroup", "name": name, "objects": members})
		res.Items = append(res.Items, Item{Category: "group", Name: g.Name, Status: status, Detail: detail})
	}

	// ---- access policy ----
	refListJSON := func(refs []fwir.Ref, status *string, details *[]string, side string) obj {
		var objects, literals []obj
		for _, r := range refs {
			switch classifyRef(x, r) {
			case refAny:
			case refNetObj:
				objects = append(objects, obj{"type": "objectRef", "name": nm.lookup(string(r))})
			case refNetGroup:
				objects = append(objects, obj{"type": "groupRef", "name": nm.lookup(string(r))})
			case refLiteralCIDR:
				literals = append(literals, obj{"type": "Network", "value": string(r)})
			case refLiteralRange:
				objects = append(objects, obj{"type": "objectRef", "name": ensureNet(string(r))})
			default:
				*status = worst(*status, StPartial)
				*details = append(*details, side+" reference "+string(r)+" unresolved — omitted, VERIFY")
			}
		}
		out := obj{}
		if len(objects) > 0 {
			out["objects"] = objects
		}
		if len(literals) > 0 {
			out["literals"] = literals
		}
		return out
	}
	var rules []obj
	for _, r := range x.Rules {
		status := StConverted
		var details []string
		rule := obj{
			"type":    "AccessRule",
			"name":    firstNonEmpty(r.Name, fmt.Sprintf("rule-%d", r.Index)),
			"action":  map[bool]string{true: "ALLOW", false: "BLOCK"}[r.Action == "allow"],
			"enabled": r.Enabled,
		}
		if len(r.SrcZones) > 0 {
			rule["sourceZones"] = zoneRefs(mapZones(m, r.SrcZones))
		}
		if len(r.DstZones) > 0 {
			rule["destinationZones"] = zoneRefs(mapZones(m, r.DstZones))
		}
		if v := refListJSON(r.SrcAddrs, &status, &details, "source"); len(v) > 0 {
			rule["sourceNetworks"] = v
		}
		if v := refListJSON(r.DstAddrs, &status, &details, "destination"); len(v) > 0 {
			rule["destinationNetworks"] = v
		}
		var pObjs, pLits []obj
		for _, s := range r.Services {
			switch classifySvc(x, s) {
			case svcAny:
			case svcObj, svcGroup:
				pObjs = append(pObjs, obj{"type": "objectRef", "name": nm.lookup(string(s))})
			case svcLiteral:
				proto, port, _ := s.SplitSvcLiteral()
				if proto == "ip" {
					continue
				}
				pLits = append(pLits, obj{"type": "PortLiteral", "protocol": strings.ToUpper(protoSplitFirst(proto)), "port": port})
			default:
				status = worst(status, StPartial)
				details = append(details, "service "+string(s)+" unresolved — omitted, VERIFY")
			}
		}
		if len(pObjs)+len(pLits) > 0 {
			dp := obj{}
			if len(pObjs) > 0 {
				dp["objects"] = pObjs
			}
			if len(pLits) > 0 {
				dp["literals"] = pLits
			}
			rule["destinationPorts"] = dp
		}
		if r.Log {
			rule["logBegin"] = false
			rule["logEnd"] = true
			rule["sendEventsToFMC"] = true
		}
		if r.Desc != "" {
			rule["commentHistoryList"] = []obj{{"comment": r.Desc}}
		}
		if len(r.Apps) > 0 {
			status = worst(status, StPartial)
			details = append(details, "L7 applications ("+strings.Join(r.Apps, ", ")+") — map to FTD application conditions manually")
		}
		if len(r.URLCats) > 0 {
			status = worst(status, StPartial)
			details = append(details, "URL categories — recreate with FTD URL filtering (license required)")
		}
		rules = append(rules, rule)
		res.Items = append(res.Items, Item{Category: "rule", Name: firstNonEmpty(r.Name, fmt.Sprintf("rule %d", r.Index)), Status: status, Detail: strings.Join(details, "; ")})
	}

	// ---- NAT policy ----
	var natRules []obj
	for _, n := range x.NATs {
		status := StConverted
		var details []string
		nr := obj{
			"type":    "FTDManualNatRule",
			"enabled": n.Enabled,
		}
		switch n.Kind {
		case fwir.NATStatic, fwir.NATTwice:
			nr["natType"] = "STATIC"
		default:
			nr["natType"] = "DYNAMIC"
		}
		if n.SrcIface != "" && n.SrcIface != "any" {
			nr["sourceInterface"] = obj{"type": "SecurityZone", "name": m.MapZone(n.SrcIface)}
			addZone(m.MapZone(n.SrcIface))
		}
		if n.DstIface != "" && n.DstIface != "any" {
			nr["destinationInterface"] = obj{"type": "SecurityZone", "name": m.MapZone(n.DstIface)}
			addZone(m.MapZone(n.DstIface))
		}
		setRef := func(key string, r fwir.Ref) {
			if r == "" || r.IsAny() {
				return
			}
			if r == "interface" {
				nr["interfaceInTranslatedSource"] = true
				return
			}
			switch classifyRef(x, r) {
			case refNetObj, refNetGroup:
				nr[key] = obj{"name": nm.lookup(string(r))}
			case refLiteralCIDR, refLiteralRange:
				nr[key] = obj{"name": ensureNet(string(r))}
			default:
				status = worst(status, StPartial)
				details = append(details, key+" "+string(r)+" unresolved — VERIFY")
			}
		}
		setRef("originalSource", n.OrigSrc)
		setRef("originalDestination", n.OrigDst)
		setRef("translatedSource", n.TransSrc)
		setRef("translatedDestination", n.TransDst)
		if n.OrigSvc != "" && !n.OrigSvc.IsAny() {
			if hn, ok := ensurePort(n.OrigSvc); ok {
				nr["originalSourcePort"] = obj{"name": hn}
			} else if x.Objects.FindSvc(string(n.OrigSvc)) != nil {
				nr["originalSourcePort"] = obj{"name": nm.lookup(string(n.OrigSvc))}
			}
		}
		if n.TransSvc != "" && !n.TransSvc.IsAny() {
			if hn, ok := ensurePort(n.TransSvc); ok {
				nr["translatedSourcePort"] = obj{"name": hn}
			}
		}
		if n.Desc != "" {
			nr["description"] = n.Desc
		}
		natRules = append(natRules, nr)
		res.Items = append(res.Items, Item{Category: "nat", Name: firstNonEmpty(n.Name, fmt.Sprintf("nat %d", n.Index)), Status: status, Detail: strings.Join(details, "; ")})
	}

	// ---- interface & route worksheet ----
	var ws strings.Builder
	ws.WriteString("# RuleForge — FTD interface & routing worksheet\n")
	ws.WriteString("# FMC configures interfaces per managed device; apply these in Device > Interfaces.\n\n")
	ws.WriteString(fmt.Sprintf("%-28s %-14s %-20s %-18s %-10s %s\n", "INTERFACE", "KIND", "IP", "ZONE", "VLAN", "NOTES"))
	for _, ifc := range x.Interfaces {
		zone := m.MapZone(firstNonEmpty(ifc.Zone, ifc.Alias))
		notes := ifc.Desc
		if len(ifc.Members) > 0 {
			notes = strings.TrimSpace(notes + " members:" + strings.Join(ifc.Members, ","))
		}
		if ifc.Shutdown {
			notes = strings.TrimSpace(notes + " (shutdown)")
		}
		vlan := ""
		if ifc.VlanID > 0 {
			vlan = fmt.Sprintf("%d", ifc.VlanID)
		}
		ws.WriteString(fmt.Sprintf("%-28s %-14s %-20s %-18s %-10s %s\n",
			m.MapIface(ifc.Name), ifc.Kind, strings.Join(ifc.IPs, ","), zone, vlan, notes))
		st := StConverted
		det := "apply via FMC device interface page (worksheet)"
		if ifc.Kind == fwir.IfBridge || ifc.Kind == fwir.IfAggregate {
			st = StPartial
			det = "bridge/port-channel: create in FMC device page first, then bind members"
		}
		res.Items = append(res.Items, Item{Category: "interface", Name: ifc.Name, Status: st, Detail: det})
	}
	ws.WriteString("\n# Static routes (Device > Routing > Static Route)\n")
	ws.WriteString(fmt.Sprintf("%-24s %-20s %-16s %s\n", "DESTINATION", "GATEWAY", "INTERFACE", "METRIC"))
	for _, r := range x.Routes {
		ws.WriteString(fmt.Sprintf("%-24s %-20s %-16s %d\n", r.Dest, r.Gateway, m.MapZone(m.MapIface(r.Iface)), r.Metric))
		res.Items = append(res.Items, Item{Category: "route", Name: r.Dest, Status: StConverted, Detail: "apply via FMC static-route page (worksheet)"})
	}

	bundle["securityZones"] = zones
	bundle["networkObjects"] = nets
	bundle["networkGroups"] = netGroups
	bundle["portObjects"] = ports
	bundle["portGroups"] = portGroups
	bundle["accessPolicy"] = obj{
		"type": "AccessPolicy", "name": "RF-" + safeFile(x.Name),
		"defaultAction": obj{"action": "BLOCK", "logBegin": true},
		"rules":         rules,
	}
	bundle["natPolicy"] = obj{"type": "FTDNatPolicy", "name": "RF-" + safeFile(x.Name) + "-NAT", "rules": natRules}

	jb, _ := json.MarshalIndent(bundle, "", "  ")

	readme := `# RuleForge — FMC import bundle

This bundle follows the FMC REST API object model. Import order:

1. POST securityZones      → /api/fmc_config/v1/domain/{DOMAIN}/object/securityzones
2. POST networkObjects     → …/object/hosts | /object/networks | /object/ranges | /object/fqdns  (bulk=true supported)
3. POST portObjects        → …/object/protocolportobjects | /object/icmpv4objects
4. POST networkGroups      → …/object/networkgroups   (resolve "objectRef"/"groupRef" names to ids first)
5. POST portGroups         → …/object/portobjectgroups
6. POST accessPolicy       → …/policy/accesspolicies, then its rules to …/accesspolicies/{id}/accessrules (bulk=true)
7. POST natPolicy          → …/policy/ftdnatpolicies, then rules to …/ftdnatpolicies/{id}/manualnatrules
8. Interfaces & routes     → apply from the worksheet in Device management (per-device, not policy objects)

Name → id resolution: GET each object type once, build a name→id map, replace
"objectRef"/"groupRef" entries with {"type": "...", "id": "..."} before POSTing
groups/rules. Any REST client or a ~50-line script does this; the bundle keeps
names so it stays readable and auditable.
`
	res.Files = append(res.Files,
		File{Name: "ftd-" + safeFile(x.Name) + "-fmc-bundle.json", Content: string(jb)},
		File{Name: "ftd-" + safeFile(x.Name) + "-interfaces.txt", Content: ws.String()},
		File{Name: "ftd-README.md", Content: readme},
	)
	captureItems(x, res)
	res.Renames = nm.Renames
	return res
}

func zoneRefs(names []string) map[string]any {
	var objs []map[string]any
	for _, n := range names {
		objs = append(objs, map[string]any{"type": "SecurityZone", "name": n})
	}
	return map[string]any{"objects": objs}
}
