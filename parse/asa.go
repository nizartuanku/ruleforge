package parse

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/nizartuanku/ruleforge/fwir"
)

// parseASAInputs handles Cisco ASA and FTD (whose `show running-config` is
// ASA syntax). Each input file becomes one context unless a file itself
// contains multi-context markers, in which case it is split.
func parseASAInputs(vendor string, inputs []Input) (*fwir.Config, error) {
	cfg := &fwir.Config{Vendor: vendor}
	for _, in := range inputs {
		for _, part := range splitASAContexts(in) {
			ctx, hostname, version := parseASAContext(part.name, part.text)
			if hostname != "" && cfg.Hostname == "" {
				cfg.Hostname = hostname
			}
			if version != "" && cfg.Version == "" {
				cfg.Version = version
			}
			cfg.Contexts = append(cfg.Contexts, *ctx)
		}
	}
	if len(cfg.Contexts) == 1 && cfg.Contexts[0].Name == "" {
		cfg.Contexts[0].Name = "default"
	}
	return cfg, nil
}

type asaPart struct {
	name string
	text string
}

var asaCtxMarker = regexp.MustCompile(`(?m)^\s*(?:changeto\s+context\s+(\S+)|[:!]\s*[Cc]ontext\s*[:]?\s*(\S+))\s*$`)

// splitASAContexts splits a capture that contains several contexts separated
// by `changeto context NAME` (session captures) or `! Context: NAME` /
// `: Context: NAME` banner lines. A file without markers is one context named
// after the file (multi-file uploads) or "" (single upload → "default").
func splitASAContexts(in Input) []asaPart {
	idx := asaCtxMarker.FindAllStringSubmatchIndex(in.Content, -1)
	if len(idx) == 0 {
		name := ""
		if base := fileBase(in.Name); base != "" {
			name = base
		}
		return []asaPart{{name: name, text: in.Content}}
	}
	var parts []asaPart
	// Text before the first marker (system context preamble) attaches to the
	// first named context so nothing is lost.
	prev := 0
	prevName := ""
	for _, m := range idx {
		if prev < m[0] {
			seg := in.Content[prev:m[0]]
			if strings.TrimSpace(seg) != "" {
				parts = append(parts, asaPart{name: prevName, text: seg})
			}
		}
		name := ""
		if m[2] >= 0 {
			name = in.Content[m[2]:m[3]]
		} else if m[4] >= 0 {
			name = in.Content[m[4]:m[5]]
		}
		prevName = name
		prev = m[1]
	}
	if strings.TrimSpace(in.Content[prev:]) != "" {
		parts = append(parts, asaPart{name: prevName, text: in.Content[prev:]})
	}
	// Merge segments with the same name, keep order of first appearance.
	merged := map[string]int{}
	var out []asaPart
	for _, p := range parts {
		if i, ok := merged[p.name]; ok {
			out[i].text += "\n" + p.text
			continue
		}
		merged[p.name] = len(out)
		out = append(out, p)
	}
	for i := range out {
		if out[i].name == "" {
			out[i].name = "system"
		}
	}
	return out
}

func fileBase(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	if i := strings.LastIndexAny(name, "/\\"); i >= 0 {
		name = name[i+1:]
	}
	if i := strings.LastIndexByte(name, '.'); i > 0 {
		name = name[:i]
	}
	return name
}

// parseASAContext parses one context's running-config.
func parseASAContext(name, text string) (*fwir.Context, string, string) {
	x := &fwir.Context{Name: name}
	var hostname, version string
	lines := strings.Split(text, "\n")

	aclRemark := map[string]string{}       // acl → pending remark
	aclBind := map[string]aclBinding{}     // acl name → interface binding
	ifaceByName := map[string]int{}        // config name → index in x.Interfaces
	bridgeMembers := map[int][]string{}    // bridge-group → member iface names
	channelMembers := map[string][]string{} // Port-channelN → members
	timeRanges := map[string]bool{}

	i := 0
	for i < len(lines) {
		raw := lines[i]
		line := strings.TrimRight(raw, "\r")
		trim := strings.TrimSpace(line)
		i++
		if trim == "" || trim == "!" || strings.HasPrefix(trim, ": ") {
			continue
		}
		toks := fields(trim)
		switch {
		case toks[0] == "hostname" && len(toks) >= 2:
			hostname = toks[1]
		case toks[0] == "ASA" && len(toks) >= 3 && toks[1] == "Version":
			version = toks[2]
		case toks[0] == "NGFW" && len(toks) >= 3 && toks[1] == "Version":
			version = toks[2]

		case toks[0] == "interface" && len(toks) >= 2:
			body, next := collectIndentedASA(lines, i)
			i = next
			parseASAInterface(x, toks[1], body, ifaceByName, bridgeMembers, channelMembers)

		case toks[0] == "object" && len(toks) >= 3 && toks[1] == "network":
			body, next := collectIndentedASA(lines, i)
			i = next
			parseASAObjectNetwork(x, toks[2], body)

		case toks[0] == "object" && len(toks) >= 3 && toks[1] == "service":
			body, next := collectIndentedASA(lines, i)
			i = next
			parseASAObjectService(x, toks[2], body)

		case toks[0] == "object-group" && len(toks) >= 3:
			body, next := collectIndentedASA(lines, i)
			i = next
			parseASAObjectGroup(x, toks, body, trim)

		case toks[0] == "name" && len(toks) >= 3 && net.ParseIP(toks[1]) != nil:
			// legacy: name 10.1.1.5 dbserver → a host object
			x.Objects.Networks = append(x.Objects.Networks, fwir.NetObject{
				Name: toks[2], Kind: fwir.NetHost, Value: toks[1], Desc: joinFrom(toks, 3),
			})

		case toks[0] == "access-list" && len(toks) >= 3 && toks[2] == "remark":
			aclRemark[toks[1]] = joinFrom(toks, 3)

		case toks[0] == "access-list":
			if r, ok := parseASAACL(toks, trim); ok {
				r.Desc = aclRemark[toks[1]]
				delete(aclRemark, toks[1])
				x.Rules = append(x.Rules, r)
			} else {
				x.Unparsed = append(x.Unparsed, trim)
			}

		case toks[0] == "access-group" && len(toks) >= 2:
			b := aclBinding{}
			if len(toks) >= 5 && toks[3] == "interface" {
				b.iface, b.dir = toks[4], toks[2] // in|out
			} else if len(toks) >= 3 && toks[2] == "global" {
				b.global = true
			}
			aclBind[toks[1]] = b

		case toks[0] == "nat" && len(toks) >= 3:
			if n, ok := parseASAManualNAT(toks, trim); ok {
				x.NATs = append(x.NATs, n)
			} else {
				x.Unparsed = append(x.Unparsed, trim)
			}

		case toks[0] == "route" && len(toks) >= 5:
			dest, err := fwir.CIDRFromIPMask(toks[2], toks[3])
			if err != nil {
				x.Unparsed = append(x.Unparsed, trim)
				break
			}
			metric := 0
			if len(toks) >= 6 {
				metric, _ = strconv.Atoi(toks[5])
			}
			x.Routes = append(x.Routes, fwir.StaticRoute{
				Iface: toks[1], Dest: dest, Gateway: toks[4], Metric: metric, Raw: trim,
			})

		case toks[0] == "mtu" && len(toks) >= 3:
			if mtu, err := strconv.Atoi(toks[2]); err == nil {
				for j := range x.Interfaces {
					if x.Interfaces[j].Alias == toks[1] {
						x.Interfaces[j].MTU = mtu
					}
				}
			}

		case toks[0] == "time-range" && len(toks) >= 2:
			body, next := collectIndentedASA(lines, i)
			i = next
			timeRanges[toks[1]] = true
			x.AddCaptured(fwir.CapOther, toks[1], "time-range (schedule)", append([]string{trim}, body...)...)

		// ---- recognised features captured for the report ----
		case toks[0] == "crypto":
			body, next := collectIndentedASA(lines, i)
			i = next
			cat, det := fwir.CapVPN, "crypto configuration"
			if len(toks) >= 2 {
				switch toks[1] {
				case "ca":
					cat, det = fwir.CapCert, "PKI trustpoint/certificate"
				case "key":
					cat, det = fwir.CapCert, "crypto key"
				}
			}
			x.AddCaptured(cat, joinFrom(toks, 1), det, append([]string{trim}, body...)...)
		case toks[0] == "tunnel-group":
			body, next := collectIndentedASA(lines, i)
			i = next
			x.AddCaptured(fwir.CapVPN, strings.Join(toks[1:min(3, len(toks))], " "), "VPN tunnel-group", append([]string{trim}, body...)...)
		case toks[0] == "group-policy":
			body, next := collectIndentedASA(lines, i)
			i = next
			x.AddCaptured(fwir.CapVPN, tok(toks, 1), "VPN group-policy", append([]string{trim}, body...)...)
		case toks[0] == "webvpn":
			body, next := collectIndentedASA(lines, i)
			i = next
			x.AddCaptured(fwir.CapVPN, "webvpn", "remote-access VPN portal", append([]string{trim}, body...)...)
		case toks[0] == "router" && len(toks) >= 2:
			body, next := collectIndentedASA(lines, i)
			i = next
			x.AddCaptured(fwir.CapDynRouting, joinFrom(toks, 1), "dynamic routing process ("+toks[1]+")", append([]string{trim}, body...)...)
		case toks[0] == "failover":
			x.AddCaptured(fwir.CapHA, "failover", "HA failover configuration", trim)
		case toks[0] == "aaa-server" || toks[0] == "aaa":
			body, next := collectIndentedASA(lines, i)
			i = next
			x.AddCaptured(fwir.CapUserID, joinFrom(toks, 0), "AAA/authentication", append([]string{trim}, body...)...)
		case toks[0] == "class-map" || toks[0] == "policy-map":
			body, next := collectIndentedASA(lines, i)
			i = next
			x.AddCaptured(fwir.CapInspection, tok(toks, 1), toks[0]+" (MPF inspection)", append([]string{trim}, body...)...)
		case toks[0] == "service-policy":
			x.AddCaptured(fwir.CapInspection, tok(toks, 1), "service-policy binding", trim)
		case toks[0] == "snmp-server" || toks[0] == "ssh" || toks[0] == "http" ||
			toks[0] == "telnet" || toks[0] == "ntp" || toks[0] == "logging" ||
			toks[0] == "dhcpd" || toks[0] == "dns" || toks[0] == "domain-name":
			x.AddCaptured(fwir.CapMgmt, toks[0], "management service", trim)
		case toks[0] == "same-security-traffic":
			x.AddCaptured(fwir.CapOther, "same-security-traffic", "inter/intra-interface permit — review zone policy on target", trim)
		case toks[0] == "mode" && len(toks) >= 2 && toks[1] == "multiple":
			x.AddCaptured(fwir.CapOther, "mode multiple", "multi-context system config", trim)
		case toks[0] == "context" && len(toks) >= 2:
			body, next := collectIndentedASA(lines, i)
			i = next
			x.AddCaptured(fwir.CapOther, toks[1], "context definition (system)", append([]string{trim}, body...)...)

		default:
			x.Unparsed = append(x.Unparsed, trim)
		}
	}

	// Bridge groups: attach members to BVI interfaces.
	for bg, members := range bridgeMembers {
		bviName := fmt.Sprintf("BVI%d", bg)
		if j, ok := ifaceByName[bviName]; ok {
			x.Interfaces[j].Members = append(x.Interfaces[j].Members, members...)
		} else {
			x.Interfaces = append(x.Interfaces, fwir.Interface{
				Name: bviName, Kind: fwir.IfBridge, Members: members, SecLevel: -1,
			})
		}
	}
	// Channel groups: attach members to Port-channel interfaces.
	for pc, members := range channelMembers {
		if j, ok := ifaceByName[pc]; ok {
			x.Interfaces[j].Members = append(x.Interfaces[j].Members, members...)
		} else {
			x.Interfaces = append(x.Interfaces, fwir.Interface{
				Name: pc, Kind: fwir.IfAggregate, Members: members, SecLevel: -1,
			})
		}
	}

	// Zones: one synthetic zone per nameif.
	for _, ifc := range x.Interfaces {
		if ifc.Alias != "" {
			x.Zones = append(x.Zones, fwir.Zone{Name: ifc.Alias, Interfaces: []string{ifc.Name}, Synthetic: true})
		}
	}

	// Apply ACL bindings: rules named after a bound ACL get the interface zone.
	for j := range x.Rules {
		if b, ok := aclBind[x.Rules[j].Name]; ok && !b.global {
			if b.dir == "out" {
				x.Rules[j].DstZones = []string{b.iface}
			} else {
				x.Rules[j].SrcZones = []string{b.iface}
			}
		}
	}
	for j := range x.Rules {
		x.Rules[j].Index = j + 1
	}
	for j := range x.NATs {
		x.NATs[j].Index = j + 1
	}
	return x, hostname, version
}

type aclBinding struct {
	iface  string
	dir    string
	global bool
}

func tok(toks []string, i int) string {
	if i < len(toks) {
		return toks[i]
	}
	return ""
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// collectIndentedASA gathers the indented body lines following a block header.
func collectIndentedASA(lines []string, i int) (body []string, next int) {
	for i < len(lines) {
		l := strings.TrimRight(lines[i], "\r")
		if l == "" || strings.TrimSpace(l) == "!" {
			i++
			continue
		}
		if !strings.HasPrefix(l, " ") && !strings.HasPrefix(l, "\t") {
			break
		}
		body = append(body, strings.TrimSpace(l))
		i++
	}
	return body, i
}

var asaSubIf = regexp.MustCompile(`^(.+)\.(\d+)$`)

func parseASAInterface(x *fwir.Context, name string, body []string, byName map[string]int, bridgeMembers map[int][]string, channelMembers map[string][]string) {
	ifc := fwir.Interface{Name: name, Kind: fwir.IfPhysical, SecLevel: -1, Raw: body}
	lower := strings.ToLower(name)
	switch {
	case strings.HasPrefix(lower, "port-channel"):
		ifc.Kind = fwir.IfAggregate
	case strings.HasPrefix(lower, "bvi"):
		ifc.Kind = fwir.IfBridge
	case strings.HasPrefix(lower, "vlan"):
		ifc.Kind = fwir.IfVLAN
		if v, err := strconv.Atoi(strings.TrimPrefix(lower, "vlan")); err == nil {
			ifc.VlanID = v
		}
	case strings.HasPrefix(lower, "loopback"):
		ifc.Kind = fwir.IfLoopback
	case strings.HasPrefix(lower, "tunnel"):
		ifc.Kind = fwir.IfTunnel
	case strings.HasPrefix(lower, "management"):
		ifc.Kind = fwir.IfMgmt
	}
	if m := asaSubIf.FindStringSubmatch(name); m != nil {
		ifc.Kind = fwir.IfSubIf
		ifc.Parent = m[1]
	}
	for _, b := range body {
		t := fields(b)
		if len(t) == 0 {
			continue
		}
		switch t[0] {
		case "nameif":
			ifc.Alias = tok(t, 1)
		case "security-level":
			ifc.SecLevel, _ = strconv.Atoi(tok(t, 1))
		case "vlan":
			ifc.VlanID, _ = strconv.Atoi(tok(t, 1))
			if ifc.Kind == fwir.IfPhysical {
				ifc.Kind = fwir.IfSubIf
			}
		case "ip":
			if len(t) >= 4 && t[1] == "address" {
				if cidr, err := fwir.CIDRFromIPMask(t[2], t[3]); err == nil {
					ifc.IPs = append(ifc.IPs, cidr)
				}
			}
		case "description":
			ifc.Desc = joinFrom(t, 1)
		case "shutdown":
			ifc.Shutdown = true
		case "bridge-group":
			if bg, err := strconv.Atoi(tok(t, 1)); err == nil {
				bridgeMembers[bg] = append(bridgeMembers[bg], name)
			}
		case "channel-group":
			if n := tok(t, 1); n != "" {
				pc := "Port-channel" + n
				channelMembers[pc] = append(channelMembers[pc], name)
			}
		}
	}
	byName[name] = len(x.Interfaces)
	x.Interfaces = append(x.Interfaces, ifc)
}

func parseASAObjectNetwork(x *fwir.Context, name string, body []string) {
	obj := fwir.NetObject{Name: name}
	for _, b := range body {
		t := fields(b)
		if len(t) == 0 {
			continue
		}
		switch t[0] {
		case "host":
			obj.Kind, obj.Value = fwir.NetHost, tok(t, 1)
		case "subnet":
			if cidr, err := fwir.CIDRFromIPMask(tok(t, 1), tok(t, 2)); err == nil {
				obj.Kind, obj.Value = fwir.NetSubnet, cidr
			}
		case "range":
			obj.Kind, obj.Value, obj.Value2 = fwir.NetRange, tok(t, 1), tok(t, 2)
		case "fqdn":
			v := tok(t, 1)
			if v == "v4" || v == "v6" {
				v = tok(t, 2)
			}
			obj.Kind, obj.Value = fwir.NetFQDN, v
		case "description":
			obj.Desc = joinFrom(t, 1)
		case "nat":
			// Object NAT lives inside the object block.
			if n, ok := parseASAObjectNAT(name, t, b); ok {
				x.NATs = append(x.NATs, n)
			} else {
				x.Unparsed = append(x.Unparsed, "object network "+name+": "+b)
			}
		}
	}
	if obj.Kind != "" {
		x.Objects.Networks = append(x.Objects.Networks, obj)
	}
}

func parseASAObjectService(x *fwir.Context, name string, body []string) {
	obj := fwir.SvcObject{Name: name}
	for _, b := range body {
		t := fields(b)
		if len(t) == 0 {
			continue
		}
		switch t[0] {
		case "service":
			// service tcp destination eq 443 / service udp destination range 1 100 / service icmp echo
			if len(t) >= 2 {
				obj.Proto = t[1]
			}
			for j := 2; j < len(t); j++ {
				switch t[j] {
				case "destination":
					obj.Port = parseASAPortSpec(t, j+1)
				case "source":
					obj.SrcPort = parseASAPortSpec(t, j+1)
				}
			}
			if obj.Proto == "icmp" && len(t) >= 3 && t[2] != "destination" && t[2] != "source" {
				obj.ICMPType = t[2]
			}
		case "description":
			obj.Desc = joinFrom(t, 1)
		}
	}
	if obj.Proto != "" {
		x.Objects.Services = append(x.Objects.Services, obj)
	}
}

// parseASAPortSpec reads eq N | range A B | gt N | lt N at position i.
func parseASAPortSpec(t []string, i int) string {
	if i >= len(t) {
		return ""
	}
	switch t[i] {
	case "eq":
		return svcPortNum(tok(t, i+1))
	case "range":
		return svcPortNum(tok(t, i+1)) + "-" + svcPortNum(tok(t, i+2))
	case "gt":
		if n, err := strconv.Atoi(svcPortNum(tok(t, i+1))); err == nil {
			return fmt.Sprintf("%d-65535", n+1)
		}
	case "lt":
		if n, err := strconv.Atoi(svcPortNum(tok(t, i+1))); err == nil {
			return fmt.Sprintf("0-%d", n-1)
		}
	case "neq":
		return "" // cannot express; caller keeps any and the review flags it
	}
	return ""
}

// svcPortNum maps well-known ASA port names to numbers (subset that matters).
var asaPortNames = map[string]string{
	"aol": "5190", "bgp": "179", "chargen": "19", "cifs": "3020", "citrix-ica": "1494",
	"daytime": "13", "discard": "9", "domain": "53", "echo": "7", "exec": "512",
	"finger": "79", "ftp": "21", "ftp-data": "20", "gopher": "70", "h323": "1720",
	"hostname": "101", "http": "80", "https": "443", "ident": "113", "imap4": "143",
	"irc": "194", "kerberos": "750", "klogin": "543", "kshell": "544", "ldap": "389",
	"ldaps": "636", "login": "513", "lotusnotes": "1352", "lpd": "515", "netbios-ssn": "139",
	"nntp": "119", "ntp": "123", "pcanywhere-data": "5631", "pim-auto-rp": "496",
	"pop2": "109", "pop3": "110", "pptp": "1723", "rsh": "514", "rtsp": "554",
	"sip": "5060", "smtp": "25", "snmp": "161", "snmptrap": "162", "sqlnet": "1522",
	"ssh": "22", "sunrpc": "111", "syslog": "514", "tacacs": "49", "talk": "517",
	"telnet": "23", "tftp": "69", "time": "37", "uucp": "540", "whois": "43", "www": "80",
	"netbios-ns": "137", "netbios-dgm": "138", "isakmp": "500", "radius": "1645",
	"radius-acct": "1646", "dnsix": "195", "mobile-ip": "434", "nameserver": "42",
	"ripv6": "521", "rip": "520", "secureid-udp": "5510", "vxlan": "4789",
}

func svcPortNum(p string) string {
	if p == "" {
		return ""
	}
	if _, err := strconv.Atoi(p); err == nil {
		return p
	}
	if n, ok := asaPortNames[strings.ToLower(p)]; ok {
		return n
	}
	return p // unknown name kept verbatim; generators pass it through
}

func parseASAObjectGroup(x *fwir.Context, toks []string, body []string, header string) {
	kind, name := toks[1], toks[2]
	switch kind {
	case "network":
		g := fwir.Group{Name: name}
		for _, b := range body {
			t := fields(b)
			if len(t) == 0 {
				continue
			}
			switch t[0] {
			case "network-object":
				switch {
				case tok(t, 1) == "host":
					g.Members = append(g.Members, tok(t, 2))
				case tok(t, 1) == "object":
					g.Members = append(g.Members, tok(t, 2))
				case len(t) >= 3:
					if cidr, err := fwir.CIDRFromIPMask(t[1], t[2]); err == nil {
						g.Members = append(g.Members, cidr)
					} else {
						g.Members = append(g.Members, tok(t, 1)) // named object shorthand
					}
				case len(t) == 2:
					g.Members = append(g.Members, t[1])
				}
			case "group-object":
				g.Members = append(g.Members, tok(t, 1))
			case "description":
				g.Desc = joinFrom(t, 1)
			}
		}
		x.Objects.NetGroups = append(x.Objects.NetGroups, g)
	case "service":
		proto := tok(toks, 3) // may be tcp|udp|tcp-udp or empty (generic)
		g := fwir.Group{Name: name}
		n := 0
		for _, b := range body {
			t := fields(b)
			if len(t) == 0 {
				continue
			}
			switch t[0] {
			case "port-object":
				port := parseASAPortSpec(t, 1)
				pr := proto
				if pr == "" {
					pr = "tcp"
				}
				lit := string(fwir.SvcLiteral(pr, port))
				g.Members = append(g.Members, lit)
				n++
			case "service-object":
				switch {
				case tok(t, 1) == "object":
					g.Members = append(g.Members, tok(t, 2))
				default:
					pr := tok(t, 1)
					port := ""
					for j := 2; j < len(t); j++ {
						if t[j] == "destination" {
							port = parseASAPortSpec(t, j+1)
						}
					}
					if port == "" && len(t) >= 4 && t[2] == "eq" { // service-object tcp eq 80 (short form)
						port = svcPortNum(t[3])
					}
					g.Members = append(g.Members, string(fwir.SvcLiteral(pr, port)))
				}
				n++
			case "group-object":
				g.Members = append(g.Members, tok(t, 1))
				n++
			case "description":
				g.Desc = joinFrom(t, 1)
			}
		}
		x.Objects.SvcGroups = append(x.Objects.SvcGroups, g)
		_ = n
	case "protocol", "icmp-type":
		x.AddCaptured(fwir.CapOther, name, "object-group "+kind+" — review on target", append([]string{header}, body...)...)
	default:
		x.Unparsed = append(x.Unparsed, header)
	}
}

// parseASAACL parses one extended access-list entry into an IR rule.
func parseASAACL(toks []string, raw string) (fwir.Rule, bool) {
	r := fwir.Rule{Enabled: true, Raw: raw, Name: toks[1]}
	i := 2
	if tok(toks, i) == "extended" || tok(toks, i) == "standard" {
		i++
	}
	if tok(toks, i) == "line" {
		i += 2
	}
	switch tok(toks, i) {
	case "permit":
		r.Action = "allow"
	case "deny":
		r.Action = "deny"
	default:
		return r, false
	}
	i++
	// protocol
	var svcProto string
	var svcNamed string
	switch tok(toks, i) {
	case "object-group", "object":
		svcNamed = tok(toks, i+1)
		i += 2
	default:
		svcProto = tok(toks, i)
		i++
	}
	// src
	src, si, ok := parseASAAddr(toks, i)
	if !ok {
		return r, false
	}
	i = si
	srcPort, i2 := parseASAACLPort(toks, i)
	i = i2
	dst, di, ok := parseASAAddr(toks, i)
	if !ok {
		return r, false
	}
	i = di
	dstPort, i3 := parseASAACLPort(toks, i)
	i = i3
	// trailing: icmp type, log, inactive, time-range
	for i < len(toks) {
		switch toks[i] {
		case "log":
			r.Log = true
			i++
			// optional level / interval args
			for i < len(toks) && toks[i] != "inactive" && toks[i] != "time-range" {
				i++
			}
		case "inactive":
			r.Enabled = false
			i++
		case "time-range":
			r.Desc = strings.TrimSpace(r.Desc + " [time-range " + tok(toks, i+1) + "]")
			i += 2
		default:
			if svcProto == "icmp" && dstPort == "" {
				// icmp type keyword
				i++
				continue
			}
			i++
		}
	}
	if !src.IsAny() {
		r.SrcAddrs = []fwir.Ref{src}
	}
	if !dst.IsAny() {
		r.DstAddrs = []fwir.Ref{dst}
	}
	switch {
	case svcNamed != "":
		r.Services = []fwir.SvcRef{fwir.SvcRef(svcNamed)}
	default:
		svc := fwir.SvcLiteral(svcProto, dstPort)
		if !svc.IsAny() {
			r.Services = []fwir.SvcRef{svc}
		}
	}
	_ = srcPort // source ports are rare; surfaced via raw when present
	return r, true
}

// parseASAAddr reads an address clause starting at i, returning the Ref and
// the next index.
func parseASAAddr(toks []string, i int) (fwir.Ref, int, bool) {
	switch tok(toks, i) {
	case "":
		return "", i, false
	case "any", "any4", "any6":
		return "any", i + 1, true
	case "host":
		return fwir.Ref(tok(toks, i+1) + "/32"), i + 2, true
	case "object", "object-group":
		return fwir.Ref(tok(toks, i+1)), i + 2, true
	case "interface":
		return fwir.Ref("interface:" + tok(toks, i+1)), i + 2, true
	default:
		// ip mask
		if cidr, err := fwir.CIDRFromIPMask(tok(toks, i), tok(toks, i+1)); err == nil {
			return fwir.Ref(cidr), i + 2, true
		}
		// bare object name (older syntax) — accept single token
		return fwir.Ref(tok(toks, i)), i + 1, true
	}
}

// parseASAACLPort reads an optional port clause (eq/range/gt/lt/neq/object-group)
// at i; returns the port string and next index.
func parseASAACLPort(toks []string, i int) (string, int) {
	switch tok(toks, i) {
	case "eq":
		return svcPortNum(tok(toks, i+1)), i + 2
	case "range":
		return svcPortNum(tok(toks, i+1)) + "-" + svcPortNum(tok(toks, i+2)), i + 3
	case "gt":
		if n, err := strconv.Atoi(svcPortNum(tok(toks, i+1))); err == nil {
			return fmt.Sprintf("%d-65535", n+1), i + 2
		}
		return "", i + 2
	case "lt":
		if n, err := strconv.Atoi(svcPortNum(tok(toks, i+1))); err == nil {
			return fmt.Sprintf("0-%d", n-1), i + 2
		}
		return "", i + 2
	case "neq":
		return "", i + 2 // inexpressible: widened to any (flagged in review)
	}
	return "", i
}

// parseASAObjectNAT parses object NAT: nat (real,mapped) static X [service ...]
// or nat (real,mapped) dynamic X|interface [interface].
func parseASAObjectNAT(objName string, t []string, raw string) (fwir.NAT, bool) {
	n := fwir.NAT{Enabled: true, Raw: "object network " + objName + ": " + raw, Name: objName, OrigSrc: fwir.Ref(objName)}
	i := 1
	if strings.HasPrefix(tok(t, i), "(") {
		pair := strings.Trim(tok(t, i), "()")
		parts := strings.SplitN(pair, ",", 2)
		if len(parts) == 2 {
			n.SrcIface, n.DstIface = parts[0], parts[1]
		}
		i++
	}
	switch tok(t, i) {
	case "static":
		n.Kind = fwir.NATStatic
		n.TransSrc = fwir.Ref(tok(t, i+1))
		i += 2
		for i < len(t) {
			if t[i] == "service" && i+3 < len(t)+1 {
				proto := tok(t, i+1)
				n.OrigSvc = fwir.SvcLiteral(proto, svcPortNum(tok(t, i+2)))
				n.TransSvc = fwir.SvcLiteral(proto, svcPortNum(tok(t, i+3)))
				i += 4
				continue
			}
			i++
		}
		return n, true
	case "dynamic":
		next := tok(t, i+1)
		if next == "interface" {
			n.Kind = fwir.NATDynamicPAT
			n.TransSrc = "interface"
		} else if next == "pat-pool" {
			n.Kind = fwir.NATDynamicPAT
			n.TransSrc = fwir.Ref(tok(t, i+2))
		} else {
			n.Kind = fwir.NATDynamic
			n.TransSrc = fwir.Ref(next)
			// trailing "interface" = fallback PAT; noted in raw
		}
		return n, true
	}
	return n, false
}

// parseASAManualNAT parses twice/manual NAT:
// nat (in,out) [after-auto] source static|dynamic A [B|interface] [destination static C D] [service S1 S2] [description ...] [inactive]
func parseASAManualNAT(toks []string, raw string) (fwir.NAT, bool) {
	n := fwir.NAT{Enabled: true, Raw: raw, Kind: fwir.NATTwice}
	i := 1
	if strings.HasPrefix(tok(toks, i), "(") {
		pair := strings.Trim(tok(toks, i), "()")
		parts := strings.SplitN(pair, ",", 2)
		if len(parts) == 2 {
			n.SrcIface, n.DstIface = parts[0], parts[1]
		}
		i++
	}
	if tok(toks, i) == "after-auto" {
		i++
	}
	if tok(toks, i) != "source" {
		return n, false
	}
	i++
	mode := tok(toks, i) // static | dynamic
	i++
	n.OrigSrc = fwir.Ref(tok(toks, i))
	i++
	// mapped source (may be "interface" or omitted for identity)
	if v := tok(toks, i); v != "" && v != "destination" && v != "service" && v != "description" && v != "inactive" {
		n.TransSrc = fwir.Ref(v)
		i++
	}
	if mode == "dynamic" {
		if n.TransSrc == "interface" {
			n.Kind = fwir.NATDynamicPAT
		} else {
			n.Kind = fwir.NATDynamic
		}
	} else if tok(toks, i) != "destination" {
		// pure source static NAT
		n.Kind = fwir.NATStatic
	}
	for i < len(toks) {
		switch toks[i] {
		case "destination":
			// destination static MAPPED REAL  (ASA order: mapped first!)
			if tok(toks, i+1) == "static" {
				n.TransDst = fwir.Ref(tok(toks, i+2))
				n.OrigDst = fwir.Ref(tok(toks, i+3))
				i += 4
			} else {
				i += 2
			}
		case "service":
			n.OrigSvc = fwir.SvcRef(tok(toks, i+1))
			n.TransSvc = fwir.SvcRef(tok(toks, i+2))
			i += 3
		case "description":
			n.Desc = joinFrom(toks, i+1)
			i = len(toks)
		case "inactive":
			n.Enabled = false
			i++
		case "unidirectional":
			i++
		case "no-proxy-arp", "route-lookup":
			i++
		default:
			i++
		}
	}
	if n.OrigSrc == n.TransSrc && n.OrigDst != "" {
		// identity source + dest NAT
	}
	return n, true
}
