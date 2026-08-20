package parse

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/nizartuanku/ruleforge/fwir"
)

// parseCheckPointInputs accepts a mix of:
//   - Gaia clish `show configuration` text (interfaces, bonds, VLANs, routes)
//   - mgmt_cli JSON exports: `show access-rulebase … --format json`,
//     `show nat-rulebase … --format json`, and object listings
//     (`show hosts/networks/groups/services-* --format json`).
//
// All inputs merge into one context per policy package (JSON rulebase name),
// with Gaia network config attached to the first/default context.
func parseCheckPointInputs(inputs []Input) (*fwir.Config, error) {
	cfg := &fwir.Config{Vendor: fwir.VendorCheckPoint}
	x := &fwir.Context{Name: "default"}
	cp := &cpState{uid: map[string]cpObj{}}
	for _, in := range inputs {
		body := strings.TrimSpace(in.Content)
		if strings.HasPrefix(body, "{") || strings.HasPrefix(body, "[") {
			if err := cp.parseJSON(x, body, in.Name); err != nil {
				x.Unparsed = append(x.Unparsed, fmt.Sprintf("%s: JSON not understood: %v", in.Name, err))
			}
		} else {
			hostname := parseGaia(x, body)
			if hostname != "" && cfg.Hostname == "" {
				cfg.Hostname = hostname
			}
		}
	}
	cp.finish(x)
	for j := range x.Rules {
		x.Rules[j].Index = j + 1
	}
	for j := range x.NATs {
		x.NATs[j].Index = j + 1
	}
	if cp.pkg != "" {
		x.Name = cp.pkg
	}
	cfg.Contexts = append(cfg.Contexts, *x)
	return cfg, nil
}

// ---- Gaia clish ----

func parseGaia(x *fwir.Context, text string) string {
	hostname := ""
	bondMembers := map[string][]string{}
	for _, rawLine := range strings.Split(text, "\n") {
		line := strings.TrimSpace(strings.TrimRight(rawLine, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		t := ftTokens(line) // same quote-aware tokenizer
		if len(t) < 2 {
			continue
		}
		verb := t[0]
		if verb != "set" && verb != "add" {
			x.Unparsed = append(x.Unparsed, line)
			continue
		}
		switch t[1] {
		case "hostname":
			hostname = tokAt(t, 2)
		case "interface":
			name := tokAt(t, 2)
			ifc := ensureIface(x, name)
			if ifc.Kind == "" || ifc.Kind == fwir.IfPhysical {
				ifc.Kind = gaiaIfKind(name)
				if ifc.Kind == fwir.IfSubIf {
					parts := strings.SplitN(name, ".", 2)
					ifc.Parent = parts[0]
					ifc.VlanID = atoi(parts[1])
				}
			}
			for i := 3; i < len(t); i++ {
				switch t[i] {
				case "ipv4-address":
					ip := tokAt(t, i+1)
					maskLen := ""
					for j := i + 2; j < len(t); j++ {
						if t[j] == "mask-length" {
							maskLen = tokAt(t, j+1)
						}
						if t[j] == "subnet-mask" {
							if cidr, err := fwir.CIDRFromIPMask(ip, tokAt(t, j+1)); err == nil {
								ifc.IPs = appendUnique(ifc.IPs, cidr)
							}
						}
					}
					if maskLen != "" {
						ifc.IPs = appendUnique(ifc.IPs, ip+"/"+maskLen)
					}
				case "comments":
					ifc.Desc = tokAt(t, i+1)
				case "state":
					if tokAt(t, i+1) == "off" {
						ifc.Shutdown = true
					}
				case "mtu":
					ifc.MTU = atoi(tokAt(t, i+1))
				case "vlan":
					// add interface eth0 vlan 100
					sub := ensureIface(x, name+"."+tokAt(t, i+1))
					sub.Kind = fwir.IfSubIf
					sub.Parent = name
					sub.VlanID = atoi(tokAt(t, i+1))
				}
			}
		case "bonding":
			// add bonding group 1 / set bonding group 1 interface eth1 / mode
			if tokAt(t, 2) == "group" {
				bond := "bond" + tokAt(t, 3)
				b := ensureIface(x, bond)
				b.Kind = fwir.IfAggregate
				for i := 4; i < len(t); i++ {
					if t[i] == "interface" {
						bondMembers[bond] = append(bondMembers[bond], tokAt(t, i+1))
					}
				}
			}
		case "static-route":
			dest := tokAt(t, 2)
			if dest == "default" {
				dest = "0.0.0.0/0"
			}
			r := fwir.StaticRoute{Dest: dest, Raw: line}
			for i := 3; i < len(t); i++ {
				if t[i] == "address" {
					r.Gateway = tokAt(t, i+1)
				}
				if t[i] == "priority" {
					r.Metric = atoi(tokAt(t, i+1))
				}
			}
			if r.Gateway == "" && !strings.Contains(line, "gateway") {
				x.Unparsed = append(x.Unparsed, line)
				continue
			}
			// merge duplicate fragments
			dup := false
			for i := range x.Routes {
				if x.Routes[i].Dest == r.Dest && (x.Routes[i].Gateway == r.Gateway || r.Gateway == "") {
					dup = true
					break
				}
			}
			if !dup {
				x.Routes = append(x.Routes, r)
			}
		case "management", "user", "aaa", "snmp", "ntp", "dns", "timezone", "expert-password", "clienv", "web", "syslog":
			x.AddCaptured(fwir.CapMgmt, t[1], "Gaia OS setting", line)
		case "ospf", "bgp", "router-id", "rip":
			x.AddCaptured(fwir.CapDynRouting, t[1], "Gaia dynamic routing", line)
		case "cluster":
			x.AddCaptured(fwir.CapHA, "cluster", "ClusterXL configuration", line)
		default:
			x.Unparsed = append(x.Unparsed, line)
		}
	}
	for bond, members := range bondMembers {
		b := ensureIface(x, bond)
		for _, m := range members {
			b.Members = appendUnique(b.Members, m)
		}
	}
	return hostname
}

func gaiaIfKind(name string) string {
	l := strings.ToLower(name)
	switch {
	case strings.Contains(l, "."):
		return fwir.IfSubIf
	case strings.HasPrefix(l, "bond"):
		return fwir.IfAggregate
	case strings.HasPrefix(l, "lo"):
		return fwir.IfLoopback
	case strings.HasPrefix(l, "mgmt"):
		return fwir.IfMgmt
	case strings.HasPrefix(l, "vpnt"):
		return fwir.IfTunnel
	case strings.HasPrefix(l, "br"):
		return fwir.IfBridge
	}
	return fwir.IfPhysical
}

// ---- mgmt_cli JSON ----

type cpObj struct {
	name string
	typ  string
}

type cpState struct {
	uid map[string]cpObj // uid → object
	pkg string           // policy package / layer name
}

// genericJSON is the loosely-typed shape of every mgmt_cli export we accept.
type cpJSON struct {
	Name              string            `json:"name"`
	Objects           []json.RawMessage `json:"objects"`
	ObjectsDictionary []json.RawMessage `json:"objects-dictionary"`
	Rulebase          []json.RawMessage `json:"rulebase"`
}

func (cp *cpState) parseJSON(x *fwir.Context, body, filename string) error {
	// Accept either one export object or an array of them.
	var raws []json.RawMessage
	b := strings.TrimSpace(body)
	if strings.HasPrefix(b, "[") {
		if err := json.Unmarshal([]byte(b), &raws); err != nil {
			return err
		}
	} else {
		raws = []json.RawMessage{json.RawMessage(b)}
	}
	for _, raw := range raws {
		var doc cpJSON
		if err := json.Unmarshal(raw, &doc); err != nil {
			return err
		}
		for _, o := range doc.ObjectsDictionary {
			cp.object(x, o, true)
		}
		for _, o := range doc.Objects {
			cp.object(x, o, false)
		}
		if len(doc.Rulebase) > 0 {
			if cp.pkg == "" && doc.Name != "" {
				cp.pkg = doc.Name
			}
			cp.rulebase(x, doc.Rulebase, strings.Contains(strings.ToLower(filename+doc.Name), "nat"))
		}
	}
	return nil
}

// object ingests one Check Point object (from objects-dictionary or a
// listing). dictOnly objects register uid→name; listings also materialise IR
// objects (dictionary entries materialise too — dedup by name).
func (cp *cpState) object(x *fwir.Context, raw json.RawMessage, dict bool) {
	var o map[string]any
	if err := json.Unmarshal(raw, &o); err != nil {
		return
	}
	uid, _ := o["uid"].(string)
	name, _ := o["name"].(string)
	typ, _ := o["type"].(string)
	if uid != "" {
		cp.uid[uid] = cpObj{name: name, typ: typ}
	}
	if name == "" {
		return
	}
	switch typ {
	case "host":
		if x.Objects.FindNet(name) == nil {
			ip, _ := o["ipv4-address"].(string)
			x.Objects.Networks = append(x.Objects.Networks, fwir.NetObject{Name: name, Kind: fwir.NetHost, Value: ip, Desc: str(o["comments"])})
		}
	case "network":
		if x.Objects.FindNet(name) == nil {
			subnet, _ := o["subnet4"].(string)
			ml := num(o["mask-length4"])
			x.Objects.Networks = append(x.Objects.Networks, fwir.NetObject{Name: name, Kind: fwir.NetSubnet, Value: fmt.Sprintf("%s/%d", subnet, ml), Desc: str(o["comments"])})
		}
	case "address-range":
		if x.Objects.FindNet(name) == nil {
			x.Objects.Networks = append(x.Objects.Networks, fwir.NetObject{Name: name, Kind: fwir.NetRange, Value: str(o["ipv4-address-first"]), Value2: str(o["ipv4-address-last"]), Desc: str(o["comments"])})
		}
	case "dns-domain":
		if x.Objects.FindNet(name) == nil {
			x.Objects.Networks = append(x.Objects.Networks, fwir.NetObject{Name: name, Kind: fwir.NetFQDN, Value: strings.TrimPrefix(name, "."), Desc: "dns-domain"})
		}
	case "group":
		if x.Objects.FindNetGroup(name) == nil {
			x.Objects.NetGroups = append(x.Objects.NetGroups, fwir.Group{Name: name, Members: cp.memberNames(o["members"]), Desc: str(o["comments"])})
		}
	case "service-tcp":
		cp.svc(x, name, "tcp", o)
	case "service-udp":
		cp.svc(x, name, "udp", o)
	case "service-icmp":
		if x.Objects.FindSvc(name) == nil {
			x.Objects.Services = append(x.Objects.Services, fwir.SvcObject{Name: name, Proto: "icmp", ICMPType: str(o["icmp-type"])})
		}
	case "service-other":
		if x.Objects.FindSvc(name) == nil {
			proto := str(o["ip-protocol"])
			if proto == "" {
				proto = "ip"
			}
			x.Objects.Services = append(x.Objects.Services, fwir.SvcObject{Name: name, Proto: proto})
		}
	case "service-group":
		if x.Objects.FindSvcGroup(name) == nil {
			x.Objects.SvcGroups = append(x.Objects.SvcGroups, fwir.Group{Name: name, Members: cp.memberNames(o["members"]), Desc: str(o["comments"])})
		}
	case "access-role":
		x.AddCaptured(fwir.CapUserID, name, "access-role (identity) object", "type: access-role")
	case "application-site", "application-site-category", "application-site-group":
		x.AddCaptured(fwir.CapAppID, name, typ, "type: "+typ)
	case "vpn-community-meshed", "vpn-community-star":
		x.AddCaptured(fwir.CapVPN, name, typ, "type: "+typ)
	case "simple-gateway", "simple-cluster", "CpmiGatewayCluster", "checkpoint-host":
		x.AddCaptured(fwir.CapOther, name, "gateway object ("+typ+")", "type: "+typ)
	case "Global", "CpmiAnyObject", "RulebaseAction", "Track", "service-dce-rpc", "Internet":
		// dictionary scaffolding
	default:
		if !dict && typ != "" {
			x.AddCaptured(fwir.CapOther, name, "object type "+typ+" — review", "type: "+typ)
		}
	}
}

func (cp *cpState) svc(x *fwir.Context, name, proto string, o map[string]any) {
	if x.Objects.FindSvc(name) != nil {
		return
	}
	x.Objects.Services = append(x.Objects.Services, fwir.SvcObject{
		Name: name, Proto: proto, Port: str(o["port"]), SrcPort: str(o["source-port"]), Desc: str(o["comments"]),
	})
}

func (cp *cpState) memberNames(v any) []string {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	var out []string
	for _, m := range arr {
		switch t := m.(type) {
		case string:
			if o, ok := cp.uid[t]; ok {
				out = append(out, o.name)
			} else {
				out = append(out, t)
			}
		case map[string]any:
			if n, ok := t["name"].(string); ok {
				out = append(out, n)
			}
		}
	}
	return out
}

// rulebase walks an access- or NAT rulebase (sections flatten, order kept).
func (cp *cpState) rulebase(x *fwir.Context, items []json.RawMessage, isNAT bool) {
	for _, raw := range items {
		var o map[string]any
		if err := json.Unmarshal(raw, &o); err != nil {
			continue
		}
		typ, _ := o["type"].(string)
		switch typ {
		case "access-section", "nat-section":
			if sub, ok := o["rulebase"].([]any); ok {
				var subRaws []json.RawMessage
				for _, s := range sub {
					if b, err := json.Marshal(s); err == nil {
						subRaws = append(subRaws, b)
					}
				}
				cp.rulebase(x, subRaws, isNAT)
			}
		case "access-rule":
			cp.accessRule(x, o)
		case "nat-rule":
			cp.natRule(x, o)
		default:
			if isNAT {
				cp.natRule(x, o)
			} else {
				cp.accessRule(x, o)
			}
		}
	}
}

func (cp *cpState) accessRule(x *fwir.Context, o map[string]any) {
	r := fwir.Rule{Enabled: boolOr(o["enabled"], true), Action: "deny"}
	r.Name = str(o["name"])
	if r.Name == "" {
		r.Name = "rule-" + str(o["rule-number"])
	}
	action := cp.refName(o["action"])
	switch strings.ToLower(action) {
	case "accept", "allow", "client auth", "auth":
		r.Action = "allow"
	}
	track := strings.ToLower(cp.refName(o["track"]))
	if track != "" && track != "none" {
		r.Log = true
	}
	r.SrcAddrs = cp.refList(o["source"])
	r.DstAddrs = cp.refList(o["destination"])
	for _, s := range cp.refList(o["service"]) {
		r.Services = append(r.Services, fwir.SvcRef(s))
	}
	r.Desc = str(o["comments"])
	if b, ok := o["source-negate"].(bool); ok && b {
		x.AddCaptured(fwir.CapOther, r.Name, "source-negate on rule — invert manually", "rule "+r.Name)
	}
	if b, ok := o["destination-negate"].(bool); ok && b {
		x.AddCaptured(fwir.CapOther, r.Name, "destination-negate on rule — invert manually", "rule "+r.Name)
	}
	if il, ok := o["inline-layer"]; ok && il != nil {
		x.AddCaptured(fwir.CapOther, r.Name, "inline layer under rule — flatten manually if used", "rule "+r.Name)
	}
	x.Rules = append(x.Rules, r)
}

func (cp *cpState) natRule(x *fwir.Context, o map[string]any) {
	if _, hasOS := o["original-source"]; !hasOS {
		if _, hasM := o["method"]; !hasM {
			return
		}
	}
	n := fwir.NAT{Enabled: boolOr(o["enabled"], true), Raw: "nat-rule " + str(o["rule-number"])}
	if auto, ok := o["auto-generated"].(bool); ok && auto {
		n.Desc = "auto-generated"
	}
	method := strings.ToLower(str(o["method"]))
	switch method {
	case "hide":
		n.Kind = fwir.NATDynamicPAT
	case "static":
		n.Kind = fwir.NATStatic
	default:
		n.Kind = fwir.NATTwice
	}
	os := cp.refName(o["original-source"])
	if !isCPAny(os) {
		n.OrigSrc = fwir.Ref(os)
	}
	od := cp.refName(o["original-destination"])
	if !isCPAny(od) {
		n.OrigDst = fwir.Ref(od)
	}
	osvc := cp.refName(o["original-service"])
	if !isCPAny(osvc) {
		n.OrigSvc = fwir.SvcRef(osvc)
	}
	ts := cp.refName(o["translated-source"])
	if !isCPAny(ts) && ts != "" {
		n.TransSrc = fwir.Ref(ts)
	}
	td := cp.refName(o["translated-destination"])
	if !isCPAny(td) && td != "" {
		n.TransDst = fwir.Ref(td)
	}
	tsvc := cp.refName(o["translated-service"])
	if !isCPAny(tsvc) && tsvc != "" {
		n.TransSvc = fwir.SvcRef(tsvc)
	}
	x.NATs = append(x.NATs, n)
}

func isCPAny(name string) bool {
	l := strings.ToLower(name)
	return l == "" || l == "any" || l == "original" || l == "all"
}

// refName resolves an action/track/object reference (uid string or inline
// object) to a display name.
func (cp *cpState) refName(v any) string {
	switch t := v.(type) {
	case string:
		if o, ok := cp.uid[t]; ok {
			return o.name
		}
		return t
	case map[string]any:
		if n, ok := t["name"].(string); ok {
			return n
		}
		if typ, ok := t["type"].(string); ok {
			return typ
		}
	}
	return ""
}

func (cp *cpState) refList(v any) []fwir.Ref {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	var out []fwir.Ref
	for _, m := range arr {
		n := cp.refName(m)
		if isCPAny(n) {
			continue
		}
		out = append(out, fwir.Ref(n))
	}
	return out
}

func (cp *cpState) finish(x *fwir.Context) {}

func str(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return fmtInt(int(t))
	}
	return ""
}

func num(v any) int {
	if f, ok := v.(float64); ok {
		return int(f)
	}
	return 0
}

func boolOr(v any, def bool) bool {
	if b, ok := v.(bool); ok {
		return b
	}
	return def
}
