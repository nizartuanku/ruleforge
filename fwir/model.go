// Package fwir is RuleForge's vendor-neutral intermediate representation.
// Every parser produces a Config; every generator consumes one. The IR is
// deliberately richer than an audit model: object names are preserved (never
// flattened to CIDRs), NAT keeps its original/translated pairs, interfaces
// keep their layer-2 shape (VLAN, bridge, aggregate) — because a converter
// must reproduce structure, not just semantics.
//
// The honesty rule: anything a parser recognises but the pipeline cannot yet
// auto-convert is stored in Context.Captured with its raw lines; anything a
// parser does not recognise at all lands in Context.Unparsed. Nothing is ever
// silently dropped.
package fwir

// Vendor identifiers used across the pipeline.
const (
	VendorASA        = "cisco-asa"
	VendorFTD        = "cisco-ftd"
	VendorPANOS      = "paloalto"
	VendorFortiGate  = "fortinet"
	VendorCheckPoint = "checkpoint"
)

// Vendors lists every vendor id, in display order.
func Vendors() []string {
	return []string{VendorASA, VendorFTD, VendorPANOS, VendorFortiGate, VendorCheckPoint}
}

// VendorLabel is the human name for a vendor id.
func VendorLabel(v string) string {
	switch v {
	case VendorASA:
		return "Cisco ASA"
	case VendorFTD:
		return "Cisco FTD (FMC)"
	case VendorPANOS:
		return "Palo Alto PAN-OS"
	case VendorFortiGate:
		return "Fortinet FortiGate"
	case VendorCheckPoint:
		return "Check Point"
	}
	return v
}

// Config is one parsed source: a device (or management export) holding one or
// more security contexts.
type Config struct {
	Vendor   string    `json:"vendor"`
	Hostname string    `json:"hostname,omitempty"`
	Version  string    `json:"version,omitempty"` // OS version if detected
	Contexts []Context `json:"contexts"`
}

// Context is one tenant of policy: an ASA security context, a FortiGate VDOM,
// a PAN-OS vsys or Panorama device-group, a Check Point policy package — or
// simply the whole device when the source is single-tenant ("default").
type Context struct {
	Name       string        `json:"name"`
	Interfaces []Interface   `json:"interfaces,omitempty"`
	Zones      []Zone        `json:"zones,omitempty"`
	Objects    Objects       `json:"objects"`
	Rules      []Rule        `json:"rules,omitempty"`
	NATs       []NAT         `json:"nats,omitempty"`
	Routes     []StaticRoute `json:"routes,omitempty"`
	Captured   []Captured    `json:"captured,omitempty"` // recognised, not auto-converted
	Unparsed   []string      `json:"unparsed,omitempty"` // not recognised at all
}

// Interface kinds.
const (
	IfPhysical  = "physical"
	IfSubIf     = "subinterface" // dot1q sub-interface / VLAN interface
	IfVLAN      = "vlan"         // switch VLAN interface (SVI)
	IfBridge    = "bridge"       // bridge group / BVI / transparent pair
	IfAggregate = "aggregate"    // port-channel / etherchannel / aggregate-ethernet
	IfLoopback  = "loopback"
	IfTunnel    = "tunnel"
	IfMgmt      = "management"
)

// Interface is one L2/L3 interface in vendor-neutral shape.
type Interface struct {
	Name     string   `json:"name"`               // vendor name: GigabitEthernet0/1, port1, ethernet1/1
	Alias    string   `json:"alias,omitempty"`    // logical name (ASA nameif, description-derived)
	Kind     string   `json:"kind"`               // one of the If* constants
	Parent   string   `json:"parent,omitempty"`   // physical parent for sub-interfaces
	VlanID   int      `json:"vlan_id,omitempty"`  // dot1q tag / vlan id
	Members  []string `json:"members,omitempty"`  // aggregate or bridge members
	IPs      []string `json:"ips,omitempty"`      // CIDR notation
	Zone     string   `json:"zone,omitempty"`     // owning zone, if the vendor binds here
	SecLevel int      `json:"sec_level,omitempty"`// ASA security-level (0-100), -1 = unset
	MTU      int      `json:"mtu,omitempty"`
	Desc     string   `json:"desc,omitempty"`
	Shutdown bool     `json:"shutdown,omitempty"`
	Raw      []string `json:"-"`
}

// Zone groups interfaces for policy.
type Zone struct {
	Name       string   `json:"name"`
	Interfaces []string `json:"interfaces,omitempty"`
	Synthetic  bool     `json:"synthetic,omitempty"` // created by RuleForge (e.g. from ASA nameif)
}

// Objects is the named-object universe of one context.
type Objects struct {
	Networks  []NetObject `json:"networks,omitempty"`
	Services  []SvcObject `json:"services,omitempty"`
	NetGroups []Group     `json:"net_groups,omitempty"`
	SvcGroups []Group     `json:"svc_groups,omitempty"`
}

// NetObject kinds.
const (
	NetHost   = "host"
	NetSubnet = "subnet"
	NetRange  = "range"
	NetFQDN   = "fqdn"
)

// NetObject is a named network object.
type NetObject struct {
	Name  string `json:"name"`
	Kind  string `json:"kind"`            // host | subnet | range | fqdn
	Value string `json:"value"`           // host IP, CIDR, range start, or fqdn
	Value2 string `json:"value2,omitempty"` // range end
	Desc  string `json:"desc,omitempty"`
}

// SvcObject is a named service object.
type SvcObject struct {
	Name    string `json:"name"`
	Proto   string `json:"proto"`              // tcp | udp | tcp-udp | icmp | ip | sctp | <number>
	Port    string `json:"port,omitempty"`     // dst port: "80", "1000-2000", "" = any
	SrcPort string `json:"srcport,omitempty"`  //
	ICMPType string `json:"icmp_type,omitempty"`
	Desc    string `json:"desc,omitempty"`
}

// Group is a named group of object names (network or service).
type Group struct {
	Name    string   `json:"name"`
	Members []string `json:"members"` // names of objects/groups, or literals
	Desc    string   `json:"desc,omitempty"`
}

// Ref is a reference in a rule/NAT: either the name of an object/group in the
// context's Objects, or a literal ("any", "10.0.0.0/8", "192.0.2.1/32",
// "host.example.com").
type Ref string

// SvcRef references a service: a named service/group or a literal
// "tcp/443", "udp/53", "icmp", "any".
type SvcRef string

// Rule is one access-control rule.
type Rule struct {
	Index    int      `json:"index"` // 1-based order within the context
	Name     string   `json:"name,omitempty"`
	Action   string   `json:"action"` // allow | deny
	SrcZones []string `json:"src_zones,omitempty"`
	DstZones []string `json:"dst_zones,omitempty"`
	SrcAddrs []Ref    `json:"src_addrs,omitempty"` // empty = any
	DstAddrs []Ref    `json:"dst_addrs,omitempty"`
	Services []SvcRef `json:"services,omitempty"` // empty = any
	Apps     []string `json:"apps,omitempty"`     // App-ID / application names (L7)
	URLCats  []string `json:"url_cats,omitempty"` // URL categories
	Log      bool     `json:"log,omitempty"`
	Enabled  bool     `json:"enabled"`
	Desc     string   `json:"desc,omitempty"`
	Raw      string   `json:"-"`
}

// NAT kinds.
const (
	NATStatic     = "static"      // 1:1, possibly bidirectional
	NATDynamicPAT = "dynamic-pat" // many:1 with port translation (hide/overload)
	NATDynamic    = "dynamic"     // many:pool
	NATTwice      = "twice"       // manual/policy NAT: src+dst together
)

// NAT is one translation rule.
type NAT struct {
	Index    int    `json:"index"`
	Name     string `json:"name,omitempty"`
	Kind     string `json:"kind"`
	SrcIface string `json:"src_iface,omitempty"` // ingress interface/zone ("any" ok)
	DstIface string `json:"dst_iface,omitempty"` // egress interface/zone
	OrigSrc  Ref    `json:"orig_src,omitempty"`
	OrigDst  Ref    `json:"orig_dst,omitempty"`
	OrigSvc  SvcRef `json:"orig_svc,omitempty"`
	TransSrc Ref    `json:"trans_src,omitempty"` // "interface" = egress-interface address
	TransDst Ref    `json:"trans_dst,omitempty"`
	TransSvc SvcRef `json:"trans_svc,omitempty"`
	Bidir    bool   `json:"bidir,omitempty"`
	Enabled  bool   `json:"enabled"`
	Desc     string `json:"desc,omitempty"`
	Raw      string `json:"-"`
}

// StaticRoute is one static route.
type StaticRoute struct {
	Iface   string `json:"iface,omitempty"` // egress interface or its alias
	Dest    string `json:"dest"`            // CIDR, "0.0.0.0/0" for default
	Gateway string `json:"gateway,omitempty"`
	Metric  int    `json:"metric,omitempty"`
	Desc    string `json:"desc,omitempty"`
	Raw     string `json:"-"`
}

// Captured categories — recognised features the pipeline reports rather than
// auto-converts in v1. Keep in sync with docs §4.
const (
	CapVPN        = "vpn"
	CapCert       = "certificate"
	CapURLFilter  = "url-filtering"
	CapAppID      = "app-id"
	CapDynRouting = "dynamic-routing"
	CapHA         = "high-availability"
	CapUserID     = "user-identity"
	CapMgmt       = "management"
	CapInspection = "inspection"
	CapOther      = "other"
)

// Captured is one recognised-but-not-auto-converted feature instance.
type Captured struct {
	Category string   `json:"category"`
	Name     string   `json:"name,omitempty"`
	Detail   string   `json:"detail,omitempty"`
	Raw      []string `json:"raw,omitempty"`
}

// Ctx returns the named context, or nil.
func (c *Config) Ctx(name string) *Context {
	for i := range c.Contexts {
		if c.Contexts[i].Name == name {
			return &c.Contexts[i]
		}
	}
	return nil
}

// AddCaptured appends a captured feature to the context.
func (x *Context) AddCaptured(category, name, detail string, raw ...string) {
	x.Captured = append(x.Captured, Captured{Category: category, Name: name, Detail: detail, Raw: raw})
}

// FindNet returns the named network object, or nil.
func (o *Objects) FindNet(name string) *NetObject {
	for i := range o.Networks {
		if o.Networks[i].Name == name {
			return &o.Networks[i]
		}
	}
	return nil
}

// FindSvc returns the named service object, or nil.
func (o *Objects) FindSvc(name string) *SvcObject {
	for i := range o.Services {
		if o.Services[i].Name == name {
			return &o.Services[i]
		}
	}
	return nil
}

// FindNetGroup returns the named network group, or nil.
func (o *Objects) FindNetGroup(name string) *Group {
	for i := range o.NetGroups {
		if o.NetGroups[i].Name == name {
			return &o.NetGroups[i]
		}
	}
	return nil
}

// FindSvcGroup returns the named service group, or nil.
func (o *Objects) FindSvcGroup(name string) *Group {
	for i := range o.SvcGroups {
		if o.SvcGroups[i].Name == name {
			return &o.SvcGroups[i]
		}
	}
	return nil
}
