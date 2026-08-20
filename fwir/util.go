package fwir

import (
	"fmt"
	"net"
	"strings"
)

// IsAny reports whether a Ref means "everything".
func (r Ref) IsAny() bool {
	s := strings.ToLower(strings.TrimSpace(string(r)))
	return s == "" || s == "any" || s == "any4" || s == "any6" || s == "all" || s == "0.0.0.0/0" || s == "::/0"
}

// IsLiteral reports whether the Ref is an address literal rather than an
// object name: a parseable IP/CIDR or something FQDN-shaped is only literal
// when it is not the name of a defined object (callers check objects first).
func (r Ref) IsLiteral() bool {
	s := string(r)
	if r.IsAny() {
		return true
	}
	if _, _, err := net.ParseCIDR(s); err == nil {
		return true
	}
	if net.ParseIP(s) != nil {
		return true
	}
	if strings.Contains(s, "-") { // range literal a-b
		parts := strings.SplitN(s, "-", 2)
		if net.ParseIP(parts[0]) != nil && net.ParseIP(parts[1]) != nil {
			return true
		}
	}
	return false
}

// IsAny reports whether a SvcRef means "any service".
func (s SvcRef) IsAny() bool {
	v := strings.ToLower(strings.TrimSpace(string(s)))
	return v == "" || v == "any" || v == "ip" || v == "all"
}

// SplitSvcLiteral parses a literal "tcp/443", "udp/1000-2000", "icmp",
// returning ok=false for named references.
func (s SvcRef) SplitSvcLiteral() (proto, port string, ok bool) {
	v := strings.ToLower(strings.TrimSpace(string(s)))
	if v == "" || v == "any" {
		return "ip", "", true
	}
	switch v {
	case "icmp", "ip", "gre", "esp", "ah", "tcp", "udp", "sctp":
		return v, "", true
	}
	if i := strings.IndexByte(v, '/'); i > 0 {
		p, rest := v[:i], v[i+1:]
		switch p {
		case "tcp", "udp", "sctp", "tcp-udp", "icmp":
			return p, rest, true
		}
	}
	return "", "", false
}

// SvcLiteral builds a service literal SvcRef.
func SvcLiteral(proto, port string) SvcRef {
	proto = strings.ToLower(strings.TrimSpace(proto))
	port = strings.TrimSpace(port)
	if proto == "" || proto == "ip" || proto == "any" {
		return "any"
	}
	if port == "" || port == "any" || port == "0-65535" {
		return SvcRef(proto)
	}
	return SvcRef(proto + "/" + port)
}

// CIDRFromIPMask converts "10.1.1.0","255.255.255.0" to "10.1.1.0/24".
// A host address ("10.1.1.5","255.255.255.255" or empty mask) becomes /32.
func CIDRFromIPMask(ip, mask string) (string, error) {
	a := net.ParseIP(strings.TrimSpace(ip))
	if a == nil {
		return "", fmt.Errorf("bad IP %q", ip)
	}
	mask = strings.TrimSpace(mask)
	if mask == "" {
		if a.To4() != nil {
			return a.String() + "/32", nil
		}
		return a.String() + "/128", nil
	}
	m := net.ParseIP(mask)
	if m == nil {
		return "", fmt.Errorf("bad mask %q", mask)
	}
	m4 := m.To4()
	if m4 == nil {
		return "", fmt.Errorf("non-IPv4 mask %q", mask)
	}
	ones, bits := net.IPMask(m4).Size()
	if bits == 0 {
		return "", fmt.Errorf("non-contiguous mask %q", mask)
	}
	n := &net.IPNet{IP: a.Mask(net.IPMask(m4)), Mask: net.IPMask(m4)}
	return fmt.Sprintf("%s/%d", n.IP, ones), nil
}

// PrefixToMask converts a prefix length (0-32) to dotted mask.
func PrefixToMask(prefix int) string {
	m := net.CIDRMask(prefix, 32)
	return net.IP(m).String()
}

// SplitCIDR returns network address and dotted mask for "10.0.0.0/24".
// A bare IP is treated as /32.
func SplitCIDR(cidr string) (ip, mask string, err error) {
	s := strings.TrimSpace(cidr)
	if !strings.Contains(s, "/") {
		if net.ParseIP(s) == nil {
			return "", "", fmt.Errorf("bad address %q", cidr)
		}
		return s, "255.255.255.255", nil
	}
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		return "", "", err
	}
	ones, _ := n.Mask.Size()
	return n.IP.String(), PrefixToMask(ones), nil
}

// IsHostCIDR reports whether the CIDR is a /32 (or bare IP).
func IsHostCIDR(cidr string) bool {
	if !strings.Contains(cidr, "/") {
		return net.ParseIP(cidr) != nil
	}
	return strings.HasSuffix(cidr, "/32") || strings.HasSuffix(cidr, "/128")
}

// HostPart returns the address without any prefix suffix.
func HostPart(cidr string) string {
	if i := strings.IndexByte(cidr, '/'); i > 0 {
		return cidr[:i]
	}
	return cidr
}
