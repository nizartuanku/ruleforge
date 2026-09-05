package engine

import (
	"fmt"
	"sort"
	"strings"

	"github.com/nizartuanku/ruleforge/fwir"
)

// ValueCheck is one value-level round-trip metric: it compares the actual
// values carried by the source and by the re-parsed generated config, not how
// many of them there are.
//
// Counting was the whole of round-trip verification until now, and counting is
// blind to corruption: a generator that writes an interface address as
// 198.51.100.0/28 instead of 198.51.100.2/28 still writes exactly one address,
// so every count matched and the check passed while the config was wrong. That
// is what happened in v0.1.0. A count check can only catch loss; this catches
// change.
type ValueCheck struct {
	Metric  string   `json:"metric"`
	Checked int      `json:"checked"` // distinct source values compared
	Missing []string `json:"missing,omitempty"`
	Extra   []string `json:"extra,omitempty"` // target-only values, reported but not a failure
	OK      bool     `json:"ok"`
	Note    string   `json:"note,omitempty"`
}

// maxReported caps how many differing values a check names. The point is to
// show the reader a concrete value to go and look at, not to dump the config.
const maxReported = 12

// valueSets are the categories whose values must survive generation unchanged.
// Rules and NAT are deliberately absent: their zone names, object names and
// ordering are legitimately rewritten by the mapping and the namer, so a value
// comparison there would report differences that are not defects. What is
// compared here is the part of a config that has one correct answer.
func buildValueChecks(src, rt *fwir.Config) []ValueCheck {
	type set struct {
		metric string
		of     func(*fwir.Context) []string
	}
	sets := []set{
		{"interface addresses", ifaceAddrs},
		{"static routes", routeValues},
		{"network object values", netObjValues},
		{"service object values", svcObjValues},
	}
	var out []ValueCheck
	for _, s := range sets {
		want := collect(src, s.of)
		got := collect(rt, s.of)
		out = append(out, compareSets(s.metric, want, got))
	}
	return out
}

func collect(cfg *fwir.Config, of func(*fwir.Context) []string) map[string]bool {
	m := map[string]bool{}
	for i := range cfg.Contexts {
		for _, v := range of(&cfg.Contexts[i]) {
			if v != "" {
				m[v] = true
			}
		}
	}
	return m
}

// compareSets reports source values with no counterpart in the target. Extra
// target values are listed but never fail the check: generators legitimately
// add helper objects, split tcp-udp services and expand ranges.
func compareSets(metric string, want, got map[string]bool) ValueCheck {
	vc := ValueCheck{Metric: metric, Checked: len(want), OK: true}
	for v := range want {
		if !got[v] {
			vc.Missing = append(vc.Missing, v)
		}
	}
	for v := range got {
		if !want[v] {
			vc.Extra = append(vc.Extra, v)
		}
	}
	sort.Strings(vc.Missing)
	sort.Strings(vc.Extra)
	if len(vc.Missing) > 0 {
		vc.OK = false
		vc.Note = fmt.Sprintf("%d source value(s) are not present in the generated config — they were dropped or changed, not merely renamed", len(vc.Missing))
	} else if len(vc.Extra) > 0 {
		vc.Note = "generated config carries additional values (helper objects, split services) — expected"
	}
	vc.Missing = trimList(vc.Missing)
	vc.Extra = trimList(vc.Extra)
	return vc
}

func trimList(ss []string) []string {
	if len(ss) <= maxReported {
		return ss
	}
	out := append([]string{}, ss[:maxReported]...)
	return append(out, fmt.Sprintf("… and %d more", len(ss)-maxReported))
}

// ---- value extractors ----

// normAddr puts an address in one shape so that "10.0.0.1" and "10.0.0.1/32"
// compare equal — vendors disagree about writing the /32, and that difference
// is notation, not meaning.
func normAddr(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return ""
	}
	if fwir.IsHostCIDR(s) {
		return fwir.HostPart(s)
	}
	return s
}

func ifaceAddrs(x *fwir.Context) []string {
	var out []string
	for _, ifc := range x.Interfaces {
		for _, ip := range ifc.IPs {
			// The address alone, without the interface name: a generator may
			// legitimately map GigabitEthernet0/1 to ethernet1/1, but the
			// address it carries has to be the same address.
			if v := normAddr(ip); v != "" {
				out = append(out, v)
			}
		}
	}
	return out
}

func routeValues(x *fwir.Context) []string {
	var out []string
	for _, r := range x.Routes {
		dest := normAddr(r.Dest)
		if dest == "" {
			continue
		}
		out = append(out, dest+" via "+normAddr(r.Gateway))
	}
	return out
}

func netObjValues(x *fwir.Context) []string {
	var out []string
	for _, o := range x.Objects.Networks {
		v := normAddr(o.Value)
		if v == "" {
			continue
		}
		if o.Value2 != "" {
			v += "-" + normAddr(o.Value2)
		}
		out = append(out, v)
	}
	return out
}

func svcObjValues(x *fwir.Context) []string {
	var out []string
	for _, s := range x.Objects.Services {
		proto := strings.ToLower(strings.TrimSpace(s.Proto))
		if proto == "" {
			continue
		}
		v := proto
		if s.Port != "" {
			v += "/" + strings.TrimSpace(s.Port)
		}
		if s.SrcPort != "" {
			v += " src " + strings.TrimSpace(s.SrcPort)
		}
		// tcp-udp is generated as two objects on vendors that have no combined
		// type, so compare it as its two halves.
		if proto == "tcp-udp" {
			base := ""
			if s.Port != "" {
				base = "/" + strings.TrimSpace(s.Port)
			}
			out = append(out, "tcp"+base, "udp"+base)
			continue
		}
		out = append(out, v)
	}
	return out
}
