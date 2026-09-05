package gen

import (
	"testing"

	"github.com/nizartuanku/ruleforge/fwir"
)

// Every rule in an ASA ACL carries the same ACL name, so unique() is asked for
// the same base tens of thousands of times in a real job. It used to restart
// the "_2, _3, _4 …" probe from scratch on every call, which made the n-th name
// cost n lookups and the whole job quadratic — a 20k-rule config spent most of
// its time here.
//
// 50k names is the guard: with the old probe this test would take minutes
// (about 1.25 billion map lookups), so it fails as a timeout if the resumption
// is ever removed, while still asserting the property that actually matters —
// the names must all be different.
func TestNamer_UniqueStaysUniqueAtScale(t *testing.T) {
	n := newNamer(fwir.VendorASA)
	const count = 50000
	seen := make(map[string]bool, count)
	for i := 0; i < count; i++ {
		got := n.unique("OUTSIDE-ACL")
		if seen[got] {
			t.Fatalf("unique() returned %q twice (call %d)", got, i)
		}
		seen[got] = true
	}
	if len(seen) != count {
		t.Fatalf("got %d distinct names, want %d", len(seen), count)
	}
}

// The resumed counter must still yield to a name that is genuinely taken,
// including one that happens to look like a generated suffix.
func TestNamer_UniqueAvoidsNamesTakenBySource(t *testing.T) {
	n := newNamer(fwir.VendorASA)
	first := n.unique("ACL")  // ACL
	second := n.unique("ACL") // ACL_2
	taken := n.name("ACL_3")  // reserves ACL_3 for a source object of that name
	third := n.unique("ACL")  // must skip ACL_3
	if first == second || second == third || first == third {
		t.Fatalf("names collided: %q %q %q", first, second, third)
	}
	if third == taken {
		t.Fatalf("unique() handed out %q, which the source already owns", taken)
	}
}

// name() must stay idempotent for repeated references to the same object: a
// rule that names an object twice has to resolve to one object, not two.
func TestNamer_NameIsIdempotent(t *testing.T) {
	n := newNamer(fwir.VendorPANOS)
	for i := 0; i < 100; i++ {
		if got := n.name("LAN-NET"); got != "LAN-NET" {
			t.Fatalf("call %d returned %q, want LAN-NET", i, got)
		}
	}
}

// Two different sources that normalise to the same target name must still get
// distinct names, and the rename must be recorded.
func TestNamer_NameDisambiguatesDistinctSources(t *testing.T) {
	n := newNamer(fwir.VendorASA)
	a := n.name("LAN NET") // space is not allowed on ASA -> LAN_NET
	b := n.name("LAN/NET") // also -> LAN_NET, must not collide
	if a == b {
		t.Fatalf("both sources became %q", a)
	}
	if n.Renames["LAN NET"] != a || n.Renames["LAN/NET"] != b {
		t.Fatalf("renames not recorded: %v", n.Renames)
	}
}

// Long names must stay inside the vendor limit even once a suffix is added.
func TestNamer_RespectsVendorNameLimit(t *testing.T) {
	n := newNamer(fwir.VendorPANOS)
	max := nameRules[fwir.VendorPANOS].max
	long := ""
	for len(long) < max+20 {
		long += "abcdefghij"
	}
	for i := 0; i < 50; i++ {
		got := n.unique(long)
		if len(got) > max {
			t.Fatalf("name %q is %d chars, limit is %d", got, len(got), max)
		}
	}
}
