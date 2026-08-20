// Package parse turns raw vendor configuration text into the fwir model.
// One file per vendor; all honest: recognised-but-not-convertible features go
// to Context.Captured, unknown lines to Context.Unparsed — never dropped.
package parse

import (
	"fmt"
	"strings"

	"github.com/nizartuanku/ruleforge/fwir"
)

// Input is one uploaded source file.
type Input struct {
	Name    string // filename, used to label per-file contexts
	Content string
}

// Parse dispatches to the vendor parser. Multiple inputs are supported for
// vendors whose multi-tenant form ships as one file per tenant (ASA contexts
// collected separately, FTD instances); single-file multi-tenant forms
// (FortiGate VDOMs, Panorama device-groups, ASA with context markers) are
// split automatically.
func Parse(vendor string, inputs []Input) (*fwir.Config, error) {
	if len(inputs) == 0 {
		return nil, fmt.Errorf("no input files")
	}
	switch vendor {
	case fwir.VendorASA, fwir.VendorFTD:
		return parseASAInputs(vendor, inputs)
	case fwir.VendorPANOS:
		return parsePANOSInputs(inputs)
	case fwir.VendorFortiGate:
		return parseFortiGateInputs(inputs)
	case fwir.VendorCheckPoint:
		return parseCheckPointInputs(inputs)
	}
	return nil, fmt.Errorf("unsupported vendor %q", vendor)
}

// DetectVendor guesses the vendor of a config text. Returns "" when unsure.
func DetectVendor(content string) string {
	head := content
	if len(head) > 200000 {
		head = head[:200000]
	}
	l := strings.ToLower(head)
	switch {
	case strings.Contains(l, "config system interface") || strings.Contains(l, "config firewall policy") ||
		strings.Contains(l, "#config-version="):
		return fwir.VendorFortiGate
	case strings.Contains(l, "set rulebase security rules") || strings.Contains(l, "set device-group") ||
		strings.Contains(l, "set network interface ethernet") || strings.Contains(l, "set address "):
		return fwir.VendorPANOS
	case strings.Contains(l, "\"access-rule\"") || strings.Contains(l, "add access-rule") ||
		strings.Contains(l, "set interface eth") && strings.Contains(l, "clish"):
		return fwir.VendorCheckPoint
	case strings.Contains(l, "ngfw version") || strings.Contains(l, "cisco firepower threat defense"):
		return fwir.VendorFTD
	case strings.Contains(l, "asa version") || strings.Contains(l, "access-list") && strings.Contains(l, "nameif"):
		return fwir.VendorASA
	}
	return ""
}

// trimComment strips trailing config comments introduced by " !"; used
// sparingly — most parsers work token-wise.
func fields(line string) []string { return strings.Fields(line) }

// joinFrom joins tokens from index i with single spaces.
func joinFrom(toks []string, i int) string {
	if i >= len(toks) {
		return ""
	}
	return strings.Join(toks[i:], " ")
}

// unquote removes surrounding double quotes.
func unquote(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}
