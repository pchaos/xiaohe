// Package apprules derives per-application firewall rules from the user's
// white/black lists. Pure rule derivation lives here so it is fully
// testable on any OS; the netsh application layer is Windows-only.
//
// Semantics (see docs/superpowers/specs/2026-10-31-app-rules-design.md):
//   - Blacklist = completely block the program's outbound traffic.
//   - Whitelist has two modes: loose (default, blacklist only) and strict
//     (everything outside the whitelist is blocked; loopback/LAN/core/self
//     are baseline-allowed so the app and the tunnel keep working).
//   - A program in both lists yields both rules; Windows Firewall's default
//     "block wins" precedence makes the blacklist effective.
package apprules

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

// MaxListLen caps each list. netsh costs ~100-200ms per rule as a subprocess,
// so an uncapped list would stall application for tens of seconds.
const MaxListLen = 100

// Rule is one firewall rule in the AE-App-* group.
// Program is empty for baseline (remoteip) and catch-all rules.
type Rule struct {
	Name     string // AE-App-<n>
	Program  string // exe path, or "" for remoteip/catch-all rules
	Action   string // allow | block
	RemoteIP string // comma-separated CIDRs, only for baseline allows
}

// Args returns the netsh argv for this rule. exec.Command passes each element
// as one token (no shell), so paths with spaces need no quoting — same
// approach the killswitch package uses.
func (r Rule) Args() []string {
	args := []string{
		"advfirewall", "firewall", "add", "rule",
		"name=" + r.Name,
		"dir=out",
		"action=" + r.Action,
	}
	if r.Program != "" {
		args = append(args, "program="+r.Program)
	}
	if r.RemoteIP != "" {
		args = append(args, "remoteip="+r.RemoteIP)
	}
	return args
}

// Options feeds Derive. Whitelist/Blacklist entries are exe paths and may
// contain * wildcards, which ExpandWildcards resolves to real paths.
type Options struct {
	Strict    bool
	Whitelist []string
	Blacklist []string
	CoreExe   string // the aether engine binary, baseline-allowed in strict mode
	XiaoheExe string // this client's own binary, baseline-allowed in strict mode
}

const (
	actionAllow = "allow"
	actionBlock = "block"

	loopbackIPs = "127.0.0.0/8,::1/128"
	lanIPs      = "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16"
)

// ExpandWildcards resolves * (and ?) entries against the filesystem and
// returns real paths. Literal entries pass through unchanged; patterns that
// match nothing are dropped. The separator style of the input is preserved in
// the output (backslash in → backslash out), so Windows-style paths fed to
// netsh stay Windows-style and tests on Linux stay readable.
func ExpandWildcards(paths []string) []string {
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		if !strings.ContainsAny(p, "*?") {
			out = append(out, p)
			continue
		}
		winStyle := strings.Contains(p, "\\")
		q := strings.ReplaceAll(p, "\\", "/")
		matches, err := filepath.Glob(q)
		if err != nil || len(matches) == 0 {
			continue
		}
		for _, m := range matches {
			if winStyle {
				m = strings.ReplaceAll(m, "/", "\\")
			}
			out = append(out, m)
		}
	}
	return out
}

// Derive turns the user's lists into the ordered rule set. Groups are emitted
// in a fixed order (baseline allows → whitelist allows → blacklist blocks →
// catch-all block) with each group sorted, so the output is deterministic;
// the firewall decides precedence by rule specificity, not insertion order.
func Derive(opts Options) ([]Rule, error) {
	white := dedupe(ExpandWildcards(opts.Whitelist))
	black := dedupe(ExpandWildcards(opts.Blacklist))
	if len(white) > MaxListLen {
		return nil, fmt.Errorf("白名单超过 %d 条上限（含通配展开）", MaxListLen)
	}
	if len(black) > MaxListLen {
		return nil, fmt.Errorf("黑名单超过 %d 条上限（含通配展开）", MaxListLen)
	}
	sort.Strings(white)
	sort.Strings(black)

	var rules []Rule
	next := func(r Rule) {
		r.Name = fmt.Sprintf("AE-App-%d", len(rules))
		rules = append(rules, r)
	}
	if opts.Strict {
		next(Rule{Action: actionAllow, RemoteIP: loopbackIPs})
		next(Rule{Action: actionAllow, RemoteIP: lanIPs})
		if opts.CoreExe != "" {
			next(Rule{Action: actionAllow, Program: opts.CoreExe})
		}
		if opts.XiaoheExe != "" {
			next(Rule{Action: actionAllow, Program: opts.XiaoheExe})
		}
		for _, p := range white {
			next(Rule{Action: actionAllow, Program: p})
		}
		for _, p := range black {
			next(Rule{Action: actionBlock, Program: p})
		}
		next(Rule{Action: actionBlock})
	} else {
		// Loose mode: Windows allows outbound by default, so only the
		// blacklist needs rules — no allow baseline.
		for _, p := range black {
			next(Rule{Action: actionBlock, Program: p})
		}
	}
	return rules, nil
}

func dedupe(paths []string) []string {
	seen := make(map[string]struct{}, len(paths))
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	return out
}
