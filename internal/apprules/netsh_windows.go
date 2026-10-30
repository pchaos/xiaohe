//go:build windows

package apprules

import (
	"fmt"
	"os/exec"
	"strings"
	"sync"
)

// The AE-App-<n> group owns all rules this package creates. Names are
// deterministic, so a crash can never strand rules the client can't address.
const groupPrefix = "AE-App-"

var (
	mu      sync.Mutex
	applied bool     // a ruleset is currently applied this session
	added   []string // rule names added by the current apply
)

func netsh(args ...string) error {
	out, err := exec.Command("netsh", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("netsh %s: %v: %s", strings.Join(args, " "), err, out)
	}
	return nil
}

// Apply rebuilds the AE-App-* group to contain exactly rules: any previously
// applied set is cleared first (idempotent), then rules are added in order.
// On a partial failure the group is rolled back so a half-applied ruleset can
// never strand the machine.
func Apply(rules []Rule) error {
	mu.Lock()
	defer mu.Unlock()
	if applied {
		if err := clearLocked(); err != nil {
			return err
		}
	}
	for i, r := range rules {
		if err := netsh(r.Args()...); err != nil {
			_ = clearLocked()
			return fmt.Errorf("应用第 %d 条规则失败: %w", i+1, err)
		}
		added = append(added, r.Name)
	}
	applied = len(rules) > 0
	return nil
}

// Clear removes the AE-App-* group. Safe to call when nothing is applied.
func Clear() error {
	mu.Lock()
	defer mu.Unlock()
	return clearLocked()
}

// ClearAllStale removes every AE-App-* rule left behind by a previous session
// (crash, killed process). It is best-effort: without elevation the
// PowerShell firewall module fails and the rules survive — callers decide
// whether that matters. Locale-independent because it filters by rule name,
// not by parsing netsh's localized output. Must not be called concurrently
// with Apply/Clear.
func ClearAllStale() error {
	mu.Lock()
	defer mu.Unlock()
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command",
		"Get-NetFirewallRule -Name '"+groupPrefix+"*' | Remove-NetFirewallRule")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("clear stale app rules: %v: %s", err, out)
	}
	added = nil
	applied = false
	return nil
}

// Applied reports whether a ruleset is currently applied this session.
func Applied() bool {
	mu.Lock()
	defer mu.Unlock()
	return applied
}

func clearLocked() error {
	var firstErr error
	for _, name := range added {
		// Deleting a rule that no longer exists is fine: the goal is an empty
		// group, and netsh reports an error we can safely ignore.
		if err := netsh("advfirewall", "firewall", "delete", "rule", "name="+name); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	added = nil
	applied = false
	return firstErr
}
