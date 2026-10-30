//go:build windows

package apprules

import (
	"fmt"
	"os/exec"
	"strings"
	"sync"
)

// The AE-App-<n> group owns all rules this package creates. Names are
// deterministic, so the client can always address every rule it ever created,
// including rules left behind by a crashed session.
const groupPrefix = "AE-App-"

var mu sync.Mutex

func netsh(args ...string) error {
	out, err := exec.Command("netsh", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("netsh %s: %v: %s", strings.Join(args, " "), err, out)
	}
	return nil
}

// clearGroup removes every AE-App-* rule, including residue from crashed or
// killed sessions. It filters by rule name via Get-NetFirewallRule instead of
// parsing netsh's localized "show rule" output, so it works on any Windows
// language. That PowerShell call is the one deliberate deviation from the
// killswitch package's pure-netsh style: killswitch deletes five fixed rule
// names, this group's membership is unknown here.
func clearGroup() error {
	out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command",
		"Get-NetFirewallRule -Name '"+groupPrefix+"*' | Remove-NetFirewallRule").CombinedOutput()
	if err != nil {
		return fmt.Errorf("clear %s group: %v: %s", groupPrefix+"*", err, out)
	}
	return nil
}

// Apply rebuilds the AE-App-* group to contain exactly rules. The whole group
// is cleared first, so rules for entries the user removed (or residue from a
// previous session) can never survive a re-apply, and a duplicate rule name
// can never fail the rebuild. On a partial failure the group is rolled back so
// a half-applied ruleset can never strand the machine.
func Apply(rules []Rule) error {
	mu.Lock()
	defer mu.Unlock()
	if err := clearGroup(); err != nil {
		return err
	}
	for i, r := range rules {
		if err := netsh(r.Args()...); err != nil {
			_ = clearGroup()
			return fmt.Errorf("应用第 %d 条规则失败: %w", i+1, err)
		}
	}
	return nil
}

// Clear removes every AE-App-* rule, including residue from a crashed or
// killed session. Safe to call when nothing is applied.
func Clear() error {
	mu.Lock()
	defer mu.Unlock()
	return clearGroup()
}
