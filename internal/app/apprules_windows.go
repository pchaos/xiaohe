//go:build windows

package app

import (
	"golang.org/x/sys/windows"

	"github.com/aethergui/aethergui/internal/apprules"
)

// isElevatedProcess reports whether the process holds an elevated token; the
// netsh firewall commands require one. Deliberately separate from elevate.go's
// isElevated (wgtun-tagged): app rules must work in every build, not only the
// native-WireGuard ones.
func isElevatedProcess() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

func applyAppRules(rules []apprules.Rule) error { return apprules.Apply(rules) }

func clearAppRules() error { return apprules.Clear() }

func clearStaleAppRules() error { return apprules.ClearAllStale() }

// ListProcesses feeds the "add from running process" picker on the rules page.
func (a *App) ListProcesses() ([]apprules.Process, error) {
	return apprules.ListProcesses()
}
