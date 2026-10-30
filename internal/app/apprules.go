package app

import (
	"os"

	"github.com/aethergui/aethergui/internal/apprules"
	"github.com/aethergui/aethergui/internal/config"
	"github.com/aethergui/aethergui/internal/logx"
)

// AppRulesState is the UI-visible state of the per-application firewall
// rules. State ∈ off|pending|applied|not_elevated|failed.
type AppRulesState struct {
	Enabled bool   `json:"enabled"`
	Strict  bool   `json:"strict"`
	WhiteN  int    `json:"whitelistCount"`
	BlackN  int    `json:"blacklistCount"`
	State   string `json:"state"`
	Error   string `json:"error"`
}

const (
	appRulesOff         = "off"
	appRulesPending     = "pending"
	appRulesApplied     = "applied"
	appRulesNotElevated = "not_elevated"
	appRulesFailed      = "failed"
)

// AppRulesSnapshot returns the current app-rules state for the UI snapshot.
func (a *App) AppRulesSnapshot() AppRulesState {
	a.appRulesMu.Lock()
	defer a.appRulesMu.Unlock()
	return a.appRules
}

// appRulesChanged reports whether any app-rules field differs between two
// settings, so SaveSettings only re-applies the firewall when it matters.
func appRulesChanged(a, b config.Settings) bool {
	return a.AppRulesEnabled != b.AppRulesEnabled ||
		a.AppRulesStrict != b.AppRulesStrict ||
		!equalStrings(a.AppWhitelist, b.AppWhitelist) ||
		!equalStrings(a.AppBlacklist, b.AppBlacklist)
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// requestAppRulesApply reconciles the firewall with a settings snapshot. It
// marks the state pending then applies latest-wins: every request bumps a
// generation and a goroutine that lost the race skips, so a fast burst of
// settings writes always ends with the newest configuration. Runs off the
// caller's goroutine because tens of netsh subprocesses must never block a
// settings save.
func (a *App) requestAppRulesApply(s config.Settings) {
	a.appRulesMu.Lock()
	a.appRulesGen++
	gen := a.appRulesGen
	a.appRules = AppRulesState{
		Enabled: s.AppRulesEnabled,
		Strict:  s.AppRulesStrict,
		WhiteN:  len(s.AppWhitelist),
		BlackN:  len(s.AppBlacklist),
		State:   appRulesPending,
	}
	a.appRulesMu.Unlock()
	go a.syncAppRules(s, gen)
}

func (a *App) syncAppRules(s config.Settings, gen uint64) {
	if !s.AppRulesEnabled {
		if err := clearAppRules(); err != nil {
			logx.Warnf("[app] app rules clear failed: %v", err)
			a.setAppRulesState(gen, AppRulesState{State: appRulesFailed, Error: err.Error()})
			return
		}
		a.setAppRulesState(gen, AppRulesState{State: appRulesOff})
		return
	}

	coreExe := ""
	if a.Core != nil {
		coreExe = a.Core.Path()
	}
	self, err := os.Executable()
	if err != nil {
		self = ""
	}
	rules, err := apprules.Derive(apprules.Options{
		Strict:    s.AppRulesStrict,
		Whitelist: s.AppWhitelist,
		Blacklist: s.AppBlacklist,
		CoreExe:   coreExe,
		XiaoheExe: self,
	})
	st := AppRulesState{
		Enabled: s.AppRulesEnabled,
		Strict:  s.AppRulesStrict,
		WhiteN:  len(s.AppWhitelist),
		BlackN:  len(s.AppBlacklist),
	}
	if err != nil {
		st.State = appRulesFailed
		st.Error = err.Error()
		a.setAppRulesState(gen, st)
		return
	}
	if !isElevatedProcess() {
		// Keep whatever rules the firewall currently holds: they persist by
		// design (system firewall, not process lifetime) and still enforce the
		// last elevated configuration until the app runs as admin again.
		st.State = appRulesNotElevated
		a.setAppRulesState(gen, st)
		logx.Warnf("[app] app rules not applied: process is not elevated")
		return
	}
	if err := applyAppRules(rules); err != nil {
		st.State = appRulesFailed
		st.Error = err.Error()
		a.setAppRulesState(gen, st)
		logx.Warnf("[app] app rules apply failed: %v", err)
		return
	}
	st.State = appRulesApplied
	a.setAppRulesState(gen, st)
	logx.Infof("[app] app rules applied (%d rules)", len(rules))
}

// setAppRulesState stores st only when gen is still the newest request.
func (a *App) setAppRulesState(gen uint64, st AppRulesState) {
	a.appRulesMu.Lock()
	defer a.appRulesMu.Unlock()
	if gen != a.appRulesGen {
		return
	}
	a.appRules = st
}

// initAppRules reconciles the firewall at startup: enabled rebuilds the rules
// (or reports not-elevated), disabled clears rules left behind by a crash
// between a switch flip and its Clear. Both paths must not block startup.
func (a *App) initAppRules() {
	if !a.Settings.AppRulesEnabled {
		go func() {
			if err := clearStaleAppRules(); err != nil {
				logx.Warnf("[app] stale app rules cleanup failed: %v", err)
			}
		}()
		return
	}
	a.requestAppRulesApply(a.Settings)
}
