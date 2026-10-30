//go:build !windows

package app

import (
	"github.com/aethergui/aethergui/internal/apprules"
)

func appRulesPlatformSupported() bool { return false }

func applyAppRules([]apprules.Rule) error { return errAppRulesUnsupported }

func clearAppRules() error { return nil }

// ListProcesses answers the web endpoint with an empty list off Windows; the
// rule picker cannot do anything useful here anyway.
func (a *App) ListProcesses() ([]apprules.Process, error) { return nil, nil }
