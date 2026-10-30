//go:build !windows

package app

import (
	"errors"

	"github.com/aethergui/aethergui/internal/apprules"
)

// errAppRulesUnsupported marks the firewall feature as unavailable off
// Windows; the state machine still derives rules and reports the failure.
var errAppRulesUnsupported = errors.New("app rules are unsupported on this platform")

func isElevatedProcess() bool { return false }

func applyAppRules([]apprules.Rule) error { return errAppRulesUnsupported }

func clearAppRules() error { return nil }

func clearStaleAppRules() error { return nil }

// ListProcesses answers the web endpoint with an empty list off Windows; the
// rule picker cannot do anything useful here anyway.
func (a *App) ListProcesses() ([]apprules.Process, error) { return nil, nil }
