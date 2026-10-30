//go:build windows

package app

import (
	"testing"

	"github.com/aethergui/aethergui/internal/config"
)

func TestAppRulesChanged(t *testing.T) {
	base := config.Settings{}
	if appRulesChanged(base, base) {
		t.Error("identical settings must not trigger re-apply")
	}
	same := config.Settings{AppWhitelist: []string{"C:\\x.exe"}}
	clone := config.Settings{AppWhitelist: []string{"C:\\x.exe"}}
	if appRulesChanged(same, clone) {
		t.Error("same list content must not trigger re-apply")
	}
	cases := []struct {
		name   string
		mutate func(*config.Settings)
	}{
		{"enabled", func(s *config.Settings) { s.AppRulesEnabled = true }},
		{"strict", func(s *config.Settings) { s.AppRulesStrict = true }},
		{"whitelist", func(s *config.Settings) { s.AppWhitelist = []string{"C:\\a.exe"} }},
		{"whitelist order", func(s *config.Settings) { s.AppWhitelist = []string{"b.exe", "a.exe"} }},
		{"blacklist", func(s *config.Settings) { s.AppBlacklist = []string{"C:\\b.exe"} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := base
			tc.mutate(&s)
			if !appRulesChanged(base, s) {
				t.Errorf("%s change must trigger re-apply", tc.name)
			}
		})
	}
}
