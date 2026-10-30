//go:build wgtun && windows

package app

import (
	"errors"
	"os"
	"testing"

	"golang.org/x/sys/windows"
)

func TestIsElevationError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil is not elevation", nil, false},
		{"access denied code", windows.ERROR_ACCESS_DENIED, true},
		{"wrapped access denied", errors.New("wgtun: creating wintun adapter: Access is denied."), true},
		{"lowercase denied", errors.New("access denied"), true},
		{"unrelated error", errors.New("network is unreachable"), false},
		{"wrapped unrelated", errors.New("wgtun: endpoint scan: i/o timeout"), false},
		// A missing wintun.dll fails with ERROR_MOD_NOT_FOUND, which is NOT an
		// elevation problem: relaunching as admin cannot conjure the DLL. The
		// packaging fix (release.ps1 staging wintun.dll next to the exe) is what
		// makes that error go away; misclassifying it here would relaunch into a
		// UAC prompt that cannot help.
		{"module not found", windows.ERROR_MOD_NOT_FOUND, false},
		{"module not found text", errors.New("creating wintun adapter: The specified module could not be found."), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isElevationError(tc.err); got != tc.want {
				t.Fatalf("isElevationError(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func TestRelaunchArgs(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want []string
	}{
		{"no args adds -connect", nil, []string{"-connect"}},
		{"keeps mode and adds -connect", []string{"-ui", "browser"}, []string{"-ui", "browser", "-connect"}},
		{"keeps existing -connect", []string{"-connect"}, []string{"-connect"}},
		{"keeps existing --connect", []string{"--connect"}, []string{"--connect"}},
		{"does not add a second", []string{"-ui", "window", "-connect"}, []string{"-ui", "window", "-connect"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			old := os.Args
			os.Args = append([]string{"Xiaohe.exe"}, tc.args...)
			defer func() { os.Args = old }()
			got := relaunchArgs()
			if len(got) != len(tc.want) {
				t.Fatalf("relaunchArgs() = %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("relaunchArgs() = %v, want %v", got, tc.want)
				}
			}
		})
	}
}
