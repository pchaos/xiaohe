//go:build wgtun && windows

package app

import (
	"errors"
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
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isElevationError(tc.err); got != tc.want {
				t.Fatalf("isElevationError(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}
