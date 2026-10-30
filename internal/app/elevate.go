//go:build wgtun && windows

package app

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/aethergui/aethergui/internal/logx"
	"golang.org/x/sys/windows"
)

// elevateEnv marks a process that was relaunched by maybeElevateForNative, so a
// failed elevation attempt (user clicked "No" on the UAC prompt, or the token
// is still limited) does not loop: the second attempt logs and gives up instead
// of prompting again.
const elevateEnv = "XIAOHE_ELEVATING"

// isElevated reports whether the current process holds an elevated (admin) token.
func isElevated() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

// maybeElevateForNative relaunches the current executable as administrator when
// the native WireGuard backend needs the wintun kernel driver but the process
// is not elevated. It returns true when a relaunch was requested (the current
// process should stop its connect and let the elevated child take over).
//
// It is a no-op when already elevated, when an elevation attempt already ran
// (elevateEnv is set), or when the current executable cannot be identified.
//
// The relaunch uses ShellExecuteW("runas"), which makes Windows raise the UAC
// prompt; the user's choice determines whether the child starts elevated. The
// child inherits the same command line, plus a forced `-connect` (so a connect
// started from the GUI survives the handoff) and the elevateEnv marker — which
// must be exported BEFORE the child is spawned, since the child inherits the
// environment block as it exists at ShellExecute time.
func maybeElevateForNative() bool {
	if isElevated() {
		return false
	}
	if os.Getenv(elevateEnv) == "1" {
		logx.Warnf("[app] native WireGuard needs elevation but the elevated relaunch did not happen (UAC declined?)")
		return false
	}
	exe, err := os.Executable()
	if err != nil {
		logx.Warnf("[app] cannot resolve executable for elevation: %v", err)
		return false
	}
	exe, err = filepath.Abs(exe)
	if err != nil {
		logx.Warnf("[app] cannot absolutize executable for elevation: %v", err)
		return false
	}
	args := relaunchArgs()
	verb, _ := windows.UTF16PtrFromString("runas")
	file, _ := windows.UTF16PtrFromString(exe)
	argstr, _ := windows.UTF16PtrFromString(strings.Join(args, " "))
	cwd, _ := windows.UTF16PtrFromString(filepath.Dir(exe))
	logx.Infof("[app] native WireGuard needs admin; relaunching %s as administrator", exe)
	// The elevated child must know it is a child of an elevation request, so it
	// does not prompt again on a second connect. Set BEFORE ShellExecute: the
	// child inherits the environment block as it is at spawn time.
	_ = os.Setenv(elevateEnv, "1")
	// ShellExecute returns an error when the user declines the UAC prompt
	// (ERROR_CANCELLED), which is fine - we simply keep the un-elevated session.
	if err := windows.ShellExecute(0, verb, file, argstr, cwd, windows.SW_SHOWNORMAL); err != nil {
		logx.Warnf("[app] elevation relaunch not accepted (%v); staying un-elevated", err)
		return false
	}
	return true
}

// isElevationError reports whether an error is the wintun driver's
// access-denied: the native backend needs an elevated token and the current
// process does not have one. It is a string match as well as an errors.Is on
// the Win32 code, because the error crosses the wgtun boundary wrapped in
// context ("creating wintun adapter: ...") and may be a syscall.Errno rather
// than the canonical windows.ERROR_ACCESS_DENIED.
func isElevationError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		return true
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "access is denied") || strings.Contains(s, "access denied")
}

// relaunchArgs rebuilds the current command line for the elevated child. The
// GUI keeps the same args (mode, port, connect) so an autostart `-connect` or a
// pinned `-port` survives the relaunch.
//
// A `-connect` is forced in: without it, a connect started from the GUI (which
// passes no flags) would relaunch into a child that never connects, leaving the
// user with two windows and a session that quietly never started. The flag is
// idempotent, so a child that already had it keeps it.
func relaunchArgs() []string {
	args := append([]string(nil), os.Args[1:]...)
	hasConnect := false
	for _, a := range args {
		if a == "-connect" || a == "--connect" {
			hasConnect = true
			break
		}
	}
	if !hasConnect {
		args = append(args, "-connect")
	}
	return args
}
