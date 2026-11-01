//go:build windows

package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"time"

	webview2 "github.com/jchv/go-webview2"
	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"
	"golang.org/x/sys/windows"

	"github.com/aethergui/aethergui/internal/app"
	"github.com/aethergui/aethergui/internal/config"
	"github.com/aethergui/aethergui/internal/logx"
	"github.com/aethergui/aethergui/internal/vpn"
	"github.com/aethergui/aethergui/internal/webbridge"
)

const (
	appTitle = "Xiaohe"
	prefW    = 1280 // preferred size; shrunk to fit the current desktop
	prefH    = 860
	minW     = 960
	minH     = 640
)

// systemDPI is the desktop DPI (96 = 100% scaling).
func systemDPI() int {
	dpi, _, _ := procGetDpiForSystem.Call()
	if dpi < 96 {
		return 96
	}
	if dpi > 480 {
		return 480
	}
	return int(dpi)
}

// screenPixels is the primary display size in physical pixels.
func screenPixels() (int, int) {
	w, _, _ := procGetSystemMetrics.Call(uintptr(smCXScreen))
	h, _, _ := procGetSystemMetrics.Call(uintptr(smCYSCREEN))
	return int(w), int(h)
}

// windowSize returns the window size in physical pixels.
//
// The UI is designed in 96-DPI units and the embedded browser renders at the
// desktop scaling factor, so a physical size of prefW×prefH on a 200% desktop
// would leave the page with a 640-pixel-wide viewport. Both the window and its
// viewport must be scaled by the same factor.
func windowSize() (int, int) {
	dpi := systemDPI()
	lw, lh := prefW, prefH
	sw, sh := screenPixels()
	if sw > 0 && sh > 0 {
		// Keep a margin for the taskbar and the window frame.
		maxW := (sw - 40*dpi/96) * 96 / dpi
		maxH := (sh - 120*dpi/96) * 96 / dpi
		if lw > maxW {
			lw = maxW
		}
		if lh > maxH {
			lh = maxH
		}
		if lw < minW {
			lw = minW
		}
		if lh < minH {
			lh = minH
		}
		if lw*dpi/96 > sw {
			lw = sw * 96 / dpi
		}
		if lh*dpi/96 > sh {
			lh = sh * 96 / dpi
		}
	}
	return lw * dpi / 96, lh * dpi / 96
}

// runUI opens the desktop shell and blocks until the process should stop.
//
// Preferred host: the standard go-webview2 window (a real Win32 window owning
// an embedded Edge control). Fallback: a chromium browser opened in --app mode
// with the same tray, so nothing about the client changes for the user.
func runUI(a *app.App, br *webbridge.Bridge, url, mode string) {
	// Every window here belongs to this thread for its whole lifetime.
	runtime.LockOSThread()

	if mode != "browser" {
		if sh, err := newWindowShell(a, br, url); err == nil {
			logx.Infof("[gui] native WebView2 window ready")
			if mode != "window" {
				go superviseEmbeddedView(sh, br)
			}
			sh.run()
			return
		} else {
			logx.Warnf("[gui] WebView2 window unavailable (%v); using the browser shell", err)
		}
	}
	newBrowserShell(a, br, url).run()
}

// shell owns the host window, the browser control and the tray icon.
type shell struct {
	a            *app.App
	br           *webbridge.Bridge
	wv           webview2.WebView // nil in browser mode
	host         *walk.MainWindow // message owner for the tray icon
	hwnd         uintptr
	trayOK       bool
	url          string
	quitting     atomic.Bool // first quit request starts the teardown (CAS)
	teardownDone atomic.Bool // set once the teardown finished, so WM_CLOSE may destroy the window
	prevWndProc  uintptr     // original window proc (CallWindowProc target) after subclassing
}

func (s *shell) run() {
	if s.wv != nil {
		s.wv.Run() // blocks until the control's window is destroyed
		return
	}
	s.host.Run()
}

// superviseEmbeddedView is the safety net for a silently broken embedded view
// (a runtime that starts but never renders, enterprise policy, …): if the page
// never reaches the UI service, a browser window is opened instead so the user
// is never left staring at a blank window.
func superviseEmbeddedView(sh *shell, br *webbridge.Bridge) {
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(400 * time.Millisecond)
		if br.Clients() > 0 {
			return
		}
	}
	if br.Clients() > 0 {
		return
	}
	logx.Warnf("[gui] the embedded view never attached to the UI service; opening the browser shell")
	sh.hideWindow()
	openBrowserShellWindow(sh.url)
}

// ---------------------------------------------------------------------------
// native window host (WebView2)
// ---------------------------------------------------------------------------

func newWindowShell(a *app.App, br *webbridge.Bridge, url string) (*shell, error) {
	// The control must never use the WinINET proxy: while the tunnel is up our
	// take-over points the system proxy at the core's listener, and a proxied
	// request to 127.0.0.1 would be pushed into the tunnel — leaving the window
	// blank. The UI is served from loopback only, so no proxy is ever needed.
	_ = os.Setenv("WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS",
		"--no-proxy-server --disable-gpu --disable-features=Translate,msEdgeTranslate")

	sh := &shell{a: a, br: br, url: url}
	winW, winH := windowSize()

	view := webview2.NewWithOptions(webview2.WebViewOptions{
		AutoFocus: true,
		DataPath:  filepath.Join(config.Dir(), "webview2"),
		WindowOptions: webview2.WindowOptions{
			Title:  appTitle + " — Fast · Secure · Global",
			Width:  uint(winW),
			Height: uint(winH),
			Center: true,
		},
	})
	if view == nil {
		return nil, errors.New("the WebView2 runtime refused to start")
	}
	sh.wv = view
	sh.hwnd = uintptr(view.Window())
	webviewHost = sh
	hookCloseWindow(sh)

	dpi := systemDPI()
	logx.Infof("[gui] window %dx%d px (dpi %d)", winW, winH, dpi)

	view.SetSize(minW*dpi/96, minH*dpi/96, webview2.HintMin)
	view.SetSize(winW, winH, webview2.HintNone)
	view.Navigate(url)

	sh.attachTrayHost()
	// Bring the window to the front: it was created while the launcher may
	// still own the foreground.
	_, _, _ = procSetForeground.Call(sh.hwnd)
	return sh, nil
}

// attachTrayHost creates the hidden window that owns the notify icon. The
// browser control's message loop dispatches its messages, so a second event
// loop is never needed.
func (s *shell) attachTrayHost() {
	var hw *walk.MainWindow
	if err := (MainWindow{
		AssignTo: &hw,
		Title:    appTitle,
		Name:     appTitle + " host",
		Visible:  false,
		MinSize:  Size{Width: 1, Height: 1},
		Size:     Size{Width: 1, Height: 1},
	}.Create()); err != nil {
		logx.Warnf("[gui] tray host window failed: %v", err)
		return
	}
	s.host = hw
	if err := attachTray(s); err != nil {
		logx.Warnf("[gui] tray unavailable: %v", err)
		return
	}
	s.trayOK = true
}

func (s *shell) hideWindow() { _, _, _ = procShowWindow.Call(s.hwnd, swHide) }
func (s *shell) showWindow() {
	_, _, _ = procShowWindow.Call(s.hwnd, swShow)
	_, _, _ = procSetForeground.Call(s.hwnd)
}

// exitFromUI tears the app down and closes the window.
func (s *shell) exitFromUI() { s.beginQuit() }

// beginQuit is the single exit path. The teardown (core stop, proxy restore,
// kill-switch / app-rules cleanup) can take seconds, so the first quit request
// — window X, tray menu or the browser-shell watchdog — puts a visible
// "quitting…" notice up front instead of letting the window vanish and the
// process linger invisibly (that is what "the terminal window never closes"
// usually is: the app is still alive, tearing down). Exactly one teardown
// runs; the window is destroyed once it is done.
func (s *shell) beginQuit() {
	if !s.quitting.CompareAndSwap(false, true) {
		return // a teardown is already running
	}
	log.Println("[gui] exiting, please wait…")
	logx.Infof("[gui] exiting, please wait…")
	s.showQuittingOverlay()
	go func() {
		start := time.Now()
		s.a.Close()
		logx.Infof("[gui] teardown finished in %s", time.Since(start))
		log.Printf("[gui] exit complete in %s", time.Since(start))
		s.teardownDone.Store(true)
		if s.wv != nil {
			s.wv.Destroy() // re-posts WM_CLOSE; wndProcHook lets it through now
			return
		}
		s.host.Synchronize(func() { _ = s.host.Close() })
	}()
}

// showQuittingOverlay puts the "please wait" notice on whichever surface is on
// screen: the embedded page for the native window (direct JS call), and an SSE
// push for the browser-fallback window (the only surface we can draw on there).
func (s *shell) showQuittingOverlay() {
	if s.wv != nil {
		s.wv.Eval("window.showQuitting && window.showQuitting()")
	}
	s.br.NotifyQuitting()
}

// wndProcHook is the subclassed window proc of the webview host window. The
// go-webview2 default destroys the window on WM_CLOSE immediately, leaving the
// teardown to run after the UI is already gone. Here the first WM_CLOSE starts
// the quitting sequence and is swallowed; a WM_CLOSE arriving after the
// teardown finished (s.wv.Destroy() re-posts it) falls through to the
// library's handler, which closes the window and ends the message loop.
func wndProcHook(hwnd, msg, wparam, lparam uintptr) uintptr {
	if msg == wmClose {
		if sh := webviewHost; sh != nil {
			if !sh.quitting.Load() {
				sh.beginQuit()
				return 0
			}
			if !sh.teardownDone.Load() {
				return 0 // still tearing down: keep the overlay up
			}
		}
	}
	if sh := webviewHost; sh != nil && sh.prevWndProc != 0 {
		r, _, _ := procCallWindowProc.Call(sh.prevWndProc, hwnd, msg, wparam, lparam)
		return r
	}
	r, _, _ := procDefWindowProc.Call(hwnd, msg, wparam, lparam)
	return r
}

// hookCloseWindow subclasses the webview host window so WM_CLOSE can be
// deferred while the app tears down. Failure is non-fatal: quit then behaves
// as before, closing the window first and tearing down in the background.
func hookCloseWindow(s *shell) {
	if prev, _, _ := procGetWindowLongPtr.Call(s.hwnd, uintptr(gwlpWndProc)); prev == 0 {
		logx.Warnf("[gui] cannot hook window close (GetWindowLongPtrW)")
		return
	} else {
		s.prevWndProc = prev
	}
	if r, _, _ := procSetWindowLongPtr.Call(s.hwnd, uintptr(gwlpWndProc), wndProcCallback); r == 0 {
		logx.Warnf("[gui] cannot hook window close (SetWindowLongPtrW)")
		s.prevWndProc = 0
	}
}

// ---------------------------------------------------------------------------
// tiny user32 helpers
// ---------------------------------------------------------------------------

var (
	user32               = windows.NewLazySystemDLL("user32.dll")
	procShowWindow       = user32.NewProc("ShowWindow")
	procSetForeground    = user32.NewProc("SetForegroundWindow")
	procIsWindowVisible  = user32.NewProc("IsWindowVisible")
	procGetDpiForSystem  = user32.NewProc("GetDpiForSystem")
	procGetSystemMetrics = user32.NewProc("GetSystemMetrics")
	procSetWindowLongPtr = user32.NewProc("SetWindowLongPtrW")
	procGetWindowLongPtr = user32.NewProc("GetWindowLongPtrW")
	procCallWindowProc   = user32.NewProc("CallWindowProcW")
	procDefWindowProc    = user32.NewProc("DefWindowProcW")
)

// wndProcCallback is the subclassed window proc of the single webview host
// window (kept alive for the lifetime of the process).
var wndProcCallback = windows.NewCallback(wndProcHook)

// webviewHost is the live webview shell. The window proc is installed before
// the message loop starts, so it is always set when wndProcHook runs.
var webviewHost *shell

// gwlpWndProc is GWLP_WNDPROC: -4 on 32-bit, -6 on 64-bit Windows.
var gwlpWndProc int

func init() {
	gwlpWndProc = -4 // GWL_WNDPROC (32-bit index space)
	if runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64" {
		gwlpWndProc = -6 // GWLP_WNDPROC (64-bit index space)
	}
}

// GetSystemMetrics indices.
const (
	smCXScreen = 0
	smCYSCREEN = 1
)

// isWindowVisible reports whether the host window is currently shown.
func isWindowVisible(hwnd uintptr) bool {
	r, _, _ := procIsWindowVisible.Call(hwnd)
	return r != 0
}

const (
	swHide  = 0
	swShow  = 5
	wmClose = 0x0010
)

// ---------------------------------------------------------------------------
// browser fallback host
// ---------------------------------------------------------------------------

// newBrowserShell is the fallback host: a hidden window that pumps messages for
// the tray plus a chromium app window showing the same URL.
func newBrowserShell(a *app.App, br *webbridge.Bridge, url string) *shell {
	s := &shell{a: a, br: br, url: url}

	var hw *walk.MainWindow
	if err := (MainWindow{
		AssignTo: &hw,
		Title:    appTitle,
		Name:     appTitle + " host",
		Visible:  false,
		MinSize:  Size{Width: 1, Height: 1},
		Size:     Size{Width: 1, Height: 1},
	}.Create()); err != nil {
		logx.Errorf("[gui] host window failed: %v", err)
		<-quitCh // nothing can pump messages: wait for the quit signal
		return s
	}
	s.host = hw
	if err := attachTray(s); err != nil {
		logx.Warnf("[gui] tray unavailable: %v", err)
	} else {
		s.trayOK = true
	}

	launched, shellExited := openBrowserApp(url)
	if !launched {
		openDefaultBrowser(url)
	}

	// The browser window can close without telling us: leave once the UI has
	// been gone for a while.
	go func() {
		seen := time.Now()
		t := time.NewTicker(4 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-quitCh:
				return
			case <-shellExited:
				logx.Infof("[gui] browser shell closed")
				s.exitFromUI()
				return
			case <-t.C:
				if br.Clients() > 0 {
					seen = time.Now()
					continue
				}
				// Chromium keeps background processes alive after the app window
				// closes, so shellExited often never fires — this watchdog is the
				// real exit path. Idle budget: 8s normally (a page reload re-
				// attaches the SSE stream within a second or two), 3s while
				// disconnected/failed — with no tunnel to keep alive a closed
				// window should end the process promptly ("why is the console
				// still open?").
				idle := time.Since(seen)
				limit := 8 * time.Second
				switch s.a.VPN.State().Status {
				case vpn.StatusDisconnected, vpn.StatusFailed:
					limit = 3 * time.Second
				}
				if idle < limit {
					continue
				}
				logx.Infof("[gui] UI detached; exiting")
				s.exitFromUI()
				return
			}
		}
	}()
	return s
}

// never is a channel that never fires (used to retire the one-shot exit signal).
var never = make(chan struct{})

// chromiumApp returns installed chromium browsers, in preference order.
func chromiumApp() []string {
	var out []string
	pf := os.Getenv("ProgramFiles")
	pf86 := os.Getenv("ProgramFiles(x86)")
	local := os.Getenv("LOCALAPPDATA")
	for _, p := range []string{
		filepath.Join(pf86, "Microsoft", "Edge", "Application", "msedge.exe"),
		filepath.Join(pf, "Microsoft", "Edge", "Application", "msedge.exe"),
		filepath.Join(local, "Google", "Chrome", "Application", "chrome.exe"),
		filepath.Join(pf, "Google", "Chrome", "Application", "chrome.exe"),
		filepath.Join(pf86, "Google", "Chrome", "Application", "chrome.exe"),
	} {
		if p != "" {
			if _, err := os.Stat(p); err == nil {
				out = append(out, p)
			}
		}
	}
	return out
}

// openBrowserApp launches a chrome-less app window. The returned channel fires
// once that window has closed.
func openBrowserApp(url string) (bool, <-chan struct{}) {
	winW, winH := windowSize()
	for _, exe := range chromiumApp() {
		profile := filepath.Join(config.Dir(), "shell-profile")
		_ = os.MkdirAll(profile, 0o755)
		cmd := exec.Command(exe,
			"--app="+url,
			"--user-data-dir="+profile,
			fmt.Sprintf("--window-size=%d,%d", winW, winH),
			// Same reason as the embedded view: never send loopback through
			// the tunnel's system proxy.
			"--no-proxy-server",
			"--no-first-run",
			"--no-default-browser-check",
			"--disable-features=Translate",
		)
		cmd.Dir = filepath.Dir(exe)
		if err := cmd.Start(); err == nil {
			exited := make(chan struct{})
			go func() {
				_ = cmd.Wait()
				close(exited)
			}()
			return true, exited
		}
	}
	return false, never
}

func openDefaultBrowser(url string) {
	_ = exec.Command("cmd", "/c", "start", "", url).Start()
}

// openBrowserShellWindow shows the same UI in a chrome-less chromium window.
func openBrowserShellWindow(url string) {
	if launched, _ := openBrowserApp(url); !launched {
		openDefaultBrowser(url)
	}
}
