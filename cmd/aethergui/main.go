// aethergui is the Windows VPN client on top of the Aether Core.
//
// Architecture (see ARCHITECTURE.md):
//
//	aethergui.exe (Go shell: native window + tray + local UI service)
//	    └── internal/webbridge  (loopback HTTP + SSE, the UI's only channel)
//	            └── App         (Core Controller, VPN, nodes, proxy, …)
//	                    └── Aether Core (separate process/dll: WARP / WireGuard
//	                        / MASQUE / Gool / MASQUE-in-MASQUE, gateway discovery)
package main

import (
	"flag"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"syscall"

	"github.com/aethergui/aethergui/internal/app"
	"github.com/aethergui/aethergui/internal/logx"
	"github.com/aethergui/aethergui/internal/webbridge"
)

// Version is reported on the about page.
const Version = "1.2.1"


// browserUnsafePorts mirrors Chromium's restricted-ports list
// (net/base/port_util.cc → ERR_UNSAFE_PORT). The UI URL is opened by
// Edge/Chrome in browser-fallback mode, so the loopback port must never land
// on one of these. Real-world trigger: machines whose TCP dynamic range is
// overridden (e.g. 1024-15000) put 6665-6669/6697/10080 inside the range the
// OS assigns to ":0" listeners — a fallback browser then refuses the page.
var browserUnsafePorts = map[int]bool{
	1: true, 7: true, 9: true, 11: true, 13: true, 15: true, 17: true, 19: true,
	20: true, 21: true, 22: true, 23: true, 25: true, 37: true, 42: true, 43: true,
	53: true, 69: true, 77: true, 79: true, 87: true, 95: true, 101: true, 102: true,
	103: true, 104: true, 109: true, 110: true, 111: true, 113: true, 115: true, 117: true,
	119: true, 123: true, 135: true, 137: true, 139: true, 143: true, 161: true, 179: true,
	389: true, 427: true, 465: true, 512: true, 513: true, 514: true, 515: true, 526: true,
	530: true, 531: true, 532: true, 540: true, 548: true, 554: true, 556: true, 563: true,
	587: true, 601: true, 636: true, 989: true, 990: true, 993: true, 995: true, 1719: true,
	1720: true, 1723: true, 2049: true, 3659: true, 4045: true, 5060: true, 5061: true,
	6000: true, 6566: true, 6665: true, 6666: true, 6667: true, 6668: true, 6669: true,
	6697: true, 10080: true,
}

// listenLoopback binds the UI service on 127.0.0.1. With port 0 the OS picks a
// free port; if it lands on a browser-restricted port, the listener is closed
// and retried. An explicitly requested restricted port is an error so the user
// hears about it instead of staring at ERR_UNSAFE_PORT in the fallback browser.
func listenLoopback(port int) (net.Listener, error) {
	if port != 0 && browserUnsafePorts[port] {
		return nil, fmt.Errorf("port %d is browser-restricted (ERR_UNSAFE_PORT); pick a different -port", port)
	}
	for range 64 {
		ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprint(port)))
		if err != nil {
			return nil, err
		}
		if p := ln.Addr().(*net.TCPAddr).Port; !browserUnsafePorts[p] {
			return ln, nil
		}
		_ = ln.Close() // OS handed out a restricted port; ask again
	}
	return nil, fmt.Errorf("retried 64 loopback ports, all browser-restricted (very unlikely)")
}
// guiFS holds the embedded frontend for this build.
var guiFS fs.FS

// crashLog persists a panic for post-mortem: the release build has no console,
// so without this a panic looks like a silent flash-exit.
func crashLog(v any) {
	dir := os.Getenv("LOCALAPPDATA")
	if dir == "" {
		dir = "."
	}
	dir = filepath.Join(dir, "AetherGUI")
	_ = os.MkdirAll(dir, 0o755)
	msg := "panic: " + fmt.Sprint(v) + "\n\n" + string(debug.Stack()) + "\n"
	_ = os.WriteFile(filepath.Join(dir, "crash.log"), []byte(msg), 0o644)
}

// quit is closed exactly once when something asks the process to shut down.
var (
	quitOnce sync.Once
	quitCh   = make(chan struct{})
)

func requestQuit() { quitOnce.Do(func() { close(quitCh) }) }

func main() {
	defer func() {
		if v := recover(); v != nil {
			crashLog(v)
			os.Exit(1)
		}
	}()

	var (
		connectFlag = flag.Bool("connect", false, "connect right after launch (used by autostart)")
		uiMode      = flag.String("ui", "auto", "UI host: auto (WebView2 window), window, browser, none (service only)")
		portFlag    = flag.Int("port", 0, "loopback port for the UI service (0 = pick a free one)")
		printURL    = flag.Bool("print-url", false, "print the UI URL to stdout")
		stackedFlag = flag.Bool("stacked", false, "run warp-in-warp (stacked) mode: outer from aether.toml, inner from -account")
		accountFlag = flag.String("account", "", "path to the inner WARP account JSON (required with -stacked)")
	)
	flag.Parse()

	// Route SIGINT/SIGTERM into the normal quit path instead of the default hard
	// kill. This matters most in headless mode: a Ctrl+C must still run the
	// deferred application.Close(), which tears down the native tunnel (revert
	// routes/DNS/metric, close the wintun adapter) rather than leaking that state
	// and black-holing the network until a reboot.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		s := <-sigCh
		logx.Infof("[gui] signal %s received, shutting down", s)
		requestQuit()
	}()

	// Stacked (warp-in-warp) mode: build the outer + inner configs and run the
	// double tunnel directly, bypassing the app/Core state machine. Only present
	// in wgtun builds (runStacked is stubbed out otherwise). The signal handler
	// above is already armed, so Ctrl+C tears the stack down cleanly via quitCh.
	if *stackedFlag {
		runStacked(*accountFlag)
		return
	}

	guiFS = uiAssets()

	application, err := app.New()
	if err != nil {
		crashLog(err)
		os.Exit(1)
	}
	defer application.Close()

	bridge := webbridge.New(webbridge.Config{App: application, Assets: guiFS, Version: Version})
	bridge.SetOnQuit(requestQuit)
	// When wintun needs a higher token, the native connect relaunches this
	// instance as administrator (UAC) and the elevated child re-connects (the
	// relaunch appends -connect). The parent must exit: it owns no tunnel yet
	// (Start failed with access-denied, so there is no adapter/routes/DNS to
	// tear down), and staying alive would double the windows/tray and let two
	// instances race on the same state file. os.Exit skips application.Close's
	// deferred cleanup, which is exactly what we want here — there is nothing
	// to clean on this side, and a partial Close from a connect goroutine could
	// interfere with the child's takeover.
	application.OnElevatedRelaunch(func() {
		logx.Infof("[gui] elevated child launched; exiting parent instance")
		os.Exit(0)
	})

	ln, err := listenLoopback(*portFlag)
	if err != nil {
		fmt.Fprintln(os.Stderr, "xiaohe:", err)
		crashLog(err)
		os.Exit(1)
	}
	go func() { _ = http.Serve(ln, bridge.Handler()) }()

	url := bridge.URL(ln.Addr().String())
	logx.Infof("[gui] UI service listening on %s", ln.Addr())
	if *printURL {
		fmt.Println(url)
	}

	if *connectFlag || application.Settings.AutoConnect {
		go func() {
			defer func() { _ = recover() }()
			if err := application.Connect(); err != nil {
				logx.Errorf("[main] auto connect failed: %v", err)
			}
		}()
	}

	switch strings.ToLower(*uiMode) {
	case "none":
		// Service-only (headless): useful for remote debugging of the UI.
		logx.Infof("[gui] headless mode – %s", url)
		<-quitCh
	default:
		runUI(application, bridge, url, strings.ToLower(*uiMode))
	}

	logx.Infof("[gui] shutting down")
}
