// Command awgprobe measures amneziawg-go handshake success against WARP
// endpoints under different AmneziaWG obfuscation configs. It exists to
// answer empirically "do i2..i5 / extra junk help or hurt against
// Cloudflare WARP?" — the one-sided subset theory says packet-outside
// decoys are transparent to the peer, but only a probe can show it.
//
// Usage (Windows, from the repo root after `go build -tags wgtun` or on any
// OS with a UDP path to the endpoints):
//
//	awgprobe.exe                                    # baseline: junk off
//	awgprobe.exe -i1 "<b 0d0a0d0a><t><rc 20-40>"   # single fake first packet
//	awgprobe.exe -jc 6 -jmin 48 -jmax 190          # decoys only
//	awgprobe.exe -i1 ... -i5 ... -jc 12 -jmin 96 -jmax 420   # gfw-style
//
// Identity: reads wg_private_key / wg_peer_public_key from the aether.toml
// beside the exe (or -identity FILE); override with -priv / -pub (base64).
// Template syntax is amneziawg-go's (<b hex>, <t>, <c>, <r n>, <rc n>,
// <rd n>). Handshake is driven by persistent_keepalive_interval=1 so the
// probe never depends on tunnel traffic.
package main

import (
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
)

// ---------------------------------------------------------------------------
// tun stub: blocking reads only (an immediate read error closes the device)
// ---------------------------------------------------------------------------

type stubTun struct{}

func (d *stubTun) BatchSize() int                  { return 1 }
func (d *stubTun) File() *os.File                  { return nil }
func (d *stubTun) Read([][]byte, []int, int) (int, error) { select {} }
func (d *stubTun) Write([][]byte, int) (int, error)       { return 0, nil }
func (d *stubTun) MTU() (int, error)                      { return 1420, nil }
func (d *stubTun) Name() (string, error)                  { return "awgprobe", nil }
func (d *stubTun) Events() <-chan tun.Event               { return make(chan tun.Event) }
func (d *stubTun) Close() error                           { return nil }

func silent() *device.Logger {
	return &device.Logger{Verbosef: func(string, ...any) {}, Errorf: func(string, ...any) {}}
}

// ---------------------------------------------------------------------------
// identity from aether.toml (key = "value" lines)
// ---------------------------------------------------------------------------

var tomlCandidates = []string{
	"aether.toml",                                    // cwd
	filepath.Join(os.Getenv("LOCALAPPDATA"), "AetherGUI", "aether.toml"),
}

func identityFromToml(path string) (privB64, pubB64 string, err error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", "", err
	}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if i := strings.IndexByte(line, '='); i > 0 {
			k := strings.TrimSpace(line[:i])
			v := strings.Trim(strings.TrimSpace(line[i+1:]), `"'`)
			switch k {
			case "wg_private_key":
				privB64 = v
			case "wg_peer_public_key":
				pubB64 = v
			}
		}
	}
	if privB64 == "" || pubB64 == "" {
		return "", "", fmt.Errorf("%s: missing wg_private_key / wg_peer_public_key", path)
	}
	return privB64, pubB64, nil
}

func b64ToHex(s string) string {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic("bad base64 identity: " + err.Error())
	}
	return hex.EncodeToString(raw)
}

// ---------------------------------------------------------------------------

func hasHandshake(s string) bool {
	for _, line := range strings.Split(s, "\n") {
		if v, ok := strings.CutPrefix(line, "last_handshake_time_sec="); ok && strings.TrimSpace(v) != "0" {
			return true
		}
	}
	return false
}

type config struct {
	privHex, pubHex string
	endpoint        string
	timeout         time.Duration
	i1, i2, i3, i4, i5 string
	jc, jmin, jmax  int
	verbose         bool
}

func (c config) describe() string {
	parts := []string{}
	if c.jc > 0 {
		parts = append(parts, fmt.Sprintf("jc=%d jmin=%d jmax=%d", c.jc, c.jmin, c.jmax))
	}
	for _, p := range []struct{ k, v string }{{"i1", c.i1}, {"i2", c.i2}, {"i3", c.i3}, {"i4", c.i4}, {"i5", c.i5}} {
		if p.v != "" {
			parts = append(parts, fmt.Sprintf("%s=%s", p.k, p.v))
		}
	}
	if len(parts) == 0 {
		return "plain (no obfuscation)"
	}
	return strings.Join(parts, " ")
}

func (c config) uapi() string {
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\nlisten_port=0\n", c.privHex)
	// Device-level obfuscation keys MUST precede the peer block
	// (amneziawg-go dispatches to handlePeerLine once public_key is seen).
	for _, p := range []struct{ k, v string }{{"i1", c.i1}, {"i2", c.i2}, {"i3", c.i3}, {"i4", c.i4}, {"i5", c.i5}} {
		if p.v != "" {
			fmt.Fprintf(&b, "%s=%s\n", p.k, p.v)
		}
	}
	if c.jc > 0 {
		fmt.Fprintf(&b, "jc=%d\njmin=%d\njmax=%d\n", c.jc, c.jmin, c.jmax)
	}
	fmt.Fprintf(&b, "public_key=%s\nendpoint=%s\nallowed_ip=0.0.0.0/0\nallowed_ip=::/0\npersistent_keepalive_interval=1\n", c.pubHex, c.endpoint)
	return b.String()
}

// probeOne returns true when a handshake completes within the timeout.
func probeOne(c config) bool {
	dev := device.NewDevice(&stubTun{}, conn.NewDefaultBind(), silent())
	// No Close(): the blocking stub tun read keeps Close from finishing; the
	// process exits right after the run, so leaked goroutines are fine.
	if err := dev.IpcSet(c.uapi()); err != nil {
		fmt.Fprintf(os.Stderr, "  [%s] IpcSet: %v\n", c.endpoint, err)
		return false
	}
	if err := dev.Up(); err != nil {
		fmt.Fprintf(os.Stderr, "  [%s] Up: %v\n", c.endpoint, err)
		return false
	}
	dl := time.Now().Add(c.timeout)
	for time.Now().Before(dl) {
		if s, err := dev.IpcGet(); err == nil && hasHandshake(s) {
			return true
		}
		time.Sleep(200 * time.Millisecond)
	}
	return false
}

func main() {
	var (
		identity = flag.String("identity", "", "aether.toml path (default: beside exe / %%LOCALAPPDATA%%/AetherGUI)")
		priv     = flag.String("priv", "", "private key, base64 (overrides -identity)")
		pub      = flag.String("pub", "", "peer public key, base64")
		endpoints = flag.String("endpoints", "162.159.192.1:4233,8.39.204.254:3581,162.159.193.10:1701,8.47.69.210:7281,8.39.204.236:946", "comma-separated host:port list")
		timeout  = flag.Duration("timeout", 8*time.Second, "per-attempt handshake budget")
		repeat   = flag.Int("repeat", 1, "attempts per endpoint")
		verbose  = flag.Bool("v", false, "print all lines (device logs)")
	)
	i1 := flag.String("i1", "", "fake-first-packet template")
	i2 := flag.String("i2", "", "")
	i3 := flag.String("i3", "", "")
	i4 := flag.String("i4", "", "")
	i5 := flag.String("i5", "", "")
	jc := flag.Int("jc", 0, "junk packet count (0 = off)")
	jmin := flag.Int("jmin", 48, "junk min size")
	jmax := flag.Int("jmax", 190, "junk max size")
	flag.Parse()

	privB64, pubB64 := *priv, *pub
	if privB64 == "" || pubB64 == "" {
		path := *identity
		if path == "" {
			for _, cand := range tomlCandidates {
				if _, err := os.Stat(cand); err == nil {
					path = cand
					break
				}
			}
		}
		var err error
		privB64, pubB64, err = identityFromToml(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "awgprobe: no identity: %v (use -priv/-pub or -identity)\n", err)
			os.Exit(2)
		}
	}

	cfg := config{
		privHex: b64ToHex(privB64), pubHex: b64ToHex(pubB64),
		timeout: *timeout,
		i1: *i1, i2: *i2, i3: *i3, i4: *i4, i5: *i5,
		jc: *jc, jmin: *jmin, jmax: *jmax,
		verbose: *verbose,
	}

	fmt.Printf("identity: priv %s… pub %s…\n", privB64[:8], pubB64[:8])
	fmt.Printf("config  : %s\n", cfg.describe())
	fmt.Printf("timeout : %v per attempt × %d\n\n", *timeout, *repeat)

	eps := strings.Split(*endpoints, ",")
	totalOK, totalTry := 0, 0
	for _, ep := range eps {
		ep = strings.TrimSpace(ep)
		cfg.endpoint = ep
		ok := 0
		for range *repeat {
			if probeOne(cfg) {
				ok++
			}
		}
		totalOK += ok
		totalTry += *repeat
		fmt.Printf("%-22s %d/%d handshakes\n", ep, ok, *repeat)
	}
	fmt.Printf("\nTOTAL %d/%d (%.0f%%)\n", totalOK, totalTry, 100*float64(totalOK)/float64(totalTry))
}