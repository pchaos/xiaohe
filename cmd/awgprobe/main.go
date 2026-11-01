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
// Template syntax is amneziawg-go's (<b hex>, <t>, <r n>, <rc n>, <rd n> —
// no <c>, no min-max ranges). Handshake is driven by
// persistent_keepalive_interval=1 so the probe never depends on tunnel
// traffic. -i1profile quic builds Xiaohe's i1gen QUIC fake-first-packet.
package main

import (
	crand "crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
)

// stubTun is a no-traffic tun.Device that can optionally feed crafted packets
// INTO the tunnel after a handshake and count what comes back out. Blocking
// reads only: an immediate read error would close the device.
type stubTun struct {
	mu   sync.Mutex
	feed [][]byte
	rx   atomic.Int64
}

func (d *stubTun) feedPkt(p []byte) {
	d.mu.Lock()
	d.feed = append(d.feed, p)
	d.mu.Unlock()
}

func (d *stubTun) feedLen() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.feed)
}

func (d *stubTun) BatchSize() int { return 1 }
func (d *stubTun) File() *os.File { return nil }
func (d *stubTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	d.mu.Lock()
	if len(d.feed) > 0 {
		pkt := d.feed[0]
		d.feed = d.feed[1:]
		d.mu.Unlock()
		n := copy(bufs[0][offset:], pkt)
		sizes[0] = n
		return 1, nil
	}
	d.mu.Unlock()
	select {}
}
func (d *stubTun) Write(bufs [][]byte, offset int) (int, error) {
	var n int64
	for _, b := range bufs {
		if len(b) > offset {
			n += int64(len(b) - offset)
		}
	}
	d.rx.Add(n)
	return len(bufs), nil
}
func (d *stubTun) MTU() (int, error)        { return 1420, nil }
func (d *stubTun) Name() (string, error)    { return "awgprobe", nil }
func (d *stubTun) Events() <-chan tun.Event { return make(chan tun.Event) }
func (d *stubTun) Close() error             { return nil }

func silent() *device.Logger {
	return &device.Logger{Verbosef: func(string, ...any) {}, Errorf: func(string, ...any) {}}
}

// ---------------------------------------------------------------------------
// identity from aether.toml (key = "value" lines)
// ---------------------------------------------------------------------------

var tomlCandidates = []string{
	"aether.toml", // cwd
	filepath.Join(os.Getenv("LOCALAPPDATA"), "AetherGUI", "aether.toml"),
}

func identityFromToml(path string) (privB64, pubB64, ipv4 string, err error) {
	raw, errN := os.ReadFile(path)
	if errN != nil {
		return "", "", "", errN
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
			case "ipv4":
				ipv4 = v
			}
		}
	}
	if privB64 == "" || pubB64 == "" {
		return "", "", "", fmt.Errorf("%s: missing wg_private_key / wg_peer_public_key", path)
	}
	return privB64, pubB64, ipv4, nil
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
	privHex, pubHex    string
	ipv4               string
	endpoint           string
	timeout            time.Duration
	i1, i2, i3, i4, i5 string
	jc, jmin, jmax     int
	datatest           int // MB to push through the tunnel after handshake (0 = off)
	verbose            bool
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

type probeResult struct {
	ok   bool
	rx   int64
	mbps float64
}

// probeOne attempts a handshake; on success optionally runs the data-plane /
// throughput phase.
func probeOne(c config) probeResult {
	t := &stubTun{}
	dev := device.NewDevice(t, conn.NewDefaultBind(), silent())
	// No Close(): the blocking stub tun read keeps Close from finishing; the
	// process exits right after the run, so leaked goroutines are fine.
	if err := dev.IpcSet(c.uapi()); err != nil {
		fmt.Fprintf(os.Stderr, "  [%s] IpcSet: %v\n", c.endpoint, err)
		return probeResult{}
	}
	if err := dev.Up(); err != nil {
		fmt.Fprintf(os.Stderr, "  [%s] Up: %v\n", c.endpoint, err)
		return probeResult{}
	}
	hs := false
	dl := time.Now().Add(c.timeout)
	for time.Now().Before(dl) {
		if s, err := dev.IpcGet(); err == nil && hasHandshake(s) {
			hs = true
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if !hs {
		return probeResult{}
	}
	res := probeResult{ok: true}
	if c.datatest > 0 && c.ipv4 != "" {
		res.rx, res.mbps = dataPlane(c, t)
	}
	return res
}

// dataPlane pushes MB of UDP datagrams through the live tunnel towards the
// data target and counts what comes back out. Any inbound reply (DNS answer
// or ICMP) proves the tunnel carries data both ways; the send rate is the
// outbound throughput approximation (a real 20 MB download still needs
// Xiaohe's own speed sample over a real connection).
func dataPlane(c config, t *stubTun) (rx int64, mbps float64) {
	src, err := netip.ParseAddr(c.ipv4)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  [%s] bad tunnel ipv4 %q\n", c.endpoint, c.ipv4)
		return 0, 0
	}
	dst, _ := netip.ParseAddr("1.1.1.1")
	pkt := buildProbePacket(src, dst, 53)
	n := int64(c.datatest) * 1048576 / int64(len(pkt))
	start := time.Now()
	for range n {
		t.feedPkt(pkt)
	}
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		if t.feedLen() == 0 && time.Since(start) > 500*time.Millisecond {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	time.Sleep(2 * time.Second) // let queued packets drain and replies land
	el := time.Since(start)
	return t.rx.Load(), float64(n*int64(len(pkt))) * 8 / el.Seconds() / 1e6
}

// checksum is the classic IPv4 one's-complement header checksum.
func checksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// buildProbePacket makes an IPv4/UDP datagram sourced from the tunnel's own
// address, shaped as a DNS query to 1.1.1.1:53. The WARP endpoint forwards
// it out and the reply (DNS answer or ICMP) travels back through the tunnel.
func buildProbePacket(src, dst netip.Addr, dport uint16) []byte {
	payload := []byte{
		0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x0a, 'c', 'l', 'o', 'u', 'd', 'f', 'l', 'a', 'r', 'e',
		0x03, 'c', 'o', 'm', 0x00, 0x00, 0x01, 0x00, 0x01,
	}
	udpLen := 8 + len(payload)
	udp := make([]byte, udpLen)
	udp[0], udp[1] = 0x04, 0xd2 // sport 1234
	udp[2], udp[3] = byte(dport>>8), byte(dport)
	udp[4], udp[5] = byte(udpLen>>8), byte(udpLen)
	copy(udp[8:], payload) // UDP checksum 0 is valid on IPv4

	total := 20 + udpLen
	s4, d4 := src.As4(), dst.As4()
	hdr := make([]byte, 20)
	hdr[0] = 0x45
	hdr[2], hdr[3] = byte(total>>8), byte(total)
	hdr[8], hdr[9] = 64, 17 // ttl, udp
	copy(hdr[12:16], s4[:])
	copy(hdr[16:20], d4[:])
	sum := checksum(hdr)
	hdr[10], hdr[11] = byte(sum>>8), byte(sum)

	out := make([]byte, 0, total)
	out = append(out, hdr...)
	out = append(out, udp...)
	return out
}

// xiaoheQUIC builds Xiaohe's i1gen "quic" fake first packet: a structurally
// correct QUIC Initial long header (0xC0, version 1) with random DCID/SCID,
// a 256-byte CRYPTO-shaped payload and the default SNI (www.apple.com),
// wrapped in amneziawg-go's <b hex> template form. Bytes are random per call
// (crypto/rand), matching Xiaohe's nil-generator path.
func xiaoheQUIC() string {
	const sni = "www.apple.com"
	randBytes := func(n int) []byte {
		b := make([]byte, n)
		_, _ = crand.Read(b)
		return b
	}
	dcid := randBytes(8)
	scid := randBytes(8)
	payload := randBytes(256)
	body := make([]byte, 0, 3+len(payload)+len(sni))
	body = append(body, 0x06, 0x41, 0x00)
	body = append(body, payload...)
	body = append(body, sni...)
	pkt := make([]byte, 0, 5+1+len(dcid)+1+len(scid)+1+2+4+len(body))
	pkt = append(pkt, 0xC0, 0x00, 0x00, 0x00, 0x01)
	pkt = append(pkt, uint8(len(dcid)))
	pkt = append(pkt, dcid...)
	pkt = append(pkt, uint8(len(scid)))
	pkt = append(pkt, scid...)
	pkt = append(pkt, 0x00)
	total := len(body) + 4
	pkt = append(pkt, 0x40|uint8(total>>8), uint8(total))
	pkt = append(pkt, randBytes(4)...)
	pkt = append(pkt, body...)
	return "<b " + hex.EncodeToString(pkt) + ">"
}

func main() {
	var (
		identity  = flag.String("identity", "", "aether.toml path (default: beside exe / %%LOCALAPPDATA%%/AetherGUI)")
		priv      = flag.String("priv", "", "private key, base64 (overrides -identity)")
		pub       = flag.String("pub", "", "peer public key, base64")
		endpoints = flag.String("endpoints", "162.159.192.1:4233,8.39.204.254:3581,162.159.193.10:1701,8.47.69.210:7281,8.39.204.236:946", "comma-separated host:port list")
		timeout   = flag.Duration("timeout", 8*time.Second, "per-attempt handshake budget")
		repeat    = flag.Int("repeat", 1, "attempts per endpoint")
		verbose   = flag.Bool("v", false, "print all lines (device logs)")
		ipv4      = flag.String("ipv4", "", "tunnel IPv4 (data-plane source; default: read from aether.toml)")
	)
	i1 := flag.String("i1", "", "fake-first-packet template")
	i2 := flag.String("i2", "", "")
	i3 := flag.String("i3", "", "")
	i4 := flag.String("i4", "", "")
	i5 := flag.String("i5", "", "")
	jc := flag.Int("jc", 0, "junk packet count (0 = off)")
	jmin := flag.Int("jmin", 48, "junk min size")
	jmax := flag.Int("jmax", 190, "junk max size")
	i1profile := flag.String("i1profile", "", "build i1 from Xiaohe's i1gen shape (quic), instead of a -i1 template")
	datatest := flag.Int("datatest", 0, "after a handshake, push this many MB of UDP through the tunnel and count replies (0 = off)")
	flag.Parse()

	privB64, pubB64, tunnelIPv4 := *priv, *pub, *ipv4
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
		privB64, pubB64, tunnelIPv4, err = identityFromToml(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "awgprobe: no identity: %v (use -priv/-pub or -identity)\n", err)
			os.Exit(2)
		}
	}

	cfg := config{
		privHex: b64ToHex(privB64), pubHex: b64ToHex(pubB64),
		timeout: *timeout,
		i1:      *i1, i2: *i2, i3: *i3, i4: *i4, i5: *i5,
		jc: *jc, jmin: *jmin, jmax: *jmax,
		verbose: *verbose,
	}
	cfg.ipv4 = tunnelIPv4
	cfg.datatest = *datatest
	if *i1profile != "" {
		switch strings.ToLower(strings.TrimSpace(*i1profile)) {
		case "quic":
			cfg.i1 = xiaoheQUIC()
		default:
			fmt.Fprintf(os.Stderr, "awgprobe: unknown -i1profile %q (want: quic)\n", *i1profile)
			os.Exit(2)
		}
	}

	if *datatest > 0 && tunnelIPv4 == "" {
		fmt.Fprintln(os.Stderr, "awgprobe: -datatest needs the tunnel IPv4 (aether.toml `ipv4` or -ipv4)")
		os.Exit(2)
	}
	fmt.Printf("identity: priv %s… pub %s…\n", privB64[:8], pubB64[:8])
	fmt.Printf("config  : %s\n", cfg.describe())
	fmt.Printf("timeout : %v per attempt × %d\n\n", *timeout, *repeat)

	eps := strings.Split(*endpoints, ",")
	totalOK, totalTry := 0, 0
	for _, ep := range eps {
		ep = strings.TrimSpace(ep)
		cfg.endpoint = ep
		ok, dtOK, dtRx, dtSum, dtN := 0, 0, int64(0), 0.0, 0
		for range *repeat {
			r := probeOne(cfg)
			if r.ok {
				ok++
			}
			if r.rx > 0 {
				dtOK++
				dtRx += r.rx
				dtSum += r.mbps
				dtN++
			}
		}
		totalOK += ok
		totalTry += *repeat
		line := fmt.Sprintf("%-24s %d/%d handshakes", ep, ok, *repeat)
		if *datatest > 0 {
			avg := 0.0
			if dtN > 0 {
				avg = dtSum / float64(dtN)
			}
			line += fmt.Sprintf("  dataplane %d/%d (rx=%d B, avg≈%.1f Mbps)", dtOK, *repeat, dtRx, avg)
		}
		fmt.Println(line)
	}
	fmt.Printf("\nTOTAL %d/%d (%.0f%%)\n", totalOK, totalTry, 100*float64(totalOK)/float64(totalTry))
}
