//go:build windows

package webbridge

import (
	"testing"

	"github.com/aethergui/aethergui/internal/config"
)

// TestProtocolsHasAWGInsteadOfH2 pins the switcher change: MASQUE/H2 (measured
// failing with core 2.1.0 on this network) is gone and AWG took its slot.
func TestProtocolsHasAWGInsteadOfH2(t *testing.T) {
	var awg *Protocol
	for i := range Protocols {
		switch Protocols[i].Key {
		case "h2":
			t.Fatal("the h2 (MasqueH2) entry must be gone from the switcher")
		case "awg":
			awg = &Protocols[i]
		}
	}
	if awg == nil {
		t.Fatal("no awg entry in the switcher")
	}
	if !awg.Native || !awg.AWG {
		t.Fatalf("awg entry = %+v, want Native+AWG (it only exists on the native backend)", *awg)
	}
	if awg.Mode != string(config.ModeWireGuard) {
		t.Fatalf("awg mode = %s, want %s (AWG is WireGuard + obfuscation)", awg.Mode, config.ModeWireGuard)
	}
	if awg.Note == "" {
		t.Fatal("awg entry must carry an honest note (only junk is implemented, I1 is not)")
	}
}

// TestApplyProtocolAWG proves the switch actually reaches the backend: AWG has
// to turn the native backend on and the junk decoys with it, and switching back
// has to return to the plain WireGuard baseline — otherwise "WireGuard" would
// silently stay obfuscated and every junk A/B would be meaningless.
func TestApplyProtocolAWG(t *testing.T) {
	awg, ok := ProtocolByKey("awg")
	if !ok {
		t.Fatal("ProtocolByKey(awg) not found")
	}
	wg, ok := ProtocolByKey("wg")
	if !ok {
		t.Fatal("ProtocolByKey(wg) not found")
	}

	s := applyProtocol(config.Defaults(), awg)
	if !s.NativeWireGuard {
		t.Fatal("AWG must enable the native backend")
	}
	if !s.AWGJunk {
		t.Fatal("AWG must enable the junk decoys")
	}
	if s.JunkCount != config.DefaultJunkCount || s.JunkMinSize != config.DefaultJunkMinSize || s.JunkMaxSize != config.DefaultJunkMaxSize {
		t.Fatalf("junk = %d/%d/%d, want the defaults %d/%d/%d",
			s.JunkCount, s.JunkMinSize, s.JunkMaxSize,
			config.DefaultJunkCount, config.DefaultJunkMinSize, config.DefaultJunkMaxSize)
	}
	if got := ProtocolKey(s); got != "awg" {
		t.Fatalf("ProtocolKey after AWG = %s, want awg", got)
	}

	back := applyProtocol(s, wg)
	if back.AWGJunk {
		t.Fatal("switching back to WireGuard must turn the junk off (baseline)")
	}
	if got := ProtocolKey(back); got != "wg" {
		t.Fatalf("ProtocolKey after WireGuard = %s, want wg", got)
	}
}

// TestApplyProtocolClearsNative pins the sticky-native bug: switching from AWG
// (which turns the native backend on) to a core-driven transport (MASQUE) must
// turn the native backend back off. Before the fix, NativeWireGuard stayed true
// and the client kept trying the native wintun path (elevation required) no
// matter what the user picked next — a non-admin user saw "Access is denied"
// instead of the MASQUE tunnel they asked for.
func TestApplyProtocolClearsNative(t *testing.T) {
	awg, ok := ProtocolByKey("awg")
	if !ok {
		t.Fatal("ProtocolByKey(awg) not found")
	}
	h3, ok := ProtocolByKey("h3")
	if !ok {
		t.Fatal("ProtocolByKey(h3) not found")
	}

	s := applyProtocol(config.Defaults(), awg)
	if !s.NativeWireGuard {
		t.Fatal("precondition: AWG must enable the native backend")
	}

	back := applyProtocol(s, h3)
	if back.NativeWireGuard {
		t.Fatal("switching from AWG to MasqueH3 must clear the native backend (it is not sticky)")
	}
	if back.AWGJunk {
		t.Fatal("switching to MasqueH3 must clear the junk decoys")
	}
}
