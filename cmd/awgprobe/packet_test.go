package main

import (
	"net/netip"
	"testing"
)

func TestProbePacketChecksum(t *testing.T) {
	src := netip.MustParseAddr("172.16.0.2")
	dst := netip.MustParseAddr("1.1.1.1")
	p := buildProbePacket(src, dst, 53)

	if len(p) != 20+8+32 {
		t.Fatalf("unexpected packet length %d (want 60)", len(p))
	}
	// A valid IPv4 header checksum makes the sum over the header equal 0xffff.
	var sum uint32
	for i := 0; i+1 < 20; i += 2 {
		sum += uint32(p[i])<<8 | uint32(p[i+1])
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	if sum != 0xffff {
		t.Fatalf("IP header checksum invalid: sum=%#x", sum)
	}
	if p[9] != 17 || p[12] != src.As4()[0] {
		t.Fatalf("packet fields wrong: proto=%d src0=%d", p[9], p[12])
	}
	if sport := uint16(p[20])<<8 | uint16(p[21]); sport != 1234 {
		t.Fatalf("udp sport=%d (want 1234)", sport)
	}
	if dport := uint16(p[22])<<8 | uint16(p[23]); dport != 53 {
		t.Fatalf("udp dport=%d (want 53)", dport)
	}
}