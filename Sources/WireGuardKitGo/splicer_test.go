package main

import (
	"net/netip"
	"testing"

	"golang.zx2c4.com/wireguard/tun/netstack"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

func TestSplicedTun(t *testing.T) {
	a, aNet, _ := netstack.CreateNetTUN([]netip.Addr{aIp}, []netip.Addr{}, 1420)
	userSubnets := []netip.Prefix{netip.MustParsePrefix("172.16.10.0/24")}
	sourceAddress := aIp
	userAddress := netip.MustParseAddr("172.16.10.3")

	splicer, splicedTun := NewSplicer(a, userSubnets, sourceAddress, netip.IPv6Unspecified(), userAddress, netip.IPv6Unspecified())

	go func() {
		packetBuf := [1700]byte{}
		splicer.Read(packetBuf[:], 0)
	}()

	conn, err := aNet.DialUDPAddrPort(netip.AddrPortFrom(aIp, 0), netip.MustParseAddrPort("172.16.10.2:80"))

	if err != nil {
		t.Fatalf("Failed to open UDP connection")
	}
	conn.Write([]byte{1, 2, 3, 4, 5, 6})

	packetBuf := [1700]byte{}
	n, err := splicedTun.Read(packetBuf[:], 0)
	if err != nil {
		t.Fatalf("Failed to read packet from splicedTun: %v", err)
	}
	expectedPacketSize := header.IPv4MinimumSize + header.UDPMinimumSize + 6
	if n != expectedPacketSize {
		t.Fatalf("Expeceted a packet of size %d, got size %d", expectedPacketSize, n)

	}
}

func TestSplicer(t *testing.T) {
	a, aNet, _ := netstack.CreateNetTUN([]netip.Addr{aIp}, []netip.Addr{}, 1420)
	userSubnets := []netip.Prefix{netip.MustParsePrefix("172.16.10.0/24")}
	sourceAddress := aIp
	userAddress := netip.MustParseAddr("172.16.10.3")

	splicer, _ := NewSplicer(a, userSubnets, sourceAddress, netip.IPv6Unspecified(), userAddress, netip.IPv6Unspecified())

	conn, err := aNet.DialUDPAddrPort(netip.AddrPortFrom(aIp, 0), netip.MustParseAddrPort("172.16.9.2:80"))

	if err != nil {
		t.Fatalf("Failed to open UDP connection")
	}
	conn.Write([]byte{1, 2, 3, 4, 5, 6})

	packetBuf := [1700]byte{}
	n, err := splicer.Read(packetBuf[:], 0)
	if err != nil {
		t.Fatalf("Failed to read packet from splicedTun: %v", err)
	}
	expectedPacketSize := header.IPv4MinimumSize + header.UDPMinimumSize + 6
	if n != expectedPacketSize {
		t.Fatalf("Expeceted a packet of size %d, got size %d", expectedPacketSize, n)

	}
}

func TestSplicerSplitting(t *testing.T) {
	a, _, _ := netstack.CreateNetTUN([]netip.Addr{aIp}, []netip.Addr{}, 1420)
	userSubnets := []netip.Prefix{netip.MustParsePrefix("172.16.10.0/24")}
	sourceAddress := aIp
	userAddress := netip.MustParseAddr("172.16.10.3")

	splicer, _ := NewSplicer(a, userSubnets, sourceAddress, netip.IPv6Unspecified(), userAddress, netip.IPv6Unspecified())

	var matchingPacketBuf [1700]byte
	matchingDestIp := netip.MustParseAddr("172.16.10.15")
	ipv4Fields := header.IPv4Fields{
		TOS:            0,
		TotalLength:    0,
		ID:             0,
		Flags:          0,
		FragmentOffset: 0,
		TTL:            0,
		Protocol:       4,
		Checksum:       0,
		SrcAddr:        tcpip.Address{},
		DstAddr:        tcpip.AddrFromSlice(matchingDestIp.AsSlice()),
		Options:        []header.IPv4SerializableOption{},
	}
	matchingPacket := header.IPv4(matchingPacketBuf[:])
	matchingPacket.Encode(&ipv4Fields)

	if !splicer.packetMatchesUserNet(matchingPacket) {
		t.Fatalf("Expected %s to match user subnet", matchingDestIp)
	}

	var unmatchingPacketBuf [1700]byte
	unmatchingDestIp := netip.MustParseAddr("172.16.9.15")
	unmatchingPacket := header.IPv4(unmatchingPacketBuf[:])
	ipv4Fields = header.IPv4Fields{
		TOS:            0,
		TotalLength:    0,
		ID:             0,
		Flags:          0,
		FragmentOffset: 0,
		TTL:            0,
		Protocol:       4,
		Checksum:       0,
		SrcAddr:        tcpip.Address{},
		DstAddr:        tcpip.AddrFromSlice(unmatchingDestIp.AsSlice()),
		Options:        []header.IPv4SerializableOption{},
	}

	unmatchingPacket.Encode(&ipv4Fields)

	if splicer.packetMatchesUserNet(unmatchingPacket) {
		t.Fatalf("Expected %s to not match user subnet", unmatchingDestIp)
	}
}
