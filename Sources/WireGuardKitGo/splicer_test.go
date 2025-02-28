package main

import (
	"math/rand"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

func TestSplicedTun(t *testing.T) {
	a, aNet, _ := netstack.CreateNetTUN([]netip.Addr{aIp}, []netip.Addr{}, 1420)
	userSubnets := []netip.Prefix{netip.MustParsePrefix("172.16.10.0/24")}
	sourceAddress := aIp
	userAddress := netip.MustParseAddr("172.16.10.3")

	splicer, splicedTun := NewSplicer(a, userSubnets, sourceAddress, netip.IPv6Unspecified(), userAddress, nil)

	go func() {
		for {
			packetBuf := [1700]byte{}
			splicer.Read(packetBuf[:], 0)
		}
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
	readPacket := header.IPv4(packetBuf[:n])

	expectedPacketSize := header.IPv4MinimumSize + header.UDPMinimumSize + 6
	if n != expectedPacketSize {
		t.Fatalf("Expeceted a packet of size %d, got size %d", expectedPacketSize, n)
	}

	if !readPacket.IsValid(n) {
		t.Fatalf("IPv4 checksum invalid")
	}

	udpPacket := header.UDP(readPacket.Payload())

	payloadChecksum := checksum.Checksum(udpPacket.Payload(), 0)
	if !udpPacket.IsChecksumValid(readPacket.SourceAddress(), readPacket.DestinationAddress(), payloadChecksum) {
		t.Fatalf("UDP packet not valid")
	}

	if readPacket.SourceAddress() != tcpip.AddrFromSlice(userAddress.AsSlice()) {
		t.Fatalf("Expected user address (%v) and source address (%v) to be the same", userAddress, readPacket.SourceAddress())
	}

	validUdpPacket := constructValidUdpPacket(readPacket.DestinationAddress(), readPacket.SourceAddress(), udpPacket.DestinationPort(), udpPacket.SourcePort(), []byte{1, 2, 3, 4, 5})

	n, err = splicedTun.Write(validUdpPacket, 0)
	if err != nil {
		t.Fatalf("Failed to write to splicedTun")
	}

	var returnBuf [1700]byte
	n, err = conn.Read(returnBuf[:])
	if err != nil {
		t.Fatalf("failed to receive UDP packet: %s", err)
	}

}

func TestSplicer(t *testing.T) {
	a, aNet, _ := netstack.CreateNetTUN([]netip.Addr{aIp}, []netip.Addr{}, 1420)
	userSubnets := []netip.Prefix{netip.MustParsePrefix("172.16.10.0/24")}
	sourceAddress := aIp
	userAddress := netip.MustParseAddr("172.16.10.3")

	splicer, _ := NewSplicer(a, userSubnets, sourceAddress, netip.IPv6Unspecified(), userAddress, nil)

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

	splicer, _ := NewSplicer(a, userSubnets, sourceAddress, netip.IPv6Unspecified(), userAddress, nil)

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

func TestSplicerMultipleUdp(t *testing.T) {
	a, aNet, _ := netstack.CreateNetTUN([]netip.Addr{aIp}, []netip.Addr{}, 1420)
	userSubnets := []netip.Prefix{netip.MustParsePrefix("172.16.10.0/24")}
	sourceAddress := aIp
	userAddress := netip.MustParseAddr("172.16.10.3")

	splicer, _ := NewSplicer(a, userSubnets, sourceAddress, netip.IPv6Unspecified(), userAddress, nil)

	listenAddr := netip.MustParseAddrPort("172.16.9.2:80")
	clientAddr := netip.AddrPortFrom(aIp, 123)
	conn, err := aNet.DialUDPAddrPort(clientAddr, listenAddr)

	if err != nil {
		t.Fatalf("Failed to open UDP connection")
	}
	conn.Write([]byte{1, 2, 3, 4, 5, 6})

	backingBuf := [1700]byte{}
	packetBuf := header.IPv4(backingBuf[:])
	_, err = splicer.Read(packetBuf[:], 0)
	if err != nil {
		t.Fatalf("Failed to read packet from splicedTun: %v", err)
	}

	recvUdpHeader := header.UDP(packetBuf.Payload())

	for i := 0; i < 10; i += 1 {
		packet := constructValidUdpPacket(packetBuf.DestinationAddress(), packetBuf.SourceAddress(), recvUdpHeader.DestinationPort(), recvUdpHeader.SourcePort(), []byte{1, 2, 3})
		_, err := splicer.Write(packet, 0)
		if err != nil {
			t.Fatalf("Experienced a write error - %s", err)
		}
		var buf [1700]byte
		n, err := conn.Read(buf[:])
		if err != nil {
			t.Fatalf("Failed to receive UDP packet")
		}
		if n != 3 {
			t.Fatalf("Expected to receive a packet with a payload of 3, instead got %d", n)
		}
	}
}

func TestSplicedMultipleUdp(t *testing.T) {
	a, aNet, _ := netstack.CreateNetTUN([]netip.Addr{aIp}, []netip.Addr{}, 1420)
	userSubnets := []netip.Prefix{netip.MustParsePrefix("172.16.10.0/24")}
	sourceAddress := aIp
	userAddress := netip.MustParseAddr("172.16.10.3")

	splicer, splicedTun := NewSplicer(a, userSubnets, sourceAddress, netip.IPv6Unspecified(), userAddress, nil)

	listenAddr := netip.MustParseAddrPort("172.16.10.2:80")
	clientAddr := netip.AddrPortFrom(aIp, 123)
	conn, err := aNet.DialUDPAddrPort(clientAddr, listenAddr)

	go func() {
		var err error
		err = nil
		var buf [1700]byte
		for err == nil {
			_, err = splicer.Read(buf[:], 0)
		}
	}()

	if err != nil {
		t.Fatalf("Failed to open UDP connection")
	}
	conn.Write([]byte{1, 2, 3, 4, 5, 6})

	backingBuf := [1700]byte{}
	packetBuf := header.IPv4(backingBuf[:])
	_, err = splicedTun.Read(packetBuf[:], 0)
	if err != nil {
		t.Fatalf("Failed to read packet from splicedTun: %v", err)
	}

	recvUdpHeader := header.UDP(packetBuf.Payload())

	for i := 0; i < 10; i += 1 {
		packet := constructValidUdpPacket(packetBuf.DestinationAddress(), packetBuf.SourceAddress(), recvUdpHeader.DestinationPort(), recvUdpHeader.SourcePort(), []byte{1, 2, 3})
		_, err := splicedTun.Write(packet, 0)
		if err != nil {
			t.Fatalf("Experienced a write error - %s", err)
		}
		var buf [1700]byte
		n, err := conn.Read(buf[:])
		if err != nil {
			t.Fatalf("Failed to receive UDP packet")
		}
		if n != 3 {
			t.Fatalf("Expected to receive a packet with a payload of 3, instead got %d", n)
		}
	}
}

func constructValidUdpPacket(source, destination tcpip.Address, sourcePort, destPort uint16, payload []byte) []byte {
	packet := [1700]byte{}
	ipPacket := header.IPv4(packet[:])

	ipv4Fields := header.IPv4Fields{
		TOS:            0,
		TotalLength:    uint16(header.IPv4MinimumSize + header.UDPMinimumSize + len(payload)),
		ID:             uint16(rand.Uint32() >> 16),
		Flags:          0,
		FragmentOffset: 0,
		TTL:            63,
		Protocol:       uint8(header.UDPProtocolNumber),
		Checksum:       0,
		SrcAddr:        source,
		DstAddr:        destination,
		Options:        []header.IPv4SerializableOption{},
	}
	ipPacket.Encode(&ipv4Fields)
	ipPacket.SetChecksum(^ipPacket.CalculateChecksum())

	udpHeader := header.UDP(ipPacket.Payload())
	udpFields := header.UDPFields{
		SrcPort:  sourcePort,
		DstPort:  destPort,
		Length:   uint16(len(payload) + header.UDPMinimumSize),
		Checksum: 0,
	}
	udpHeader.Encode(&udpFields)
	copy(udpHeader.Payload()[:], payload)

	payloadXsum := checksum.Checksum(udpHeader.Payload(), 0)
	xsum := checksum.Combine(
		header.PseudoHeaderChecksum(header.UDPProtocolNumber, source, destination, uint16(udpHeader.Length())),
		payloadXsum,
	)
	xsum = udpHeader.CalculateChecksum(xsum)

	udpHeader.SetChecksum(^xsum)
	if !udpHeader.IsChecksumValid(source, destination, payloadXsum) {
		panic("checksum invalid")
	}

	return packet[:ipPacket.TotalLength()]
}

func TestRewriteV4TCP(t *testing.T) {
	newSource := ipFromStr("1.2.3.4")
	newDestination := ipFromStr("1.2.3.5")

	packet := []byte("E\000\000L\000\000@\000@\006\251\270\254\020\n\325(r\261\234\366\024\001\273\027=V\302\200\372\005\267\200\030\b\000D\f\000\000\001\001\b\np\205\371\004\223\243\344\243\027\003\003\000\023\037\350aG\251\026\f\253aX\270\201\315\020\221\376\345\302\262")
	ipHeader := header.IPv4(packet)
	oldDestination := ipHeader.DestinationAddress()
	oldSource := ipHeader.SourceAddress()
	assert.Equal(t, oldSource.AsSlice(), netip.MustParseAddr("172.16.10.213").AsSlice())
	assert.Equal(t, oldDestination.AsSlice(), netip.MustParseAddr("40.114.177.156").AsSlice())

	assertRewriteV4(t, ipHeader, newSource, newDestination)
}

func TestRewritev6TcpHeader(t *testing.T) {
	newSource := ipFromStr("200f::10c9:6b77:3fff:13cb")
	newDestination := ipFromStr("200f::16:6696:de73:dfba")

	oldSource := ipFromStr("fe80::10c9:6b77:3fff:13cb")
	oldDestination := ipFromStr("fe80::16:6696:de73:dfba")

	packet := []byte("`\v\206o\000y\006@\376\200\000\000\000\000\000\000\020\311kw?\377\023\313\376\200\000\000\000\000\000\000\000\026f\226\336s\337\272\327\215\365?wc\354\245,\316\206\264\200\030\020\0007\232\000\000\001\001\b\n\324.\210\317\021\2104R\027\003\003\000T\000\000\000\000\000\000\030|\002\356( \370=\316)~UR\277/\312\026\327c\023_\320\244\360JE\f\352\201\244\251\2565\210\211\331\352|>\230\212\270\324\025.\334\002z\321\264\276\231\030 \240\233)\213\267\3639\345J\365E>\030h\235A\225O\235;\224\351\256\354")
	ipHeader := header.IPv6(packet)
	assert.Equal(t, oldSource, ipHeader.SourceAddress())
	assert.Equal(t, oldDestination, ipHeader.DestinationAddress())

	assertRewriteV6(t, ipHeader, newSource, newDestination)
}

func assertRewriteV6(t *testing.T, packet header.IPv6, newSource, newDestination tcpip.Address) {

	rewriteOutgoingHeader6(packet, newSource)
	assert.Equal(t, newSource, packet.SourceAddress())
	if !packet.IsValid(len(packet)) {
		t.Fatalf("ip header is not valid after changing source address")
	}
	rewriteIncomingHeader6(packet, newDestination)
	assert.Equal(t, newDestination, packet.DestinationAddress())

	if !packet.IsValid(len(packet)) {
		t.Fatalf("ip header is not valid after changing destination address")
	}
}

func assertRewriteV4(t *testing.T, packet header.IPv4, newSource, newDestination tcpip.Address) {

	rewriteOutgoingHeader4(packet, newSource)
	assert.Equal(t, newSource, packet.SourceAddress())
	if !packet.IsValid(len(packet)) {
		t.Fatalf("ip header is not valid after changing source address")
	}
	rewriteIncomingHeader4(packet, newDestination)
	assert.Equal(t, newDestination, packet.DestinationAddress())

	if !packet.IsValid(len(packet)) {
		t.Fatalf("ip header is not valid after changing destination address")
	}
}

func TestRewriteV6UdpHeader(t *testing.T) {
	// Src: fe80::16:6696:de73:dfba, Dst: fe80::4ae:1db:e2f9:d2c9
	oldSource := ipFromStr("fe80::16:6696:de73:dfba")
	oldDestination := ipFromStr("fe80::4ae:1db:e2f9:d2c9")

	newSource := ipFromStr("2001::16:6696:de73:dfba")
	newDestination := ipFromStr("2001::4ae:1db:e2f9:d2c9")
	packet := []byte("`\000\r\000\000\f\021@\376\200\000\000\000\000\000\000\000\026f\226\336s\337\272\376\200\000\000\000\000\000\000\004\256\001\333\342\371\322\311\016\212\016\212\000\f\327~-\032\000\000")

	ipHeader := header.IPv6(packet)
	assert.Equal(t, oldSource, ipHeader.SourceAddress())
	assert.Equal(t, oldDestination, ipHeader.DestinationAddress())
	assertRewriteV6(t, ipHeader, newSource, newDestination)
}

func ipFromStr(s string) tcpip.Address {
	return tcpip.AddrFromSlice(netip.MustParseAddr(s).AsSlice())
}

func TesetRewriteV6ICMP(t *testing.T) {
	oldSource := ipFromStr("fe80::16:6696:de73:dfba")
	oldDestination := ipFromStr("ff02::1:ff69:c516")

	newSource := ipFromStr("2001::16:6696:de73:dfba")
	newDestination := ipFromStr("2001::4ae:1db:e2f9:d2c9")

	packet := header.IPv6("`\000\000\000\000 :\377\376\200\000\000\000\000\000\000\000\026f\226\336s\337\272\377\002\000\000\000\000\000\000\000\000\000\001\377i\305\026\207\000\245\202\000\000\000\000\376\200\000\000\000\000\000\000\000\024\303\f\002i\305\026\001\001\200e|\306d\363")

	assert.Equal(t, oldSource, packet.SourceAddress())
	assert.Equal(t, oldDestination, packet.DestinationAddress())

	assertRewriteV6(t, packet, newSource, newDestination)
}

func TestRewriteV4ICMP(t *testing.T) {
	oldSource := ipFromStr("172.16.10.154")
	oldDestination := ipFromStr("172.16.10.213")

	newSource := ipFromStr("8.8.7.7")
	newDestination := ipFromStr("7.7.4.4")

	packet := header.IPv4("E\000\0008\364\257\000\000@\001\030\206\254\020\n\232\254\020\n\325\003\003\337\334\000\000\000\000E\000\000 0\243\000\000@\021\334\232\254\020\n\325\254\020\n\232\016\212\016\212\000\f\000\000")

	assert.Equal(t, oldSource, packet.SourceAddress())
	assert.Equal(t, oldDestination, packet.DestinationAddress())

	assertRewriteV4(t, packet, newSource, newDestination)
}

func TestRewriteV4UDP(t *testing.T) {
	oldSource := ipFromStr("172.16.10.213")
	oldDestination := ipFromStr("172.16.10.154")

	newSource := ipFromStr("8.8.7.7")
	newDestination := ipFromStr("7.7.4.4")

	packet := header.IPv4("E\000\000 \020\260\000\000@\021\374\215\254\020\n\325\254\020\n\232\016\212\016\212\000\f\024*a\b\000\000")

	assert.Equal(t, oldSource, packet.SourceAddress())
	assert.Equal(t, oldDestination, packet.DestinationAddress())

	assertRewriteV4(t, packet, newSource, newDestination)
}

func TestNoSplicer(t *testing.T) {
	a, aNet, _ := netstack.CreateNetTUN([]netip.Addr{aIp}, []netip.Addr{}, 1420)
	// userSubnets := []netip.Prefix{netip.MustParsePrefix("172.16.10.0/24")}
	// sourceAddress := aIp

	listenAddr := netip.MustParseAddrPort("172.16.9.2:80")
	clientAddr := netip.AddrPortFrom(aIp, 123)
	conn, err := aNet.DialUDPAddrPort(clientAddr, listenAddr)

	if err != nil {
		t.Fatalf("Failed to open UDP connection")
	}
	conn.Write([]byte{1, 2, 3, 4, 5, 6})

	backingBuf := [1700]byte{}
	packetBuf := header.IPv4(backingBuf[:])
	_, err = a.Read(packetBuf[:], 0)
	if err != nil {
		t.Fatalf("Failed to read packet from splicedTun: %v", err)
	}

	recvUdpHeader := header.UDP(packetBuf.Payload())

	for i := 0; i < 10; i += 1 {
		packet := constructValidUdpPacket(packetBuf.DestinationAddress(), packetBuf.SourceAddress(), recvUdpHeader.DestinationPort(), recvUdpHeader.SourcePort(), []byte{1, 2, 3})

		_, err := a.Write(packet, 0)
		if err != nil {
			t.Fatalf("Experienced a write error - %s", err)
		}

		var buf [1700]byte
		n, err := conn.Read(buf[:])
		if err != nil {
			t.Fatalf("Failed to receive UDP packet")
		}
		if n != 3 {
			t.Fatalf("Expected to receive a packet with a payload of 3, instead got %d", n)
		}
	}
}
