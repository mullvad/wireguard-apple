package main

import (
	"io"
	"math"
	"net/netip"
	"os"
	"sync"

	"golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

type Splicer struct {
	tun            tun.Device
	sb             *sharedBuf
	targetNetworks []netip.Prefix
}

func NewSplicer(tun tun.Device, subnets []netip.Prefix, source4Address, source6Address, user4Address, user6Address netip.Addr) (Splicer, SplicedTun) {
	sharedBuf := newSharedBuf()

	splicer := Splicer{
		tun, &sharedBuf, subnets,
	}

	splicedTun := SplicedTun{
		tun,
		&sharedBuf,
		tcpip.AddrFromSlice(source4Address.AsSlice()),
		tcpip.AddrFromSlice(source6Address.AsSlice()),
		tcpip.AddrFromSlice(user4Address.AsSlice()),
		tcpip.AddrFromSlice(user6Address.AsSlice()),
	}

	return splicer, splicedTun
}

// Close implements tun.Device.
func (s Splicer) Close() error {
	s.sb.Close()
	return s.tun.Close()
}

// Events implements tun.Device.
func (s Splicer) Events() <-chan tun.Event {
	return s.tun.Events()
}

// File implements tun.Device.
func (s Splicer) File() *os.File {
	return s.tun.File()
}

// Flush implements tun.Device.
func (s Splicer) Flush() error {
	return s.tun.Flush()
}

// MTU implements tun.Device.
func (s Splicer) MTU() (int, error) {
	return s.tun.MTU()
}

// Name implements tun.Device.
func (s Splicer) Name() (string, error) {
	return s.tun.Name()
}

// Read implements tun.Device.
func (s Splicer) Read(packet []byte, prefix int) (int, error) {
	var n int
	var err error
	for {
		n, err = s.tun.Read(packet, prefix)
		if err != nil {
			return 0, err
		}

		if s.packetMatchesUserNet(packet[prefix:n]) {
			s.sb.Write(packet[prefix:n])
			continue
		}

		break
	}

	return n, nil
}

func (s Splicer) packetMatchesUserNet(packet []byte) bool {
	var destinationAddress tcpip.Address

	if len(packet) < header.IPv4MinimumSize {
		return false
	}

	ipVersion := (packet[0] >> 4) & 0x0f
	switch ipVersion {
	case 4:
		destinationAddress = header.IPv4(packet).DestinationAddress()
	case 6:
		if len(packet) < header.IPv6MinimumSize {
			return false
		}
		destinationAddress = header.IPv6(packet).DestinationAddress()
	default:
		return false
	}

	// ignoring the OK value since a slice of tcpip.Address will always convert to a netip.Addr
	addr, _ := netip.AddrFromSlice(destinationAddress.AsSlice())
	for _, subnet := range s.targetNetworks {
		if subnet.Contains(addr) {
			return true
		}
	}

	return false
}

// Write implements tun.Device.
func (s Splicer) Write(packet []byte, offset int) (int, error) {
	return s.tun.Write(packet, offset)
}

// Used to send writes to splicerTun from Splicer
type sharedBuf struct {
	buffer  [128][1700]byte
	lens    [128]int
	lastIdx int
	lock    *sync.Mutex
	cond    *sync.Cond
	closed  bool
}

func newSharedBuf() sharedBuf {
	lock := &sync.Mutex{}
	cond := sync.NewCond(lock)

	var buffer [128][1700]byte
	var lens [128]int
	lastIdx := -1
	closed := false

	return sharedBuf{
		buffer,
		lens,
		lastIdx,
		lock,
		cond,
		closed,
	}

}

func (sb *sharedBuf) Close() {
	sb.lock.Lock()
	defer sb.lock.Unlock()
	sb.closed = true
	sb.cond.Broadcast()
}

func (sb *sharedBuf) Write(packet []byte) {
	sb.lock.Lock()
	defer sb.lock.Unlock()
	// Don't block until the reader side is ready to accept more packets, just drop 'em
	if len(sb.buffer) <= sb.lastIdx || sb.closed {
		return
	}

	sb.lastIdx += 1
	copy(sb.buffer[sb.lastIdx][:], packet)
	sb.lens[sb.lastIdx] = len(packet)
	sb.cond.Broadcast()
}

func (sb *sharedBuf) Read(packet []byte) (int, bool) {
	sb.lock.Lock()
	defer sb.lock.Unlock()

	if sb.closed {
		return 0, true
	}

	for sb.lastIdx < 0 && !sb.closed {
		sb.cond.Wait()
	}

	if sb.closed {
		return 0, true
	}

	packetLen := sb.lens[sb.lastIdx]
	copy(packet, sb.buffer[sb.lastIdx][:packetLen])
	sb.lastIdx -= 1

	return packetLen, false
}

type SplicedTun struct {
	parentTun   tun.Device
	sb          *sharedBuf
	realSource4 tcpip.Address
	realSource6 tcpip.Address

	userSource4 tcpip.Address
	userSource6 tcpip.Address
}

// Close implements tun.Device.
func (s SplicedTun) Close() error {
	s.sb.Close()
	return nil
}

// Events implements tun.Device.
func (s SplicedTun) Events() <-chan tun.Event {
	return make(chan tun.Event)
}

// File implements tun.Device.
func (s SplicedTun) File() *os.File {
	return nil
}

// Flush implements tun.Device.
func (s SplicedTun) Flush() error {
	return nil
}

// MTU implements tun.Device.
func (s SplicedTun) MTU() (int, error) {
	return s.parentTun.MTU()
}

// Name implements tun.Device.
func (s SplicedTun) Name() (string, error) {
	return s.parentTun.Name()
}

// Read implements tun.Device.
func (s SplicedTun) Read(packet []byte, offset int) (int, error) {
	n, isClosed := s.sb.Read(packet[offset:])
	if isClosed {
		return 0, io.EOF
	}
	rewriteOutgoingHeader(packet[offset:n], s.userSource4, s.userSource6)

	return n, nil
}

func rewriteOutgoingHeader(packet []byte, v4Source, v6Source tcpip.Address) {
	if len(packet) < header.IPv4MinimumSize {
		return
	}
	ipVersion := (packet[0] >> 4) & 0x0f
	switch ipVersion {
	case 4:
		rewriteOutgoingHeader4(packet, v4Source)
	case 6:
		rewriteOutgoingHeader6(packet, v6Source)
	default:
	}
}

func rewriteIncomingHeader(packet []byte, v4Destination, v6Destination tcpip.Address) {
	if len(packet) < header.IPv4MinimumSize {
		return
	}

	ipVersion := (packet[0] >> 4) & 0x0f
	switch ipVersion {
	case 4:
		rewriteIncomingHeader4(packet, v4Destination)
	case 6:
		rewriteIncomingHeader6(packet, v6Destination)
	default:
	}
}

func rewriteOutgoingHeader4(packet []byte, source tcpip.Address) {
	if len(packet) < header.IPv4MinimumSize {
		return
	}

	ipHeader := header.IPv4(packet)
	ipHeader.SetSourceAddressWithChecksumUpdate(source)

	switch ipHeader.TransportProtocol() {
	case header.TCPProtocolNumber:
		rewriteTcpHeader(ipHeader.SourceAddress(), ipHeader.DestinationAddress(), ipHeader.Payload())
	case header.UDPProtocolNumber:
		rewriteUdpHeader(ipHeader.SourceAddress(), ipHeader.DestinationAddress(), ipHeader.Payload())
	case header.ICMPv4ProtocolNumber:
		rewriteIcmp4Header(ipHeader.SourceAddress(), ipHeader.DestinationAddress(), ipHeader.Payload())
	default:
		return
	}
}

func rewriteIncomingHeader4(packet []byte, destination tcpip.Address) {
	if len(packet) < header.IPv4MinimumSize {
		return
	}

	ipHeader := header.IPv4(packet)
	ipHeader.SetDestinationAddressWithChecksumUpdate(destination)
	switch ipHeader.TransportProtocol() {
	case header.TCPProtocolNumber:
		rewriteTcpHeader(ipHeader.SourceAddress(), ipHeader.DestinationAddress(), ipHeader.Payload())
	case header.UDPProtocolNumber:
		rewriteUdpHeader(ipHeader.SourceAddress(), ipHeader.DestinationAddress(), ipHeader.Payload())
	case header.ICMPv4ProtocolNumber:
		rewriteIcmp4Header(ipHeader.SourceAddress(), ipHeader.DestinationAddress(), ipHeader.Payload())
	default:
		return
	}
}

func rewriteOutgoingHeader6(packet []byte, source tcpip.Address) {
	if len(packet) < header.IPv6MinimumSize {
		return
	}

	ipHeader := header.IPv6(packet)
	ipHeader.SetSourceAddress(source)
	switch ipHeader.TransportProtocol() {
	case header.TCPProtocolNumber:
		rewriteTcpHeader(ipHeader.SourceAddress(), ipHeader.DestinationAddress(), ipHeader.Payload())
	case header.UDPProtocolNumber:
		rewriteUdpHeader(ipHeader.SourceAddress(), ipHeader.DestinationAddress(), ipHeader.Payload())
	case header.ICMPv6ProtocolNumber:
		rewriteIcmp6Header(ipHeader.SourceAddress(), ipHeader.DestinationAddress(), ipHeader.Payload())
	default:
		return
	}
}

func rewriteIncomingHeader6(packet []byte, destination tcpip.Address) {
	if len(packet) < header.IPv6MinimumSize {
		return
	}

	ipHeader := header.IPv6(packet)
	ipHeader.SetDestinationAddress(destination)
	switch ipHeader.TransportProtocol() {
	case header.TCPProtocolNumber:
		rewriteTcpHeader(ipHeader.SourceAddress(), ipHeader.DestinationAddress(), ipHeader.Payload())
	case header.UDPProtocolNumber:
		rewriteUdpHeader(ipHeader.SourceAddress(), ipHeader.DestinationAddress(), ipHeader.Payload())
	case header.ICMPv6ProtocolNumber:
		rewriteIcmp6Header(ipHeader.SourceAddress(), ipHeader.DestinationAddress(), ipHeader.Payload())
	default:
		return
	}
}

func rewriteUdpHeader(source, destination tcpip.Address, packet []byte) {
	if len(packet) < header.UDPMinimumSize {
		return
	}

	udpHeader := header.UDP(packet)
	udpHeader.SetChecksum(0)
	xsum := header.PseudoHeaderChecksum(header.UDPProtocolNumber, source, destination, udpHeader.Length())
	xsum = checksum.Combine(xsum, checksum.Checksum(udpHeader.Payload(), 0))
	xsum = udpHeader.CalculateChecksum(xsum)

	if xsum != math.MaxUint16 {
		xsum = ^xsum
	}
	udpHeader.SetChecksum(xsum)
	if !udpHeader.IsChecksumValid(source, destination, checksum.Checksum(udpHeader.Payload(), 0)) {
		panic("udp checksum not valid")
	}

}

func rewriteTcpHeader(source, destination tcpip.Address, packet []byte) {
	if len(packet) < header.TCPMinimumSize {
		return
	}

	tcpHeader := header.TCP(packet)
	tcpHeader.SetChecksum(0)
	xsum := header.PseudoHeaderChecksum(
		header.TCPProtocolNumber,
		source,
		destination,
		uint16(len(packet)),
	)
	xsum = checksum.Checksum(tcpHeader.Payload(), xsum)
	tcpHeader.SetChecksum(^tcpHeader.CalculateChecksum(xsum))

	payloadXsum := checksum.Checksum(tcpHeader.Payload(), 0)

	if !tcpHeader.IsChecksumValid(source, destination, payloadXsum, uint16(len(tcpHeader.Payload()))) {
		panic("TCP checksum not valid")
	}
}

func rewriteIcmp4Header(source, destination tcpip.Address, packet []byte) {
	if len(packet) < header.ICMPv4MinimumSize {
		return
	}

	icmpHeader := header.ICMPv4(packet)
	icmpHeader.SetChecksum(0)
	icmpHeader.SetChecksum(^header.ICMPv4Checksum(icmpHeader, 0))
}

func rewriteIcmp6Header(source, destination tcpip.Address, packet []byte) {
	if len(packet) < header.ICMPv6MinimumSize {
		return
	}

	icmpHeader := header.ICMPv6(packet)
	icmpHeader.SetChecksum(0)
	checksumParams := header.ICMPv6ChecksumParams{
		Header:      icmpHeader,
		Src:         source,
		Dst:         destination,
		PayloadLen:  len(packet),
		PayloadCsum: 0,
	}
	icmpHeader.SetChecksum(^header.ICMPv6Checksum(checksumParams))
}

// Write implements tun.Device.
func (s SplicedTun) Write(packet []byte, offset int) (int, error) {
	rewriteIncomingHeader(packet[offset:], s.realSource4, s.realSource6)
	return s.parentTun.Write(packet, offset)
}
