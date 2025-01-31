package main

import (
	"io"
	"os"
	"sync"

	"golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

type Splicer struct {
	tun            tun.Device
	sb             sharedBuf
	targetNetworks []byte
}

// Close implements tun.Device.
func (s Splicer) Close() error {
	s.sb.Close()
	s.tun.Close()
	return nil
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
func (s Splicer) Read([]byte, int) (int, error) {
	panic("unimplemented")
}

// Write implements tun.Device.
func (s Splicer) Write([]byte, int) (int, error) {
	panic("unimplemented")
}

// Used to send writes to splicerTun from Splicer
type sharedBuf struct {
	buffer  [2048][1700]byte
	lens    [2048]int
	lastIdx int
	lock    *sync.Mutex
	cond    *sync.Cond
	closed  bool
}

func newSharedBuf() sharedBuf {
	lock := &sync.Mutex{}
	cond := sync.NewCond(lock)

	var buffer [2048][1700]byte
	var lens [2048]int
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
	for len(sb.buffer) <= sb.lastIdx {
		sb.cond.Wait()
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

type packet struct {
	buffer [1700]byte
	offset int
}

type SplicerTun struct {
	parentTun   tun.Device
	sb          sharedBuf
	realSource4 tcpip.Address
	realSource6 tcpip.Address

	userSource4 tcpip.Address
	userSource6 tcpip.Address
}

// Close implements tun.Device.
func (s SplicerTun) Close() error {
	s.parentTun.Close()
	s.sb.Close()
	return nil
}

// Events implements tun.Device.
func (s SplicerTun) Events() <-chan tun.Event {
	return make(chan tun.Event)
}

// File implements tun.Device.
func (s SplicerTun) File() *os.File {
	return nil
}

// Flush implements tun.Device.
func (s SplicerTun) Flush() error {
	return nil
}

// MTU implements tun.Device.
func (s SplicerTun) MTU() (int, error) {
	return s.parentTun.MTU()
}

// Name implements tun.Device.
func (s SplicerTun) Name() (string, error) {
	return s.parentTun.Name()
}

// Read implements tun.Device.
func (s SplicerTun) Read(packet []byte, offset int) (int, error) {
	n, isClosed := s.sb.Read(packet[offset:])
	if isClosed {
		return 0, io.EOF
	}
	rewriteOutgoingHeader(packet[offset:n], s.userSource4, s.userSource6)
	return n, nil
}

func rewriteOutgoingHeader(packet []byte, v4Source, v6Source tcpip.Address) {
	if len(packet) > header.IPv4MinimumSize {
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
	if len(packet) > header.IPv4MinimumSize {
		return
	}

	ipVersion := (packet[0] >> 4) & 0x0f
	switch ipVersion {
	case 4:
		rewriteIncomingHeader4(packet, v4Destination)
	case 6:
		rewriteOutgoingHeader6(packet, v6Destination)
	default:
	}
}

func rewriteOutgoingHeader4(packet []byte, source tcpip.Address) {
	if len(packet) > header.IPv4MinimumSize {
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
	if len(packet) > header.IPv4MinimumSize {
		return
	}

	ipHeader := header.IPv4(packet)
	ipHeader.SetSourceAddressWithChecksumUpdate(destination)
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
	if len(packet) > header.IPv6MinimumSize {
		return
	}

	ipHeader := header.IPv6(packet)
	ipHeader.SetDestinationAddress(source)
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
	if len(packet) > header.IPv6MinimumSize {
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
	if len(packet) < header.TCPMinimumSize {
		return
	}

	udpHeader := header.UDP(packet)
	udpHeader.SetChecksum(0)
	udpHeader.SetChecksum(^udpHeader.CalculateChecksum(header.PseudoHeaderChecksum(
		header.UDPProtocolNumber,
		source,
		destination,
		uint16(len(packet)),
	)))
}

func rewriteTcpHeader(source, destination tcpip.Address, packet []byte) {
	if len(packet) < header.TCPMinimumSize {
		return
	}

	tcpHeader := header.TCP(packet)
	tcpHeader.SetChecksum(0)
	tcpHeader.SetChecksum(^tcpHeader.CalculateChecksum(header.PseudoHeaderChecksum(
		header.TCPProtocolNumber,
		source,
		destination,
		uint16(len(packet)),
	)))
}
func rewriteIcmp4Header(source, destination tcpip.Address, packet []byte) {
	if len(packet) < header.ICMPv4MinimumSize  {
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
func (s SplicerTun) Write(packet []byte, offset int) (int, error) {
	rewriteIncomingHeader(packet[offset:], s.realSource4, s.realSource6)
	return s.parentTun.Write(packet, offset)
}
