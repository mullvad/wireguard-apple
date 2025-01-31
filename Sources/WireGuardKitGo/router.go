package main

import (
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
	"os"
	"sync"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// The standard packet offset, which WireGuardGo's real tunnel device expects to be at least 4
// when reading.
// See: https://github.com/WireGuard/wireguard-go/blob/12269c2761734b15625017d8565745096325392f/tun/tun_darwin.go#L228
const defaultOffset = 4

// A packet batch contains within itself a buffer used to store packet data and
// whether it is a virtual packet or not. This allows an individual reader
// goroutine to send a read packet to whatever `Router.Read` where its contents
// will be copied over. This is essential for multiplexing between different
// devices.
type PacketBatch struct {
	packet     []byte
	index      int
	completion chan *PacketBatch
}

func (batch PacketBatch) isVirtual() bool {
	// it is assumed that the real device will always have an index of 0
	return batch.index != 0
}

// A router routes traffic between two different tunnel devices. This allows us
// to multiplex between real, user traffic and our own virtual networking stack
// to work around iOS limitations.
type Router struct {
	real     tun.Device
	virtuals []tun.Device
	read     routerRead
	write    routerWrite
}

type routerRead struct {
	virtualRoutes    map[PacketIdentifier]int
	virtualRouteChan chan virtualRoute
	rxChannel        chan *PacketBatch
	rxShutdown       chan struct{}
	waitGroup        *sync.WaitGroup
	errorChannel     chan error
	error            error
}

type virtualRoute struct {
	index      int
	identifier PacketIdentifier
}

type routerWrite struct {
	virtualRoutes    map[PacketIdentifier]int
	virtualRouteChan chan virtualRoute
}

// Close implements tun.Device.
func (r *Router) Close() error {
	close(r.read.rxShutdown)
	err1 := r.real.Close()
	virtualErrs := []error{}
	for idx := range r.virtuals {
		virtualErrs = append(virtualErrs, r.virtuals[idx].Close())
	}
	if err1 != nil {
		return err1
	}

	for idx := range virtualErrs {
		if virtualErrs[idx] != nil {
			return virtualErrs[idx]
		}
	}
	return nil
}

// Events implements tun.Device.
func (r *Router) Events() <-chan tun.Event {
	return r.real.Events()
}

// File implements tun.Device.
func (r *Router) File() *os.File {
	return r.real.File()
}

// MTU implements tun.Device.
func (r *Router) MTU() (int, error) {
	return r.real.MTU()
}

// Name implements tun.Device.
func (r *Router) Name() (string, error) {
	return r.real.Name()
}

// Name implements tun.Device.
func (r *Router) Flush() error {
	for _, dev := range r.virtuals {
		dev.Flush()
	}
	return r.real.Flush()
}

type PacketHeaderData struct {
	protocol   tcpip.TransportProtocolNumber
	localPort  uint16
	remoteAddr netip.Addr
	remotePort uint16
	// Flow ID for IPv6, Ident field for ICMPv4, 0 for anything else
	sessionId uint32
}

// protocol (1 byte) + padding (1 byte) + src port (2 bytes) + dest addr (16 bytes, some possibly unused) + dest port + session id
type PacketIdentifier [26]byte

func (pi PacketHeaderData) asPacketIdentifier() PacketIdentifier {
	result := PacketIdentifier{}
	destAddrBytes := pi.remoteAddr.As16()
	result[0] = uint8(pi.protocol)
	result[1] = 0
	binary.BigEndian.PutUint16(result[2:], pi.localPort)
	copy(result[4:], destAddrBytes[:])
	binary.BigEndian.PutUint16(result[20:], pi.remotePort)
	binary.BigEndian.PutUint32(result[22:], pi.sessionId)
	return result
}

func getPorts(protocol tcpip.TransportProtocolNumber, protocolHeader []byte) (srcPort uint16, destPort uint16) {
	switch protocol {
	case header.TCPProtocolNumber, header.UDPProtocolNumber:
		return uint16(protocolHeader[1]) | uint16(protocolHeader[0])<<8, uint16(protocolHeader[3]) | uint16(protocolHeader[2])<<8
	default:
		return 0, 0
	}
}

func fillPacketHeaderData4(packet []byte, packetHeaderData *PacketHeaderData, isIncoming bool) bool {
	var destAddress netip.Addr
	var srcPort, destPort uint16
	headerLength := int(packet[0]&0x0f) * 4
	if len(packet) < headerLength+4 {
		return false
	}
	protocol := tcpip.TransportProtocolNumber(packet[9])
	if isIncoming {
		destAddress = netip.AddrFrom4(*((*[4]byte)(packet[12:16])))
		destPort, srcPort = getPorts(protocol, packet[headerLength:])
	} else {
		destAddress = netip.AddrFrom4(*((*[4]byte)(packet[16:20])))
		srcPort, destPort = getPorts(protocol, packet[headerLength:])
	}
	sessionId := uint32(0)
	if protocol == header.ICMPv4ProtocolNumber {
		sessionId = uint32(header.ICMPv4(packet).Ident())
	}
	*packetHeaderData = PacketHeaderData{protocol, srcPort, destAddress, destPort, sessionId}
	return true
}

func fillPacketHeaderData6(packet []byte, packetHeaderData *PacketHeaderData, isIncoming bool) bool {
	var destAddress netip.Addr
	var srcPort, destPort uint16
	if len(packet) < 44 {
		return false
	}
	protocol := tcpip.TransportProtocolNumber(packet[6])
	if isIncoming {
		destAddress = netip.AddrFrom16(*((*[16]byte)(packet[8:24])))
		destPort, srcPort = getPorts(protocol, packet[40:])
	} else {
		destAddress = netip.AddrFrom16(*((*[16]byte)(packet[24:40])))
		srcPort, destPort = getPorts(protocol, packet[40:])
	}
	_, sessionId := header.IPv6(packet).TOS()

	*packetHeaderData = PacketHeaderData{protocol, srcPort, destAddress, destPort, sessionId}
	return true
}

func fillPacketHeaderData(packet []byte, packetHeaderData *PacketHeaderData, isIncoming bool) bool {
	ipVersion := (packet[0] >> 4) & 0x0f
	switch ipVersion {
	case 4:
		return fillPacketHeaderData4(packet, packetHeaderData, isIncoming)
	case 6:
		return fillPacketHeaderData6(packet, packetHeaderData, isIncoming)
	default:
		return false
	}
}

func (r *routerRead) setVirtualRoute(header PacketHeaderData, index int) {
	identifier := header.asPacketIdentifier()
	r.virtualRoutes[identifier] = index
	r.virtualRouteChan <- virtualRoute{index, identifier}
}

// Read implements tun.Device.
func (r *Router) Read(bufs []byte, offset int) (n int, err error) {
	// this could theoretically be executed in parallel, but we don't currently do that.
	// this code is in itself not parallel-safe, so add locking or similar if this changes
	var batch *PacketBatch
	if r.read.error != nil {
		return 0, r.read.error
	}

	var ok bool
	select {
	case err = <-r.read.errorChannel:
		r.read.error = err
		return 0, err
	case _, _ = <-r.read.rxShutdown:
		return 0, io.EOF
	case batch, ok = <-r.read.rxChannel:
		if !ok {
			return 0, errors.New("reader shut down")
		}
	}

	headerData := PacketHeaderData{}
	packet := batch.packet

	copy(bufs[offset:], packet)

	if batch.isVirtual() && fillPacketHeaderData(bufs[offset:], &headerData, false) {
		r.read.setVirtualRoute(headerData, batch.index)
	}

	// important to unblock the underlying reader.
	select {
	case _, _ = <-r.read.rxShutdown:
		return 0, io.EOF
	case batch.completion <- batch:
	}

	return len(packet), nil
}

func (r *routerWrite) updateVirtualRoutes() {
	for {
		select {
		case newVirtualRoute := <-r.virtualRouteChan:
			r.virtualRoutes[newVirtualRoute.identifier] = newVirtualRoute.index
		default:
			return
		}
	}
}

// Write implements tun.Device.
func (r *Router) Write(packet []byte, offset int) (int, error) {
	r.write.updateVirtualRoutes()

	headerData := PacketHeaderData{}

	isVirtual := false
	index := 0
	if fillPacketHeaderData(packet[offset:], &headerData, true) {
		identifier := headerData.asPacketIdentifier()
		index, isVirtual = r.write.virtualRoutes[identifier]
	}

	if !isVirtual {
		return r.real.Write(packet, offset)
	} else {
		return r.virtuals[index-1].Write(packet, offset)
	}
}

func initializeReadPacketBuffer(size int) [][]byte {
	buffer := make([][]byte, size, size)
	for idx := range buffer {
		buffer[idx] = make([]byte, device.MaxSegmentSize)
	}

	return buffer
}

func (r *routerRead) readWorker(device tun.Device, index int) {
	defer r.waitGroup.Done()
	completion := make(chan *PacketBatch)
	buffer := make([]byte, 1700)
	batch := &PacketBatch{
		packet:     buffer,
		index:      index,
		completion: completion,
	}
	for r.error == nil {
		select {
		case <-r.rxShutdown:
			return
		default:
		}
		n, err := device.Read(batch.packet, defaultOffset)
		if err != nil {
			select {
			case r.errorChannel <- err:
			case <-r.rxShutdown:
			}
			return
		}

		batch.packet = batch.packet[defaultOffset : n+defaultOffset]
		batch.index = index
		// Submitting read from virtual device to router
		select {
		case _, _ = <-r.rxShutdown:
			return
		case r.rxChannel <- batch:
		}

		// Waiting for router to finish the submitted read
		select {
		case _, _ = <-r.rxShutdown:
			return
		case batch, ok := <-completion:
			if !ok {
				return
			}
			batch.packet = buffer
		}
	}
}

func newRouterRead(real tun.Device, virtuals []tun.Device, virtualRouteChan chan virtualRoute) routerRead {
	rxChannel := make(chan *PacketBatch)
	rxShutdown := make(chan struct{}, len(virtuals))
	errorChannel := make(chan error, 1)
	result := routerRead{
		map[PacketIdentifier]int{},
		virtualRouteChan,
		rxChannel,
		rxShutdown,
		&sync.WaitGroup{},
		errorChannel,
		nil,
	}

	result.waitGroup.Add(2)
	go result.readWorker(real, 0)
	for index, virtual := range virtuals {
		go result.readWorker(virtual, index)
	}
	return result
}

func newRouterWrite(virtualRouteChan chan virtualRoute) routerWrite {
	return routerWrite{
		map[PacketIdentifier]int{},
		virtualRouteChan,
	}
}

func NewRouter(real, virtual tun.Device) Router {
	virtualRouteChan := make(chan virtualRoute, 128)

	virtuals := []tun.Device{virtual}
	result := Router{
		real,
		virtuals,
		newRouterRead(real, virtuals, virtualRouteChan),
		newRouterWrite(virtualRouteChan),
	}
	return result
}
