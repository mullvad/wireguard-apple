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

// how many buffers we should preallocate.
// Currently, WireGuardGo sends buffers one at a time, so this is 128, though the API says that
// this is not set in stone.
const expectedBufferCount = 128

// A packet batch contains within itself a buffer used to store packet data and
// whether it is a virtual packet or not. This allows an individual reader
// goroutine to send a read packet to whatever `Router.Read` where its contents
// will be copied over. This is essential for multiplexing between different
// devices.
type PacketBatch struct {
	packet     []byte
	isVirtual  bool
	completion chan *PacketBatch
}

// A router routes traffic between two different tunnel devices. This allows us
// to multiplex between real, user traffic and our own virtual networking stack
// to work around iOS limitations.
type Router struct {
	real, virtual tun.Device
	read          routerRead
	write         routerWrite
}

type routerRead struct {
	virtualRoutes    map[PacketIdentifier]bool
	virtualRouteChan chan PacketIdentifier
	rxChannel        chan *PacketBatch
	rxShutdown       chan struct{}
	waitGroup        *sync.WaitGroup
	errorChannel     chan error
	error            error
}

type routerWrite struct {
	virtualRoutes    map[PacketIdentifier]bool
	virtualRouteChan chan PacketIdentifier
}

// Close implements tun.Device.
func (r *Router) Close() error {
	close(r.read.rxShutdown)
	err1 := r.real.Close()
	err2 := r.virtual.Close()
	if err1 != nil {
		return err1
	}
	return err2
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
	r.virtual.Flush()
	return r.real.Flush()
}

type PacketHeaderData struct {
	protocol   tcpip.TransportProtocolNumber
	localPort  uint16
	remoteAddr netip.Addr
	remotePort uint16
}

// protocol (1 byte) + padding (1 byte) + src port (2 bytes) + dest addr (16 bytes, some possibly unused) + dest port
type PacketIdentifier [22]byte

func (pi PacketHeaderData) asPacketIdentifier() PacketIdentifier {
	result := PacketIdentifier{}
	destAddrBytes := pi.remoteAddr.As16()
	result[0] = uint8(pi.protocol)
	result[1] = 0
	copy(result[4:], destAddrBytes[:])
	binary.BigEndian.PutUint16(result[2:], pi.localPort)
	binary.BigEndian.PutUint16(result[20:], pi.remotePort)
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
	*packetHeaderData = PacketHeaderData{protocol, srcPort, destAddress, destPort}
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
	// TODO: skip the chain of IPv6 extension headers to get to the ports.
	// For now, we just ignore them and assume no ports if there are extension headers
	*packetHeaderData = PacketHeaderData{protocol, srcPort, destAddress, destPort}
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

func (r *routerRead) setVirtualRoute(header PacketHeaderData) {
	identifier := header.asPacketIdentifier()
	r.virtualRoutes[identifier] = true
	r.virtualRouteChan <- identifier
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
		defer func() {
			// Avoid reading nil values if a read happens after rxChannel is closed
			if batch != nil {
				batch.completion <- batch
			}
		}()
		if !ok {
			return 0, errors.New("reader shut down")
		}
	}

	headerData := PacketHeaderData{}
	packet := batch.packet

	copy(bufs[offset:], packet)

	if batch.isVirtual && fillPacketHeaderData(bufs[offset:], &headerData, false) {
		r.read.setVirtualRoute(headerData)
	}

	return len(packet), nil
}

func (r *routerWrite) updateVirtualRoutes() {
	for {
		select {
		case newVirtualRoute := <-r.virtualRouteChan:
			r.virtualRoutes[newVirtualRoute] = true
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
	if fillPacketHeaderData(packet[offset:], &headerData, true) {
		identifier := headerData.asPacketIdentifier()
		_, isVirtual = r.write.virtualRoutes[identifier]
	}

	if !isVirtual {
		return r.real.Write(packet, offset)
	} else {
		return r.virtual.Write(packet, offset)
	}
}

func initializeReadPacketBuffer(size int) [][]byte {
	buffer := make([][]byte, size, size)
	for idx := range buffer {
		buffer[idx] = make([]byte, device.MaxSegmentSize)
	}

	return buffer
}

func (r *routerRead) readWorker(device tun.Device, isVirtual bool) {
	defer r.waitGroup.Done()
	completion := make(chan *PacketBatch)
	buffer := make([]byte, 1700)
	batch := &PacketBatch{
		packet:     buffer,
		isVirtual:  isVirtual,
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
		batch.isVirtual = isVirtual
		select {
		case _, _ = <-r.rxShutdown:
			return
		case r.rxChannel <- batch:
		}
		select {
		case _, _ = <-r.rxShutdown:
			return
		case batch = <-completion:
			batch.packet = buffer
		}
	}
}

func newRouterRead(real, virtual tun.Device, virtualRouteChan chan PacketIdentifier) routerRead {
	rxChannel := make(chan *PacketBatch)
	rxShutdown := make(chan struct{}, 2)
	errorChannel := make(chan error, 1)
	result := routerRead{
		map[PacketIdentifier]bool{},
		virtualRouteChan,
		rxChannel,
		rxShutdown,
		&sync.WaitGroup{},
		errorChannel,
		nil,
	}
	go result.readWorker(real, false)
	go result.readWorker(virtual, true)
	result.waitGroup.Add(2)
	return result
}

func newRouterWrite(virtualRouteChan chan PacketIdentifier) routerWrite {
	return routerWrite{
		map[PacketIdentifier]bool{},
		virtualRouteChan,
	}
}

func NewRouter(real, virtual tun.Device) Router {
	virtualRouteChan := make(chan PacketIdentifier, 128)

	result := Router{
		real,
		virtual,
		newRouterRead(real, virtual, virtualRouteChan),
		newRouterWrite(virtualRouteChan),
	}
	return result
}
