package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"sync"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// the number of bytes to allocate before the start of each packet to allow for offsets
const maxOffset = 128

// how many buffers we should preallocate.
// Currently, WireGuardGo sends buffers one at a time, so this is 1, though the API says that
// this is not set in stone.
const expectedBufferCount = conn.IdealBatchSize

type PacketBatch struct {
	packets   [][]byte
	sizes     []int
	isVirtual bool
}

// truncate a PacketBatch to a maximum size, allocating and returning a new PacketBatch to
// hold the overflow if needed.  The function for allocating the batch is injected, to decouple
// this from specific memory management methods (such as the use of a Pool, as in practice, or
// simple allocation, as in tests)
func (pb *PacketBatch) truncate(limit int, makeBatch func() *PacketBatch) *PacketBatch {
	excess := len(pb.packets) - limit
	if excess <= 0 {
		return nil
	}
	overflow := makeBatch()
	overflow.packets = pb.packets[limit:]
	overflow.sizes = pb.sizes[limit:]
	overflow.isVirtual = pb.isVirtual
	pb.packets = pb.packets[:limit]
	pb.sizes = pb.sizes[:limit]
	return overflow
}

type routerRead struct {
	virtualRoutes    map[PacketIdentifier]bool
	virtualRouteChan chan PacketIdentifier
	rxChannel        chan *PacketBatch
	rxShutdown       chan struct{}
	waitGroup        *sync.WaitGroup
	overflow         *PacketBatch
	batchPool        *sync.Pool
}

type routerWrite struct {
	virtualRoutes    map[PacketIdentifier]bool
	virtualRouteChan chan PacketIdentifier
	realPackets      [][]byte
	virtualPackets   [][]byte
}

type Router struct {
	real, virtual tun.Device
	read          routerRead
	write         routerWrite
}

// BatchSize implements tun.Device.
func (r *Router) BatchSize() int {
	return r.real.BatchSize()
}

// Close implements tun.Device.
func (r *Router) Close() error {
	// TODO: anything else we need to shut down here
	// This is doubled to shut down both readWorker goroutines
	r.read.rxShutdown <- struct{}{}
	r.read.rxShutdown <- struct{}{}
	err1 := r.real.Close()
	err2 := r.virtual.Close()
	r.read.waitGroup.Wait()
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
func (r *Router) Read(bufs [][]byte, sizes []int, offset int) (n int, err error) {
	// this could theoretically be executed in parallel, but we don't currently do that.
	// this code is in itself not parallel-safe, so add locking or similar if this changes
	if offset > maxOffset {
		return 0, fmt.Errorf("illegal offset %d > %d", offset, maxOffset)
	}
	var packetBatch *PacketBatch
	if r.read.overflow != nil {
		packetBatch = r.read.overflow
		r.read.overflow = nil
	} else {
		var ok bool
		packetBatch, ok = <-r.read.rxChannel
		if !ok {
			return 0, errors.New("reader shut down")
		}
	}
	defer func() {
		r.read.batchPool.Put(packetBatch)
	}()

	r.read.overflow = packetBatch.truncate(len(bufs), func() *PacketBatch { return r.read.batchPool.Get().(*PacketBatch) })
	headerData := PacketHeaderData{}
	for packetIndex := range packetBatch.packets {

		copy(bufs[packetIndex][offset:], packetBatch.packets[packetIndex][maxOffset:])
		sizes[packetIndex] = packetBatch.sizes[packetIndex]

		if packetBatch.isVirtual && fillPacketHeaderData(bufs[packetIndex][offset:], &headerData, false) {
			r.read.setVirtualRoute(headerData)
		}
	}

	return len(packetBatch.packets), nil
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
func (r *Router) Write(bufs [][]byte, offset int) (int, error) {
	r.write.updateVirtualRoutes()

	headerData := PacketHeaderData{}
	r.write.realPackets = r.write.realPackets[:0]
	r.write.virtualPackets = r.write.virtualPackets[:0]

	for packetIdx, packetRef := range bufs {
		isVirtual := false
		if fillPacketHeaderData(packetRef[offset:], &headerData, true) {
			identifier := headerData.asPacketIdentifier()
			_, isVirtual = r.write.virtualRoutes[identifier]
		}

		if !isVirtual {
			r.write.realPackets = append(r.write.realPackets, bufs[packetIdx])
		} else {
			r.write.virtualPackets = append(r.write.virtualPackets, bufs[packetIdx])
		}
	}

	realWritten := 0
	virtualWritten := 0
	var err error
	if len(r.write.realPackets) > 0 {
		realWritten, err = r.real.Write(r.write.realPackets, offset)
	}
	if realWritten < len(r.write.realPackets) || err != nil {
		return realWritten, err
	}
	if len(r.write.virtualPackets) > 0 {
		virtualWritten, err = r.virtual.Write(r.write.virtualPackets, offset)
	}
	if err != nil {
		virtualWritten = 0
	}
	return realWritten + virtualWritten, err
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
	for {
		select {
		case _ = <-r.rxShutdown:
			return
		default:
		}
		batch := r.batchPool.Get().(*PacketBatch)
		_, err := device.Read(batch.packets, batch.sizes, maxOffset)
		if err != nil {
			r.batchPool.Put(batch)
			return
		}
		batch.isVirtual = isVirtual
		r.rxChannel <- batch
	}
}

func newRouterRead(real, virtual tun.Device, virtualRouteChan chan PacketIdentifier) routerRead {
	rxChannel := make(chan *PacketBatch)
	rxShutdown := make(chan struct{}, 2)
	result := routerRead{
		map[PacketIdentifier]bool{},
		virtualRouteChan,
		rxChannel,
		rxShutdown,
		&sync.WaitGroup{},
		nil,
		&sync.Pool{
			New: func() any {
				batch := new(PacketBatch)
				batch.packets = initializeReadPacketBuffer(conn.IdealBatchSize)
				batch.sizes = make([]int, conn.IdealBatchSize)
				return batch
			},
		},
	}
	go result.readWorker(real, false)
	go result.readWorker(virtual, true)
	result.waitGroup.Add(2)
	go func() {
		result.waitGroup.Wait()
		close(result.rxChannel)
	}()
	return result
}

func newRouterWrite(virtualRouteChan chan PacketIdentifier) routerWrite {
	return routerWrite{
		map[PacketIdentifier]bool{},
		virtualRouteChan,
		make([][]byte, 0, expectedBufferCount),
		make([][]byte, 0, expectedBufferCount),
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
