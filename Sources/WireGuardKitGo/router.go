package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"sync"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/tun"
)

const maxOffset = 128

// how many buffers we should preallocate.
// Currently, WireGuardGo sends buffers one at a time, so this is 1, though the API says that
// this is not set in stone.
const expectedBufferCount = 1

type PacketBatch struct {
	packets   [][]byte
	sizes     []int
	isVirtual bool
}

// truncate a PacketBatch to a maximum size, allocating and returning a new PacketBatch to
// hold the overflow if needed.  The function for allocating the batch is injected, to decouple
// this from specific memory management methods (such as the use of a Pool, as in practice, or
// simple allocation, as in tests)
func (pb *PacketBatch) truncate(headsize int, makeBatch func() *PacketBatch) *PacketBatch {
	overflowSize := len(pb.packets) - headsize
	if overflowSize <= 0 {
		return nil
	}
	overflow := makeBatch()
	overflow.packets = pb.packets[headsize:]
	overflow.sizes = pb.sizes[headsize:]
	overflow.isVirtual = pb.isVirtual
	pb.packets = pb.packets[:headsize]
	pb.sizes = pb.sizes[:headsize]
	return overflow
}

type Router struct {
	real, virtual       tun.Device
	rxChannel           chan *PacketBatch
	rxShutdown          chan struct{}
	rxVirtualRoutes     map[PacketIdentifier]bool
	virtualRoutes       map[PacketIdentifier]bool
	virtualRouteChan    chan PacketIdentifier
	readerWaitGroup     *sync.WaitGroup
	overflow            *PacketBatch
	batchPool           *sync.Pool
	writeRealPackets    [][]byte
	writeVirtualPackets [][]byte
}

// BatchSize implements tun.Device.
func (r *Router) BatchSize() int {
	return r.real.BatchSize()
}

// Close implements tun.Device.
func (r *Router) Close() error {
	// TODO: anything else we need to shut down here
	// This is doubled to shut down both readWorker goroutines
	r.rxShutdown <- struct{}{}
	r.rxShutdown <- struct{}{}
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

type PacketHeaderData struct {
	protocol   byte
	sourcePort uint16
	destAddr   netip.Addr
	destPort   uint16
}

// protocol (1 byte) + padding (1 byte) + src port (2 bytes) + dest addr (16 bytes, some possibly unused) + dest port
type PacketIdentifier [22]byte

func (pi PacketHeaderData) asPacketIdentifier() PacketIdentifier {
	result := PacketIdentifier{}
	destAddrBytes := pi.destAddr.As16()
	result[0] = pi.protocol
	result[1] = 0
	copy(result[4:], destAddrBytes[:])
	binary.BigEndian.PutUint16(result[2:], pi.sourcePort)
	binary.BigEndian.PutUint16(result[20:], pi.destPort)
	return result
}

const ProtocolICMP = 1
const ProtocolTCP = 6
const ProtocolUDP = 17

func getPorts(protocol byte, protocolHeader []byte) (uint16, uint16) {
	switch protocol {
	case ProtocolTCP:
		return uint16(protocolHeader[1]) | uint16(protocolHeader[0])<<8, uint16(protocolHeader[3]) | uint16(protocolHeader[2])<<8
	case ProtocolUDP:
		return uint16(protocolHeader[1]) | uint16(protocolHeader[0])<<8, uint16(protocolHeader[3]) | uint16(protocolHeader[2])<<8
	default:
		return 0, 0
	}
}

func getPacketHeaderData4(packet []byte, isIncoming bool) PacketHeaderData {
	var destAddress netip.Addr
	var srcPort, destPort uint16
	headerLength := (packet[0] & 0xff) * 4
	protocol := packet[9]
	if isIncoming {
		destAddress = netip.AddrFrom4(*((*[4]byte)(packet[12:16])))
		destPort, srcPort = getPorts(protocol, packet[headerLength:])
	} else {
		destAddress = netip.AddrFrom4(*((*[4]byte)(packet[16:20])))
		srcPort, destPort = getPorts(protocol, packet[headerLength:])
	}
	return PacketHeaderData{protocol, srcPort, destAddress, destPort}
}

func getPacketHeaderData6(packet []byte, isIncoming bool) PacketHeaderData {
	var destAddress netip.Addr
	var srcPort, destPort uint16
	protocol := packet[6]
	if isIncoming {
		destAddress = netip.AddrFrom16(*((*[16]byte)(packet[8:24])))
		destPort, srcPort = getPorts(protocol, packet[40:])
	} else {
		destAddress = netip.AddrFrom16(*((*[16]byte)(packet[24:40])))
		srcPort, destPort = getPorts(protocol, packet[40:])
	}
	// TODO: skip the chain of IPv6 extension headers to get to the ports.
	// For now, we just ignore them and assume no ports if there are extension headers
	return PacketHeaderData{protocol, srcPort, destAddress, destPort}
}

func fillPacketHeaderData(packet []byte, packetHeaderData *PacketHeaderData, isIncoming bool) bool {
	ipVersion := (packet[0] >> 4) & 0x0f
	switch ipVersion {
	case 4:
		*packetHeaderData = getPacketHeaderData4(packet, isIncoming)
		return true
	case 6:
		*packetHeaderData = getPacketHeaderData6(packet, isIncoming)
		return true
	default:
		return false
	}
}

func (r *Router) setVirtualRoute(header PacketHeaderData) {
	identifier := header.asPacketIdentifier()
	r.rxVirtualRoutes[identifier] = true
	r.virtualRouteChan <- identifier
}

// Read implements tun.Device.
func (r *Router) Read(bufs [][]byte, sizes []int, offset int) (n int, err error) {
	// can be executed in parallel
	if offset > maxOffset {
		return 0, fmt.Errorf("illegal offset %d > %d", offset, maxOffset)
	}
	var packets *PacketBatch
	if r.overflow != nil {
		packets = r.overflow
		r.overflow = nil
	} else {
		var ok bool
		packets, ok = <-r.rxChannel
		if !ok {
			return 0, errors.New("reader shut down")
		}
	}
	defer func() {
		r.batchPool.Put(packets)
	}()

	r.overflow = packets.truncate(len(bufs), func() *PacketBatch { return r.batchPool.Get().(*PacketBatch) })
	headerData := PacketHeaderData{}
	for packetIndex := range packets.packets {

		copy(bufs[packetIndex][offset:], packets.packets[packetIndex][maxOffset:])
		sizes[packetIndex] = packets.sizes[packetIndex]

		if packets.isVirtual && fillPacketHeaderData(bufs[packetIndex][offset:], &headerData, false) {
			r.setVirtualRoute(headerData)
		}
	}

	return len(packets.packets), nil
}

func (r *Router) updateVirtualRoutes() {
	for {
		select {
		case newVirtualRoute := <-r.virtualRouteChan:
			r.virtualRoutes[newVirtualRoute] = true
			continue
		default:
			return
		}
	}
}

// Write implements tun.Device.
func (r *Router) Write(bufs [][]byte, offset int) (int, error) {
	r.updateVirtualRoutes()

	headerData := PacketHeaderData{}
	// realPackets := initializeWritePacketBuffer(len(bufs))
	// virtualPackets := initializeWritePacketBuffer(len(bufs))
	r.writeRealPackets = r.writeRealPackets[:0]
	r.writeVirtualPackets = r.writeVirtualPackets[:0]

	for packetIdx, packetRef := range bufs {
		isVirtual := false
		if fillPacketHeaderData(packetRef[offset:], &headerData, true) {
			identifier := headerData.asPacketIdentifier()
			_, isVirtual = r.virtualRoutes[identifier]
		}

		if !isVirtual {
			r.writeRealPackets = append(r.writeRealPackets, bufs[packetIdx])
		} else {
			r.writeVirtualPackets = append(r.writeVirtualPackets, bufs[packetIdx])
		}
	}

	rw := 0
	vw := 0
	var err error
	if len(r.writeRealPackets) > 0 {
		rw, err = r.real.Write(r.writeRealPackets, offset)
	}
	if rw < len(r.writeRealPackets) || err != nil {
		return rw, err
	}
	if len(r.writeVirtualPackets) > 0 {
		vw, err = r.virtual.Write(r.writeVirtualPackets, offset)
	}
	return rw + vw, err
}

func initializeReadPacketBuffer(size int) [][]byte {
	buffer := make([][]byte, size, size)
	for idx := range buffer {
		buffer[idx] = make([]byte, 1500+maxOffset)
	}

	return buffer
}

func (r *Router) readWorker(device tun.Device, isVirtual bool) {
	defer r.readerWaitGroup.Done()
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

func NewRouter(real, virtual tun.Device) Router {
	rxChannel := make(chan *PacketBatch)
	rxShutdown := make(chan struct{}, 2)
	virtualRouteChan := make(chan PacketIdentifier, 128)

	result := Router{
		real,
		virtual,
		rxChannel,
		rxShutdown,
		map[PacketIdentifier]bool{},
		map[PacketIdentifier]bool{},
		virtualRouteChan,
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
		make([][]byte, 0, expectedBufferCount),
		make([][]byte, 0, expectedBufferCount),
	}
	go result.readWorker(real, false)
	go result.readWorker(virtual, true)
	result.readerWaitGroup.Add(2)
	go func() {
		result.readerWaitGroup.Wait()
		close(result.rxChannel)
	}()
	return result
}
