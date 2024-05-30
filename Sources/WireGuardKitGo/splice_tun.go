// A tunnel combining the Darwin native tunnel and the virtual network tunnel in one efficient package

package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

// this is just copied from tun_darwin.go. Not sure if it should be changed
const utunControlName = "com.apple.net.utun_control"

// some of these may be redundant
type SpliceTun struct {
	// from NativeTun
	name        string
	tunFile     *os.File
	events      chan tun.Event
	errors      chan error
	routeSocket int
	closeOnce   sync.Once
	// from netTun, minus duplicates
	ep             *channel.Endpoint
	stack          *stack.Stack
	incomingPacket chan *buffer.View
	mtu            int
	dnsServers     []netip.Addr
	hasV4, hasV6   bool
}

func (tun *SpliceTun) operateOnFd(fn func(fd uintptr)) {
	sysconn, err := tun.tunFile.SyscallConn()
	if err != nil {
		tun.errors <- fmt.Errorf("unable to find sysconn for tunfile: %s", err.Error())
		return
	}
	err = sysconn.Control(fn)
	if err != nil {
		tun.errors <- fmt.Errorf("unable to control sysconn for tunfile: %s", err.Error())
	}
}

func retryInterfaceByIndex(index int) (iface *net.Interface, err error) {
	for i := 0; i < 20; i++ {
		iface, err = net.InterfaceByIndex(index)
		if err != nil && errors.Is(err, unix.ENOMEM) {
			time.Sleep(time.Duration(i) * time.Second / 3)
			continue
		}
		return iface, err
	}
	return nil, err
}

func (tunnel *SpliceTun) routineRouteListener(tunIfindex int) {
	var (
		statusUp  bool
		statusMTU int
	)

	defer close(tunnel.events)

	data := make([]byte, os.Getpagesize())
	for {
	retry:
		n, err := unix.Read(tunnel.routeSocket, data)
		if err != nil {
			if errno, ok := err.(unix.Errno); ok && errno == unix.EINTR {
				goto retry
			}
			tunnel.errors <- err
			return
		}

		if n < 14 {
			continue
		}

		if data[3 /* type */] != unix.RTM_IFINFO {
			continue
		}
		ifindex := int(*(*uint16)(unsafe.Pointer(&data[12 /* ifindex */])))
		if ifindex != tunIfindex {
			continue
		}

		iface, err := retryInterfaceByIndex(ifindex)
		if err != nil {
			tunnel.errors <- err
			return
		}

		// Up / Down event
		up := (iface.Flags & net.FlagUp) != 0
		if up != statusUp && up {
			tunnel.events <- tun.EventUp
		}
		if up != statusUp && !up {
			tunnel.events <- tun.EventDown
		}
		statusUp = up

		// MTU changes
		if iface.MTU != statusMTU {
			tunnel.events <- tun.EventMTUUpdate
		}
		statusMTU = iface.MTU
	}
}

func (tun *SpliceTun) setUpRealInterface() error {
	// Code for setting up the real part of the tunnel

	name, err := tun.Name()
	if err != nil {
		tun.tunFile.Close()
		return err
	}

	tunIfindex, err := func() (int, error) {
		iface, err := net.InterfaceByName(name)
		if err != nil {
			return -1, err
		}
		return iface.Index, nil
	}()
	if err != nil {
		tun.tunFile.Close()
		return err
	}

	tun.routeSocket, err = socketCloexec(unix.AF_ROUTE, unix.SOCK_RAW, unix.AF_UNSPEC)
	if err != nil {
		tun.tunFile.Close()
		return err
	}

	go tun.routineRouteListener(tunIfindex)

	if tun.mtu > 0 {
		err = tun.setMTU(tun.mtu)
		if err != nil {
			tun.Close()
			return err
		}
	}
	return nil
}

func (dev *SpliceTun) setUpVirtualInterface(localAddresses []netip.Addr) error {
	sackEnabledOpt := tcpip.TCPSACKEnabled(true) // TCP SACK is disabled by default
	tcpipErr := dev.stack.SetTransportProtocolOption(tcp.ProtocolNumber, &sackEnabledOpt)
	if tcpipErr != nil {
		return fmt.Errorf("could not enable TCP SACK: %v", tcpipErr)
	}
	dev.ep.AddNotify(dev)
	tcpipErr = dev.stack.CreateNIC(1, dev.ep)
	if tcpipErr != nil {
		return fmt.Errorf("CreateNIC: %v", tcpipErr)
	}
	for _, ip := range localAddresses {
		var protoNumber tcpip.NetworkProtocolNumber
		if ip.Is4() {
			protoNumber = ipv4.ProtocolNumber
		} else if ip.Is6() {
			protoNumber = ipv6.ProtocolNumber
		}
		protoAddr := tcpip.ProtocolAddress{
			Protocol:          protoNumber,
			AddressWithPrefix: tcpip.AddrFromSlice(ip.AsSlice()).WithPrefix(),
		}
		tcpipErr := dev.stack.AddProtocolAddress(1, protoAddr, stack.AddressProperties{})
		if tcpipErr != nil {
			return fmt.Errorf("AddProtocolAddress(%v): %v", ip, tcpipErr)
		}
		if ip.Is4() {
			dev.hasV4 = true
		} else if ip.Is6() {
			dev.hasV6 = true
		}
	}
	if dev.hasV4 {
		dev.stack.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: 1})
	}
	if dev.hasV6 {
		dev.stack.AddRoute(tcpip.Route{Destination: header.IPv6EmptySubnet, NIC: 1})
	}
	//dev.events <- tun.EventUp
	return nil
}

func CreateSpliceTUNWithFile(file *os.File, mtu int, localAddresses, dnsServers []netip.Addr) (tun.Device, error) {
	//  Options for the virtual part of the tunnel.
	//  TODO: Perhaps we can eliminate ipv6 options if we don't use them
	opts := stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol6, icmp.NewProtocol4},
		HandleLocal:        true,
	}

	tun := &SpliceTun{
		tunFile:        file,
		events:         make(chan tun.Event, 10),
		errors:         make(chan error, 5),
		ep:             channel.New(1024, uint32(mtu), ""),
		stack:          stack.New(opts),
		incomingPacket: make(chan *buffer.View),
		// TODO: do we need dnsServers for the virtual part?
		dnsServers: dnsServers,
		mtu:        mtu,
	}

	err := tun.setUpRealInterface()
	if err != nil {
		return nil, err
	}
	err = tun.setUpVirtualInterface(localAddresses)
	if err != nil {
		return nil, err
	}

	// todo: set up the virtual part here

	return tun, nil

}

func (tun *SpliceTun) Name() (string, error) {
	// taken entirely from the real tunnel
	var err error
	tun.operateOnFd(func(fd uintptr) {
		tun.name, err = unix.GetsockoptString(
			int(fd),
			2, /* #define SYSPROTO_CONTROL 2 */
			2, /* #define UTUN_OPT_IFNAME 2 */
		)
	})

	if err != nil {
		return "", fmt.Errorf("GetSockoptString: %w", err)
	}

	return tun.name, nil
}

func (tun *SpliceTun) File() *os.File {
	// taken entirely from the real tunnel
	return tun.tunFile
}

func (tun *SpliceTun) Events() <-chan tun.Event {
	// the same in both
	return tun.events
}

func (tun *SpliceTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	/// the NativeTun Read code

	// 
	// realTun := make(chan interface{})
	// go func() {
	// 	tun.tunFile.Peek()
	// 	realTun <- struct{}{}
	// }
	select {
	case err := <-tun.errors:
		return 0, err

		// from the virtual interface
	case view, ok := <-tun.incomingPacket:
		if !ok {
			return 0, os.ErrClosed
		}

		n, err := view.Read(bufs[0][offset:])
		if err != nil {
			return 0, err
		}
		sizes[0] = n
		return 1, nil

	// Wait on the real tun notification channel here
	// case _ := <- realTun :
	default:
		// from the NativeTun Read code
		buf := bufs[0][offset-4:]
		n, err := tun.tunFile.Read(buf[:])
		if n < 4 {
			return 0, err
		}
		sizes[0] = n - 4
		return 1, err
	}
	///
}

func (tun *SpliceTun) writeReal(bufs [][]byte, offset int) (int, error) {
	/// the NativeTun write code
	if offset < 4 {
		return 0, io.ErrShortBuffer
	}
	for i, buf := range bufs {
		buf = buf[offset-4:]
		buf[0] = 0x00
		buf[1] = 0x00
		buf[2] = 0x00
		switch buf[4] >> 4 {
		case 4:
			buf[3] = unix.AF_INET
		case 6:
			buf[3] = unix.AF_INET6
		default:
			return i, unix.EAFNOSUPPORT
		}
		if _, err := tun.tunFile.Write(buf); err != nil {
			return i, err
		}
	}
	return len(bufs), nil
}

func (tun *SpliceTun) writeVirtual(buf [][]byte, offset int) (int, error) {
	for _, buf := range buf {
		packet := buf[offset:]
		if len(packet) == 0 {
			continue
		}

		pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(packet)})
		switch packet[0] >> 4 {
		case 4:
			tun.ep.InjectInbound(header.IPv4ProtocolNumber, pkb)
		case 6:
			tun.ep.InjectInbound(header.IPv6ProtocolNumber, pkb)
		default:
			return 0, syscall.EAFNOSUPPORT
		}
	}
	return len(buf), nil
}

// Determine if a packet is for the virtual device.
// This is the MVP that works by simple inspection.
func belongsToVirtual(packet []byte, offset int) bool {
	packet = packet[offset:]
	ipVersion := (packet[0] >> 4) & 0x0f
	virtualHost := []byte{10, 64, 0, 1}
	// Only IPv4 packets can be virtual
	if ipVersion != 4 {
		return false
	}
	if !bytes.Equal(packet[12:16], virtualHost) {
		return false
	}
	switch packet[9] {
	case ProtocolICMP:
		return true
	case ProtocolTCP:
		portOffset := (packet[0] & 0xff) * 4
		return (uint16(packet[portOffset])<<8 | uint16(packet[portOffset+1])) == 1337
	default:
		return false
	}
}

func (tun *SpliceTun) Write(bufs [][]byte, offset int) (int, error) {
	// Assumption: all buffers are bound for the same interface.
	// This is trivially true in practice as there's only one buffer
	if belongsToVirtual(bufs[0], offset) {
		return tun.writeVirtual(bufs, offset)
	}
	return tun.writeReal(bufs, offset)
}

func (tun *SpliceTun) Close() error {
	/// the NativeTun close code
	var err1, err2 error
	tun.closeOnce.Do(func() {
		err1 = tun.tunFile.Close()
		if tun.routeSocket != -1 {
			unix.Shutdown(tun.routeSocket, unix.SHUT_RDWR)
			err2 = unix.Close(tun.routeSocket)
		}
		if tun.events != nil {
			close(tun.events)
		}
		// The virtual close code
		tun.stack.RemoveNIC(1)
		tun.ep.Close()

		if tun.incomingPacket != nil {
			close(tun.incomingPacket)
		}
	})

	// ---
	if err1 != nil {
		return err1
	}
	return err2
}

func (tun *SpliceTun) setMTU(n int) error {
	// the NativeTun code
	fd, err := socketCloexec(
		unix.AF_INET,
		unix.SOCK_DGRAM,
		0,
	)
	if err != nil {
		return err
	}

	defer unix.Close(fd)

	var ifr unix.IfreqMTU
	copy(ifr.Name[:], tun.name)
	ifr.MTU = int32(n)
	err = unix.IoctlSetIfreqMTU(fd, &ifr)
	if err != nil {
		return fmt.Errorf("failed to set MTU on %s: %w", tun.name, err)
	}

	return nil
}

func (tun *SpliceTun) MTU() (int, error) {
	// the NativeTun code
	fd, err := socketCloexec(
		unix.AF_INET,
		unix.SOCK_DGRAM,
		0,
	)
	if err != nil {
		return 0, err
	}

	defer unix.Close(fd)

	ifr, err := unix.IoctlGetIfreqMTU(fd, tun.name)
	if err != nil {
		return 0, fmt.Errorf("failed to get MTU on %s: %w", tun.name, err)
	}

	return int(ifr.MTU), nil
}

func (tun *SpliceTun) BatchSize() int {
	// the NativeTun code
	return 1
}

func socketCloexec(family, sotype, proto int) (fd int, err error) {
	// See go/src/net/sys_cloexec.go for background.
	syscall.ForkLock.RLock()
	defer syscall.ForkLock.RUnlock()

	fd, err = unix.Socket(family, sotype, proto)
	if err == nil {
		unix.CloseOnExec(fd)
	}
	return
}

// from the virtual interface
func (tun *SpliceTun) WriteNotify() {
	pkt := tun.ep.Read()
	if pkt.IsNil() {
		return
	}

	view := pkt.ToView()
	pkt.DecRef()

	tun.incomingPacket <- view
}
