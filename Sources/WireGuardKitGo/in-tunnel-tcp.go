package main

import "C"

import (
	"context"
	"net"
	"net/netip"
	"time"
	"unsafe"

	"golang.zx2c4.com/wireguard/tun/netstack"
)

//export wgOpenInTunnelTCP
func wgOpenInTunnelTCP(tunnelHandle int32, address *C.char, timeout uint64) int32 {
	tun := tunnels.Get(tunnelHandle)
	if tun == nil {
		return errNoSuchTunnel
	}
	if tun.VirtualNet == nil {
		return errNoTunnelVirtualInterface
	}

	netAddr, err := netip.ParseAddrPort(C.GoString(address))
	if err != nil {
		return errBadIPString
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	return tun.AddSocket(func(vnet *netstack.Net) (net.Conn, error) {
		var connection net.Conn
		var err error
		connection, err = vnet.DialContextTCPAddrPort(ctx, netAddr)
		return connection, err
	})
}

//export wgCloseInTunnelTCP
func wgCloseInTunnelTCP(tunnelHandle int32, socketHandle int32) bool {
	tun := tunnels.Get(tunnelHandle)
	if tun == nil {
		return false
	}

	return tun.RemoveAndCloseSocket(socketHandle)
}

// Sends the data array into the TCP socket in a blocking fashion. The data
// pointer should point to at least `dataLen` bytes for the entirety of this
// call. This function is technically threadsafe, but multiple calls will not
// have a defined order, which can lead to unordered writes.
//
//export wgSendInTunnelTCP
func wgSendInTunnelTCP(tunnelHandle int32, socketHandle int32, data *byte, dataLen int32) int32 {
	tun := tunnels.Get(tunnelHandle)
	if tun == nil {
		return errNoSuchTunnel
	}

	socket, ok := tun.GetSocket(socketHandle)
	if !ok {
		return errTCPNoSocket
	}
	byteBuffer := C.GoBytes(unsafe.Pointer(data), C.int(dataLen))

	n, err := socket.Write(byteBuffer)
	if err != nil {
		tun.logger.Errorf("Failed to write to TCP connection: %v", err)
		return errTCPWrite
	}
	if n != int(dataLen) {
		tun.logger.Errorf("Expected to write %v bytes, instead wrote %v", err)
		return errTCPWrite
	}

	return int32(n)
}

// Blocking call to receive bytes into the buffer from a TCP connection. The
// `data` pointer should point to at least `dataLen` bytes, and be valid until
// this call returns. 
//export wgRecvInTunnelTCP
func wgRecvInTunnelTCP(tunnelHandle int32, socketHandle int32, data *byte, dataLen int32) int32 {
	tun := tunnels.Get(tunnelHandle)
	if tun == nil {
		return errNoSuchTunnel
	}

	socket, ok := tun.GetSocket(socketHandle)
	if !ok {
		return errTCPNoSocket
	}
	byteBuffer := unsafe.Slice(data, dataLen)

	n, err := socket.Read(byteBuffer)
	if err != nil {
		tun.logger.Errorf("Failed to read from TCP connection: %v", err)
		return errTCPRead
	}

	return int32(n)
}
