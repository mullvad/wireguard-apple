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

// Opens a TCP connection to the specified address as though it was bound to the tunnel.
// This function returns a socket handle immediately, and it can be used immediately after,
// but the socket may not be connected immediately. When writing or reading from the socket,
// the calls will wait until the socket connection is established or it times out.
//
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

	connectTcpSocket := func(ctx context.Context, vnet *netstack.Net) (net.Conn, error) {
		connection, err := vnet.DialContextTCPAddrPort(ctx, netAddr)
		cancel()
		return connection, err
	}

	return tun.AddSocket(ctx, connectTcpSocket)
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

	socket, err, ok := tun.GetSocket(socketHandle)
	if !ok {
		return errTCPNoSocket
	}
	if err != nil {
		tun.logger.Errorf("Failed to open TCP socket: %s", err)
		tun.RemoveAndCloseSocket(socketHandle)
		return errTCPNoSocket
	}

	n, err := socket.Write(unsafe.Slice(data, dataLen))
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
//
//export wgRecvInTunnelTCP
func wgRecvInTunnelTCP(tunnelHandle int32, socketHandle int32, data *byte, dataLen int32) int32 {
	tun := tunnels.Get(tunnelHandle)
	if tun == nil {
		return errNoSuchTunnel
	}

	socket, err, ok := tun.GetSocket(socketHandle)
	if !ok {
		return errTCPNoSocket
	}

	if err != nil {
		tun.logger.Errorf("Failed to open TCP socket: %s", err)
		tun.RemoveAndCloseSocket(socketHandle)
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
