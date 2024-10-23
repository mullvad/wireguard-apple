package main

import "C"

import (
	"net"
	"unsafe"

	"golang.zx2c4.com/wireguard/tun/netstack"
)

// export wgOpenInTunnelTCP
func wgOpenInTunnelTCP(tunnelHandle int32, address *C.char) int32 {
	tun := tunnels.Get(tunnelHandle)
	if tun == nil {
		return errNoSuchTunnel
	}
	if tun.VirtualNet == nil {
		return errNoTunnelVirtualInterface
	}

	return tun.AddSocket(func(vnet *netstack.Net) (net.Conn, error) {
		return vnet.Dial("tcp", C.GoString(address))
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
// wgSendInTunnelTCP
func wgSendInTunnelTCP(tunnelHandle int32, socketHandle int32, data *byte, dataLen int) int32 {
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
	if n != dataLen {
		tun.logger.Errorf("Expected to write %v bytes, instead wrote %v", err)
		return errTCPWrite
	}

	return 0
}

// Blocking call to receive bytes into the buffer from a TCP connection. The
// `data` pointer should point to at least `dataLen` bytes, and be valid until
// this call returns. 
// export wgRecvInTunnelTCP
func wgRecvInTunnelTCP(tunnelHandle int32, socketHandle int32, data *byte, dataLen int) int32 {
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
		tun.logger.Errorf("Failed to write to TCP connection: %v", err)
		return errTCPRead
	}
	if n != dataLen {
		tun.logger.Errorf("Expected to write %v bytes, instead wrote %v", err)
		return errTCPRead
	}

	return int32(n)
}
