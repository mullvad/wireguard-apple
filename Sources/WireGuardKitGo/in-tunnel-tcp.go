package main

import "C"

import "net"

type tcpHandle struct {
	tunnelHandle int32
	tcpSocket    *net.Conn
}

var tcpHandles = make(map[int32]tcpHandle)

// this could be generalised with the ICMP opener
//

//export wgOpenInTunnelTCP
func wgOpenInTunnelTCP(tunnelHandle int32, address *C.char) int32 {
	handle, ok := tunnelHandles[tunnelHandle]
	if !ok {
		return errNoSuchTunnel
	}
	if handle.virtualNet == nil {
		return errNoTunnelVirtualInterface
	}
	conn, _ := handle.virtualNet.Dial("tcp", C.GoString(address))

	result := insertHandle(tcpHandles, tcpHandle{tunnelHandle, &conn})
	if result < 0 {
		conn.Close()
	}
	return result
}

//export wgCloseInTunnelTCP
func wgCloseInTunnelTCP(socketHandle int32) bool {
	socket, ok := tcpHandles[socketHandle]
	if ok {
		(*(socket.tcpSocket)).Close()
		delete(tcpHandles, socketHandle)
	}
	return ok
}

//

//export wgSendAndAwaitInTunnelTCP
func wgSendAndAwaitInTunnelTCP(tunnelHandle int32, socketHandle int32, data []byte, replyBuf []byte) int32 {
	socket, ok := tcpHandles[socketHandle]
	if !ok {
		// TODO: rename this to not be ICMP-specific, i.e., errOpenInTunnelConnection
		return errICMPOpenSocket
	}

	_, err := (*(socket.tcpSocket)).Write(data)
	if err != nil {
		// Also rename to generalise
		return errICMPWriteSocket
	}

	readBytes, err := (*(socket.tcpSocket)).Read(replyBuf)
	if readBytes <= 0 || err != nil {
		// ditto
		return errICMPReadSocket
	}

	return int32(readBytes)

}
