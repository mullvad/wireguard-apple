package main

import "C"

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

	result := insertHandle(socketHandles, socketHandle{tunnelHandle, socketTypeTCP, &conn})
	if result < 0 {
		conn.Close()
	}
	return result
}

//export wgCloseInTunnelTCP
func wgCloseInTunnelTCP(socketHandle int32) bool {
	return wgCloseInTunnelSocketHandle(socketHandle)
}

//

//export wgSendAndAwaitInTunnelTCP
func wgSendAndAwaitInTunnelTCP(tunnelHandle int32, socketHandle int32, data []byte, replyBuf []byte) int32 {
	socket, ok := socketHandles[socketHandle]
	if !ok || socket.socketType != socketTypeTCP {
		return errNoMatchingSocket
	}

	_, err := (*(socket.socket)).Write(data)
	if err != nil {
		return errWriteSocket
	}

	readBytes, err := (*(socket.socket)).Read(replyBuf)
	if readBytes <= 0 || err != nil {
		// ditto
		return errReadSocket
	}

	return int32(readBytes)

}
