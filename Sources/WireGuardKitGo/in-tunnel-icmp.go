package main

import "C"

import (
	"net"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

//export wgOpenInTunnelICMP
func wgOpenInTunnelICMP(tunnelHandle int32, address *C.char) int32 {
	handle, ok := tunnelHandles[tunnelHandle]
	if !ok {
		return errNoSuchTunnel
	}
	if handle.virtualNet == nil {
		return errNoTunnelVirtualInterface
	}
	conn, _ := handle.virtualNet.Dial("ping4", C.GoString(address))

	result := insertHandle(icmpHandles, icmpHandle{tunnelHandle, conn})
	if result < 0 {
		conn.Close()
	}
	return result
}

//export wgCloseInTunnelICMP
func wgCloseInTunnelICMP(socketHandle int32) bool {
	socket, ok := icmpHandles[socketHandle]
	if ok {
		socket.icmpSocket.Close()
		delete(icmpHandles, socketHandle)
	}
	return ok
}

// returns the sequence number or an error code
func parsePingResponse(socket net.Conn) int32 {
	readBuff := make([]byte, 1024)
	readBytes, err := socket.Read(readBuff)
	if readBytes <= 0 || err != nil {
		return errICMPReadSocket
	}
	replyPacket, err := icmp.ParseMessage(1, readBuff[:readBytes])
	if err != nil {
		return errICMPResponseFormat
	}
	replyPing, ok := replyPacket.Body.(*icmp.Echo)
	if !ok {
		return errICMPResponseFormat
	}
	return int32(replyPing.Seq)
}

//export wgRecvInTunnelPing
func wgRecvInTunnelPing(tunnelHandel int32, socketHandle int32) int32 {
			handle, ok := icmpHandles[socketHandle]
			if !ok {
				return errICMPOpenSocket
			}

			for {
				result := recvInTunnelPing(handle.icmpSocket)
				if result != errICMPResponseFormat {
					return result
				}
			}
}

func recvInTunnelPing(ping net.Conn)  int32 {
			return parsePingResponse(ping)
}

// this returns the sequence number or a negative value if an error occurred
// This function can be called concurrently.
//
//export wgSendInTunnelPing
func wgSendInTunnelPing(tunnelHandle int32, socketHandle int32, pingId uint16, pingSize int, sequenceNumber uint16) int32 {
	socket, ok := icmpHandles[socketHandle]
	if !ok {
		return errICMPOpenSocket
	}
	pingdata := make([]byte, pingSize)
	_, err := rng.Read(pingdata)


	ping := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Body: &icmp.Echo{
			ID:   int(pingId),
			Seq:  int(sequenceNumber),
			Data: pingdata,
		},
	}
	pingBytes, err := ping.Marshal(nil)
	if err != nil {
		return errICMPWriteSocket
	}
	_, err = socket.icmpSocket.Write(pingBytes)
	if err != nil {
		return errICMPWriteSocket
	}
	return 0
}

