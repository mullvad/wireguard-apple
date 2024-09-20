package main

import "C"

import (
	"bytes"
	"net"
	"time"

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

	result := insertHandle(socketHandles, socketHandle{tunnelHandle, socketTypeICMP, &conn})
	if result < 0 {
		conn.Close()
	}
	return result
}

//export wgCloseInTunnelICMP
func wgCloseInTunnelICMP(socketHandle int32) bool {
	return wgCloseInTunnelSocketHandle(socketHandle)
}

// returns the sequence number or an error code
func parsePingResponse(socket *net.Conn, pingdata []byte) int {
	readBuff := make([]byte, 1024)
	readBytes, err := (*(socket)).Read(readBuff)
	if readBytes <= 0 || err != nil {
		return errReadSocket
	}
	replyPacket, err := icmp.ParseMessage(1, readBuff[:readBytes])
	if err != nil {
		return errICMPResponseFormat
	}
	replyPing, ok := replyPacket.Body.(*icmp.Echo)
	if !ok {
		return errICMPResponseFormat
	}
	if !bytes.Equal(replyPing.Data, pingdata) {
		return errICMPResponseContent
	}
	return replyPing.Seq
}

// this returns the sequence number or a negative value if an error occurred
//
//export wgSendAndAwaitInTunnelPing
func wgSendAndAwaitInTunnelPing(tunnelHandle int32, socketHandle int32, sequenceNumber uint16) int32 {
	socket, ok := socketHandles[socketHandle]
	if !ok || socket.socketType != socketTypeICMP {
		return errNoMatchingSocket
	}
	dataLength := 16
	pingdata := make([]byte, dataLength)
	_, err := rng.Read(pingdata)
	pingid := rng.Int()

	resultChannel := make(chan int)
	shutdownChannel := make(chan struct{})

	// the reading goroutine
	go func() {
		for {
			select {
			case <-shutdownChannel:
				return
			default:
			}
			result := parsePingResponse(socket.socket, pingdata)
			if result == errICMPResponseContent || result >= 0 {
				resultChannel <- result
				return
			}
		}
	}()

	// probably not worth checking for an error here
	ping := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Body: &icmp.Echo{
			ID:   pingid,
			Seq:  int(sequenceNumber),
			Data: pingdata,
		},
	}
	pingBytes, err := ping.Marshal(nil)
	_, err = (*(socket.socket)).Write(pingBytes)
	if err != nil {
		return errWriteSocket
	}
	defer close(shutdownChannel)
	select {
	case result := <-resultChannel:
		return int32(result)
	case <-time.After(10 * time.Second):
		return errICMPTimeout
	}
}
