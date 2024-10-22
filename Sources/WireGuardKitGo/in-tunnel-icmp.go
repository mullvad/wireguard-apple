package main

import "C"

import (
	"net"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

//export wgOpenInTunnelICMP
func wgOpenInTunnelICMP(tunnelHandle int32, address *C.char) int32 {
	tun := tunnels.Get(tunnelHandle)
	if tun == nil {
		return errNoSuchTunnel
	}

	if tun.VirtualNet == nil {
		return errNoTunnelVirtualInterface
	}

	return tun.AddSocket(func(vnet *netstack.Net) (net.Conn, error) {
		conn, _ := vnet.Dial("ping4", C.GoString(address))
		return conn, nil
	})
}

//export wgCloseInTunnelICMP
func wgCloseInTunnelICMP(tunnelHandle int32, socketHandle int32) bool {
	tun := tunnels.Get(tunnelHandle)
	if tun == nil {
		return false
	}
	return tun.RemoveAndCloseSocket(socketHandle)
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

// This function blocks until the ICMP socket is closed or an ICMP echo-response is received.
//
//export wgRecvInTunnelPing
func wgRecvInTunnelPing(tunnelHandel int32, socketHandle int32) int32 {
	tun := tunnels.Get(tunnelHandel)
	if tun == nil {
		return errNoSuchTunnel
	}
	socket, ok := tun.GetSocket(socketHandle)
	if !ok {
		return errICMPOpenSocket
	}

	for {
		// Receive ICMP packets until an echo-response is received
		result := recvInTunnelPing(socket)
		// Only break the loop if the error has nothing to do with the ICMP response format.
		// It should ignore malformed responses and non-echo-responses.
		if result != errICMPResponseFormat {
			return result
		}
	}
}

func recvInTunnelPing(ping net.Conn) int32 {
	return parsePingResponse(ping)
}

// This function returns a negative value if an error occurred. Otherwise, it returns 0.
// This function can be called concurrently.
//
//export wgSendInTunnelPing
func wgSendInTunnelPing(tunnelHandle int32, socketHandle int32, pingId uint16, pingSize int, sequenceNumber uint16) int32 {
	tun := tunnels.Get(tunnelHandle)
	if tun == nil {
		return errNoSuchTunnel
	}
	socket, ok := tun.GetSocket(socketHandle)
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
	_, err = socket.Write(pingBytes)
	if err != nil {
		return errICMPWriteSocket
	}
	return 0
}
