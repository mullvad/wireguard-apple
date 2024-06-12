package main

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
)

type NetstackBind struct {
	*netstack.Net
	socket       *gonet.UDPConn
	peerEndpoint net.UDPAddr
	logger       *device.Logger
}

type NetstackBindAddr struct {
	remoteEndpoint *net.UDPAddr
	localEndpoint  *net.UDPAddr
}

// ClearSrc implements conn.Endpoint.
func (a *NetstackBindAddr) ClearSrc() {
	a.localEndpoint = nil
}

// DstIP implements conn.Endpoint.
func (a *NetstackBindAddr) DstIP() netip.Addr {
	return a.remoteEndpoint.AddrPort().Addr()
}

// DstToBytes implements conn.Endpoint.
func (a *NetstackBindAddr) DstToBytes() []byte {
	b, _ := a.remoteEndpoint.AddrPort().MarshalBinary()
	return b
}

// DstToString implements conn.Endpoint.
func (a *NetstackBindAddr) DstToString() string {
	return a.remoteEndpoint.String()
}

// SrcIP implements conn.Endpoint.
func (a *NetstackBindAddr) SrcIP() netip.Addr {
	return a.remoteEndpoint.AddrPort().Addr()
}

// SrcToString implements conn.Endpoint.
func (a *NetstackBindAddr) SrcToString() string {
	return a.localEndpoint.String()
}

func NewNetstackBind(net *netstack.Net, peerEndpoint net.UDPAddr, logger *device.Logger) NetstackBind {
	return NetstackBind{
		net,
		nil,
		peerEndpoint,
		logger,
	}

}

// BatchSize implements conn.Bind.
func (*NetstackBind) BatchSize() int {
	return 1
}

// Close implements conn.Bind.
func (b *NetstackBind) Close() error {
	if b.socket != nil {
		return b.socket.Close()
	}
	return nil
}

// Open implements conn.Bind.
func (b *NetstackBind) Open(port uint16) (fns []conn.ReceiveFunc, actualPort uint16, err error) {

	bindAddr := netip.AddrPortFrom(netip.IPv4Unspecified(), port)
	listener, err := b.ListenUDPAddrPort(bindAddr)
	if err != nil {
		return []conn.ReceiveFunc{}, 0, err
	}

	listenAddr := listener.LocalAddr().(*net.UDPAddr)
	b.logger.Verbosef("Opened local socket with addr %v", listenAddr)

	b.socket = listener

	recvFunc := func(packets [][]byte, sizes []int, eps []conn.Endpoint) (n int, err error) {
		b.logger.Verbosef("Reading from local socket %v", listenAddr)
		if len(packets) == 0 {
			return
		}
		bytesRead, addr, err := listener.ReadFrom(packets[0])
		udpAddr, ok := addr.(*net.UDPAddr)
		if !ok {
			return 0, errors.New(fmt.Sprintf("Unrecognized UDP addr: %v", addr))
		}
		eps[0] = &NetstackBindAddr{remoteEndpoint: udpAddr, localEndpoint: listenAddr}
		sizes[0] = bytesRead
		if err != nil {
			n = 1
		}
		return
	}

	return []conn.ReceiveFunc{recvFunc}, uint16(listenAddr.Port), nil
}

// ParseEndpoint implements conn.Bind.
func (*NetstackBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	addr, err := net.ResolveUDPAddr("udp", s)
	if err != nil {
		return nil, err
	}

	return &NetstackBindAddr{remoteEndpoint: addr}, nil
}

// Send implements conn.Bind.
// Endpoint argument is ignored, the endpoint is known ahead of time anyway.
func (b *NetstackBind) Send(bufs [][]byte, ep conn.Endpoint) (err error) {
	b.logger.Verbosef("AYYO Sending to %v", ep)
	for idx := range bufs {
		_, err = b.socket.WriteTo(bufs[idx], &b.peerEndpoint)
		if err != nil {
			b.logger.Verbosef("Failed to send to %v: %v", ep, err)
		}
	}
	return

}

// SetMark implements conn.Bind.
func (*NetstackBind) SetMark(mark uint32) error {
	return nil
}

// Parse a wireguard config and return the first endpoint address it finds and
// parses successfully.
func parseEndpointFromGoConfig(config string) *net.UDPAddr {
	scanner := bufio.NewScanner(strings.NewReader(config))
	for scanner.Scan() {
		line := scanner.Text()
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}

		if key == "endpoint" {
			endpoint, err := net.ResolveUDPAddr("udp", value)
			if err == nil && endpoint != nil {
				return endpoint
			}
		}

	}
	return nil
}
