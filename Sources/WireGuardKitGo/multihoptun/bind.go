package multihoptun

import (
	"math/rand"
	"net"

	"golang.zx2c4.com/wireguard/conn"

	"gvisor.dev/gvisor/pkg/tcpip/header"
)

type multihopBind struct {
	*MultihopTun
	socketShutdown chan struct{}
}

// Close implements tun.Device
func (st *multihopBind) Close() error {
	select {
	case <-st.socketShutdown:
		return nil
	default:
		close(st.socketShutdown)
	}
	return nil
}

// Open implements conn.Bind.
func (st *multihopBind) Open(port uint16) (fns []conn.ReceiveFunc, actualPort uint16, err error) {
	if port != 0 {
		st.localPort = port
	} else {
		st.localPort = uint16(rand.Uint32()>>16) | 1
	}
	// WireGuard will close existing sockets before bringing up a new device on Bind updates.
	// This guarantees that the socket shutdown channel is always available.
	st.socketShutdown = make(chan struct{})

	actualPort = st.localPort
	fns = []conn.ReceiveFunc{
		func(packets [][]byte, sizes []int, eps []conn.Endpoint) (n int, err error) {
			var batch packetBatch
			var ok bool

			select {
			case <-st.shutdownChan:
			case <-st.socketShutdown:
				return 0, net.ErrClosed
			case batch, ok = <-st.writeRecv:
				break
			}
			if !ok {
				return 0, net.ErrClosed
			}

			packetsToProcess := len(packets)
			if len(batch.packets) < packetsToProcess {
				packetsToProcess = len(batch.packets)
			}

			for idx := 0; idx < packetsToProcess; idx += 1 {
				rxPacket := batch.packets[idx][batch.offset:]
				ipVersion := header.IPVersion(rxPacket)
				if ipVersion == 4 {
					var v4 header.IPv4
					var udp header.UDP
					v4 = rxPacket
					udp = v4.Payload()
					copy(packets[idx], udp.Payload())
					sizes[idx] = len(udp.Payload())

				} else if ipVersion == 6 {
					var v6 header.IPv6
					var udp header.UDP
					v6 = rxPacket
					udp = v6.Payload()
					copy(packets[idx], udp.Payload())
					sizes[idx] = len(udp.Payload())
				}

				eps[idx] = st.endpoint
				n += 1
			}
			batch.packetsCopied = n
			select {
			case batch.completion <- batch:
			case <-st.shutdownChan:
			}

			return
		},
	}

	return fns, actualPort, nil
}

// ParseEndpoint implements conn.Bind.
func (*multihopBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	return conn.NewStdNetBind().ParseEndpoint(s)
}

// Send implements conn.Bind.
func (st *multihopBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	var packetBatch packetBatch
	var ok bool

	select {
	case <-st.shutdownChan:
	case <-st.socketShutdown:
		// it is important to return a net.ErrClosed, since it implements the
		// net.Error interface and indicates that it is not a recoverable error.
		// wg-go uses the net.Error interface to deduce if it should try to send
		// packets again after some time or if it should give up.
		return net.ErrClosed
	case packetBatch, ok = <-st.readRecv:
		break
	}

	if !ok {
		return net.ErrClosed
	}

	var err error
	var size int
	packetBatch.packetsCopied = 0
	for idx := range bufs {
		targetPacket := packetBatch.packets[idx][packetBatch.offset:]
		size, err = st.writePayload(targetPacket[:], bufs[idx])
		if err != nil {
			continue
		}
		packetBatch.sizes[idx] = size
		packetBatch.packetsCopied += 1
	}

	select {
	case packetBatch.completion <- packetBatch:
	case <-st.shutdownChan:
		break
	}

	return err
}

// SetMark implements conn.Bind.
func (*multihopBind) SetMark(mark uint32) error {
	return nil
}
