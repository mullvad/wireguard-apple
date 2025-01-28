package main

import (
	"net/netip"
	"time"
	"unsafe"

	"testing"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// Verify that closing a socket will terminate any in-flight reads.
func TestIcmpSocketCloseTerminatesRead(t *testing.T) {
	_, virtualNet, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("1.2.3.3")}, []netip.Addr{}, 1280)
	if err != nil {
		t.Fatalf("Failed to initialize ")
	}
	conn, _ := virtualNet.Dial("ping4", "1.2.3.4")
	closeChan := make(chan int32)
	go func() {
		err := recvInTunnelPing(conn)
		closeChan <- err
	}()
	// the sleep is a horrible hack to try and ensure the read is actually in flight
	time.Sleep(time.Second * 1)
	conn.Close()

	closeResult := <-closeChan
	if closeResult != errICMPReadSocket {
		t.Fatalf("Expected the ICMP socket read to fail with error %d , thus expected a negative erorr code, instead got %d", errICMPReadSocket, closeResult)
	}
}

// Verify that closing a socket will fail any subsequent reads.
func TestIcmpSocketCloseFailsReadImmediately(t *testing.T) {
	_, virtualNet, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("1.2.3.3")}, []netip.Addr{}, 1280)
	if err != nil {
		t.Fatalf("Failed to initialize ")
	}
	conn, _ := virtualNet.Dial("ping4", "1.2.3.4")
	conn.Close()
	recvResult := recvInTunnelPing(conn)

	if recvResult >= 0 {
		t.Fatalf("Expected the ICMP socket read to fail with an error, thus expected a negative erorr code, instead got %d", err)
	}
}

func TestIcmpSocketParse(t *testing.T) {
	aIp := netip.AddrFrom4([4]byte{1, 2, 3, 4})
	bIp := netip.AddrFrom4([4]byte{1, 2, 3, 5})

	a, _, _ := netstack.CreateNetTUN([]netip.Addr{aIp}, []netip.Addr{}, 1280)
	b, _, _ := netstack.CreateNetTUN([]netip.Addr{bIp}, []netip.Addr{}, 1280)

	configs, endpointConfigs := genConfigs(t)
	aConfig := configs[0] + endpointConfigs[0]
	bConfig := configs[1] + endpointConfigs[1]

	tunnel := wgTurnOnIANFromExistingTunnel(a, aConfig, aIp, nil)

	bDev := device.NewDevice(b, conn.NewStdNetBind(), device.NewLogger(device.LogLevelSilent, ""))

	bDev.IpcSet(bConfig)
	bDev.Up()

	pingableHost := []byte(bIp.String())
	pingableHost = append(pingableHost, 0)
	icmpSocket := wgOpenInTunnelICMP(tunnel, (*_Ctype_char)(unsafe.Pointer(unsafe.SliceData(pingableHost))))

	go func() {
		id := int32(133)
		seq := uint16(1)
		for {
			result := wgSendInTunnelPing(tunnel, icmpSocket, uint16(id), id, seq)
			seq += 1
			if result < 0 {
				return
			}
		}
	}()

	result := wgRecvInTunnelPing(tunnel, icmpSocket)
	if result < 0 {
		t.Fatalf("Expected non zero result - %v", result)
	}
}
