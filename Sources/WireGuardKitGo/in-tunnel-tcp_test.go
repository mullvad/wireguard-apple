package main

import (
	"net/netip"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

func TestInTunnelTCP(t *testing.T) {

	aIp := netip.AddrFrom4([4]byte{1, 2, 3, 4})
	bIp := netip.AddrFrom4([4]byte{1, 2, 3, 5})

	a, _, _ := netstack.CreateNetTUN([]netip.Addr{aIp}, []netip.Addr{}, 1280)
	b, bNet, _ := netstack.CreateNetTUN([]netip.Addr{bIp}, []netip.Addr{}, 1280)

	configs, endpointConfigs := genConfigs(t)
	aConfig := configs[0] + endpointConfigs[0]
	bConfig := configs[1] + endpointConfigs[1]

	tunnel := wgTurnOnIANFromExistingTunnel(a, aConfig, aIp, nil, 0, 0)

	bDev := device.NewDevice(b, conn.NewStdNetBind(), device.NewLogger(device.LogLevelSilent, ""))

	bDev.IpcSet(bConfig)

	bDev.Up()
	listenAddrString := "1.2.3.5:9090"
	listenAddr := netip.MustParseAddrPort(listenAddrString)

	listener, err := bNet.ListenTCPAddrPort(listenAddr)
	if err != nil {
		t.Fatalf("Failed to start listening for a connection")
	}

	go func() {
		connection, err := listener.Accept()
		if err != nil {
			listener.Close()
		}
		readBuffer := make([]byte, 1024)
		bytesRead, _ := connection.Read(readBuffer)
		_, _ = connection.Write(readBuffer[:bytesRead])
	}()

	tcpClient := wgOpenInTunnelTCP(tunnel, cstring(listenAddrString))
	if tcpClient < 0 {
		t.Fatalf("Expected non-zero tcpClient value, got %v", tcpClient)
	}

	sendSlice := make([]byte, 1024)
	for i := range sendSlice {
		sendSlice[i] = byte(i % 256)
	}
	result := wgSendInTunnelTCP(tunnel, tcpClient, unsafe.SliceData(sendSlice), len(sendSlice))
	if result < 0 {
		t.Fatalf("Failed to send in tunnel TCP data")
	}

	recvSlice := make([]byte, 1024)
	result = wgRecvInTunnelTCP(tunnel, tcpClient, unsafe.SliceData(recvSlice), len(recvSlice))
	if result < 0 {
		t.Fatalf("Failed to receive in tunnel TCP data")
	}
	if int(result) != len(sendSlice) {
		t.Fatalf("Expected to receive %v bytes, instead got %v", len(sendSlice), result)
	}

	assert.Equal(t, sendSlice, recvSlice)

	wgCloseInTunnelTCP(tunnel, tcpClient)
}
