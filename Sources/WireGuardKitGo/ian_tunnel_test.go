package main

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// ICMP code; move this elsewhere later

func TestPing(t *testing.T) {
	a, _, _ := netstack.CreateNetTUN([]netip.Addr{aIp}, []netip.Addr{}, 1280)
	b, _, _ := netstack.CreateNetTUN([]netip.Addr{bIp}, []netip.Addr{}, 1280)

	configs, endpointConfigs := genConfigs(t)
	aConfig := configs[0] + endpointConfigs[0]
	bConfig := configs[1] + endpointConfigs[1]

	tunnel := wgTurnOnIANFromExistingTunnel(a, aConfig, aIp, nil, 0, 0)

	bDev := device.NewDevice(b, conn.NewStdNetBind(), device.NewLogger(device.LogLevelSilent, ""))

	bDev.IpcSet(bConfig)

	bDev.Up()

	pinger := wgOpenInTunnelICMP(tunnel, cstring("1.2.3.5"))

	result := wgSendAndAwaitInTunnelPing(tunnel, pinger, 1)

	assert.Equal(t, result, int32(1))

	wgCloseInTunnelICMP(pinger)
}

// Test functions for maintaining handle mappings
func TestHandleInsertion(t *testing.T) {
	handles := make(map[int32]string)

	h1 := insertHandle(handles, "foo")
	assert.Equal(t, len(handles), 1)
	h2 := insertHandle(handles, "bar")
	assert.Equal(t, len(handles), 2)
	assert.Equal(t, handles[h1], "foo")
	assert.Equal(t, handles[h2], "bar")
	delete(handles, h2)
	_, ok := handles[h2]
	assert.False(t, ok)
}
