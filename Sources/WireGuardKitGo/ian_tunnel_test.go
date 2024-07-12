package main

import (
	"fmt"
	"log"
	"net/netip"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// var aIp = netip.AddrFrom4([4]byte{1, 2, 3, 4})
// var bIp = netip.AddrFrom4([4]byte{1, 2, 3, 5})

// these are copied from router_test. Perhaps they should be moved to a testing support file?

// genConfigs generates a pair of configs that connect to each other.
// The configs use distinct, probably-usable ports.
// func genConfigs(tb testing.TB) (cfgs, endpointCfgs [2]string) {
// 	var key1, key2 device.NoisePrivateKey

// 	_, err := rand.Read(key1[:])
// 	if err != nil {
// 		tb.Errorf("unable to generate private key random bytes: %v", err)
// 	}
// 	_, err = rand.Read(key2[:])
// 	if err != nil {
// 		tb.Errorf("unable to generate private key random bytes: %v", err)
// 	}

// 	port1 := getFreeLocalUdpPort(tb)
// 	port2 := getFreeLocalUdpPort(tb)

// 	pub1, pub2 := publicKey(&key1), publicKey(&key2)

// 	cfgs[0] = uapiCfg(
// 		"private_key", hex.EncodeToString(key1[:]),
// 		"listen_port", fmt.Sprintf("%d", port1),
// 		"replace_peers", "true",
// 		"public_key", hex.EncodeToString(pub2[:]),
// 		"protocol_version", "1",
// 		"replace_allowed_ips", "true",
// 		"allowed_ip", "0.0.0.0/0",
// 	)
// 	endpointCfgs[0] = uapiCfg(
// 		"public_key", hex.EncodeToString(pub2[:]),
// 		"endpoint", fmt.Sprintf("127.0.0.1:%d", port2),
// 	)
// 	cfgs[1] = uapiCfg(
// 		"private_key", hex.EncodeToString(key2[:]),
// 		"listen_port", fmt.Sprintf("%d", port2),
// 		"replace_peers", "true",
// 		"public_key", hex.EncodeToString(pub1[:]),
// 		"protocol_version", "1",
// 		"replace_allowed_ips", "true",
// 		"allowed_ip", "0.0.0.0/0",
// 	)
// 	endpointCfgs[1] = uapiCfg(
// 		"public_key", hex.EncodeToString(pub1[:]),
// 		"endpoint", fmt.Sprintf("127.0.0.1:%d", port1),
// 	)
// 	return
// }

// func publicKey(sk *device.NoisePrivateKey) (pk device.NoisePublicKey) {
// 	apk := (*[device.NoisePublicKeySize]byte)(&pk)
// 	ask := (*[device.NoisePrivateKeySize]byte)(sk)
// 	curve25519.ScalarBaseMult(apk, ask)
// 	return
// }

// func configureDevices(t testing.TB, aDev *device.Device, bDev *device.Device) {
// 	configs, endpointConfigs := genConfigs(t)
// 	aConfig := configs[0] + endpointConfigs[0]
// 	bConfig := configs[1] + endpointConfigs[1]
// 	aDev.IpcSet(aConfig)
// 	bDev.IpcSet(bConfig)
// }

// ICMP code; move this elsewhere later

func TestOpenInTunnelICMP(t *testing.T) {

	a, _, _ := netstack.CreateNetTUN([]netip.Addr{aIp}, []netip.Addr{}, 1280)

	b, _, _ := netstack.CreateNetTUN([]netip.Addr{bIp}, []netip.Addr{}, 1280)

	// _ := device.NewDevice(a, conn.NewStdNetBind(), device.NewLogger(device.LogLevelSilent, ""))
	bDev := device.NewDevice(b, conn.NewStdNetBind(), device.NewLogger(device.LogLevelSilent, ""))

	configs, endpointConfigs := genConfigs(t)
	aConfig := configs[0] + endpointConfigs[0]
	// bConfig := configs[1] + endpointConfigs[1]

	tunnel := wgTurnOnIANFromExistingTunnel(a, aConfig, aIp)

	// configureDevices(t, aDev, bDev)

	bDev.Up()

	var recv_fd uintptr
	var send_fd uintptr

	// do the test here
	wgOpenInTunnelICMP(tunnel, "1.2.3.5", &recv_fd, &send_fd)
	sendFile := os.NewFile(send_fd, "send")
	recvFile := os.NewFile(recv_fd, "recv")

	// listen for ICMP connections on interface B

	// do we need to respond to pings manually? If so, implement the below
	go func() {
		// Start accepting ICMP connections on B, and reply as if for pings

	}()

	ping := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Body: &icmp.Echo{
			ID:   1234,
			Seq:  1,
			Data: make([]byte, 4),
		},
	}
	pingBytes, err := ping.Marshal(nil)
	if err != nil {
		log.Fatal("ping.Marshal failed")
	}
	sendFile.Write(pingBytes)

	var readBuf []byte
	numRead, err := recvFile.Read(readBuf)

	assert.Greater(t, numRead, 0)

	fmt.Printf("bytes received: %d", numRead)

	// parse the packet, check that ID and Seq match up

}
