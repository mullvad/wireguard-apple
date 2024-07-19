package main

import (
	"crypto/rand"
	"fmt"
	"io"
	"log"
	"net/netip"
	"os"
	"syscall"
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

func TestUDPSanityDirect(t *testing.T) {
	// Set up UDP directly, as a sanity check that things work as expected

	// result 1: this works fine with no router, just two interfaces
	// result 2: this works fine with a router, through its virtual interface
	// result 3: through a os.Pipe handled by a goroutine: works fine
	a, _, _ := netstack.CreateNetTUN([]netip.Addr{aIp}, []netip.Addr{}, 1280)
	aVirtual, aNet, _ := netstack.CreateNetTUN([]netip.Addr{aIp}, []netip.Addr{}, 1280)
	router := NewRouter(a, aVirtual)

	b, bNet, _ := netstack.CreateNetTUN([]netip.Addr{bIp}, []netip.Addr{}, 1280)
	aDev := device.NewDevice(&router, conn.NewStdNetBind(), device.NewLogger(device.LogLevelSilent, ""))
	bDev := device.NewDevice(b, conn.NewStdNetBind(), device.NewLogger(device.LogLevelSilent, ""))

	configs, endpointConfigs := genConfigs(t)
	aConfig := configs[0] + endpointConfigs[0]
	bConfig := configs[1] + endpointConfigs[1]
	aDev.IpcSet(aConfig)
	bDev.IpcSet(bConfig)

	aDev.Up()
	bDev.Up()

	listener, err := bNet.ListenUDPAddrPort(netip.AddrPortFrom(bIp, 1000))
	if err != nil {
		t.Fatal("Failed to open UDP socket for listening")
	}

	sendSocket, err := aNet.DialUDPAddrPort(netip.AddrPort{}, netip.AddrPortFrom(bIp, 1000))
	if err != nil {
		t.Fatal("Failed to open UDP socket for sending")
	}

	sendRx, sendTx, err := os.Pipe()
	rxShutdown := make(chan struct{})
	sendbuf := make([]byte, 1024)

	go func() { // the sender
		defer sendRx.Close()
		for {
			select {
			case _ = <-rxShutdown:
				return
			default:
			}
			count, err := sendRx.Read(sendbuf)
			if err == io.EOF {
				rxShutdown <- struct{}{}
			}
			sendSocket.Write(sendbuf[:count])
		}
	}()

	size := 20
	txBytes := make([]byte, size)
	rxBytes := make([]byte, size)
	rand.Read(txBytes[:])

	numWritten, err := sendTx.Write(txBytes)
	assert.Nil(t, err)
	assert.Equal(t, numWritten, size)

	numRead, err := listener.Read(rxBytes)
	assert.Nil(t, err)
	assert.Equal(t, numRead, size)

	assert.Equal(t, txBytes, rxBytes)
}

func TestUDPReplicatePipe(t *testing.T) {
	// set up a tunnel handle but unroll its functionality
	a, _, _ := netstack.CreateNetTUN([]netip.Addr{aIp}, []netip.Addr{}, 1280)
	b, bNet, _ := netstack.CreateNetTUN([]netip.Addr{bIp}, []netip.Addr{}, 1280)

	configs, endpointConfigs := genConfigs(t)
	aConfig := configs[0] + endpointConfigs[0]
	bConfig := configs[1] + endpointConfigs[1]

	tunnel := wgTurnOnIANFromExistingTunnel(a, aConfig, aIp)

	bDev := device.NewDevice(b, conn.NewStdNetBind(), device.NewLogger(device.LogLevelSilent, ""))

	bDev.IpcSet(bConfig)

	bDev.Up()

	listener, err := bNet.ListenUDPAddrPort(netip.AddrPortFrom(bIp, 1000))
	if err != nil {
		t.Fatal("Failed to open UDP socket for listening")
	}

	aNet := tunnelHandles[tunnel].virtualNet

	sendSocket, err := aNet.DialUDPAddrPort(netip.AddrPort{}, netip.AddrPortFrom(bIp, 1000))
	if err != nil {
		t.Fatal("Failed to open UDP socket for sending")
	}

	sendRx, sendTx, _ := os.Pipe()
	rxShutdown := make(chan struct{})
	sendbuf := make([]byte, 1024)

	go func() { // the sender
		defer sendRx.Close()
		for {
			select {
			case _ = <-rxShutdown:
				return
			default:
			}
			count, err := sendRx.Read(sendbuf)
			if err == io.EOF {
				rxShutdown <- struct{}{}
			}
			sendSocket.Write(sendbuf[:count])
		}
	}()

	size := 20
	txBytes := make([]byte, size)
	rxBytes := make([]byte, size)
	rand.Read(txBytes[:])

	numWritten, err := sendTx.Write(txBytes)
	assert.Nil(t, err)
	assert.Equal(t, numWritten, size)

	numRead, err := listener.Read(rxBytes)
	assert.Nil(t, err)
	assert.Equal(t, numRead, size)

	assert.Equal(t, txBytes, rxBytes)
}

func TestUDPPipe(t *testing.T) {
	// fails to read correctly
	a, _, _ := netstack.CreateNetTUN([]netip.Addr{aIp}, []netip.Addr{}, 1280)
	b, bNet, _ := netstack.CreateNetTUN([]netip.Addr{bIp}, []netip.Addr{}, 1280)
	// _ := device.NewDevice(a, conn.NewStdNetBind(), device.NewLogger(device.LogLevelSilent, ""))
	bDev := device.NewDevice(b, conn.NewStdNetBind(), device.NewLogger(device.LogLevelVerbose, ""))

	configs, endpointConfigs := genConfigs(t)
	aConfig := configs[0] + endpointConfigs[0]
	bConfig := configs[1] + endpointConfigs[1]
	tunnel := wgTurnOnIANFromExistingTunnel(a, aConfig, aIp)
	bDev.IpcSet(bConfig)
	bDev.Up()

	aAddrPort := netip.AddrPortFrom(aIp, 1000)
	bAddrPort := netip.AddrPortFrom(bIp, 1000)

	_, err := bNet.ListenUDPAddrPort(bAddrPort)
	if err != nil {
		t.Fatal("Failed to open UDP socket for listening")
	}
	_, recvPipe := testOpenInTunnelUDP(tunnel, bAddrPort, aAddrPort)

	fmt.Printf(">> sending to %v", aAddrPort)
	responder, err := bNet.DialUDPAddrPort(netip.AddrPort{}, aAddrPort)
	if err != nil {
		t.Fatal("Failed to open UDP socket for sending")
	}

	size := 20
	txBytes := make([]byte, size)
	rxBytes := make([]byte, size)
	// rand.Read(txBytes[:])

	// numWritten, err := sendPipe.Write(txBytes)
	// assert.Nil(t, err)
	// assert.Equal(t, numWritten, size)

	// numRead, err := listener.Read(rxBytes)
	// assert.Nil(t, err)
	// assert.Equal(t, numRead, size)

	// assert.Equal(t, txBytes, rxBytes)

	// now the other way
	rand.Read(txBytes[:])

	numWritten, err := responder.Write(txBytes)
	assert.Equal(t, numWritten, size)

	numRead, err := recvPipe.Read(rxBytes)
	assert.Nil(t, err)
	assert.Equal(t, numRead, size)

	// assert.Equal(t, txBytes, rxBytes)

}

// ICMP experimentation

func TestICMPRemotePing(t *testing.T) {
	// config data cribbed from Multihop tests
	privateKey := "1082ef213ba31c94d7ef7149f4e2bde968c06027aadbb7d50b00280ece1f2860"
	privateIp := netip.MustParseAddr("10.65.169.61")
	seGotPublic := "e4930f78eee05c86d1e429d46bf34f34ae0be46a949eb785d3f068cda8b8a65e"
	seGotEndpoint := "185.213.154.66:51820"

	endpointCfg := uapiCfg(
		"private_key", privateKey,
		"listen_port", "0",
		"replace_peers", "true",
		"public_key", seGotPublic,
		"endpoint", seGotEndpoint,
		"protocol_version", "1",
		"replace_allowed_ips", "true",
		"allowed_ip", "0.0.0.0/0",
	)

	tun, net, _ := netstack.CreateNetTUN([]netip.Addr{privateIp}, []netip.Addr{}, 1280)
	// 	multihopTun := NewMultihopTun(privateIp, netip.MustParseAddr("185.204.1.203"), 51280, 1280+80)
	dev := device.NewDevice(tun, conn.NewStdNetBind(), device.NewLogger(device.LogLevelVerbose, ""))
	dev.IpcSet(endpointCfg)

	dev.Up()

	sender, err := net.Dial("ping4", "10.64.0.1")
	assert.Nil(t, err)
	receiver, err := net.ListenPing(netstack.PingAddrFromAddr(privateIp))

	ping := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Body: &icmp.Echo{
			ID:   1234,
			Seq:  1,
			Data: make([]byte, 4),
		},
	}
	pingBytes, err := ping.Marshal(nil)

	written, err := sender.Write(pingBytes)
	assert.Nil(t, err)
	assert.Equal(t, written, len(pingBytes))

	readBuff := make([]byte, 1024)
	readBytes, err := receiver.Read(readBuff)
	assert.Nil(t, err)

}

func TestICMPSanityCheckFromFirstPrinciples(t *testing.T) {
	// Attempt to send an ICMP ping directly between netstack devices
	// This currently hangs
	a, aNet, _ := netstack.CreateNetTUN([]netip.Addr{aIp}, []netip.Addr{}, 1280)
	b, bNet, _ := netstack.CreateNetTUN([]netip.Addr{bIp}, []netip.Addr{}, 1280)
	aDev := device.NewDevice(a, conn.NewStdNetBind(), device.NewLogger(device.LogLevelSilent, ""))
	bDev := device.NewDevice(b, conn.NewStdNetBind(), device.NewLogger(device.LogLevelSilent, ""))
	configs, endpointConfigs := genConfigs(t)
	aConfig := configs[0] + endpointConfigs[0]
	bConfig := configs[1] + endpointConfigs[1]
	aDev.IpcSet(aConfig)
	bDev.IpcSet(bConfig)

	aDev.Up()
	bDev.Up()

	sender, err := aNet.Dial("ping4", "192.168.0.5")
	assert.Nil(t, err)
	receiver, err := bNet.ListenPing(netstack.PingAddrFromAddr(bIp))

	ping := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Body: &icmp.Echo{
			ID:   1234,
			Seq:  1,
			Data: make([]byte, 4),
		},
	}
	pingBytes, err := ping.Marshal(nil)

	written, err := sender.Write(pingBytes)
	assert.Nil(t, err)
	assert.Equal(t, written, len(pingBytes))

	readBuff := make([]byte, 1024)
	readBytes, err := receiver.Read(readBuff)
	assert.Nil(t, err)

}

func TestOpenInTunnelICMPPipes(t *testing.T) {
	a, _, _ := netstack.CreateNetTUN([]netip.Addr{aIp}, []netip.Addr{}, 1280)

	b, bNet, _ := netstack.CreateNetTUN([]netip.Addr{bIp}, []netip.Addr{}, 1280)

	// _ := device.NewDevice(a, conn.NewStdNetBind(), device.NewLogger(device.LogLevelSilent, ""))
	bDev := device.NewDevice(b, conn.NewStdNetBind(), device.NewLogger(device.LogLevelVerbose, ""))

	configs, endpointConfigs := genConfigs(t)
	aConfig := configs[0] + endpointConfigs[0]
	// bConfig := configs[1] + endpointConfigs[1]

	tunnel := wgTurnOnIANFromExistingTunnel(a, aConfig, aIp)

	// configureDevices(t, aDev, bDev)
	bDev.Up()

	recvRx, sendTx := openInTunnelICMP(tunnel, "1.2.3.5")

	go func() {
		// Start accepting ICMP connections on B, and reply as if for pings
		pingConn, _ := bNet.ListenPing(netstack.PingAddrFromAddr(bIp))
		pingBuf := make([]byte, 1024)
		n, _ := pingConn.Read(pingBuf)

		fmt.Printf("- read %d bytes\n", n)

		reply := icmp.Message{
			Type: ipv4.ICMPTypeEcho,
			Body: &icmp.Echo{
				ID:   1234,
				Seq:  1,
				Data: make([]byte, 4),
			},
		}

		replyBuf, _ := reply.Marshal(nil)
		pingConn.Write(replyBuf)

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

	sendTx.Write(pingBytes)

	readBuf := make([]byte, 1024)
	// numRead, err := recvFile.Read(readBuf)
	numRead, err := recvRx.Read(readBuf)

	fmt.Printf("err = %v\n", err)

	assert.Greater(t, numRead, 0)

	fmt.Printf("bytes received: %d\n", numRead)
}

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
	// sendFile := os.NewFile(send_fd, "send")
	// recvFile := os.NewFile(recv_fd, "recv")

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
	// sendFile.Write(pingBytes)
	syscall.Write(int(send_fd), pingBytes)

	// time.Sleep(1)
	// sendFile.Write(pingBytes)

	readBuf := make([]byte, 1024)
	// numRead, err := recvFile.Read(readBuf)

	numRead, err := syscall.Read(int(recv_fd), readBuf)

	fmt.Printf("err = %v\n", err)

	assert.Greater(t, numRead, 0)

	fmt.Printf("bytes received: %d\n", numRead)

	// parse the packet, check that ID and Seq match up

}
