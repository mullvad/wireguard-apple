package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"runtime/pprof"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

var aIp = netip.AddrFrom4([4]byte{1, 2, 3, 4})
var bIp = netip.AddrFrom4([4]byte{1, 2, 3, 5})
var listenPort = uint16(1000)

func TestPacketBatchTruncate(t *testing.T) {
	pb := PacketBatch{
		[][]byte{{0, 1, 2, 3}, {9, 8, 7}, {4, 5, 6, 7, 8}},
		[]int{4, 3, 5},
		true,
	}
	overflow := pb.truncate(2, func() *PacketBatch { return new(PacketBatch) })

	assert.Equal(t, pb, PacketBatch{
		[][]byte{{0, 1, 2, 3}, {9, 8, 7}},
		[]int{4, 3},
		true,
	}, "Truncated PacketBatch")
	assert.Equal(t, *overflow, PacketBatch{
		[][]byte{{4, 5, 6, 7, 8}},
		[]int{5},
		true,
	}, "Overflow PacketBatch")
}

func TestPacketBatchTruncateNoOp(t *testing.T) {
	pb := PacketBatch{
		[][]byte{{0, 1, 2, 3}, {9, 8, 7}, {4, 5, 6, 7, 8}},
		[]int{4, 3, 5},
		false,
	}
	overflow := pb.truncate(5, func() *PacketBatch { return new(PacketBatch) })

	assert.Equal(t, pb, PacketBatch{
		[][]byte{{0, 1, 2, 3}, {9, 8, 7}, {4, 5, 6, 7, 8}},
		[]int{4, 3, 5},
		false,
	}, "Truncated PacketBatch")
	assert.Nil(t, overflow, "Overflow PacketBatch")

	overflow2 := pb.truncate(3, func() *PacketBatch { return new(PacketBatch) })

	assert.Equal(t, pb, PacketBatch{
		[][]byte{{0, 1, 2, 3}, {9, 8, 7}, {4, 5, 6, 7, 8}},
		[]int{4, 3, 5},
		false,
	}, "Truncated PacketBatch")
	assert.Nil(t, overflow2, "Overflow PacketBatch")
}

func uapiCfg(cfg ...string) string {
	if len(cfg)%2 != 0 {
		panic("odd number of args to uapiReader")
	}
	buf := new(bytes.Buffer)
	for i, s := range cfg {
		buf.WriteString(s)
		sep := byte('\n')
		if i%2 == 0 {
			sep = '='
		}
		buf.WriteByte(sep)
	}
	return buf.String()
}

// genConfigs generates a pair of configs that connect to each other.
// The configs use distinct, probably-usable ports.
func genConfigs(tb testing.TB) (cfgs, endpointCfgs [2]string) {
	var key1, key2 device.NoisePrivateKey

	_, err := rand.Read(key1[:])
	if err != nil {
		tb.Errorf("unable to generate private key random bytes: %v", err)
	}
	_, err = rand.Read(key2[:])
	if err != nil {
		tb.Errorf("unable to generate private key random bytes: %v", err)
	}

	port1 := getFreeLocalUdpPort(tb)
	port2 := getFreeLocalUdpPort(tb)

	pub1, pub2 := publicKey(&key1), publicKey(&key2)

	cfgs[0] = uapiCfg(
		"private_key", hex.EncodeToString(key1[:]),
		"listen_port", fmt.Sprintf("%d", port1),
		"replace_peers", "true",
		"public_key", hex.EncodeToString(pub2[:]),
		"protocol_version", "1",
		"replace_allowed_ips", "true",
		"allowed_ip", "0.0.0.0/0",
	)
	endpointCfgs[0] = uapiCfg(
		"public_key", hex.EncodeToString(pub2[:]),
		"endpoint", fmt.Sprintf("127.0.0.1:%d", port2),
	)
	cfgs[1] = uapiCfg(
		"private_key", hex.EncodeToString(key2[:]),
		"listen_port", fmt.Sprintf("%d", port2),
		"replace_peers", "true",
		"public_key", hex.EncodeToString(pub1[:]),
		"protocol_version", "1",
		"replace_allowed_ips", "true",
		"allowed_ip", "0.0.0.0/0",
	)
	endpointCfgs[1] = uapiCfg(
		"public_key", hex.EncodeToString(pub1[:]),
		"endpoint", fmt.Sprintf("127.0.0.1:%d", port1),
	)
	return
}

func publicKey(sk *device.NoisePrivateKey) (pk device.NoisePublicKey) {
	apk := (*[device.NoisePublicKeySize]byte)(&pk)
	ask := (*[device.NoisePrivateKeySize]byte)(sk)
	curve25519.ScalarBaseMult(apk, ask)
	return
}

func configureDevices(t testing.TB, aDev *device.Device, bDev *device.Device) {
	configs, endpointConfigs := genConfigs(t)
	aConfig := configs[0] + endpointConfigs[0]
	bConfig := configs[1] + endpointConfigs[1]
	aDev.IpcSet(aConfig)
	bDev.IpcSet(bConfig)
}

func goroutineLeakCheck(t *testing.T) {
	goroutines := func() (int, []byte) {
		p := pprof.Lookup("goroutine")
		b := new(bytes.Buffer)
		p.WriteTo(b, 1)
		return p.Count(), b.Bytes()
	}

	startGoroutines, startStacks := goroutines()
	t.Cleanup(func() {
		if t.Failed() {
			return
		}
		// Give goroutines time to exit, if they need it.
		for i := 0; i < 10000; i++ {
			if runtime.NumGoroutine() <= startGoroutines {
				return
			}
			time.Sleep(1 * time.Millisecond)
		}
		endGoroutines, endStacks := goroutines()
		t.Logf("starting stacks:\n%s\n", startStacks)
		t.Logf("ending stacks:\n%s\n", endStacks)
		t.Fatalf("expected %d goroutines, got %d, leak?", startGoroutines, endGoroutines)
	})
}

func TestGoroutineLeaksBaseline(t *testing.T) {
	// run the goroutine leak check on setting up a baseline WireGuardGo connection
	goroutineLeakCheck(t)

	a, aNet, _ := netstack.CreateNetTUN([]netip.Addr{aIp}, []netip.Addr{}, 1280)
	b, bNet, _ := netstack.CreateNetTUN([]netip.Addr{bIp}, []netip.Addr{}, 1280)

	// aDev := device.NewDevice(a, conn.NewStdNetBind(), device.NewLogger(device.LogLevelVerbose, ""))
	aDev := device.NewDevice(a, conn.NewStdNetBind(), device.NewLogger(device.LogLevelVerbose, ""))
	bDev := device.NewDevice(b, conn.NewStdNetBind(), device.NewLogger(device.LogLevelVerbose, ""))

	configureDevices(t, aDev, bDev)

	aDev.Up()
	bDev.Up()

	listener, err := bNet.ListenUDPAddrPort(netip.AddrPortFrom(bIp, listenPort))
	if err != nil {
		t.Fatal("Failed to open UDP socket for listening")
	}

	udpSocket, err := aNet.DialUDPAddrPort(netip.AddrPortFrom(aIp, 1234), netip.AddrPortFrom(bIp, listenPort))
	if err != nil {
		t.Fatal("Failed to open UDP socket for sending")
	}

	for i := 0; i < 20; i++ {

		size := 4000
		txBytes := make([]byte, size)
		rand.Read(txBytes[:])

		_, err = udpSocket.Write(txBytes)
		if err != nil {
			t.Fatal("Failed to send UDP packet")
		}

		buff := make([]byte, size)
		bytesRead, err := listener.Read(buff)
		if err != nil {
			t.Fatal("Failed to read from listening socket")
		}
		if !bytes.Equal(buff, txBytes) {
			t.Fatalf("Unexpected message received, expected %v, got %v", txBytes, buff)
		}
		if bytesRead != size {
			t.Fatalf("Failed to read %d bytes from UDP", size)
		}
	}

	udpSocket.Close()
	listener.Close()
	bDev.Close()
	aDev.Close()
}

func TestGoroutineLeaks(t *testing.T) {
	goroutineLeakCheck(t)

	a, aNet, _ := netstack.CreateNetTUN([]netip.Addr{aIp}, []netip.Addr{}, 1280)
	aVirtual, _, _ := netstack.CreateNetTUN([]netip.Addr{aIp}, []netip.Addr{}, 1280)

	router := NewRouter(a, aVirtual)

	b, bNet, _ := netstack.CreateNetTUN([]netip.Addr{bIp}, []netip.Addr{}, 1280)

	// aDev := device.NewDevice(a, conn.NewStdNetBind(), device.NewLogger(device.LogLevelVerbose, ""))
	aDev := device.NewDevice(&router, conn.NewStdNetBind(), device.NewLogger(device.LogLevelVerbose, ""))
	bDev := device.NewDevice(b, conn.NewStdNetBind(), device.NewLogger(device.LogLevelVerbose, ""))

	configureDevices(t, aDev, bDev)

	aDev.Up()
	bDev.Up()

	listener, err := bNet.ListenUDPAddrPort(netip.AddrPortFrom(bIp, listenPort))
	if err != nil {
		t.Fatal("Failed to open UDP socket for listening")
	}

	udpSocket, err := aNet.DialUDPAddrPort(netip.AddrPortFrom(aIp, 1234), netip.AddrPortFrom(bIp, listenPort))
	if err != nil {
		t.Fatal("Failed to open UDP socket for sending")
	}

	for i := 0; i < 20; i++ {

		size := 4000
		txBytes := make([]byte, size)
		rand.Read(txBytes[:])

		_, err = udpSocket.Write(txBytes)
		if err != nil {
			t.Fatal("Failed to send UDP packet")
		}

		buff := make([]byte, size)
		bytesRead, err := listener.Read(buff)
		if err != nil {
			t.Fatal("Failed to read from listening socket")
		}
		if !bytes.Equal(buff, txBytes) {
			t.Fatalf("Unexpected message received, expected %v, got %v", txBytes, buff)
		}
		if bytesRead != size {
			t.Fatalf("Failed to read %d bytes from UDP", size)
		}
	}

	bDev.Close()
	aDev.Close()
}

func setUpRouterDevices(t testing.TB) (*netstack.Net, *netstack.Net, *device.Device, *netstack.Net, *device.Device) {
	a, aNet, _ := netstack.CreateNetTUN([]netip.Addr{aIp}, []netip.Addr{}, 1280)
	aVirtual, aNetV, _ := netstack.CreateNetTUN([]netip.Addr{aIp}, []netip.Addr{}, 1280)

	router := NewRouter(a, aVirtual)

	b, bNet, _ := netstack.CreateNetTUN([]netip.Addr{bIp}, []netip.Addr{}, 1280)

	aDev := device.NewDevice(&router, conn.NewStdNetBind(), device.NewLogger(device.LogLevelVerbose, ""))
	bDev := device.NewDevice(b, conn.NewStdNetBind(), device.NewLogger(device.LogLevelVerbose, ""))

	configureDevices(t, aDev, bDev)

	aDev.Up()
	bDev.Up()

	return aNet, aNetV, aDev, bNet, bDev
}

func TestUDP(t *testing.T) {

	aNet, _, aDev, bNet, bDev := setUpRouterDevices(t)

	listener, err := bNet.ListenUDPAddrPort(netip.AddrPortFrom(bIp, listenPort))
	if err != nil {
		t.Fatal("Failed to open UDP socket for listening")
	}

	udpSocket, err := aNet.DialUDPAddrPort(netip.AddrPortFrom(aIp, 1234), netip.AddrPortFrom(bIp, listenPort))
	if err != nil {
		t.Fatal("Failed to open UDP socket for sending")
	}

	for i := 0; i < 20; i++ {

		size := 4000
		txBytes := make([]byte, size)
		rand.Read(txBytes[:])

		_, err = udpSocket.Write(txBytes)
		if err != nil {
			t.Fatal("Failed to send UDP packet")
		}

		buff := make([]byte, size)
		bytesRead, err := listener.Read(buff)
		if err != nil {
			t.Fatal("Failed to read from listening socket")
		}
		if !bytes.Equal(buff, txBytes) {
			t.Fatalf("Unexpected message received, expected %v, got %v", txBytes, buff)
		}
		if bytesRead != size {
			t.Fatalf("Failed to read %d bytes from UDP", size)
		}
	}

	bDev.Close()
	aDev.Close()
}

func BenchmarkUDPBaseline(b *testing.B) {

	a, aNet, _ := netstack.CreateNetTUN([]netip.Addr{aIp}, []netip.Addr{}, 1280)

	db, bNet, _ := netstack.CreateNetTUN([]netip.Addr{bIp}, []netip.Addr{}, 1280)

	aDev := device.NewDevice(a, conn.NewStdNetBind(), device.NewLogger(device.LogLevelSilent, ""))
	bDev := device.NewDevice(db, conn.NewStdNetBind(), device.NewLogger(device.LogLevelSilent, ""))

	configureDevices(b, aDev, bDev)

	aDev.Up()
	bDev.Up()

	listener, err := bNet.ListenUDPAddrPort(netip.AddrPortFrom(bIp, listenPort))
	if err != nil {
		b.Fatal("Failed to open UDP socket for listening")
	}

	udpSocket, err := aNet.DialUDPAddrPort(netip.AddrPortFrom(aIp, 1234), netip.AddrPortFrom(bIp, listenPort))
	if err != nil {
		b.Fatal("Failed to open UDP socket for sending")
	}

	size := 1000
	txBytes := make([]byte, size)
	rxBytes := make([]byte, size)

	for i := 0; i < b.N; i++ {
		rand.Read(txBytes[:])

		_, err = udpSocket.Write(txBytes)
		if err != nil {
			b.Fatal("Failed to send UDP packet")
		}

		_, err = listener.Read(rxBytes)
		if err != nil {
			b.Fatal("Failed to read from listening socket")
		}
	}
	bDev.Close()
	aDev.Close()
}

func BenchmarkUDP(b *testing.B) {
	aNet, _, aDev, bNet, bDev := setUpRouterDevices(b)

	listener, err := bNet.ListenUDPAddrPort(netip.AddrPortFrom(bIp, listenPort))
	if err != nil {
		b.Fatal("Failed to open UDP socket for listening")
	}

	udpSocket, err := aNet.DialUDPAddrPort(netip.AddrPortFrom(aIp, 1234), netip.AddrPortFrom(bIp, listenPort))
	if err != nil {
		b.Fatal("Failed to open UDP socket for sending")
	}

	size := 1000
	txBytes := make([]byte, size)
	rxBytes := make([]byte, size)

	for i := 0; i < b.N; i++ {
		rand.Read(txBytes[:])

		_, err = udpSocket.Write(txBytes)
		if err != nil {
			b.Fatal("Failed to send UDP packet")
		}

		_, err = listener.Read(rxBytes)
		if err != nil {
			b.Fatal("Failed to read from listening socket")
		}
	}
	bDev.Close()
	aDev.Close()
}

func TestIpcGet(t *testing.T) {
	aNet, _, aDev, bNet, _ := setUpRouterDevices(t)

	testTcpTraffic(t, bNet, aNet, bIp)

	settings, err := aDev.IpcGet()
	if err != nil {
		t.Fatalf("Failed to obtain wireguar device's settings")
	}

	if len(settings) == 0 {
		t.Fatalf("Settings are empty")
	}
}

func TestTCPReal(t *testing.T) {
	aNet, _, aDev, bNet, bDev := setUpRouterDevices(t)

	testTcpTraffic(t, aNet, bNet, aIp)

	bDev.Close()
	aDev.Close()
}

func TestTCPVirtual(t *testing.T) {
	_, aNetV, aDev, bNet, bDev := setUpRouterDevices(t)

	testTcpTraffic(t, bNet, aNetV, bIp)

	bDev.Close()
	aDev.Close()
}

func testTcpTraffic(t *testing.T, serverNet, clientNet *netstack.Net, serverIP netip.Addr) {
	serverErrChan := make(chan error)
	listener, err := serverNet.ListenTCPAddrPort(netip.AddrPortFrom(serverIP, 80))
	if err != nil {
		t.Fatalf("Failed to listen for TCP connections: %v", err)
	}

	firstPayload := make([]byte, 100)
	rand.Read(firstPayload[:])
	secondPayload := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	thirdPayload := make([]byte, 100)
	rand.Read(thirdPayload[:])

	go func() {
		defer close(serverErrChan)
		conn, err := listener.Accept()
		if err != nil {
			serverErrChan <- err
			return
		}
		buff := make([]byte, 128)
		bytesRead, err := conn.Read(buff)
		if err != nil {
			serverErrChan <- err
			return
		}

		if !bytes.Equal(firstPayload, buff[:bytesRead]) {
			serverErrChan <- errors.New(fmt.Sprintf("Received unexpected bytes, got %v, expected %v", buff[:100], firstPayload))
		}

		_, err = conn.Write(secondPayload)
		if err != nil {
			serverErrChan <- err
		}

		bytesRead, err = conn.Read(buff)
		if err != nil {
			serverErrChan <- err
			return
		}

		if !bytes.Equal(thirdPayload, buff[:bytesRead]) {
			serverErrChan <- errors.New(fmt.Sprintf("Received unexpected bytes, got %v, expected %v", buff[:100], thirdPayload))
		}
	}()

	clientConnection, err := clientNet.DialTCPAddrPort(netip.AddrPortFrom(serverIP, 80))
	if err != nil {
		t.Fatalf("Failed to connect client to TCP server: %v", err)
	}

	_, err = clientConnection.Write(firstPayload)
	if err != nil {
		t.Fatalf("Failed to send data over TCP connection: %v", err)
	}

	clientBuff := make([]byte, 128)
	bytesRead, err := clientConnection.Read(clientBuff)
	if err != nil {
		t.Fatalf("Failed to receive data over TCP connection: %v", err)
	}

	if !bytes.Equal(clientBuff[:bytesRead], secondPayload) {
		t.Fatalf("Expected to receive %v, instead got %v", secondPayload, clientBuff[:bytesRead])
	}

	_, err = clientConnection.Write(thirdPayload)
	if err != nil {
		t.Fatalf("Failed to send data over TCP connection: %v", err)
	}

}

func checkAddr(t *testing.T, a netip.Addr, b string, label string) {
	assert.Equal(t, a, netip.MustParseAddr(b), label)
}
func checkPort(t *testing.T, a uint16, b uint16, label string) {
	if a != b {
		t.Fatalf(fmt.Sprintf("Invalid %s port: %d != %d", label, a, b))
	}
}

func TestHeaderParsingIPv4_UDP(t *testing.T) {
	packet := []byte{69, 0, 0, 32, 249, 138, 0, 0, 64, 17, 121, 54, 1, 2, 3, 4, 1, 2, 3, 5, 4, 210, 3, 232, 0, 12, 235, 9, 1, 2, 3, 4}

	header := &PacketHeaderData{}
	if !fillPacketHeaderData(packet, header, false) {
		t.Fatalf("Failed to parse a packet header")
	}
	assert.Equal(t, header.protocol, uint8(17))
	// checkAddr(t, header.sourceAddr, "1.2.3.4", "source")
	checkAddr(t, header.remoteAddr, "1.2.3.5", "destination")
	assert.Equal(t, header.localPort, uint16(1234))
	assert.Equal(t, header.remotePort, uint16(1000))

	if !fillPacketHeaderData(packet, header, true) {
		t.Fatalf("Failed to parse a packet header")
	}
	assert.Equal(t, header.protocol, uint8(17))
	// checkAddr(t, header.sourceAddr, "1.2.3.4", "source")
	checkAddr(t, header.remoteAddr, "1.2.3.4", "destination")
	assert.Equal(t, header.localPort, uint16(1000))
	assert.Equal(t, header.remotePort, uint16(1234))
}

func TestHeaderParsingIPv4_TCP(t *testing.T) {
	packet := []byte{0x45, 0x00, 0x00, 0x40, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06, 0x36, 0xab, 0xc0, 0xa8, 0x00, 0x6c, 0x0a, 0x80, 0xfe, 0x14, 0xfd, 0x5b, 0x01, 0xbb, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	header := &PacketHeaderData{}
	if !fillPacketHeaderData(packet, header, false) {
		t.Fatalf("Failed to parse a packet header")
	}
	if header.protocol != 6 {
		t.Fatalf(fmt.Sprintf("Not a TCP packet: protocol = 0x%02x", header.protocol))
	}
	checkAddr(t, header.remoteAddr, "10.128.254.20", "destination")
	checkPort(t, header.localPort, 64859, "source")
	checkPort(t, header.remotePort, 443, "destination")

	if !fillPacketHeaderData(packet, header, true) {
		t.Fatalf("Failed to parse a packet header")
	}
	if header.protocol != 6 {
		t.Fatalf(fmt.Sprintf("Not a TCP packet: protocol = 0x%02x", header.protocol))
	}
	checkAddr(t, header.remoteAddr, "192.168.0.108", "source")
	checkPort(t, header.localPort, 443, "destination")
	checkPort(t, header.remotePort, 64859, "source")
}

func getFreeLocalUdpPort(t testing.TB) uint16 {
	localAddr := netip.MustParseAddrPort("127.0.0.1:0")
	udpSockAddr := net.UDPAddrFromAddrPort(localAddr)
	udpConn, err := net.ListenUDP("udp4", udpSockAddr)
	if err != nil {
		t.Fatalf("Failed to open a UDP socket to assign an empty port")
	}
	defer udpConn.Close()

	port := netip.MustParseAddrPort(udpConn.LocalAddr().String()).Port()

	return port
}
