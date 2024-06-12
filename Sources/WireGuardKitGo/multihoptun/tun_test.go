package multihoptun

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

func TestMultihopTunBind(t *testing.T) {
	stIp := netip.AddrFrom4([4]byte{192, 168, 1, 1})
	virtualIp := netip.AddrFrom4([4]byte{192, 168, 1, 11})
	remotePort := uint16(5005)

	st := NewMultihopTun(stIp, virtualIp, remotePort, 1280)

	_ = device.NewDevice(&st, st.Binder(), device.NewLogger(device.LogLevelSilent, ""))
}

func TestMultihopTunTrafficV4(t *testing.T) {

	stIp := netip.AddrFrom4([4]byte{1, 2, 3, 5})
	virtualIp := netip.AddrFrom4([4]byte{1, 2, 3, 4})
	remotePort := uint16(5005)

	st := NewMultihopTun(stIp, virtualIp, remotePort, 1280)
	stBind := st.Binder()

	virtualTun, virtualNet, _ := netstack.CreateNetTUN([]netip.Addr{virtualIp}, []netip.Addr{}, 1280)

	// Pipe reads from virtualTun into multihop tun
	go func() {
		bufs := make([][]byte, 1)
		bufs[0] = make([]byte, 1600)
		sizes := make([]int, 1)
		var err error
		n := 0
		for err == nil {
			n, err = virtualTun.Read(bufs, sizes, 0)
			n, err = st.Write(bufs[:n], 0)
		}

	}()

	// Pipe reads from multihop tun into virtualTun
	go func() {
		bufs := make([][]byte, 1)
		bufs[0] = make([]byte, 1600)
		sizes := make([]int, 1)
		var err error
		n := 0
		for err == nil {
			n, err = st.Read(bufs, sizes, 0)
			for idx := range bufs {
				bufs[idx] = bufs[idx][:sizes[idx]]
			}
			n, err = virtualTun.Write(bufs[:n], 0)
		}
	}()

	recvFunc, _, err := stBind.Open(0)
	if err != nil {
		t.Fatalf("Failed to open port for multihop tun: %s", err)
	}

	payload := []byte{1, 2, 3, 4}
	readyChan := make(chan struct{})
	// Listen on the virtual tunnel
	go func() {
		conn, err := virtualNet.ListenUDPAddrPort(netip.AddrPortFrom(virtualIp, remotePort))
		if err != nil {
			panic(err)
		}
		readyChan <- struct{}{}
		buff := make([]byte, 4)
		n, addr, _ := conn.ReadFrom(buff)
		if n == 0 {
			fmt.Println("Did not receive anything")
		}

		conn.WriteTo(buff, addr)
	}()
	_, _ = <-readyChan

	err = stBind.Send([][]byte{payload}, nil)
	if err != nil {
		t.Fatalf("Failed ot send traffic to multihop tun: %s", err)
	}

	recvBuf := [][]byte{make([]byte, 1600)}
	sizes := []int{0}
	packetsReceived, err := recvFunc[0](recvBuf, sizes, make([]conn.Endpoint, 1, 1))
	if err != nil {
		t.Fatalf("Failed to receive traffic from recvFunc - %s", err)
	}
	if packetsReceived != 1 {
		t.Fatalf("Expected to recieve 1 packet, instead received %d", packetsReceived)
	}

	for idx := range payload {
		if payload[idx] != recvBuf[0][idx] {
			t.Fatalf("Expected to receive %v, instead received %v", payload, recvBuf[0])
		}
	}
}

func TestReadEnd(t *testing.T) {
	stIp := netip.AddrFrom4([4]byte{1, 2, 3, 5})
	virtualIp := netip.AddrFrom4([4]byte{1, 2, 3, 4})
	remotePort := uint16(5005)

	st := NewMultihopTun(stIp, virtualIp, remotePort, 1280)
	stBind := st.Binder()
	otherSt := NewMultihopTun(stIp, virtualIp, remotePort, 1280)

	readerDev := device.NewDevice(&st, conn.NewStdNetBind(), device.NewLogger(device.LogLevelSilent, ""))
	otherDev := device.NewDevice(&otherSt, conn.NewStdNetBind(), device.NewLogger(device.LogLevelSilent, ""))

	configureDevices(t, readerDev, otherDev)

	readerDev.Up()
	receivers, port, err := stBind.Open(0)
	if err != nil {
		t.Fatalf("Failed to open UDP socket: %s", err)
	}
	if len(receivers) != 1 {
		t.Fatalf("Expected 1 receiver func, got %v", len(receivers))
	}

	if port == 0 {
		t.Fatalf("Expected a random port to be assigned, instead got 0")
	}

	bufs := make([][]byte, 1, 128)
	bufs[0] = []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}

	err = stBind.Send(bufs, nil)
	if err != nil {
		t.Fatalf("Error when sending UDP traffic: %v", err)
	}
}

func TestMultihopTunWrite(t *testing.T) {
	stIp := netip.AddrFrom4([4]byte{1, 2, 3, 5})
	virtualIp := netip.AddrFrom4([4]byte{1, 2, 3, 4})
	remotePort := uint16(5005)

	st := NewMultihopTun(stIp, virtualIp, remotePort, 1280)
	stBind := st.Binder()

	receivers, port, err := stBind.Open(0)
	if err != nil {
		t.Fatalf("Failed to open UDP socket: %s", err)
	}
	if len(receivers) != 1 {
		t.Fatalf("Expected 1 receiver func, got %v", len(receivers))
	}

	if port == 0 {
		t.Fatalf("Expected a random port to be assigned, instead got 0")
	}

	udpPacket := []byte{69, 0, 0, 32, 164, 27, 0, 0, 64, 17, 206, 165, 1, 2, 3, 5, 1, 2, 3, 4, 209, 129, 19, 141, 0, 12, 0, 0, 1, 2, 3, 4}

	if err != nil {
		t.Fatalf("Error when sending UDP traffic: %v", err)
	}
	go func() {
		st.Write([][]byte{udpPacket}, 0)
	}()

	bufs := make([][]byte, 128, 128)
	for i := range bufs {
		bufs[i] = make([]byte, 1600, 1600)
	}
	sizes := make([]int, 128)
	endpoints := make([]conn.Endpoint, 128)
	packetsReceived, err := receivers[0](bufs, sizes, endpoints)
	if err != nil {
		t.Fatalf("Failed to receive packets: %s", err)
	}

	if packetsReceived != 1 {
		t.Fatalf("expected packets to be")
	}

	expected := []byte{1, 2, 3, 4}
	if len(bufs[0][:sizes[0]]) != len(expected) {
		t.Fatalf("Expected %v, got %v", expected, bufs[0])
	}

	for b := range bufs[0][:sizes[0]] {
		if bufs[0][b] != expected[b] {
			t.Fatalf("Expected %v, got %v", expected, bufs[0])
		}
	}
}

func configureDevices(t testing.TB, aDev *device.Device, bDev *device.Device) {
	configs, endpointConfigs := genConfigs(t)
	aConfig := configs[0] + endpointConfigs[0]
	bConfig := configs[1] + endpointConfigs[1]
	aDev.IpcSet(aConfig)
	bDev.IpcSet(bConfig)
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

func TestMultihop(t *testing.T) {
	exitConfig := "private_key=b09cb6a9cd5b09236c7610c54c5a2d7cebce1449417368fcbdc228bdd7aa5661\nlisten_port=0\nreplace_peers=true\npublic_key=bde2eaa596b347d8ff3a5d86f137eb3b7db21217358b9e3730237cae9cb51410\nendpoint=185.204.1.203:53440\npersistent_keepalive_interval=0\nreplace_allowed_ips=true\nallowed_ip=0.0.0.0/0\nallowed_ip=::/0\n"

	entryConfig := "private_key=b09cb6a9cd5b09236c7610c54c5a2d7cebce1449417368fcbdc228bdd7aa5661\nlisten_port=0\nreplace_peers=true\npublic_key=04b34736818ef3c2e357fc0305aec2514c14ccfabf7ced94c1c18bcb9ea12b2e\nendpoint=185.213.154.68:53440\npersistent_keepalive_interval=0\nreplace_allowed_ips=true\nallowed_ip=0.0.0.0/0\nallowed_ip=::/0\n"
	privateIp := netip.MustParseAddr("10.134.155.17")
	exitMtu := 1280
	exitEndpoint, err := netip.ParseAddrPort("185.204.1.203:53440")
	if err != nil {
		panic(err)
	}

	virtualDev, virtualNet, _ := netstack.CreateNetTUN([]netip.Addr{privateIp}, []netip.Addr{}, exitMtu)
	st := NewMultihopTun(privateIp, exitEndpoint.Addr(), exitEndpoint.Port(), exitMtu+80)

	exitDevice := device.NewDevice(virtualDev, st.Binder(), device.NewLogger(device.LogLevelSilent, ""))
	entryDevice := device.NewDevice(&st, conn.NewStdNetBind(), device.NewLogger(device.LogLevelVerbose, ""))

	exitDevice.IpcSet(exitConfig)
	entryDevice.IpcSet(entryConfig)
	entryDevice.Up()
	exitDevice.Up()

	sendIcmp(t, virtualNet)

	exitDevice.Close()
	entryDevice.Close()
}

func sendIcmp(t *testing.T, virtualNet *netstack.Net) {
	conn, err := virtualNet.Dial("ping4", "10.64.0.1")
	requestPing := icmp.Echo{
		Seq:  345,
		Data: []byte("gopher burrow"),
	}
	icmpBytes, _ := (&icmp.Message{Type: ipv4.ICMPTypeEcho, Code: 0, Body: &requestPing}).Marshal(nil)
	conn.SetReadDeadline(time.Now().Add(time.Second * 9))
	start := time.Now()
	_, err = conn.Write(icmpBytes)
	if err != nil {
		t.Fatal(err)
	}
	n, err := conn.Read(icmpBytes[:])
	if err != nil {
		t.Fatal(err)
	}
	replyPacket, err := icmp.ParseMessage(1, icmpBytes[:n])
	if err != nil {
		t.Fatal(err)
	}
	replyPing, ok := replyPacket.Body.(*icmp.Echo)
	if !ok {
		t.Fatalf("invalid reply type: %v", replyPacket)
	}
	if !bytes.Equal(replyPing.Data, requestPing.Data) || replyPing.Seq != requestPing.Seq {
		t.Fatalf("invalid ping reply: %v", replyPing)
	}
	fmt.Printf("Ping latency: %v\n", time.Since(start))
}

func TestShutdown(t *testing.T) {
	a, b := generateTestPair(t)
	b.Close()
	a.Close()
}

func TestReversedShutdown(t *testing.T) {
	a, b := generateTestPair(t)
	a.Close()
	b.Close()
}

func generateTestPair(t *testing.T) (*device.Device, *device.Device) {
	stIp := netip.AddrFrom4([4]byte{1, 2, 3, 5})
	virtualIp := netip.AddrFrom4([4]byte{1, 2, 3, 4})
	remotePort := uint16(5005)

	st := NewMultihopTun(stIp, virtualIp, remotePort, 1280)
	stBind := st.Binder()

	virtualDev, virtualNet, _ := netstack.CreateNetTUN([]netip.Addr{virtualIp}, []netip.Addr{}, 1280)

	readerDev := device.NewDevice(virtualDev, stBind, device.NewLogger(device.LogLevelSilent, ""))
	otherDev := device.NewDevice(&st, conn.NewStdNetBind(), device.NewLogger(device.LogLevelSilent, ""))

	configureDevices(t, readerDev, otherDev)

	readerDev.Up()
	otherDev.Up()

	conn, err := virtualNet.Dial("ping4", "10.64.0.1")
	requestPing := icmp.Echo{
		Seq:  345,
		Data: []byte("gopher burrow"),
	}
	icmpBytes, _ := (&icmp.Message{Type: ipv4.ICMPTypeEcho, Code: 0, Body: &requestPing}).Marshal(nil)
	conn.SetReadDeadline(time.Now().Add(time.Second * 9))
	_, err = conn.Write(icmpBytes)
	if err != nil {
		t.Fatal(err)
	}

	return readerDev, otherDev
}
