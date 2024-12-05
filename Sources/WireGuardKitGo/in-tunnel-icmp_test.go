package main

import (
	"encoding/base64"
	"encoding/hex"
	"net/netip"
	"time"
	"unsafe"

	"testing"

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

// This test is disabled intentionally, since it relies on valid WireGuard keys
// being set for both the client and the relay. It is left in the repo to allow
// for easier manual testing.
func testIcmpSocketParse(t *testing.T) {
	privateKey, _ := base64.StdEncoding.DecodeString("mJiFq5mdExIZQVTt2QrL2o9sACkVAlUC7d/09+1wbkw=")
	relayPubKey, _ := base64.StdEncoding.DecodeString("R5LUBgM/1UjeAR4lt+L/yA30Gee6/VqVZ9eAB3ZTajs=")
	clientConfig := uapiCfg(
		"private_key", hex.EncodeToString(privateKey[:]),
		"listen_port", "0",
		"replace_peers", "true",
		"public_key", hex.EncodeToString(relayPubKey),
		"endpoint", "45.129.56.68:51820",
		"protocol_version", "1",
		"replace_allowed_ips", "true",
		"allowed_ip", "0.0.0.0/0",
	)

	clientIp := netip.MustParseAddr("10.70.128.243")
	clientTun, _, _ := netstack.CreateNetTUN([]netip.Addr{clientIp}, []netip.Addr{}, 1280)

	tunnel := wgTurnOnIANFromExistingTunnel(clientTun, clientConfig, clientIp, nil, 0, 0)


	pingableHost := []byte("10.64.0.1")
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
