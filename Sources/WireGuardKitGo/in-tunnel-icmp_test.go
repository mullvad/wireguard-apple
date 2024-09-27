package main

import (
	"net/netip"
	"time"

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
