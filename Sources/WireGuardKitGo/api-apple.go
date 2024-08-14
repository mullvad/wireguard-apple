/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2018-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

package main

// #include <stdlib.h>
// #include <sys/types.h>
// static void callLogger(void *func, void *ctx, int level, const char *msg)
// {
// 	((void(*)(void *, int, const char *))func)(ctx, level, msg);
// }
import "C"

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/apple/multihoptun"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

const (
	_              = iota
	errBadIPString = -iota
	errDup
	errSetNonblock
	errCreateTun
	errCreateVirtualTun
	errNoVirtualNet
	errBadWgConfig
	errDeviceLimitHit
	errGetMtu
	errNoEndpointInConfig
	// Configuration for a given device contains no peers. It is peerless.
	errBadEntryConfig
	// After applying a configuration to a given WireGuard device, it fails to return a peer it was configured to have.
	errNoPeer
	// Failed to enable DAITA
	errEnableDaita
)

var loggerFunc unsafe.Pointer
var loggerCtx unsafe.Pointer

type CLogger int

func cstring(s string) *C.char {
	b, err := unix.BytePtrFromString(s)
	if err != nil {
		b := [1]C.char{}
		return &b[0]
	}
	return (*C.char)(unsafe.Pointer(b))
}

func (l CLogger) Printf(format string, args ...interface{}) {
	if uintptr(loggerFunc) == 0 {
		return
	}
	C.callLogger(loggerFunc, loggerCtx, C.int(l), cstring(fmt.Sprintf(format, args...)))
}

type tunnelHandle struct {
	exit       *device.Device
	entry      *device.Device
	logger     *device.Logger
	virtualNet *netstack.Net
}

var tunnelHandles = make(map[int32]tunnelHandle)

type HandleList[T interface{}] map[int32]T

// insert a value and return the positive handle, or errDeviceLimitHit if full
func insertHandle[T interface{}](hl map[int32]T, value T) int32 {
	var i int32
	for i = 0; i < math.MaxInt32; i++ {
		if _, exists := hl[i]; !exists {
			break
		}
	}
	if i == math.MaxInt32 {
		return errDeviceLimitHit
	}
	hl[i] = value
	return i
}

type icmpHandle struct {
	icmpSocket *net.Conn
}

var icmpHandles = make(map[int32]icmpHandle)

func init() {
	signals := make(chan os.Signal)
	signal.Notify(signals, unix.SIGUSR2)
	go func() {
		buf := make([]byte, os.Getpagesize())
		for {
			select {
			case <-signals:
				n := runtime.Stack(buf, true)
				buf[n] = 0
				if uintptr(loggerFunc) != 0 {
					C.callLogger(loggerFunc, loggerCtx, 0, (*C.char)(unsafe.Pointer(&buf[0])))
				}
			}
		}
	}()
}

//export wgSetLogger
func wgSetLogger(context, loggerFn uintptr) {
	loggerCtx = unsafe.Pointer(context)
	loggerFunc = unsafe.Pointer(loggerFn)
}

func openTUNFromSocket(tunFd int32, logger *device.Logger) (tun.Device, int32) {

	dupTunFd, err := unix.Dup(int(tunFd))
	if err != nil {
		logger.Errorf("Unable to dup tun fd: %v", err)
		return nil, errDup
	}

	err = unix.SetNonblock(dupTunFd, true)
	if err != nil {
		logger.Errorf("Unable to set tun fd as non blocking: %v", err)
		unix.Close(dupTunFd)
		return nil, errSetNonblock
	}
	tun, err := tun.CreateTUNFromFile(os.NewFile(uintptr(dupTunFd), "/dev/tun"), 0)
	if err != nil {
		logger.Errorf("Unable to create new tun device from fd: %v", err)
		unix.Close(dupTunFd)
		return nil, errCreateTun
	}

	return tun, 0
}

func bringUpDevice(dev *device.Device, settings string, logger *device.Logger) error {
	err := dev.IpcSet(settings)
	if err != nil {
		logger.Errorf("Unable to set IPC settings: %v", err)
		dev.Close()
		return err
	}

	dev.Up()
	logger.Verbosef("Device started")
	return nil
}

func addTunnelFromDevice(dev *device.Device, entryDev *device.Device, settings string, entrySettings string, virtualNet *netstack.Net, logger *device.Logger, maybeNotMachines *C.char, maybeNotMaxEvents uint32, maybeNotMaxActions uint32) int32 {
	err := bringUpDevice(dev, settings, logger)
	if err != nil {
		return errBadWgConfig
	}

	if entryDev != nil {
		err = bringUpDevice(entryDev, entrySettings, logger)
		if err != nil {
			dev.Close()
			return errBadWgConfig
		}
	}

	// Enable DAITA if DAITA parameters are passed through
	if maybeNotMachines != nil {
		returnValue := configureDaita(entryDev, entrySettings, C.GoString(maybeNotMachines), maybeNotMaxEvents, maybeNotMaxActions)
		if returnValue != 0 {
			return returnValue
		}
	}

	var i int32
	for i = 0; i < math.MaxInt32; i++ {
		if _, exists := tunnelHandles[i]; !exists {
			break
		}
	}
	if i == math.MaxInt32 {
		dev.Close()
		return errDeviceLimitHit
	}
	tunnelHandles[i] = tunnelHandle{dev, entryDev, logger, virtualNet}
	return i
}

func parseFirstPubkeyFromConfig(config string) *device.NoisePublicKey {
	scanner := bufio.NewScanner(strings.NewReader(config))
	for scanner.Scan() {
		line := scanner.Text()
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}

		if key == "public_key" {
			pubkey, err := hex.DecodeString(value)
			if err == nil {
				key := device.NoisePublicKey(pubkey)
				return &key
			}
		}
	}
	return nil
}

func wgTurnOnMultihopInner(tun tun.Device, exitSettings *C.char, entrySettings *C.char, privateIp *C.char, exitMtu int, logger *device.Logger, maybeNotMachines *C.char, maybeNotMaxEvents uint32, maybeNotMaxActions uint32) int32 {
	ip, err := netip.ParseAddr(C.GoString(privateIp))
	if err != nil {
		logger.Errorf("Failed to parse private IP: %v", err)
		tun.Close()
		return errBadIPString
	}

	exitConfigString := C.GoString(exitSettings)
	entryConfigString := C.GoString(entrySettings)
	exitEndpoint := parseEndpointFromConfig(exitConfigString)
	if exitEndpoint == nil {
		tun.Close()
		return errNoEndpointInConfig
	}

	singletun := multihoptun.NewMultihopTun(ip, exitEndpoint.Addr(), exitEndpoint.Port(), exitMtu+80)

	exitDev := device.NewDevice(tun, singletun.Binder(), logger)
	entryDev := device.NewDevice(&singletun, conn.NewStdNetBind(), logger)

	return addTunnelFromDevice(exitDev, entryDev, exitConfigString, entryConfigString, nil, logger, maybeNotMachines, maybeNotMaxEvents, maybeNotMaxActions)
}

//export wgTurnOnMultihop
func wgTurnOnMultihop(exitSettings *C.char, entrySettings *C.char, privateIp *C.char, tunFd int32, maybenotMachines *C.char, maybeNotMaxEvents uint32, maybeNotMaxActons uint32) int32 {
	logger := &device.Logger{
		Verbosef: CLogger(0).Printf,
		Errorf:   CLogger(1).Printf,
	}

	tun, errCode := openTUNFromSocket(tunFd, logger)
	if tun == nil {
		return errCode
	}

	exitMtu, err := tun.MTU()
	if err != nil {
		tun.Close()
		return errGetMtu
	}

	return wgTurnOnMultihopInner(tun, exitSettings, entrySettings, privateIp, exitMtu, logger, maybenotMachines, maybeNotMaxEvents, maybeNotMaxActons)
}

//export wgTurnOn
func wgTurnOn(settings *C.char, tunFd int32, maybeNotMachines *C.char, maybeNotMaxEvents uint32, maybeNotMaxActions uint32) int32 {
	logger := &device.Logger{
		Verbosef: CLogger(0).Printf,
		Errorf:   CLogger(1).Printf,
	}
	tun, errCode := openTUNFromSocket(tunFd, logger)
	if tun == nil {
		return errCode
	}

	logger.Verbosef("Attaching to interface")
	dev := device.NewDevice(tun, conn.NewStdNetBind(), logger)

	return addTunnelFromDevice(dev, nil, C.GoString(settings), "", nil, logger, maybeNotMachines, maybeNotMaxEvents, maybeNotMaxActions)
}

func wgTurnOnIANFromExistingTunnel(tun tun.Device, settings string, privateAddr netip.Addr, maybeNotMachines *C.char, maybeNotMaxEvents uint32, maybeNotMaxActions uint32) int32 {
	logger := &device.Logger{
		Verbosef: CLogger(0).Printf,
		Errorf:   CLogger(1).Printf,
	}

	/// assign the same private IPs associated with your key
	vtun, virtualNet, err := netstack.CreateNetTUN([]netip.Addr{privateAddr}, []netip.Addr{}, 1280)
	if err != nil {
		logger.Errorf("Failed to initialize virtual tunnel device: %v", err)
		tun.Close()
		return -5
	}

	if virtualNet == nil {
		logger.Errorf("Failed to initialize virtual tunnel device")
		tun.Close()
		return -6
	}

	wrapper := NewRouter(tun, vtun)
	logger.Verbosef("Attaching to interface")
	dev := device.NewDevice(&wrapper, conn.NewStdNetBind(), logger)

	return addTunnelFromDevice(dev, nil, settings, "", virtualNet, logger, maybeNotMachines, maybeNotMaxEvents, maybeNotMaxActions) // FIXME
}

//export wgTurnOnIAN
func wgTurnOnIAN(settings *C.char, tunFd int32, privateIP *C.char, maybeNotMachines *C.char, maybeNotMaxEvents uint32, maybeNotMaxActions uint32) int32 {
	logger := &device.Logger{
		Verbosef: CLogger(0).Printf,
		Errorf:   CLogger(1).Printf,
	}

	privateAddrStr := C.GoString(privateIP)
	privateAddr, err := netip.ParseAddr(privateAddrStr)
	if err != nil {
		logger.Errorf("Invalid address: %s", privateAddrStr)
		return -1
	}

	tun, errCode := openTUNFromSocket(tunFd, logger)
	if tun == nil {
		return errCode
	}

	return wgTurnOnIANFromExistingTunnel(tun, C.GoString(settings), privateAddr, maybeNotMachines, maybeNotMaxEvents, maybeNotMaxActions)
}

//export wgTurnOff
func wgTurnOff(tunnelHandle int32) {
	handle, ok := tunnelHandles[tunnelHandle]
	if !ok {
		return
	}
	delete(tunnelHandles, tunnelHandle)

	handle.exit.Close()

	if handle.entry != nil {
		handle.entry.Close()
	}
}

//export wgSetConfig
func wgSetConfig(tunnelHandle int32, settings *C.char) int64 {
	handle, ok := tunnelHandles[tunnelHandle]
	if !ok {
		return 0
	}
	err := handle.exit.IpcSet(C.GoString(settings))
	if err != nil {
		handle.logger.Errorf("Unable to set IPC settings: %v", err)
		if ipcErr, ok := err.(*device.IPCError); ok {
			return ipcErr.ErrorCode()
		}
		return errBadWgConfig
	}
	return 0
}

//export wgGetConfig
func wgGetConfig(tunnelHandle int32) *C.char {
	handle, ok := tunnelHandles[tunnelHandle]
	if !ok {
		return nil
	}

	settings, err := handle.exit.IpcGet()
	if err != nil {
		return nil
	}
	return C.CString(settings)
}

//export wgBumpSockets
func wgBumpSockets(tunnelHandle int32) {
	handle, ok := tunnelHandles[tunnelHandle]
	if !ok {
		return
	}
	device := handle.exit
	if handle.entry != nil {
		device = handle.entry
	}

	go func() {
		for i := 0; i < 10; i++ {
			err := device.BindUpdate()
			if err == nil {
				device.SendKeepalivesToPeersWithCurrentKeypair()
				return
			}
			handle.logger.Errorf("Unable to update bind, try %d: %v", i+1, err)
			time.Sleep(time.Second / 2)
		}
		handle.logger.Errorf("Gave up trying to update bind; tunnel is likely dysfunctional")
	}()
}

//export wgDisableSomeRoamingForBrokenMobileSemantics
func wgDisableSomeRoamingForBrokenMobileSemantics(tunnelHandle int32) {
	dev, ok := tunnelHandles[tunnelHandle]
	if !ok {
		return
	}
	dev.exit.DisableSomeRoamingForBrokenMobileSemantics()
	if dev.entry != nil {
		dev.entry.DisableSomeRoamingForBrokenMobileSemantics()
	}
}

func testOpenInTunnelUDP(tunnelHandle int32, sendAddrPort, recvAddrPort netip.AddrPort) (*os.File, *os.File) {
	handle, ok := tunnelHandles[tunnelHandle]
	if !ok || handle.virtualNet == nil {
		return nil, nil
	}

	sender, err := handle.virtualNet.DialUDPAddrPort(netip.AddrPort{}, sendAddrPort)
	if err != nil {
		fmt.Printf("Failed to open UDP socket for sending\n")
		return nil, nil
	}
	listener, err := handle.virtualNet.ListenUDPAddrPort(recvAddrPort)
	fmt.Printf("-- Listening on %v\n", recvAddrPort)
	if err != nil {
		return nil, nil
	}
	sendRx, sendTx, err := os.Pipe()
	if err != nil {
		return nil, nil
	}
	recvRx, recvTx, err := os.Pipe()
	if err != nil {
		sendTx.Close()
		return nil, nil
	}

	rxShutdown := make(chan struct{})
	sendbuf := make([]byte, 1024)
	go func() { // the sender
		defer sendRx.Close()
		for {
			select {
			case _ = <-rxShutdown:
				fmt.Printf("*** closing down")
				return
			default:
			}
			count, err := sendRx.Read(sendbuf)
			if err == io.EOF {
				rxShutdown <- struct{}{}
			}
			fmt.Printf("Sent %d bytes to connection\n", count)
			sender.Write(sendbuf[:count])
		}
	}()
	recvbuf := make([]byte, 1024)
	go func() { // the receiver
		defer func() {
			fmt.Printf("Closing recvTx\n")
			recvTx.Close()
		}()
		for {
			select {
			case _ = <-rxShutdown:
				return
			default:
				fmt.Printf("Waiting to receive data\n")
				count, _ := listener.Read(recvbuf)
				// if err == io.EOF {
				// 	rxShutdown <- struct{}{}
				// }
				fmt.Printf("Received %d bytes from connection\n", count)
				recvTx.Write(recvbuf[:count])
			}
		}
	}()
	return sendTx, recvRx

}

func wgOpenInTunnelICMP(tunnelHandle int32, address *C.char) int32 {
	handle, ok := tunnelHandles[tunnelHandle]
	if !ok || handle.virtualNet == nil {
		return -1 // FIXME
	}
	conn, _ := handle.virtualNet.Dial("ping4", C.GoString(address))

	result := insertHandle(icmpHandles, icmpHandle{&conn})
	if result < 0 {
		conn.Close()
	}
	return result
}

func wgCloseInTunnelICMP(socketHandle int32) bool {
	socket, ok := icmpHandles[socketHandle]
	if ok {
		(*(socket.icmpSocket)).Close()
		delete(icmpHandles, socketHandle)
	}
	return ok
}

// the next sequence number to send in pings. We keep this global, though if there's a reason, we could put it in each opened socket structure
var pingSeqNumber int = 1

func wgSendAndAwaitInTunnelPing(tunnelHandle int32, socketHandle int32) int32 {
	socket, ok := icmpHandles[socketHandle]
	if !ok {
		return -1 // FIXME
	}
	pingdata := []byte("cookie woz ere")
	ping := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Body: &icmp.Echo{
			ID:   1234,
			Seq:  pingSeqNumber,
			Data: pingdata,
		},
	}
	pingBytes, err := ping.Marshal(nil)
	_, err = (*(socket.icmpSocket)).Write(pingBytes)
	if err != nil {
		return -1
	}
	readBuff := make([]byte, 1024)
	readBytes, err := (*(socket.icmpSocket)).Read(readBuff)
	if readBytes <= 0 || err != nil {
		return -1
	}
	replyPacket, err := icmp.ParseMessage(1, readBuff[:readBytes])
	if err != nil {
		return -1
	}
	replyPing, ok := replyPacket.Body.(*icmp.Echo)
	if !ok {
		return -1
	}
	if replyPing.Seq != pingSeqNumber || !bytes.Equal(replyPing.Data, pingdata) {
		return -1
	}
	return 0
}

//export wgVersion
func wgVersion() *C.char {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return C.CString("unknown")
	}
	for _, dep := range info.Deps {
		if dep.Path == "golang.zx2c4.com/wireguard" {
			parts := strings.Split(dep.Version, "-")
			if len(parts) == 3 && len(parts[2]) == 12 {
				return C.CString(parts[2][:7])
			}
			return C.CString(dep.Version)
		}
	}
	return C.CString("unknown")
}

func configureDaita(device *device.Device, config string, machines string, maxEvents uint32, maxActions uint32) int32 {
	entryPeerPubkey := parseFirstPubkeyFromConfig(config)
	if entryPeerPubkey == nil {
		return errBadEntryConfig
	}
	peer := device.LookupPeer(*entryPeerPubkey)
	if peer == nil {
		return errNoPeer
	}

	const maxPaddingBytes = 0.0
	const maxBlockingBytes = 0.0

	if !peer.EnableDaita(machines, uint(maxEvents), uint(maxActions), maxPaddingBytes, maxBlockingBytes) {
		return errEnableDaita
	}

	return 0
}

func main() {}

// Parse a wireguard config and return the first endpoint address it finds and
// parses successfully.
func parseEndpointFromConfig(config string) *netip.AddrPort {
	scanner := bufio.NewScanner(strings.NewReader(config))
	for scanner.Scan() {
		line := scanner.Text()
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}

		if key == "endpoint" {
			endpoint, err := netip.ParseAddrPort(value)
			if err == nil {
				return &endpoint
			}
		}

	}
	return nil
}
