/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2018-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

package main

// #include <stdint.h>
// #include <stdlib.h>
// #include <sys/types.h>
// static void callLogger(void *func, void *ctx, int level, const char *msg)
// {
// 	((void(*)(void *, int, const char *))func)(ctx, level, msg);
// }
/*
typedef struct {
    uint32_t maybeNotMaxEvents;
    uint32_t maybeNotMaxActions;
    double maybeNotMaxPadding;
    double maybeNotMaxBlocking;
} DaitaGoParameters;
*/
import "C"

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"math/rand"
	"net/netip"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/multihoptun"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

const (
	errBadIPString        = -1
	errDup                = -2
	errSetNonblock        = -3
	errCreateTun          = -4
	errCreateVirtualTun   = -5
	errNoVirtualNet       = -6
	errBadWgConfig        = -7
	errDeviceLimitHit     = -8
	errGetMtu             = -9
	errNoEndpointInConfig = -10
	// Configuration for a given device contains no peers. It is peerless.
	errBadEntryConfig = -11
	// After applying a configuration to a given WireGuard device, it fails to return a peer it was configured to have.
	errNoPeer = -12
	// Failed to enable DAITA
	errEnableDaita = -13
	// ICMP errors
	errICMPOpenSocket      = -14
	errICMPWriteSocket     = -15
	errICMPReadSocket      = -16
	errICMPResponseFormat  = -17
	errICMPResponseContent = -18
	// no such tunnel exists
	errNoSuchTunnel = -19
	// tunnel does not have virtual interface
	errNoTunnelVirtualInterface = -20
	// TCP errors
	errTCPNoSocket = -21
	errTCPWrite    = -22
	errTCPRead     = -23
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

var tunnels = NewTunnelHandles()

type daitaParameters struct {
	MaybeNotMachines    string
	MaybeNotMaxEvents   uint32
	MaybeNotMaxActions  uint32
	MaybeNotMaxPadding  float64
	MaybeNotMaxBlocking float64
}

func daitaParametersFromRaw(maybeNotMachines *C.char, p *C.DaitaGoParameters) *daitaParameters {
	if maybeNotMachines == nil || p == nil {
		return nil
	}
	return &daitaParameters{
		MaybeNotMachines:    C.GoString(maybeNotMachines),
		MaybeNotMaxEvents:   uint32(p.maybeNotMaxEvents),
		MaybeNotMaxActions:  uint32(p.maybeNotMaxActions),
		MaybeNotMaxPadding:  float64(p.maybeNotMaxPadding),
		MaybeNotMaxBlocking: float64(p.maybeNotMaxBlocking),
	}
}

var rng = rand.New(rand.NewSource(time.Now().UnixNano()))

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

//export test_daita
func test_daita(context *C.DaitaGoParameters) {
	logger := &device.Logger{
		Verbosef: CLogger(0).Printf,
		Errorf:   CLogger(1).Printf,
	}
	logger.Errorf("test %s", context)

	testParams := C.DaitaGoParameters{
		maybeNotMaxEvents:   1,
		maybeNotMaxActions:  1,
		maybeNotMaxPadding:  0.42,
		maybeNotMaxBlocking: 0.24,
	}

	logger.Errorf("test %p", &testParams)
}

func wgTurnOnMultihopInner(tun tun.Device, exitSettings *C.char, entrySettings *C.char, privateIp *C.char, exitMtu int, logger *device.Logger, maybeNotMachines *C.char, daitaParameters *C.DaitaGoParameters) int32 {
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
	entryDev := device.NewDevice(&singletun, conn.NewStdNetBind(), logger)

	vtun, virtualNet, err := netstack.CreateNetTUN([]netip.Addr{ip}, []netip.Addr{}, 1280)
	if err != nil {
		logger.Errorf("Failed to initialize virtual tunnel device: %v", err)
		tun.Close()
		return errCreateVirtualTun
	}
	if virtualNet == nil {
		logger.Errorf("Failed to initialize virtual tunnel device")
		tun.Close()
		return errNoVirtualNet
	}
	wrapper := NewRouter(tun, vtun)
	exitDev := device.NewDevice(&wrapper, singletun.Binder(), logger)

	daitaParams := daitaParametersFromRaw(maybeNotMachines, daitaParameters)
	return addTunnelFromDevice(exitDev, entryDev, exitConfigString, entryConfigString, virtualNet, logger, daitaParams)
}

//export wgTurnOnMultihop
func wgTurnOnMultihop(exitSettings *C.char, entrySettings *C.char, privateIp *C.char, tunFd int32, maybenotMachines *C.char, daitaParameters *C.DaitaGoParameters) int32 {
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

	return wgTurnOnMultihopInner(tun, exitSettings, entrySettings, privateIp, exitMtu, logger, maybenotMachines, daitaParameters)
}

//export wgTurnOn
func wgTurnOn(settings *C.char, tunFd int32, maybeNotMachines *C.char, daitaParameters *C.DaitaGoParameters) int32 {
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

	daitaParams := daitaParametersFromRaw(maybeNotMachines, daitaParameters)
	return addTunnelFromDevice(dev, nil, C.GoString(settings), "", nil, logger, daitaParams)
}

func wgTurnOnIANFromExistingTunnel(tun tun.Device, settings string, privateAddr netip.Addr, daitaParameters *daitaParameters) int32 {
	logger := &device.Logger{
		Verbosef: CLogger(0).Printf,
		Errorf:   CLogger(1).Printf,
	}

	/// assign the same private IPs associated with your key
	vtun, virtualNet, err := netstack.CreateNetTUN([]netip.Addr{privateAddr}, []netip.Addr{}, 1280)
	if err != nil {
		logger.Errorf("Failed to initialize virtual tunnel device: %v", err)
		tun.Close()
		return errCreateVirtualTun
	}

	if virtualNet == nil {
		logger.Errorf("Failed to initialize virtual tunnel device")
		tun.Close()
		return errNoVirtualNet
	}

	wrapper := NewRouter(tun, vtun)
	logger.Verbosef("Attaching to interface")
	dev := device.NewDevice(&wrapper, conn.NewStdNetBind(), logger)

	return addTunnelFromDevice(dev, nil, settings, "", virtualNet, logger, daitaParameters)
}

//export wgTurnOnIAN
func wgTurnOnIAN(settings *C.char, tunFd int32, privateIP *C.char, maybeNotMachines *C.char, daitaParameters *C.DaitaGoParameters) int32 {
	logger := &device.Logger{
		Verbosef: CLogger(0).Printf,
		Errorf:   CLogger(1).Printf,
	}

	privateAddrStr := C.GoString(privateIP)
	privateAddr, err := netip.ParseAddr(privateAddrStr)
	if err != nil {
		logger.Errorf("Invalid address: %s", privateAddrStr)
		return errBadIPString
	}

	tun, errCode := openTUNFromSocket(tunFd, logger)
	if tun == nil {
		return errCode
	}

	daitaParams := daitaParametersFromRaw(maybeNotMachines, daitaParameters)
	return wgTurnOnIANFromExistingTunnel(tun, C.GoString(settings), privateAddr, daitaParams)
}

//export wgTurnOff
func wgTurnOff(tunnelHandle int32) {
	handle := tunnels.Remove(tunnelHandle)
	if handle == nil {
		return
	}
	handle.Close()
}

//export wgSetConfig
func wgSetConfig(tunnelHandle int32, settings *C.char) int64 {
	handle := tunnels.Get(tunnelHandle)
	if handle == nil {
		return errNoSuchTunnel
	}
	return handle.SetConfig(C.GoString(settings))
}

//export wgGetConfig
func wgGetConfig(tunnelHandle int32) *C.char {
	handle := tunnels.Get(tunnelHandle)
	if handle == nil {
		return nil
	}

	settings := handle.GetConfig()
	if settings == nil {
		return nil
	}
	return C.CString(*settings)
}

//export wgBumpSockets
func wgBumpSockets(tunnelHandle int32) {
	handle := tunnels.Get(tunnelHandle)
	if handle == nil {
		return
	}
	handle.BumpSockets()
}

//export wgDisableSomeRoamingForBrokenMobileSemantics
func wgDisableSomeRoamingForBrokenMobileSemantics(tunnelHandle int32) {
	handle := tunnels.Get(tunnelHandle)
	if handle == nil {
		return
	}
	handle.DisableSomeRoamingForBrokenMobileSemantics()
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

func configureDaita(device *device.Device, config string, daitaParameters daitaParameters) int32 {
	entryPeerPubkey := parseFirstPubkeyFromConfig(config)
	if entryPeerPubkey == nil {
		return errBadEntryConfig
	}
	peer := device.LookupPeer(*entryPeerPubkey)
	if peer == nil {
		return errNoPeer
	}

	if !peer.EnableDaita(daitaParameters.MaybeNotMachines, uint(daitaParameters.MaybeNotMaxEvents), uint(daitaParameters.MaybeNotMaxActions), daitaParameters.MaybeNotMaxPadding, daitaParameters.MaybeNotMaxPadding) {
		return errEnableDaita
	}

	return 0
}

func main() {}

// Parse a wireguard config and return the first endpoint address it finds and
// parses successfully.gi b
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
