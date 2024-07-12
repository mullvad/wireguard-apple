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
	"fmt"
	"io"
	"math"
	"net/netip"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"strings"
	"time"
	"unsafe"

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

func wgTurnOnMultihopInner(tun tun.Device, exitSettings *C.char, entrySettings *C.char, privateIp *C.char, exitMtu int, logger *device.Logger) int32 {
	ip, err := netip.ParseAddr(C.GoString(privateIp))
	if err != nil {
		logger.Errorf("Failed to parse private IP: %v", err)
		tun.Close()
		return errBadIPString
	}

	exitConfigString := C.GoString(exitSettings)
	exitEndpoint := parseEndpointFromGoConfig(exitConfigString)
	if exitEndpoint == nil {
		tun.Close()
		return errNoEndpointInConfig
	}

	singletun := multihoptun.NewMultihopTun(ip, exitEndpoint.Addr(), exitEndpoint.Port(), exitMtu+80)

	exitDev := device.NewDevice(tun, singletun.Binder(), logger)
	entryDev := device.NewDevice(&singletun, conn.NewStdNetBind(), logger)

	err = entryDev.IpcSet(C.GoString(entrySettings))
	if err != nil {
		logger.Errorf("Unable to set IPC settings for entry: %v", err)
		tun.Close()
		return errBadWgConfig
	}

	err = exitDev.IpcSet(exitConfigString)
	if err != nil {
		logger.Errorf("Unable to set IPC settings for exit: %v", err)
		tun.Close()
		return errBadWgConfig
	}

	exitDev.Up()
	entryDev.Up()
	logger.Verbosef("Device started")

	var i int32
	for i = 0; i < math.MaxInt32; i++ {
		if _, exists := tunnelHandles[i]; !exists {
			break
		}
	}
	if i == math.MaxInt32 {
		tun.Close()
		return errDeviceLimitHit
	}
	tunnelHandles[i] = tunnelHandle{exitDev, entryDev, logger, nil}
	return i
}

//export wgTurnOnMultihop
func wgTurnOnMultihop(exitSettings *C.char, entrySettings *C.char, privateIp *C.char, tunFd int32) int32 {
	logger := &device.Logger{
		Verbosef: CLogger(0).Printf,
		Errorf:   CLogger(1).Printf,
	}

	dupTunFd, err := unix.Dup(int(tunFd))
	if err != nil {
		logger.Errorf("Unable to dup tun fd: %v", err)
		return errDup
	}

	err = unix.SetNonblock(dupTunFd, true)
	if err != nil {
		logger.Errorf("Unable to set tun fd as non blocking: %v", err)
		unix.Close(dupTunFd)
		return errSetNonblock
	}
	tun, err := tun.CreateTUNFromFile(os.NewFile(uintptr(dupTunFd), "/dev/tun"), 0)
	if err != nil {
		logger.Errorf("Unable to create new tun device from fd: %v", err)
		unix.Close(dupTunFd)
		return errCreateTun
	}

	exitMtu, err := tun.MTU()
	if err != nil {
		tun.Close()
		return errGetMtu
	}

	return wgTurnOnMultihopInner(tun, exitSettings, entrySettings, privateIp, exitMtu, logger)

}

func openTUNFromSocket(tunFd int32, logger *device.Logger) tun.Device {

	dupTunFd, err := unix.Dup(int(tunFd))
	if err != nil {
		logger.Errorf("Unable to dup tun fd: %v", err)
		return nil
	}

	err = unix.SetNonblock(dupTunFd, true)
	if err != nil {
		logger.Errorf("Unable to set tun fd as non blocking: %v", err)
		unix.Close(dupTunFd)
		return nil
	}
	tun, err := tun.CreateTUNFromFile(os.NewFile(uintptr(dupTunFd), "/dev/tun"), 0)
	if err != nil {
		logger.Errorf("Unable to create new tun device from fd: %v", err)
		unix.Close(dupTunFd)
		return nil
	}

	return tun
}

func addTunnelFromDevice(dev *device.Device, settings string, virtualNet *netstack.Net, logger *device.Logger) int32 {
	err := dev.IpcSet(settings)
	if err != nil {
		logger.Errorf("Unable to set IPC settings: %v", err)
		dev.Close()
		return errBadWgConfig
	}

	dev.Up()
	logger.Verbosef("Device started")

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
	tunnelHandles[i] = tunnelHandle{dev, nil, logger, virtualNet}
	return i
}

//export wgTurnOn
func wgTurnOn(settings *C.char, tunFd int32) int32 {
	logger := &device.Logger{
		Verbosef: CLogger(0).Printf,
		Errorf:   CLogger(1).Printf,
	}
	tun := openTUNFromSocket(tunFd, logger)
	if tun == nil {
		return -1
	}

	logger.Verbosef("Attaching to interface")
	dev := device.NewDevice(tun, conn.NewStdNetBind(), logger)

	return addTunnelFromDevice(dev, C.GoString(settings), nil, logger)
}

func wgTurnOnIANFromExistingTunnel(tun tun.Device, settings string, privateAddr netip.Addr) int32 {
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

	return addTunnelFromDevice(dev, settings, virtualNet, logger)
}

//export wgTurnOnIAN
func wgTurnOnIAN(settings *C.char, tunFd int32, privateIP *C.char) int32 {
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

	tun := openTUNFromSocket(tunFd, logger)
	if tun == nil {
		return -1
	}

	return wgTurnOnIANFromExistingTunnel(tun, C.GoString(settings), privateAddr)
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

func wgOpenInTunnelICMP(tunnelHandle int32, address string, recv_fd *uintptr, send_fd *uintptr) int {
	handle, ok := tunnelHandles[tunnelHandle]
	if !ok || handle.virtualNet == nil {
		return -1
	}
	conn, _ := handle.virtualNet.Dial("ping4", address)
	sendRx, sendTx, err := os.Pipe()
	recvRx, recvTx, err := os.Pipe()
	if err != nil {
		return -1
	}
	unix.SetNonblock(int(recvRx.Fd()), false)
	sendbuf := make([]byte, 1024)
	rxShutdown := make(chan struct{})
	go func() { // the sender
		defer sendRx.Close()
		select {
		case _ = <-rxShutdown:
			return
		default:
		}
		count, err := sendRx.Read(sendbuf)
		if err == io.EOF {
			rxShutdown <- struct{}{}
		}
		fmt.Printf("Sent %d bytes to connection\n", count)
		conn.Write(sendbuf[:count])
	}()
	recvbuf := make([]byte, 1024)
	go func() { // the receiver
		defer recvTx.Close()
		select {
		case _ = <-rxShutdown:
			return
		default:
		}
		count, err := conn.Read(recvbuf)
		if err == io.EOF {
			rxShutdown <- struct{}{}
		}
		fmt.Printf("Received %d bytes from connection\n", count)
		recvTx.Write(recvbuf[:count])
	}()
	*recv_fd = recvRx.Fd()
	*send_fd = sendTx.Fd()
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

func main() {}

// Parse a wireguard config and return the first endpoint address it finds and
// parses successfully.
func parseEndpointFromGoConfig(config string) *netip.AddrPort {
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
