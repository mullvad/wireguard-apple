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
	"errors"
	"fmt"
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
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
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
	*device.Device
	*device.Logger
	entryDevice *device.Device
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

// The exit settings should contain a single peer with a specific endpoint config.
// TODO: elaborate on the endpoint config.
// The _special_ endpoint will the be used to receive the exit traffic and pass
// it on to the entry device.
//
// The entry config should have a endpoint address that is reasonable and used
// by the exit config.  TODO: elaborate and make the sentence sound reasonable
//
// export wgTurnOnMultihop
func wgTurnOnMultihop(entrySettings *C.char, exitSettings *C.char, tunFd int32) int32 {
	logger := &device.Logger{
		Verbosef: CLogger(0).Printf,
		Errorf:   CLogger(1).Printf,
	}
	dupTunFd, err := unix.Dup(int(tunFd))
	if err != nil {
		logger.Errorf("Unable to dup tun fd: %v", err)
		return -1
	}

	err = unix.SetNonblock(dupTunFd, true)
	if err != nil {
		logger.Errorf("Unable to set tun fd as non blocking: %v", err)
		unix.Close(dupTunFd)
		return -1
	}
	tun, err := tun.CreateTUNFromFile(os.NewFile(uintptr(dupTunFd), "/dev/tun"), 0)
	if err != nil {
		logger.Errorf("Unable to create new tun device from fd: %v", err)
		unix.Close(dupTunFd)
		return -1
	}
	logger.Verbosef("Attaching to interface")
	exitDevice := device.NewDevice(tun, &TunnelPipe{}, logger)

	err = exitDevice.IpcSet(C.GoString(exitSettings))
	if err != nil {
		logger.Errorf("Unable to set IPC settings: %v", err)
		unix.Close(dupTunFd)
		return -1
	}

	exitDevice.Up()
	logger.Verbosef("Device started")

	var i int32
	for i = 0; i < math.MaxInt32; i++ {
		if _, exists := tunnelHandles[i]; !exists {
			break
		}
	}
	if i == math.MaxInt32 {
		unix.Close(dupTunFd)
		return -1
	}
	var entryDevice *device.Device
	var noDns []netip.Addr
	// TODO: figure out real MTU
	entryTunDevice, _, err := netstack.CreateNetTUN([]netip.Addr{}, noDns, 1280)
	if err != nil {
		return -1
	}
	entryDevice = device.NewDevice(entryTunDevice, conn.NewStdNetBind(), logger)

	// Spawn a go routine to listen on UDP loopback socket and pass packets from exit device to entry device
	go func() {

	}()

	// Spawn a go routine to send back on UDP loopback socket and pass packets from exit device to entry device
	go func() {

	}()

	tunnelHandles[i] = tunnelHandle{exitDevice, logger, entryDevice}
	return i
}

//export wgTurnOn
func wgTurnOn(settings *C.char, tunFd int32) int32 {
	logger := &device.Logger{
		Verbosef: CLogger(0).Printf,
		Errorf:   CLogger(1).Printf,
	}
	dupTunFd, err := unix.Dup(int(tunFd))
	if err != nil {
		logger.Errorf("Unable to dup tun fd: %v", err)
		return -1
	}

	err = unix.SetNonblock(dupTunFd, true)
	if err != nil {
		logger.Errorf("Unable to set tun fd as non blocking: %v", err)
		unix.Close(dupTunFd)
		return -1
	}
	tun, err := tun.CreateTUNFromFile(os.NewFile(uintptr(dupTunFd), "/dev/tun"), 0)
	if err != nil {
		logger.Errorf("Unable to create new tun device from fd: %v", err)
		unix.Close(dupTunFd)
		return -1
	}
	logger.Verbosef("Attaching to interface")
	dev := device.NewDevice(tun, conn.NewStdNetBind(), logger)

	err = dev.IpcSet(C.GoString(settings))
	if err != nil {
		logger.Errorf("Unable to set IPC settings: %v", err)
		unix.Close(dupTunFd)
		return -1
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
		unix.Close(dupTunFd)
		return -1
	}
	tunnelHandles[i] = tunnelHandle{dev, logger, nil}
	return i
}

//export wgTurnOff
func wgTurnOff(tunnelHandle int32) {
	dev, ok := tunnelHandles[tunnelHandle]
	if !ok {
		return
	}
	delete(tunnelHandles, tunnelHandle)
	dev.Close()
}

//export wgSetConfig
func wgSetConfig(tunnelHandle int32, settings *C.char) int64 {
	dev, ok := tunnelHandles[tunnelHandle]
	if !ok {
		return 0
	}
	err := dev.IpcSet(C.GoString(settings))
	if err != nil {
		dev.Errorf("Unable to set IPC settings: %v", err)
		if ipcErr, ok := err.(*device.IPCError); ok {
			return ipcErr.ErrorCode()
		}
		return -1
	}
	return 0
}

//export wgGetConfig
func wgGetConfig(tunnelHandle int32) *C.char {
	device, ok := tunnelHandles[tunnelHandle]
	if !ok {
		return nil
	}
	settings, err := device.IpcGet()
	if err != nil {
		return nil
	}
	return C.CString(settings)
}

//export wgBumpSockets
func wgBumpSockets(tunnelHandle int32) {
	dev, ok := tunnelHandles[tunnelHandle]
	if !ok {
		return
	}
	go func() {
		for i := 0; i < 10; i++ {
			err := dev.BindUpdate()
			if err == nil {
				dev.SendKeepalivesToPeersWithCurrentKeypair()
				return
			}
			dev.Errorf("Unable to update bind, try %d: %v", i+1, err)
			time.Sleep(time.Second / 2)
		}
		dev.Errorf("Gave up trying to update bind; tunnel is likely dysfunctional")
	}()
}

//export wgDisableSomeRoamingForBrokenMobileSemantics
func wgDisableSomeRoamingForBrokenMobileSemantics(tunnelHandle int32) {
	dev, ok := tunnelHandles[tunnelHandle]
	if !ok {
		return
	}
	dev.DisableSomeRoamingForBrokenMobileSemantics()
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

type TunnelPipe struct {
	writeChannel      chan [][]byte
	readChannel       chan [][]byte
	closed            bool
	leftoverReadBytes [][]byte
	source            netip.Addr
	destination       netip.Addr
}

func NewTunnelPipe(source, destination netip.Addr) TunnelPipe {
	return TunnelPipe{
		writeChannel:      make(chan [][]byte),
		readChannel:       make(chan [][]byte),
		closed:            false,
		leftoverReadBytes: [][]byte{},
		source:            source,
		destination:       destination,
	}
}

func (pipe *TunnelPipe) Open(port uint16) (fns []conn.ReceiveFunc, actualPort uint16, err error) {
	receiverFuncs := []conn.ReceiveFunc{

		func(packets [][]byte, sizes []int, eps []conn.Endpoint) (n int, err error) {
			receivedPackets, ok := <-pipe.readChannel
			if !ok {
				return 0, errors.New("Read channel closed")
			}

			numReceivedPackets := len(receivedPackets)
			if len(packets) <= numReceivedPackets {
				return 0, errors.New("Output packet buffer not big enough")
			}

			for idx, receivedPacket := range receivedPackets {
				receivedPacket := receivedPacket
				packets[idx] = receivedPacket
				sizes[idx] = len(receivedPacket)
			}

			return len(receivedPackets), nil
		},
	}

	return receiverFuncs, 0, nil
}

func (pipe *TunnelPipe) Close() error {
	return nil
}

func (pipe *TunnelPipe) SetMark(mark uint32) error {
	return nil
}

func (pipe *TunnelPipe) Send(packets [][]byte, ep conn.Endpoint) error {
	pipe.writeChannel <- packets
	return nil
}

func (pipe *TunnelPipe) BatchSize() int {
	return conn.IdealBatchSize
}

func (self *TunnelPipe) ParseEndpoint(s string) (conn.Endpoint, error) {
	return &TunnelPipeEndpoint{
		src: self.source,
		dst: self.destination,
	}, nil
}

type TunnelPipeEndpoint struct {
	src netip.Addr
	dst netip.Addr
}

func (ep *TunnelPipeEndpoint) ClearSrc() {}

func (ep *TunnelPipeEndpoint) SrcToString() string {
	return ep.src.String()

}

func (ep *TunnelPipeEndpoint) DstToString() string {
	return ep.dst.String()

}
func (ep *TunnelPipeEndpoint) DstToBytes() []byte {
	return ep.dst.AsSlice()
}

func (ep *TunnelPipeEndpoint) DstIP() netip.Addr {
	return ep.dst
}
func (ep *TunnelPipeEndpoint) SrcIP() netip.Addr {
	return ep.src
}

func main() {}
