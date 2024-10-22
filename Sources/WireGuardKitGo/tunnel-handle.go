package main

import "C"

import (
	"net"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

type tunnelHandles struct {
	handles map[int32]*tunnelHandle
	lock    sync.Mutex
}

func NewTunnelHandles() *tunnelHandles {
	return &tunnelHandles{
		handles: make(map[int32]*tunnelHandle),
		lock: sync.Mutex{},
	}

}

func (h *tunnelHandles) Get(idx int32) *tunnelHandle {
	h.lock.Lock()
	defer h.lock.Unlock()

	return h.handles[idx]
}

// Inserts handle, returns a positive index if successful. Otherwise, returns a errDeviceLimitHit.
func (h *tunnelHandles) Insert(handle *tunnelHandle) int32 {
	h.lock.Lock()
	defer h.lock.Unlock()

	return insertHandle(h.handles, handle)
}

// Removes the handle at `idx` and returns it. Returns nil if `idx` doesn't exist.
func (h *tunnelHandles) Remove(idx int32) *tunnelHandle {
	h.lock.Lock()
	defer h.lock.Unlock()
	handle := h.handles[idx]
	delete(h.handles, idx)
	return handle
}

type tunnelHandle struct {
	exit          *device.Device
	entry         *device.Device
	logger        *device.Logger
	VirtualNet    *netstack.Net
	socketHandles map[int32]net.Conn
	lock          *sync.Mutex
}

func NewTunnelHandle(exit *device.Device, entry *device.Device, logger *device.Logger, virtualNet *netstack.Net) tunnelHandle {
	return tunnelHandle{
		exit:          exit,
		entry:         entry,
		logger:        logger,
		VirtualNet:    virtualNet,
		socketHandles: make(map[int32]net.Conn),
		lock:          &sync.Mutex{},
	}
}

// Returns nil if tunnel is closed
func (tun *tunnelHandle) GetConfig() *string {
	settings, err := tun.exit.IpcGet()
	if err != nil {
		return nil
	}
	return &settings
}

func (tun *tunnelHandle) SetConfig(settings string) int64 {
	err := tun.exit.IpcSet(settings)
	if err != nil {
		tun.logger.Errorf("Unable to set IPC settings: %v", err)
		if ipcErr, ok := err.(*device.IPCError); ok {
			return ipcErr.ErrorCode()
		}
		return errBadWgConfig
	}
	return 0
}

func (tun *tunnelHandle) BumpSockets() {
	device := tun.exit
	if tun.entry != nil {
		device = tun.entry
	}

	go func() {
		for i := 0; i < 10; i++ {
			err := device.BindUpdate()
			if err == nil {
				device.SendKeepalivesToPeersWithCurrentKeypair()
				return
			}
			tun.logger.Errorf("Unable to update bind, try %d: %v", i+1, err)
			time.Sleep(time.Second / 2)
		}
		tun.logger.Errorf("Gave up trying to update bind; tunnel is likely dysfunctional")
	}()
}

func (tun *tunnelHandle) DisableSomeRoamingForBrokenMobileSemantics() {
	tun.exit.DisableSomeRoamingForBrokenMobileSemantics()
	if tun.entry != nil {
		tun.entry.DisableSomeRoamingForBrokenMobileSemantics()
	}
}

// Takes a closure that creates a socket. If the handle fails to be stored, the
// socket will be closed. Adds an associated socket to the tunnel handle. The
// caller is responsible for binding the socket via `VirtualNet`. Returns a -1
// if failed to create a socket. Returns a `errDeviceLimitHit` if too many
// sockets are open already.
func (tun *tunnelHandle) AddSocket(createSocket func(virtualNet *netstack.Net)(net.Conn, error)) int32 {
	tun.lock.Lock()
	defer tun.lock.Unlock()
	socket, err := createSocket(tun.VirtualNet)
	if err != nil {
		return -1
	}
	handle := insertHandle(tun.socketHandles, socket)
	if handle < 0 {
		socket.Close()
	}
	return handle
}

// Returns a socket bound to the virtual network
func (tun *tunnelHandle) GetSocket(id int32) (net.Conn, bool) {
	tun.lock.Lock()
	defer tun.lock.Unlock()
	socket, ok := tun.socketHandles[id]
	return socket, ok
}

func (tun *tunnelHandle) RemoveAndCloseSocket(id int32) bool {
	tun.lock.Lock()
	defer tun.lock.Unlock()
	socket, ok := tun.socketHandles[id]
	if ok {
		socket.Close()
	}

	delete(tun.socketHandles, id)
	return ok
}

func (tun *tunnelHandle) Close() {
	tun.lock.Lock()
	defer tun.lock.Unlock()

	for _, socket := range tun.socketHandles {
		socket.Close()
	}

	tun.socketHandles = make(map[int32]net.Conn)
	tun.exit.Close()
	if tun.entry != nil {
		tun.entry.Close()
	}
}
