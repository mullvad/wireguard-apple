package main

import "C"

import (
	"os"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// Functions for the various tasks involved in setting up a tunnel.
// These are composed as needed into the API functions

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
		if maybeNotMachines != nil {
			returnValue := configureDaita(entryDev, entrySettings, C.GoString(maybeNotMachines), maybeNotMaxEvents, maybeNotMaxActions)
			if returnValue != 0 {
				return returnValue
			}
		}
	} else {
		// Enable DAITA if DAITA parameters are passed through
		if maybeNotMachines != nil {
			returnValue := configureDaita(dev, settings, C.GoString(maybeNotMachines), maybeNotMaxEvents, maybeNotMaxActions)
			if returnValue != 0 {
				return returnValue
			}
		}
	}

	return insertHandle(tunnelHandles, tunnelHandle{dev, entryDev, logger, virtualNet})
}
