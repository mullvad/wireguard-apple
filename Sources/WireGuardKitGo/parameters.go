package main

import "C"

import (
	"bufio"
	"encoding/hex"
	"net/netip"
	"strings"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/multihoptun"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

type WGParameters struct {
	exitSettings    string
	entrySettings   *string
	privateIP       netip.Addr
	privateIP6      netip.Addr
	userSettings    *string
	userSource4     *netip.Addr
	userSource6     *netip.Addr
	daitaParameters *daitaParameters
}

func (p *WGParameters) Validate(logger *device.Logger) int32 {
	if p.userSettings != nil {
		if p.userSource4 == nil {
			logger.Errorf("User settings supplied but no user source address provided")
			return errNoUserIp
		}

		if len(p.UserAllowedIPs()) == 0 {
			return errNoUserPrefixes
		}
	}

	return 0
}

func (p *WGParameters) UserAllowedIPs() []netip.Prefix {
	prefixes := []netip.Prefix{}
	if p.userSettings == nil {
		return prefixes
	}
	scanner := bufio.NewScanner(strings.NewReader(*p.entrySettings))

	for scanner.Scan() {
		line := scanner.Text()
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}

		if key == "allowed_ip" {
			prefix, err := netip.ParsePrefix(value)
			if err == nil {
				prefixes = append(prefixes, prefix)
			}
		}
	}

	return prefixes
}

// Returns the root tunnel device, from which all traffic will be read, and
// optionally a device to be used for a user tunnel. This function assumes that
// `Validate()` has been called and no errors were returned
func (p *WGParameters) RootTunDevices(tunFd int32, logger *device.Logger) (tun.Device, tun.Device, *netstack.Net, int32) {
	var userDevice tun.Device
	rootDevice, errCode := openTUNFromSocket(tunFd, logger)
	if errCode != 0 {
		return nil, nil, nil, errCode
	}

	if p.userSettings != nil {
		rootDevice, userDevice = NewSplicer(rootDevice, p.UserAllowedIPs(), p.privateIP, p.privateIP6, *p.userSource4, p.userSource6)

	}

	vtun, virtualNet, err := netstack.CreateNetTUN([]netip.Addr{p.privateIP}, []netip.Addr{}, 1280)
	if err != nil {
		return nil, nil, nil, errCreateVirtualTun
	}

	router := NewRouter(rootDevice, vtun)
	rootDevice = &router

	return rootDevice, userDevice, virtualNet, 0
}

// Returns a binder for the entry device, optionally returns a tunnel device
// for the exit if it is needed. Root MTU is only used if multihop is used.
// This function is only safe to call after `Validate()` returned without
// failure.
func (p *WGParameters) RootBinder(rootMtu int) (conn.Bind, tun.Device, int32) {
	if p.entrySettings != nil {
		exitEndpoint := p.exitEndpoint()
		if exitEndpoint == nil {
			return nil, nil, errNoEndpointInConfig
		}
		// MTU of this device should be the MTU of the innermost layer + 80 byte overhead
		multiHopTun := multihoptun.NewMultihopTun(p.privateIP, exitEndpoint.Addr(), exitEndpoint.Port(), rootMtu+80)
		return multiHopTun.Binder(), &multiHopTun, 0

	}

	return conn.NewStdNetBind(), nil, 0
}

// Constructs all the WireGuard devices and brings them up. / Validate()
// must've returned successfully before calling this function. / If
// the returned tunnel handle pointer is not nil, it must be closed, even
// if an error is returned.
func (p *WGParameters) WireGuardDevices(tunFd int32, logger *device.Logger) (*tunnelHandle, int32) {
	var entry, exit, user *device.Device
	rootTun, userTun, virtualNet, errCode := p.RootTunDevices(tunFd, logger)
	if errCode != 0 {
		return nil, errCode
	}

	mtu, err := rootTun.MTU()
	if err != nil {
		return nil, errGetMtu
	}

	rootBinder, exitTun, errCode := p.RootBinder(mtu)

	// a root device can either be an entry or an exit, depending on if multihop
	// is used.
	rootDev := device.NewDevice(rootTun, rootBinder, logger)

	if p.entrySettings != nil {
		exit = rootDev
		entry = device.NewDevice(exitTun, conn.NewStdNetBind(), logger)
	} else {
		exit = rootDev
	}

	if p.userSettings != nil {
		user = device.NewDevice(userTun, conn.NewStdNetBind(), logger)
	}

	handle := NewTunnelHandle(exit, entry, logger, virtualNet, user)

	if entry != nil {
		err = bringUpDevice(entry, *p.entrySettings, logger)

		if err != nil {
			return &handle, errBadWgConfig
		}
	}

	err = bringUpDevice(exit, p.exitSettings, logger)
	if err != nil {
		return &handle, errBadWgConfig
	}



	if user != nil {
		err = bringUpDevice(user, *p.userSettings, logger)
		if err != nil {
			return &handle, errBadWgConfig
		}
	}

	if p.daitaParameters != nil {
		if entry == nil {
			errCode = p.ConfigureDaita(exit)
		} else {
			errCode = p.ConfigureDaita(entry)
		}
	}

	return &handle, errCode
}

func (p *WGParameters) ConfigureDaita(device *device.Device) int32 {
	firstHopSettings := p.exitSettings
	if p.entrySettings != nil {
		firstHopSettings = *p.entrySettings
	}

	peerPubKey := firstPublicKey(firstHopSettings)
	if peerPubKey == nil {
		return errNoPeer
	}
	peer := device.LookupPeer(*peerPubKey)
	if peer == nil {
		return errNoPeer
	}

	if p.daitaParameters == nil {
		return errNoDaitaParameters
	}

	d := p.daitaParameters
	if !peer.EnableDaita(d.MaybeNotMachines, uint(d.MaybeNotMaxEvents), uint(d.MaybeNotMaxActions), d.MaybeNotMaxPadding, d.MaybeNotMaxPadding) {
		return errEnableDaita
	}

	return 0
}

func (p *WGParameters) exitEndpoint() *netip.AddrPort {
	scanner := bufio.NewScanner(strings.NewReader(p.exitSettings))
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

func firstPublicKey(config string) *device.NoisePublicKey {
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
