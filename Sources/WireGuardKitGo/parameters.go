package main

import "C"

import (
	"bufio"
	"net/netip"
	"strings"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

type WGParameters struct {
	exitSettings    string
	entrySettings   *string
	privateIP       *netip.Addr
	privateIP6      *netip.Addr
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
		if p.privateIP == nil {
			logger.Errorf("User settings supplied but no user source address provided")
			return errNoPrivateIp
		}
		if (p.privateIP6 != nil) == (p.userSource6 != nil) {
			logger.Errorf("Only one of private or user source IPv6 addresses supplied")
			return errNoIPv6
		}

		if len(p.UserAllowedIPs()) == 0 {
			return errNoUserPrefixes
		}
	}

	if p.entrySettings != nil && p.privateIP == nil {
		logger.Errorf("Entry settings provided but no private IP address")
		return errNoPrivateIp
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
func (p *WGParameters) RootTunDevices(tunFd int32, logger *device.Logger) (tun.Device, tun.Device, int32) {
	var userDevice tun.Device
	rootDevice, errCode := openTUNFromSocket(tunFd, logger)
	if errCode != 0 {
		return nil, nil, errCode
	}

	if p.userSettings != nil {
		rootDevice, userDevice = NewSplicer(rootDevice, p.UserAllowedIPs(), *p.privateIP, *p.privateIP6, *p.userSource4, p.userSource6)

	}

	return rootDevice, userDevice, 0
}
