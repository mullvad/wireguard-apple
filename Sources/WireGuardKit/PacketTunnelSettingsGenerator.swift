// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

import Foundation
import Network
import NetworkExtension

#if SWIFT_PACKAGE
import WireGuardKitTypes
#endif

/// A type alias for `Result` type that holds a tuple with source and resolved endpoint.
typealias EndpointResolutionResult = Result<(Endpoint, Endpoint), DNSResolutionError>

struct DeviceConfiguration {
    let configuration: TunnelConfiguration
    let resolvedEndpoints: [Endpoint?]

    func generateNetworkSettings() -> NEPacketTunnelNetworkSettings {
        /* iOS requires a tunnel endpoint, whereas in WireGuard it's valid for
         * a tunnel to have no endpoint, or for there to be many endpoints, in
         * which case, displaying a single one in settings doesn't really
         * make sense. So, we fill it in with this placeholder, which is not
         * a valid IP address that will actually route over the Internet.
         */
        let networkSettings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")

        if !configuration.interface.dnsSearch.isEmpty || !configuration.interface.dns.isEmpty {
            let dnsServerStrings = configuration.interface.dns.map { $0.stringRepresentation }
            let dnsSettings = NEDNSSettings(servers: dnsServerStrings)
            dnsSettings.searchDomains = configuration.interface.dnsSearch
            if !configuration.interface.dns.isEmpty {
                dnsSettings.matchDomains = [""] // All DNS queries must first go through the tunnel's DNS
            }
            networkSettings.dnsSettings = dnsSettings
        }

        let mtu = configuration.interface.mtu ?? 0

        /* 0 means automatic MTU. In theory, we should just do
         * `networkSettings.tunnelOverheadBytes = 80` but in
         * practice there are too many broken networks out there.
         * Instead set it to 1280. Boohoo. Maybe someday we'll
         * add a nob, maybe, or iOS will do probing for us.
         */
        if mtu == 0 {
            #if os(iOS)
                networkSettings.mtu = NSNumber(value: 1280)
            #elseif os(macOS)
                networkSettings.tunnelOverheadBytes = 80
            #else
                #error("Unimplemented")
            #endif
        } else {
            networkSettings.mtu = NSNumber(value: mtu)
        }

        let (ipv4Addresses, ipv6Addresses) = addresses()
        let (ipv4IncludedRoutes, ipv6IncludedRoutes) = includedRoutes()

        let ipv4Settings = NEIPv4Settings(addresses: ipv4Addresses.map { $0.destinationAddress }, subnetMasks: ipv4Addresses.map { $0.destinationSubnetMask })
        ipv4Settings.includedRoutes = ipv4IncludedRoutes
        networkSettings.ipv4Settings = ipv4Settings

        let ipv6Settings = NEIPv6Settings(addresses: ipv6Addresses.map { $0.destinationAddress }, networkPrefixLengths: ipv6Addresses.map { $0.destinationNetworkPrefixLength })
        ipv6Settings.includedRoutes = ipv6IncludedRoutes
        networkSettings.ipv6Settings = ipv6Settings

        return networkSettings
    }

    func endpointUapiConfiguration() -> (String, [EndpointResolutionResult?]) {
        var resolutionResults = [EndpointResolutionResult?]()
        var wgSettings = ""

        assert(configuration.peers.count == resolvedEndpoints.count)
        for (peer, resolvedEndpoint) in zip(self.configuration.peers, self.resolvedEndpoints) {
            wgSettings.append("public_key=\(peer.publicKey.hexKey)\n")

            let result = resolvedEndpoint.map(PacketTunnelSettingsGenerator.reresolveEndpoint)
            if case .success((_, let resolvedEndpoint)) = result {
                if case .name = resolvedEndpoint.host { assert(false, "Endpoint is not resolved") }
                wgSettings.append("endpoint=\(resolvedEndpoint.stringRepresentation)\n")
            }
            resolutionResults.append(result)
        }

        return (wgSettings, resolutionResults)
    }

    private func addresses() -> ([NEIPv4Route], [NEIPv6Route]) {
        var ipv4Routes = [NEIPv4Route]()
        var ipv6Routes = [NEIPv6Route]()
        for addressRange in configuration.interface.addresses {
            if addressRange.address is IPv4Address {
                ipv4Routes.append(NEIPv4Route(destinationAddress: "\(addressRange.address)", subnetMask: "\(addressRange.subnetMask())"))
            } else if addressRange.address is IPv6Address {
                /* Big fat ugly hack for broken iOS networking stack: the smallest prefix that will have
                 * any effect on iOS is a /120, so we clamp everything above to /120. This is potentially
                 * very bad, if various network parameters were actually relying on that subnet being
                 * intentionally small. TODO: talk about this with upstream iOS devs.
                 */
                ipv6Routes.append(NEIPv6Route(destinationAddress: "\(addressRange.address)", networkPrefixLength: NSNumber(value: min(120, addressRange.networkPrefixLength))))
            }
        }
        return (ipv4Routes, ipv6Routes)
    }

    private func includedRoutes() -> ([NEIPv4Route], [NEIPv6Route]) {
        var ipv4IncludedRoutes = [NEIPv4Route]()
        var ipv6IncludedRoutes = [NEIPv6Route]()

        let defaultIPv4Route = NEIPv4Route.default()
        ipv4IncludedRoutes.append(defaultIPv4Route)

        let defaultIPv6Route = NEIPv6Route.default()
        ipv6IncludedRoutes.append(defaultIPv6Route)

        for addressRange in configuration.interface.addresses {
            if addressRange.address is IPv4Address {
                let route = NEIPv4Route(destinationAddress: "\(addressRange.maskedAddress())", subnetMask: "\(addressRange.subnetMask())")
                route.gatewayAddress = "\(addressRange.address)"
                ipv4IncludedRoutes.append(route)
            } else if addressRange.address is IPv6Address {
                let route = NEIPv6Route(destinationAddress: "\(addressRange.maskedAddress())", networkPrefixLength: NSNumber(value: addressRange.networkPrefixLength))
                route.gatewayAddress = "\(addressRange.address)"
                ipv6IncludedRoutes.append(route)
            }
        }

        for peer in configuration.peers {
            for addressRange in peer.allowedIPs {
                if addressRange.address is IPv4Address {
                    ipv4IncludedRoutes.append(NEIPv4Route(destinationAddress: "\(addressRange.address)", subnetMask: "\(addressRange.subnetMask())"))
                } else if addressRange.address is IPv6Address {
                    ipv6IncludedRoutes.append(NEIPv6Route(destinationAddress: "\(addressRange.address)", networkPrefixLength: NSNumber(value: addressRange.networkPrefixLength)))
                }
            }
        }
        return (ipv4IncludedRoutes, ipv6IncludedRoutes)
    }

}

class PacketTunnelSettingsGenerator {
    let exit: DeviceConfiguration
    let entry: DeviceConfiguration?

    init(exit: DeviceConfiguration, entry: DeviceConfiguration? = nil) {
        self.exit = exit
        self.entry = entry
    }

    func entryUapiConfiguration() -> (String, [EndpointResolutionResult?])? {
        if let entry {
            uapiConfiguration(for: entry)
        } else {
            nil
        }
    }

    private func uapiConfiguration(for device: DeviceConfiguration) -> (String, [EndpointResolutionResult?]) {
        var resolutionResults = [EndpointResolutionResult?]()
        var wgSettings = ""
        wgSettings.append("private_key=\(device.configuration.interface.privateKey.hexKey)\n")
        if let listenPort = device.configuration.interface.listenPort {
            wgSettings.append("listen_port=\(listenPort)\n")
        }
        if !device.configuration.peers.isEmpty {
            wgSettings.append("replace_peers=true\n")
        }
        assert(device.configuration.peers.count == device.resolvedEndpoints.count)
        for (peer, resolvedEndpoint) in zip(device.configuration.peers, device.resolvedEndpoints) {
            wgSettings.append("public_key=\(peer.publicKey.hexKey)\n")
            if let preSharedKey = peer.preSharedKey?.hexKey {
                wgSettings.append("preshared_key=\(preSharedKey)\n")
            }

            let result = resolvedEndpoint.map(Self.reresolveEndpoint)
            if case .success((_, let resolvedEndpoint)) = result {
                if case .name = resolvedEndpoint.host { assert(false, "Endpoint is not resolved") }
                wgSettings.append("endpoint=\(resolvedEndpoint.stringRepresentation)\n")
            }
            resolutionResults.append(result)

            let persistentKeepAlive = peer.persistentKeepAlive ?? 0
            wgSettings.append("persistent_keepalive_interval=\(persistentKeepAlive)\n")
            if !peer.allowedIPs.isEmpty {
                wgSettings.append("replace_allowed_ips=true\n")
                peer.allowedIPs.forEach { wgSettings.append("allowed_ip=\($0.stringRepresentation)\n") }
            }
        }
        return (wgSettings, resolutionResults)

    }
    func uapiConfiguration() -> (String, [EndpointResolutionResult?]) {
        uapiConfiguration(for: self.exit)
   }

    func generateNetworkSettings() -> NEPacketTunnelNetworkSettings {
        exit.generateNetworkSettings()
    }
    
    func endpointUapiConfiguration() -> (String, [EndpointResolutionResult?]) {
        exit.endpointUapiConfiguration()
    }
    
    func entryEndpointUapiConfiguration() -> (String, [EndpointResolutionResult?])? {
        entry?.endpointUapiConfiguration()
    }

    private func addresses() -> ([NEIPv4Route], [NEIPv6Route]) {
        var ipv4Routes = [NEIPv4Route]()
        var ipv6Routes = [NEIPv6Route]()
        for addressRange in tunnelConfiguration.interface.addresses {
            if addressRange.address is IPv4Address {
                ipv4Routes.append(NEIPv4Route(destinationAddress: "\(addressRange.address)", subnetMask: "\(addressRange.subnetMask())"))
            } else if addressRange.address is IPv6Address {
                /* Big fat ugly hack for broken iOS networking stack: the smallest prefix that will have
                 * any effect on iOS is a /120, so we clamp everything above to /120. This is potentially
                 * very bad, if various network parameters were actually relying on that subnet being
                 * intentionally small. TODO: talk about this with upstream iOS devs.
                 */
                ipv6Routes.append(NEIPv6Route(destinationAddress: "\(addressRange.address)", networkPrefixLength: NSNumber(value: min(120, addressRange.networkPrefixLength))))
            }
        }
        return (ipv4Routes, ipv6Routes)
    }

    private func includedRoutes() -> ([NEIPv4Route], [NEIPv6Route]) {
        var ipv4IncludedRoutes = [NEIPv4Route]()
        var ipv6IncludedRoutes = [NEIPv6Route]()

        let defaultIPv4Route = NEIPv4Route.default()
        ipv4IncludedRoutes.append(defaultIPv4Route)

        let defaultIPv6Route = NEIPv6Route.default()
        ipv6IncludedRoutes.append(defaultIPv6Route)

        for addressRange in tunnelConfiguration.interface.addresses {
            if addressRange.address is IPv4Address {
                let route = NEIPv4Route(destinationAddress: "\(addressRange.maskedAddress())", subnetMask: "\(addressRange.subnetMask())")
                route.gatewayAddress = "\(addressRange.address)"
                ipv4IncludedRoutes.append(route)
            } else if addressRange.address is IPv6Address {
                let route = NEIPv6Route(destinationAddress: "\(addressRange.maskedAddress())", networkPrefixLength: NSNumber(value: addressRange.networkPrefixLength))
                route.gatewayAddress = "\(addressRange.address)"
                ipv6IncludedRoutes.append(route)
            }
        }

        for peer in tunnelConfiguration.peers {
            for addressRange in peer.allowedIPs {
                if addressRange.address is IPv4Address {
                    ipv4IncludedRoutes.append(NEIPv4Route(destinationAddress: "\(addressRange.address)", subnetMask: "\(addressRange.subnetMask())"))
                } else if addressRange.address is IPv6Address {
                    ipv6IncludedRoutes.append(NEIPv6Route(destinationAddress: "\(addressRange.address)", networkPrefixLength: NSNumber(value: addressRange.networkPrefixLength)))
                }
            }
        }
        return (ipv4IncludedRoutes, ipv6IncludedRoutes)
    }

    private class func reresolveEndpoint(endpoint: Endpoint) -> EndpointResolutionResult {
        return Result { (endpoint, try endpoint.withReresolvedIP()) }
            .mapError { error -> DNSResolutionError in
                // swiftlint:disable:next force_cast
                return error as! DNSResolutionError
            }
    }
}
