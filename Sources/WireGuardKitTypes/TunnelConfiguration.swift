// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

import Foundation

public final class TunnelConfiguration {
    public var name: String?
    public var interface: InterfaceConfiguration
    public let peers: [PeerConfiguration]

    public init(name: String?, interface: InterfaceConfiguration, peers: [PeerConfiguration]) {
        self.interface = interface
        self.peers = peers
        self.name = name

        let peerPublicKeysArray = peers.map { $0.publicKey }
        let peerPublicKeysSet = Set<PublicKey>(peerPublicKeysArray)
        if peerPublicKeysArray.count != peerPublicKeysSet.count {
            fatalError("Two or more peers cannot have the same public key")
        }
    }
    
    // TODO: Remove this function, it's a hack to test multihop
    public func copyWithDifferentPeer(publicKey: PublicKey, ip: String) -> TunnelConfiguration {
        let interface = self.interface
        let name = self.name
        let port = self.peers[0].endpoint?.port ?? 51820
        var peer = PeerConfiguration(publicKey: publicKey)
        peer.endpoint = Endpoint(from: "\(ip):\(port)")
        peer.allowedIPs = self.peers[0].allowedIPs
        return Self(name: name, interface: interface, peers: [peer])
    }
}

extension TunnelConfiguration: Equatable {
    public static func == (lhs: TunnelConfiguration, rhs: TunnelConfiguration) -> Bool {
        return lhs.name == rhs.name &&
            lhs.interface == rhs.interface &&
            Set(lhs.peers) == Set(rhs.peers)
    }
}


/// Contains arguments needed to initialize DAITA for a WireGuard device.
public struct DaitaConfiguration {
    /// Contains a string describing a set of DAITA machines.
    public let machines: String
    /// Maximum amount of DAITA events to enqueue at any given time.
    public let maxEvents: UInt32
    /// Maximum amount of DAITA actions to enqueue at any given time.
    public let maxActions: UInt32

    public init(machines: String, maxEvents: UInt32, maxActions: UInt32) {
        self.machines = machines
        self.maxEvents = maxEvents
        self.maxActions = maxActions
    }
}
