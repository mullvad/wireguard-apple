// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

import Foundation
import Network

public final class TunnelConfiguration {
    public var name: String?
    public var interface: InterfaceConfiguration
    public let peers: [PeerConfiguration]
    public let pingableGateway: IPv4Address?

    public init(name: String?, interface: InterfaceConfiguration, peers: [PeerConfiguration], pingableGateway: IPv4Address? = nil) {
        self.interface = interface
        self.peers = peers
        self.name = name
        self.pingableGateway = pingableGateway

        let peerPublicKeysArray = peers.map { $0.publicKey }
        let peerPublicKeysSet = Set<PublicKey>(peerPublicKeysArray)
        if peerPublicKeysArray.count != peerPublicKeysSet.count {
            fatalError("Two or more peers cannot have the same public key")
        }
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
public struct DaitaConfiguration: Equatable {
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
