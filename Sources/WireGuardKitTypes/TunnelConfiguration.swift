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
