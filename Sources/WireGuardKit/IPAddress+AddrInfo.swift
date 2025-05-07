import Foundation
import Network

extension IPv4Address {
    init?(addrInfo: addrinfo) {
        self.init(customInit: addrInfo)
    }

    init?(customInit addrInfo: addrinfo) {
        guard addrInfo.ai_family == AF_INET else { return nil }

        let addressData = addrInfo.ai_addr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { ptr -> Data in
            return Data(bytes: &ptr.pointee.sin_addr, count: MemoryLayout<in_addr>.size)
        }

        self.init(addressData)
    }
}

extension IPv6Address {
    init?(addrInfo: addrinfo) {
        self.init(customInit: addrInfo)
    }

    init?(customInit addrInfo: addrinfo) {
        guard addrInfo.ai_family == AF_INET6 else { return nil }

        let addressData = addrInfo.ai_addr.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { ptr -> Data in
            return Data(bytes: &ptr.pointee.sin6_addr, count: MemoryLayout<in6_addr>.size)
        }

        self.init(addressData)
    }
}
