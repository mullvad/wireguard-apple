// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

import Foundation
import NetworkExtension

#if SWIFT_PACKAGE
import WireGuardKitGo
import WireGuardKitC
@_exported import WireGuardKitTypes
#endif

public enum WireGuardAdapterError: Error {
    /// Failure to locate tunnel file descriptor.
    case cannotLocateTunnelFileDescriptor

    /// Failure to perform an operation in such state.
    case invalidState

    /// Failure to resolve endpoints.
    case dnsResolution([DNSResolutionError])

    /// Failure to set network settings.
    case setNetworkSettings(Error)

    /// Failure to start WireGuard backend.
    case startWireGuardBackend(Int32)

    /// Config has no private IPs.
    case noInterfaceIp

    /// The tunnel descriptor provided does not refer to an open tunnel
    case noSuchTunnel
    
    /// the tunnel exists, but does not have a virtual interface
    case noTunnelVirtualInterface

    /// ICMP socket not open
    case icmpSocketNotOpen

    /// internal error
    case internalError(Int32)
}

/// Enum representing internal state of the `WireGuardAdapter`
private enum State {
    /// The tunnel is stopped
    case stopped

    /// The tunnel is up and running
    case started(_ handle: Int32, _ settingsGenerator: PacketTunnelSettingsGenerator)

    /// The tunnel is temporarily shutdown due to device going offline
    case temporaryShutdown(_ settingsGenerator: PacketTunnelSettingsGenerator)
}

public class WireGuardAdapter {
    public typealias LogHandler = (WireGuardLogLevel, String) -> Void

    /// Network routes monitor.
    private var networkMonitor: NWPathMonitor?

    /// Packet tunnel provider.
    private weak var packetTunnelProvider: NEPacketTunnelProvider?

    /// KVO observer for `NEProvider.defaultPath`.
    private var defaultPathObserver: NSKeyValueObservation?

    /// Last known default path.
    private var currentDefaultPath: NetworkExtension.NWPath?

    /// Log handler closure.
    private let logHandler: LogHandler

    /// Private queue used to synchronize access to `WireGuardAdapter` members.
    private let workQueue = DispatchQueue(label: "WireGuardAdapterWorkQueue")

    /// Adapter state.
    private var state: State = .stopped

    /// ICMP socket handle, if open
    private var icmpSocketHandle: Int32?

    /// Whether adapter should automatically raise the `reasserting` flag when updating
    /// tunnel configuration.
    private let shouldHandleReasserting: Bool

    /// Tunnel device file descriptor.
    private var tunnelFileDescriptor: Int32? {
        var ctlInfo = ctl_info()
        withUnsafeMutablePointer(to: &ctlInfo.ctl_name) {
            $0.withMemoryRebound(to: CChar.self, capacity: MemoryLayout.size(ofValue: $0.pointee)) {
                _ = strcpy($0, "com.apple.net.utun_control")
            }
        }
        for fd: Int32 in 0...1024 {
            var addr = sockaddr_ctl()
            var ret: Int32 = -1
            var len = socklen_t(MemoryLayout.size(ofValue: addr))
            withUnsafeMutablePointer(to: &addr) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    ret = getpeername(fd, $0, &len)
                }
            }
            if ret != 0 || addr.sc_family != AF_SYSTEM {
                continue
            }
            if ctlInfo.ctl_id == 0 {
                ret = ioctl(fd, CTLIOCGINFO, &ctlInfo)
                if ret != 0 {
                    continue
                }
            }
            if addr.sc_id == ctlInfo.ctl_id {
                return fd
            }
        }
        return nil
    }

    /// Returns a WireGuard version.
    class var backendVersion: String {
        guard let ver = wgVersion() else { return "unknown" }
        let str = String(cString: ver)
        free(UnsafeMutableRawPointer(mutating: ver))
        return str
    }

    /// Returns the tunnel device interface name, or nil on error.
    /// - Returns: String.
    public var interfaceName: String? {
        guard let tunnelFileDescriptor = self.tunnelFileDescriptor else { return nil }

        var buffer = [UInt8](repeating: 0, count: Int(IFNAMSIZ))

        return buffer.withUnsafeMutableBufferPointer { mutableBufferPointer in
            guard let baseAddress = mutableBufferPointer.baseAddress else { return nil }

            var ifnameSize = socklen_t(IFNAMSIZ)
            let result = getsockopt(
                tunnelFileDescriptor,
                2 /* SYSPROTO_CONTROL */,
                2 /* UTUN_OPT_IFNAME */,
                baseAddress,
                &ifnameSize)

            if result == 0 {
                return String(cString: baseAddress)
            } else {
                return nil
            }
        }
    }

    // MARK: - Initialization

    /// Designated initializer.
    /// - Parameter packetTunnelProvider: an instance of `NEPacketTunnelProvider`. Internally stored
    ///   as a weak reference.
    /// - Parameter shouldHandleReasserting: whether adapter should automatically raise the
    ///   `reasserting` flag when updating tunnel configuration.
    /// - Parameter logHandler: a log handler closure.
    public init(with packetTunnelProvider: NEPacketTunnelProvider, shouldHandleReasserting: Bool = true, logHandler: @escaping LogHandler) {
        self.packetTunnelProvider = packetTunnelProvider
        self.shouldHandleReasserting = shouldHandleReasserting
        self.logHandler = logHandler

        setupLogHandler()
    }

    deinit {
        // Force remove logger to make sure that no further calls to the instance of this class
        // can happen after deallocation.
        wgSetLogger(nil, nil)

        // Cancel network monitor
        networkMonitor?.cancel()

        // Shutdown the tunnel
        if case .started(let handle, _) = self.state {
            wgTurnOff(handle)
        }
    }

    // MARK: - Public methods

    /// Returns a runtime configuration from WireGuard.
    /// - Parameter completionHandler: completion handler.
    public func getRuntimeConfiguration(completionHandler: @escaping (String?) -> Void) {
        workQueue.async {
            guard case .started(let handle, _) = self.state else {
                completionHandler(nil)
                return
            }

            if let settings = wgGetConfig(handle) {
                completionHandler(String(cString: settings))
                free(settings)
            } else {
                completionHandler(nil)
            }
        }
    }
    
    public func startMultihop(exitConfiguration: TunnelConfiguration, entryConfiguration: TunnelConfiguration?, daita: DaitaConfiguration? = nil, completionHandler: @escaping (WireGuardAdapterError?) -> Void) {
        workQueue.async {
            guard case .stopped = self.state else {
                completionHandler(.invalidState)
                return
            }
            
            guard let privateAddress = exitConfiguration.interface.addresses.compactMap({ $0.address as? IPv4Address }).first else
            {
                self.logHandler(.error, "WireGuardAdapter.start: No private IPv4 address found")
                completionHandler(.noInterfaceIp)
                return
            }

            self.addDefaultPathObserver()

            do {
                let settingsGenerator = try self.makeSettingsGenerator(with: exitConfiguration, entryConfiguration: entryConfiguration, daita: daita)
                try self.setNetworkSettings(settingsGenerator.generateNetworkSettings())

                let (exitWgConfig, resolutionResults) = settingsGenerator.uapiConfiguration()
                let entryWgConfig = settingsGenerator.entryUapiConfiguration()?.0
                self.logEndpointResolutionResults(resolutionResults)

                self.state = .started(
                    try self.startWireGuardBackend(exitWgConfig: exitWgConfig, privateAddress: privateAddress, entryWgConfig: entryWgConfig, mtu: 1280, daita: daita),
                    settingsGenerator
                )

                completionHandler(nil)
            } catch let error as WireGuardAdapterError {
                self.removeDefaultPathObserver()
                completionHandler(error)
            } catch {
                fatalError()
            }
        }
    
    }

    /// Start the tunnel tunnel.
    /// - Parameters:
    ///   - tunnelConfiguration: tunnel configuration.
    ///   - completionHandler: completion handler.
    public func start(tunnelConfiguration: TunnelConfiguration, daita: DaitaConfiguration? = nil, completionHandler: @escaping (WireGuardAdapterError?) -> Void) {
        startMultihop(exitConfiguration: tunnelConfiguration, entryConfiguration: nil, daita: daita, completionHandler: completionHandler)
    }

    /// Stop the tunnel.
    /// - Parameter completionHandler: completion handler.
    public func stop(completionHandler: @escaping (WireGuardAdapterError?) -> Void) {
        workQueue.async {
            switch self.state {
            case .started(let handle, _):
                wgTurnOff(handle)

            case .temporaryShutdown:
                break

            case .stopped:
                completionHandler(.invalidState)
                return
            }

            self.removeDefaultPathObserver()

            self.state = .stopped

            completionHandler(nil)
        }
    }

    /// Update runtime configuration.
    /// - Parameters:
    ///   - tunnelConfiguration: tunnel configuration.
    ///   - completionHandler: completion handler.
    public func update(tunnelConfiguration: TunnelConfiguration, completionHandler: @escaping (WireGuardAdapterError?) -> Void) {
        workQueue.async {
            if case .stopped = self.state {
                completionHandler(.invalidState)
                return
            }

            // Tell the system that the tunnel is going to reconnect using new WireGuard
            // configuration.
            // This will broadcast the `NEVPNStatusDidChange` notification to the GUI process.
            if self.shouldHandleReasserting {
                self.packetTunnelProvider?.reasserting = true
            }

            defer {
                if self.shouldHandleReasserting {
                    self.packetTunnelProvider?.reasserting = false
                }
            }

            let settingsGenerator: PacketTunnelSettingsGenerator
            do {
                settingsGenerator = try self.makeSettingsGenerator(with: tunnelConfiguration)
            } catch let error as WireGuardAdapterError {
                completionHandler(error)
                return
            } catch {
                fatalError()
            }

            switch self.state {
            case .started(let handle, _):
                do {
                    try self.setNetworkSettings(settingsGenerator.generateNetworkSettings())
                } catch let error as WireGuardAdapterError {
                    completionHandler(error)
                    return
                } catch {
                    fatalError()
                }

                let (wgConfig, resolutionResults) = settingsGenerator.uapiConfiguration()
                let (entryConfig, _) = settingsGenerator.entryUapiConfiguration() ?? (nil, [])
                self.logEndpointResolutionResults(resolutionResults)

                wgSetConfig(handle, wgConfig, entryConfig)
                #if os(iOS)
                wgDisableSomeRoamingForBrokenMobileSemantics(handle)
                #endif

                self.state = .started(handle, settingsGenerator)

            case .temporaryShutdown:
                // On iOS 15.1 or newer, updating network settings may fail when in airplane mode.
                // Network path monitor will retry updating settings later when connectivity is
                // back online.
                do {
                    try self.setNetworkSettings(settingsGenerator.generateNetworkSettings())
                } catch let error as WireGuardAdapterError {
                    if case .setNetworkSettings(let systemError) = error {
                        self.logHandler(.verbose, "Failed to set network settings while offline. Will retry when connectivity is back online. Error: \(systemError.localizedDescription)")
                    }
                } catch {
                    fatalError()
                }

                self.state = .temporaryShutdown(settingsGenerator)

            case .stopped:
                fatalError()
            }

            completionHandler(nil)
        }
    }

    // MARK: - Private methods

    /// Setup WireGuard log handler.
    private func setupLogHandler() {
        let context = Unmanaged.passUnretained(self).toOpaque()
        wgSetLogger(context) { context, logLevel, message in
            guard let context = context, let message = message else { return }

            let unretainedSelf = Unmanaged<WireGuardAdapter>.fromOpaque(context)
                .takeUnretainedValue()

            let swiftString = String(cString: message).trimmingCharacters(in: .newlines)
            let tunnelLogLevel = WireGuardLogLevel(rawValue: logLevel) ?? .verbose

            unretainedSelf.logHandler(tunnelLogLevel, swiftString)
        }
    }

    /// Set network tunnel configuration.
    /// This method ensures that the call to `setTunnelNetworkSettings` does not time out, as in
    /// certain scenarios the completion handler given to it may not be invoked by the system.
    ///
    /// - Parameters:
    ///   - networkSettings: an instance of type `NEPacketTunnelNetworkSettings`.
    /// - Throws: an error of type `WireGuardAdapterError`.
    /// - Returns: `PacketTunnelSettingsGenerator`.
    private func setNetworkSettings(_ networkSettings: NEPacketTunnelNetworkSettings) throws {
        var systemError: Error?

        let dispatchGroup = DispatchGroup()

        dispatchGroup.enter()

        self.packetTunnelProvider?.setTunnelNetworkSettings(networkSettings) { error in
            systemError = error
            dispatchGroup.leave()
        }

        // Packet tunnel's `setTunnelNetworkSettings` times out in certain
        // scenarios & never calls the given callback.
        let setTunnelNetworkSettingsTimeout: Int = 5 // seconds

        let waitResult = dispatchGroup.wait(wallTimeout: .now() + .seconds(setTunnelNetworkSettingsTimeout))

        switch waitResult {
        case .success:
            if let systemError = systemError {
                throw WireGuardAdapterError.setNetworkSettings(systemError)
            }

        case .timedOut:
            self.logHandler(.error, "setTunnelNetworkSettings timed out after 5 seconds; proceeding anyway")
        }
    }

    /// Resolve peers of the given tunnel configuration.
    /// - Parameter tunnelConfiguration: tunnel configuration.
    /// - Throws: an error of type `WireGuardAdapterError`.
    /// - Returns: The list of resolved endpoints.
    private func resolvePeers(for tunnelConfiguration: TunnelConfiguration) throws -> [Endpoint?] {
        let endpoints = tunnelConfiguration.peers.map { $0.endpoint }
        let resolutionResults = DNSResolver.resolveSync(endpoints: endpoints)
        let resolutionErrors = resolutionResults.compactMap { result -> DNSResolutionError? in
            if case .failure(let error) = result {
                return error
            } else {
                return nil
            }
        }
        assert(endpoints.count == resolutionResults.count)
        guard resolutionErrors.isEmpty else {
            throw WireGuardAdapterError.dnsResolution(resolutionErrors)
        }

        let resolvedEndpoints = resolutionResults.map { result -> Endpoint? in
            // swiftlint:disable:next force_try
            return try! result?.get()
        }

        return resolvedEndpoints
    }

    /// Start WireGuard backend.
    /// - Parameter wgConfig: WireGuard configuration
    /// - Throws: an error of type `WireGuardAdapterError`
    /// - Returns: tunnel handle
    private func startWireGuardBackend(exitWgConfig: String, privateAddress: IPAddress, entryWgConfig: String? = nil, mtu: UInt16 = 1280, daita: DaitaConfiguration?) throws -> Int32 {
        guard let tunnelFileDescriptor = self.tunnelFileDescriptor else {
            throw WireGuardAdapterError.cannotLocateTunnelFileDescriptor
        }

        let privateAddr = "\(privateAddress)"

        let handle = if let entryWgConfig {
            wgTurnOnMultihop(exitWgConfig, entryWgConfig, privateAddr, tunnelFileDescriptor, daita?.machines ?? nil, daita?.maxEvents ?? 0, daita?.maxActions ?? 0)
        } else {
            wgTurnOnIAN(exitWgConfig, tunnelFileDescriptor, privateAddr, daita?.machines ?? nil, daita?.maxEvents ?? 0, daita?.maxActions ?? 0)
//            wgTurnOn(exitWgConfig, tunnelFileDescriptor, daita?.machines ?? nil, daita?.maxEvents ?? 0, daita?.maxActions ?? 0)
        }
        if handle < 0 {
            throw WireGuardAdapterError.startWireGuardBackend(handle)
        }
        #if os(iOS)
        wgDisableSomeRoamingForBrokenMobileSemantics(handle)
        #endif
        return handle
    }

    /// Resolves the hostnames in the given tunnel configuration and return settings generator.
    /// - Parameter exitConfiguration: an instance of type `TunnelConfiguration`.
    /// - Parameter entryConfiguration: an optional instance of type `TunnelConfiguration` for the entry WireGuard device
    /// - Parameter daita: an optional instance of type `DaitaConfiguration` for the configuration used by the Daita feature
    /// - Throws: an error of type `WireGuardAdapterError`.
    /// - Returns: an instance of type `PacketTunnelSettingsGenerator`.
    private func makeSettingsGenerator(with exitConfiguration: TunnelConfiguration, entryConfiguration: TunnelConfiguration? = nil, daita: DaitaConfiguration? = nil) throws -> PacketTunnelSettingsGenerator {
        let resolvedExitEndpoints = try self.resolvePeers(for: exitConfiguration)
        
        var entry: DeviceConfiguration? = nil
        if let entryConfiguration {
            let resolvedEntryEndpoints = try self.resolvePeers(for: entryConfiguration)
            entry = DeviceConfiguration(configuration: entryConfiguration, resolvedEndpoints: resolvedEntryEndpoints, reResolveEndpoint: true)
        }
        
        // Disable NAT64 resolution for exit relays when multihop is enabled
        return PacketTunnelSettingsGenerator(
            exit: DeviceConfiguration(configuration: exitConfiguration, resolvedEndpoints: resolvedExitEndpoints, reResolveEndpoint: entry == nil),
            entry: entry,
            daita: daita
        )
    }

    /// Log DNS resolution results.
    /// - Parameter resolutionErrors: an array of type `[DNSResolutionError]`.
    private func logEndpointResolutionResults(_ resolutionResults: [EndpointResolutionResult?]) {
        for case .some(let result) in resolutionResults {
            switch result {
            case .success((let sourceEndpoint, let resolvedEndpoint)):
                if sourceEndpoint.host == resolvedEndpoint.host {
                    self.logHandler(.verbose, "DNS64: mapped \(sourceEndpoint.host) to itself.")
                } else {
                    self.logHandler(.verbose, "DNS64: mapped \(sourceEndpoint.host) to \(resolvedEndpoint.host)")
                }
            case .failure(let resolutionError):
                self.logHandler(.error, "Failed to resolve endpoint \(resolutionError.address): \(resolutionError.errorDescription ?? "(nil)")")
            }
        }
    }

    private func addDefaultPathObserver() {
        guard let packetTunnelProvider = packetTunnelProvider else { return }

        defaultPathObserver?.invalidate()
        defaultPathObserver = packetTunnelProvider.observe(\.defaultPath, options: [.new]) { [weak self] _, change in
            guard let self = self, let defaultPath = change.newValue?.flatMap({ $0 }) else { return }

            self.workQueue.async {
                self.didReceivePathUpdate(path: defaultPath)
            }
        }

        currentDefaultPath = packetTunnelProvider.defaultPath
    }

    private func removeDefaultPathObserver() {
        defaultPathObserver?.invalidate()
        defaultPathObserver = nil
        currentDefaultPath = nil
    }

    /// Method invoked by KVO observer when new network path is received.
    /// - Parameter path: new network path
    private func didReceivePathUpdate(path: NetworkExtension.NWPath) {
        let isSamePath = currentDefaultPath?.isEqual(to: path) ?? false

        currentDefaultPath = path

        self.logHandler(.verbose, "Network change detected with \(path.status)")

        #if os(macOS)
        if case .started(let handle, _) = self.state, !isSamePath {
            wgBumpSockets(handle)
        }
        #elseif os(iOS)
        let isSatisfiable = path.status == .satisfied || path.status == .satisfiable

        switch self.state {
        case .started(let handle, let settingsGenerator):
            if isSatisfiable {
                guard !isSamePath else { return }

                let (wgConfig, resolutionResults) = settingsGenerator.endpointUapiConfiguration()
                self.logEndpointResolutionResults(resolutionResults)

                wgSetConfig(handle, wgConfig, nil)
                wgDisableSomeRoamingForBrokenMobileSemantics(handle)
                wgBumpSockets(handle)
            } else {
                self.logHandler(.verbose, "Connectivity offline, pausing backend.")

                self.state = .temporaryShutdown(settingsGenerator)
                wgTurnOff(handle)
            }

        case .temporaryShutdown(let settingsGenerator):
            guard isSatisfiable else { return }

            self.logHandler(.verbose, "Connectivity online, resuming backend.")
            
            guard let privateAddress = settingsGenerator.exit.configuration.interface.addresses.compactMap({ $0.address as? IPv4Address }).first else
            {
                self.logHandler(.error, "WireGuardAdapter.start: No private IPv4 address found")
                return
            }


            do {
                try self.setNetworkSettings(settingsGenerator.generateNetworkSettings())

                let (exitWgConfig, resolutionResults) = settingsGenerator.uapiConfiguration()
                self.logEndpointResolutionResults(resolutionResults)

                self.state = .started(
                    try self.startWireGuardBackend(exitWgConfig: exitWgConfig, privateAddress: privateAddress, daita: settingsGenerator.daita),
                    settingsGenerator
                )
            } catch {
                self.logHandler(.error, "Failed to restart backend: \(error.localizedDescription)")
            }

        case .stopped:
            // no-op
            break
        }
        #else
        #error("Unsupported")
        #endif
    }
}

// A protocol encompassing the stateful ICMP ping capabilities of the WireGuardAdapter, decoupling them from its implementation
public protocol ICMPPingProvider {
    func openICMP(address: IPv4Address) throws

    func closeICMP()

    @discardableResult func sendICMPPing(seqNumber: UInt16) throws -> Int32
}

extension WireGuardAdapter: ICMPPingProvider {
    /// MARK: ICMP Ping functionality
    public func openICMP(address: IPv4Address) throws {
        guard case .started(let tunnelHandle, _) = self.state else {
            throw WireGuardAdapterError.invalidState
        }
        // assumption: the description of an IPv4Address will always produce valid ASCII
        let addrString = "\(address)"
        let socket = wgOpenInTunnelICMP(tunnelHandle, addrString)
        if socket < 0 {
            switch socket {
            case -19: // errInvalidTunnel
                throw WireGuardAdapterError.noSuchTunnel
                // this can currently only happen if we have 2^31 sockets, so if it happens, there's a bug somewhere
                default: throw WireGuardAdapterError.internalError(socket)
            }
        }
        self.icmpSocketHandle = socket
    }

    public func closeICMP() {
        if let icmpSocketHandle {
            wgCloseInTunnelICMP(icmpSocketHandle)
            self.icmpSocketHandle = nil
        }
    }

    @discardableResult public func sendICMPPing(seqNumber: UInt16) throws -> Int32 {
        guard case .started(let tunnelHandle, _) = self.state, let icmpSocketHandle else {
            throw WireGuardAdapterError.icmpSocketNotOpen
        }
        let seq = wgSendAndAwaitInTunnelPing(tunnelHandle, icmpSocketHandle, seqNumber)
        if seq >= 0 { return seq }
        switch seq {
        case -14: // errICMPOpenSocket
            throw WireGuardAdapterError.icmpSocketNotOpen
            // TODO: more fine-grained errors
            default: throw WireGuardAdapterError.internalError(seq)
        }
    }
}

/// A enum describing WireGuard log levels defined in `api-apple.go`.
public enum WireGuardLogLevel: Int32 {
    case verbose = 0
    case error = 1
}

extension NetworkExtension.NWPathStatus: CustomDebugStringConvertible {
    public var debugDescription: String {
        switch self {
        case .unsatisfied:
            return "unsatisfied"
        case .satisfied:
            return "satisfied"
        case .satisfiable:
            return "satisfiable"
        case .invalid:
            return "invalid"
        @unknown default:
            return "unknown (rawValue = \(rawValue))"
        }
    }
}
