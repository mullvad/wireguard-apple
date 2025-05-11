import XCTest
@testable import WireGuardApp

class TunnelsManagerTests: XCTestCase {

    var tunnelsManager: TunnelsManager!

    override func setUpWithError() throws {
        try super.setUpWithError()
        tunnelsManager = TunnelsManager(tunnelProviders: [])
    }

    override func tearDownWithError() throws {
        tunnelsManager = nil
        try super.tearDownWithError()
    }

    func testAddTunnel() throws {
        let tunnelConfiguration = TunnelConfiguration(name: "TestTunnel", interface: InterfaceConfiguration(privateKey: PrivateKey()), peers: [])
        let expectation = self.expectation(description: "Add tunnel")

        tunnelsManager.add(tunnelConfiguration: tunnelConfiguration) { result in
            switch result {
            case .failure(let error):
                XCTFail("Failed to add tunnel: \(error)")
            case .success(let tunnel):
                XCTAssertEqual(tunnel.name, "TestTunnel")
            }
            expectation.fulfill()
        }

        waitForExpectations(timeout: 5, handler: nil)
    }

    func testRemoveTunnel() throws {
        let tunnelConfiguration = TunnelConfiguration(name: "TestTunnel", interface: InterfaceConfiguration(privateKey: PrivateKey()), peers: [])
        let addExpectation = self.expectation(description: "Add tunnel")
        let removeExpectation = self.expectation(description: "Remove tunnel")

        tunnelsManager.add(tunnelConfiguration: tunnelConfiguration) { result in
            switch result {
            case .failure(let error):
                XCTFail("Failed to add tunnel: \(error)")
            case .success(let tunnel):
                self.tunnelsManager.remove(tunnel: tunnel) { error in
                    if let error = error {
                        XCTFail("Failed to remove tunnel: \(error)")
                    } else {
                        XCTAssertNil(self.tunnelsManager.tunnel(named: "TestTunnel"))
                    }
                    removeExpectation.fulfill()
                }
            }
            addExpectation.fulfill()
        }

        waitForExpectations(timeout: 5, handler: nil)
    }

    func testModifyTunnel() throws {
        let tunnelConfiguration = TunnelConfiguration(name: "TestTunnel", interface: InterfaceConfiguration(privateKey: PrivateKey()), peers: [])
        let modifiedTunnelConfiguration = TunnelConfiguration(name: "ModifiedTunnel", interface: InterfaceConfiguration(privateKey: PrivateKey()), peers: [])
        let addExpectation = self.expectation(description: "Add tunnel")
        let modifyExpectation = self.expectation(description: "Modify tunnel")

        tunnelsManager.add(tunnelConfiguration: tunnelConfiguration) { result in
            switch result {
            case .failure(let error):
                XCTFail("Failed to add tunnel: \(error)")
            case .success(let tunnel):
                self.tunnelsManager.modify(tunnel: tunnel, tunnelConfiguration: modifiedTunnelConfiguration, onDemandOption: .off) { error in
                    if let error = error {
                        XCTFail("Failed to modify tunnel: \(error)")
                    } else {
                        XCTAssertEqual(tunnel.name, "ModifiedTunnel")
                    }
                    modifyExpectation.fulfill()
                }
            }
            addExpectation.fulfill()
        }

        waitForExpectations(timeout: 5, handler: nil)
    }

    func testReloadTunnels() throws {
        let tunnelConfiguration = TunnelConfiguration(name: "TestTunnel", interface: InterfaceConfiguration(privateKey: PrivateKey()), peers: [])
        let addExpectation = self.expectation(description: "Add tunnel")
        let reloadExpectation = self.expectation(description: "Reload tunnels")

        tunnelsManager.add(tunnelConfiguration: tunnelConfiguration) { result in
            switch result {
            case .failure(let error):
                XCTFail("Failed to add tunnel: \(error)")
            case .success:
                self.tunnelsManager.reload()
                XCTAssertEqual(self.tunnelsManager.numberOfTunnels(), 1)
            }
            addExpectation.fulfill()
            reloadExpectation.fulfill()
        }

        waitForExpectations(timeout: 5, handler: nil)
    }
}
