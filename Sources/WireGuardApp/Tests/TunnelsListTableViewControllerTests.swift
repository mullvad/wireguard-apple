import XCTest
@testable import WireGuardApp

class TunnelsListTableViewControllerTests: XCTestCase {

    var tunnelsListTableViewController: TunnelsListTableViewController!
    var mockTunnelsManager: MockTunnelsManager!

    override func setUpWithError() throws {
        try super.setUpWithError()
        mockTunnelsManager = MockTunnelsManager()
        tunnelsListTableViewController = TunnelsListTableViewController()
        tunnelsListTableViewController.setTunnelsManager(tunnelsManager: mockTunnelsManager)
    }

    override func tearDownWithError() throws {
        tunnelsListTableViewController = nil
        mockTunnelsManager = nil
        try super.tearDownWithError()
    }

    func testAddButtonTapped() throws {
        let expectation = self.expectation(description: "Add button tapped")
        tunnelsListTableViewController.addButtonTapped(sender: tunnelsListTableViewController.navigationItem.rightBarButtonItem!)
        DispatchQueue.main.asyncAfter(deadline: .now() + 1) {
            XCTAssertTrue(self.mockTunnelsManager.addTunnelCalled)
            expectation.fulfill()
        }
        waitForExpectations(timeout: 2, handler: nil)
    }

    func testSettingsButtonTapped() throws {
        let expectation = self.expectation(description: "Settings button tapped")
        tunnelsListTableViewController.settingsButtonTapped(sender: tunnelsListTableViewController.navigationItem.leftBarButtonItem!)
        DispatchQueue.main.asyncAfter(deadline: .now() + 1) {
            XCTAssertTrue(self.mockTunnelsManager.settingsTapped)
            expectation.fulfill()
        }
        waitForExpectations(timeout: 2, handler: nil)
    }

    func testSelectButtonTapped() throws {
        tunnelsListTableViewController.selectButtonTapped()
        XCTAssertEqual(tunnelsListTableViewController.tableState, .multiSelect(selectionCount: 0))
    }

    func testDoneButtonTapped() throws {
        tunnelsListTableViewController.doneButtonTapped()
        XCTAssertEqual(tunnelsListTableViewController.tableState, .normal)
    }

    func testSelectAllButtonTapped() throws {
        tunnelsListTableViewController.selectAllButtonTapped()
        XCTAssertEqual(tunnelsListTableViewController.tableState, .multiSelect(selectionCount: mockTunnelsManager.numberOfTunnels()))
    }

    func testCancelButtonTapped() throws {
        tunnelsListTableViewController.cancelButtonTapped()
        XCTAssertEqual(tunnelsListTableViewController.tableState, .normal)
    }

    func testDeleteButtonTapped() throws {
        let expectation = self.expectation(description: "Delete button tapped")
        tunnelsListTableViewController.deleteButtonTapped(sender: tunnelsListTableViewController.navigationItem.leftBarButtonItem!)
        DispatchQueue.main.asyncAfter(deadline: .now() + 1) {
            XCTAssertTrue(self.mockTunnelsManager.deleteTunnelsCalled)
            expectation.fulfill()
        }
        waitForExpectations(timeout: 2, handler: nil)
    }
}

class MockTunnelsManager: TunnelsManager {
    var addTunnelCalled = false
    var settingsTapped = false
    var deleteTunnelsCalled = false

    override func add(tunnelConfiguration: TunnelConfiguration, onDemandOption: ActivateOnDemandOption = .off, completionHandler: @escaping (Result<TunnelContainer, TunnelsManagerError>) -> Void) {
        addTunnelCalled = true
        completionHandler(.success(TunnelContainer(tunnel: NETunnelProviderManager())))
    }

    override func removeMultiple(tunnels: [TunnelContainer], completionHandler: @escaping (TunnelsManagerError?) -> Void) {
        deleteTunnelsCalled = true
        completionHandler(nil)
    }
}
