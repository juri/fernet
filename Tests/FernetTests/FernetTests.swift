@testable import Fernet
import XCTest

final class FernetTests: XCTestCase {
    func testDecode() throws {
        let key = "3b-Nqg6ry-jrAuDyVjSwEe8wrdyEPQfPuOQNH1q5olE"
        let encrypted = "gAAAAABhBRBGKSwa7AluNJYhwWaHrQGwAA8UpMH8Wtw3tEoTD2E_-nbeoAvxbtBpFiC0ZjbVne_ZetFinKSyMjxwWaPRnXVSVqz5QqpUXp6h-34_TL7BaDs"
        let fernet = try Fernet(encodedKey: Data(key.utf8))
        let decoded = try fernet.decode(Data(encrypted.utf8))
        XCTAssertEqual(String(data: decoded.data, encoding: .utf8), "my deep dark secret")
        XCTAssertTrue(decoded.hmacSuccess)
    }
}
