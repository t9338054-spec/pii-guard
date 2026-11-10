import XCTest
@testable import PIIGuardCore

final class DetectorTests: XCTestCase {
    private func kinds(_ text: String) -> [String] {
        Detector.find(in: text).map(\.kind)
    }

    func testEmailMask() {
        XCTAssertEqual(kinds("連絡: taro@example.com"), ["メールアドレス"])
        XCTAssertEqual(Detector.mask("taro@example.com"), "t***@example.com")
    }

    func testPhoneNotConfusedWithPostal() {
        XCTAssertEqual(kinds("tel 090-1234-5678"), ["電話番号"])
        XCTAssertEqual(Detector.mask("tel 090-1234-5678"), "tel *******5678")
    }

    func testCreditCardLuhn() {
        XCTAssertEqual(kinds("card 4111 1111 1111 1111"), ["クレジットカード"])
        XCTAssertFalse(kinds("card 4111 1111 1111 1112").contains("クレジットカード"))
    }

    func testMyNumberCheckDigit() {
        let base = [1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1]
        var s = 0
        for p in 1...11 { s += base[11 - p] * (p <= 6 ? p + 1 : p - 5) }
        let check = s % 11 <= 1 ? 0 : 11 - s % 11
        XCTAssertTrue(Detector.myNumberOK(base + [check]))
        XCTAssertFalse(Detector.myNumberOK(base + [(check + 1) % 10]))
    }

    func testAddressNameSecrets() {
        XCTAssertTrue(kinds("〒100-0001").contains("郵便番号"))
        XCTAssertTrue(kinds("東京都千代田区1-1-1").contains("住所"))
        XCTAssertTrue(kinds("氏名: 山田 太郎").contains("氏名"))
        XCTAssertTrue(kinds("password: Secret12345").contains("秘密情報(キー/トークン)"))
        XCTAssertTrue(kinds("AKIAABCDEFGHIJKLMNOP").contains("AWSキー"))
    }

    func testPlainTextHasNoFindings() {
        XCTAssertEqual(kinds("今日はいい天気です。会議は15時からです。"), [])
    }
}

final class FileCryptoTests: XCTestCase {
    func testRoundTrip() throws {
        let plain = Data("秘密のデータ".utf8)
        let enc = try FileCrypto.encrypt(plain, password: "password123")
        XCTAssertNotEqual(enc, plain)
        XCTAssertEqual(try FileCrypto.decrypt(enc, password: "password123"), plain)
    }

    func testWrongPasswordAndTamper() throws {
        let enc = try FileCrypto.encrypt(Data("data".utf8), password: "password123")
        XCTAssertThrowsError(try FileCrypto.decrypt(enc, password: "wrong-password"))
        var bad = enc
        bad[bad.count - 3] ^= 0x01
        XCTAssertThrowsError(try FileCrypto.decrypt(bad, password: "password123"))
    }

    func testRejectsShortPasswordAndForeignFile() {
        XCTAssertThrowsError(try FileCrypto.encrypt(Data("x".utf8), password: "short"))
        XCTAssertThrowsError(try FileCrypto.decrypt(Data("not encrypted file content".utf8), password: "password123"))
    }
}
