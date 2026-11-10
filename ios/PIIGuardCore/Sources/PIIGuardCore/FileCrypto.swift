import Foundation
import CryptoKit
#if canImport(CommonCrypto)
import CommonCrypto
#endif

public enum CryptoError: LocalizedError {
    case weakPassword
    case badFormat
    case wrongPasswordOrTampered
    case keyDerivationFailed

    public var errorDescription: String? {
        switch self {
        case .weakPassword: return "パスワードは8文字以上にしてください"
        case .badFormat: return "PII Guard の暗号化ファイルではありません"
        case .wrongPasswordOrTampered: return "復号に失敗しました。パスワードが違うか、ファイルが改ざんされています"
        case .keyDerivationFailed: return "鍵の生成に失敗しました"
        }
    }
}

/// パスワードによるファイル暗号化。
/// 形式: "PIIG2"(5B) + salt(16B) + AES-256-GCM の combined(nonce 12B + 暗号文 + タグ 16B)
/// 鍵は PBKDF2-HMAC-SHA256(600,000回)。注意: デスクトップ版(Python)の .enc(PIIG1, Fernet)とは互換性がありません。
public enum FileCrypto {
    static let magic = Data("PIIG2".utf8)
    static let saltLength = 16
    static let rounds: UInt32 = 600_000

    static func deriveKey(password: String, salt: Data) throws -> SymmetricKey {
        #if canImport(CommonCrypto)
        var key = Data(count: 32)
        let status = key.withUnsafeMutableBytes { keyBuf -> Int32 in
            salt.withUnsafeBytes { saltBuf -> Int32 in
                CCKeyDerivationPBKDF(
                    CCPBKDFAlgorithm(kCCPBKDF2),
                    password, password.utf8.count,
                    saltBuf.bindMemory(to: UInt8.self).baseAddress, salt.count,
                    CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                    rounds,
                    keyBuf.bindMemory(to: UInt8.self).baseAddress, 32)
            }
        }
        guard status == kCCSuccess else { throw CryptoError.keyDerivationFailed }
        return SymmetricKey(data: key)
        #else
        throw CryptoError.keyDerivationFailed
        #endif
    }

    public static func encrypt(_ data: Data, password: String) throws -> Data {
        guard password.count >= 8 else { throw CryptoError.weakPassword }
        var salt = Data(count: saltLength)
        let rc = salt.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, saltLength, $0.baseAddress!) }
        guard rc == errSecSuccess else { throw CryptoError.keyDerivationFailed }
        let key = try deriveKey(password: password, salt: salt)
        let sealed = try AES.GCM.seal(data, using: key)
        guard let combined = sealed.combined else { throw CryptoError.keyDerivationFailed }
        return magic + salt + combined
    }

    public static func decrypt(_ blob: Data, password: String) throws -> Data {
        let headerLength = magic.count + saltLength
        guard blob.count > headerLength, blob.prefix(magic.count) == magic else { throw CryptoError.badFormat }
        let salt = blob.subdata(in: magic.count..<headerLength)
        let combined = blob.subdata(in: headerLength..<blob.count)
        let key = try deriveKey(password: password, salt: salt)
        do {
            let box = try AES.GCM.SealedBox(combined: combined)
            return try AES.GCM.open(box, using: key)
        } catch {
            throw CryptoError.wrongPasswordOrTampered
        }
    }
}
