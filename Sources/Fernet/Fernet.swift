import CryptoSwift
import Foundation

/*
 A fernet key is the base64url encoding of the following fields:

 Signing-key ‖ Encryption-key
 Signing-key, 128 bits
 Encryption-key, 128 bits

 A fernet token is the base64url encoding of the concatenation of the following fields:

 Version ‖ Timestamp ‖ IV ‖ Ciphertext ‖ HMAC
 Version, 8 bits
 Timestamp, 64 bits
 IV, 128 bits
 Ciphertext, variable length, multiple of 128 bits
 HMAC, 256 bits
 */

public struct Fernet {
    let makeDate: () -> Date
    let makeIV: (Int) -> [UInt8]
    let signingKey: Data
    let encryptionKey: Data

    public init(
        encodedKey: Data,
        makeDate: @escaping () -> Date = Date.init,
        makeIV: @escaping (Int) -> [UInt8] = AES.randomIV
    ) throws {
        guard let fernetKey = Data(base64URLData: encodedKey) else { throw KeyError.invalidFormat }
        try self.init(key: fernetKey, makeDate: makeDate, makeIV: makeIV)
    }

    public init(
        key: Data,
        makeDate: @escaping () -> Date = Date.init,
        makeIV: @escaping (Int) -> [UInt8] = AES.randomIV
    ) throws {
        guard key.count == 32 else { throw KeyError.invalidLength }
        self.makeDate = makeDate
        self.makeIV = makeIV
        self.signingKey = key.prefix(16)
        self.encryptionKey = key.suffix(16)
    }

    public func decode(_ encoded: Data) throws -> DecodeOutput {
        guard let fernetToken = Data(base64URLData: encoded) else { throw DecodingError.tokenDecodingFailed }

        guard fernetToken.count >= 73 && (fernetToken.count - 57) % 16 == 0 else {
            throw DecodingError.invalidTokenFormat
        }
        let version = fernetToken[0]
        let timestamp = fernetToken[1 ..< 9]
        let iv = fernetToken[9 ..< 25]
        let ciphertext = fernetToken[25 ..< fernetToken.count - 32]
        let hmac = fernetToken[fernetToken.count - 32 ..< fernetToken.count]

        guard version == 128 else { throw DecodingError.unknownVersion }
        let plaintext = try decrypt(ciphertext: ciphertext, key: self.encryptionKey, iv: iv)
        let hmacMatches = try verifyHMAC(
            hmac,
            authenticating: Data([version]) + timestamp + iv + ciphertext,
            using: self.signingKey
        )

        return DecodeOutput(data: plaintext, hmacSuccess: hmacMatches)
    }

    public func encode(_ data: Data) throws -> Data {
        let timestamp: [UInt8] = {
            let now = self.makeDate()
            let timestamp = Int(now.timeIntervalSince1970).bigEndian
            return withUnsafeBytes(of: timestamp, Array.init)
        }()
        guard case let iv = self.makeIV(16), iv.count == 16 else { throw EncodingError.invalidIV }
        let ciphertext: [UInt8]
        do {
            let aes = try AES(key: self.encryptionKey.bytes, blockMode: CBC(iv: iv), padding: .pkcs7)
            ciphertext = try aes.encrypt(data.bytes)
        } catch {
            throw EncodingError.aesError(error)
        }
        let version: [UInt8] = [0x80]
        let hmac = try makeVerificationHMAC(data: Data(version + timestamp + iv + ciphertext), key: self.signingKey)
        let fernetToken = (version + timestamp + iv + ciphertext + hmac).base64URLEncodedData()
        return fernetToken
    }
}

extension Fernet {
    public enum KeyError: Error {
        case invalidFormat
        case invalidLength
    }

    public enum DecodingError: Error {
        case aesError(any Error)
        case hmacError(any Error)
        case invalidTokenFormat
        case keyDecodingFailed
        case tokenDecodingFailed
        case unknownVersion
    }

    public enum EncodingError: Error {
        case aesError(any Error)
        case hmacError(any Error)
        case invalidIV
    }

    public struct DecodeOutput {
        var data: Data
        var hmacSuccess: Bool
    }
}

func computeHMAC(data: Data, key: Data) throws -> Data {
    Data(try HMAC(key: key.bytes, variant: .sha2(.sha256)).authenticate(data.bytes))
}

func decrypt(ciphertext: Data, key: Data, iv: Data) throws -> Data {
    do {
        let aes = try AES(key: key.bytes, blockMode: CBC(iv: iv.bytes), padding: .pkcs7)
        let decryptedData = try aes.decrypt(ciphertext.bytes)
        return Data(decryptedData)
    } catch {
        throw Fernet.DecodingError.aesError(error)
    }
}

func makeVerificationHMAC(data: Data, key: Data) throws -> Data {
    do {
        return try computeHMAC(data: data, key: key)
    } catch {
        throw Fernet.EncodingError.hmacError(error)
    }
}

func verifyHMAC(_ mac: Data, authenticating data: Data, using key: Data) throws -> Bool {
    do {
        let auth = try computeHMAC(data: data, key: key)
        return constantTimeEquals(auth, mac)
    } catch {
        throw Fernet.DecodingError.hmacError(error)
    }
}

// Who knows how the compiler will optimize this but at least try to be constant time.
func constantTimeEquals<C1, C2>(_ lhs: C1, _ rhs: C2) -> Bool
    where C1: Collection,
    C2: Collection,
    C1.Element == UInt8,
    C2.Element == UInt8
{
    guard lhs.count == rhs.count else { return false }
    return zip(lhs, rhs).reduce(into: 0) { output, pair in output |= pair.0 ^ pair.1 } == 0
}

extension Data {
    init?(base64URLData base64: Data) {
        var decoded = base64.map { b in
            switch b {
            case ASCII.dash.rawValue: ASCII.plus.rawValue
            case ASCII.underscore.rawValue: ASCII.slash.rawValue
            default: b
            }
        }
        while decoded.count % 4 != 0 {
            decoded.append(ASCII.equals.rawValue)
        }
        self.init(base64Encoded: Data(decoded))
    }

    func base64URLEncodedData() -> Data {
        let bytes = self.base64EncodedData()
            .compactMap { b in
                switch b {
                case ASCII.plus.rawValue: ASCII.dash.rawValue
                case ASCII.slash.rawValue: ASCII.underscore.rawValue
                case ASCII.equals.rawValue: nil
                default: b
                }
            }
        return Data(bytes)
    }
}

enum ASCII: UInt8 {
    case plus = 43
    case dash = 45
    case slash = 47
    case equals = 61
    case underscore = 95
}
