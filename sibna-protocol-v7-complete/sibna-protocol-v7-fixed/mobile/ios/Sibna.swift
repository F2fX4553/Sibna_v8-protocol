import Foundation

/// Sibna Secure Messaging SDK for iOS
/// A production-ready implementation of the Signal Protocol
/// Version: 7.0.0

/// SDK Configuration
public struct SibnaConfig {
    public var enableForwardSecrecy: Bool = true
    public var enablePostCompromiseSecurity: Bool = true
    public var maxSkippedMessages: Int = 2000
    public var keyRotationInterval: TimeInterval = 86400 // 24 hours
    public var enableGroupMessaging: Bool = true
    public var maxGroupSize: Int = 256
    
    public init() {}
}

/// Identity Key Pair
public struct IdentityKeyPair {
    public let privateKey: Data
    public let ed25519PublicKey: Data
    public let x25519PublicKey: Data
    
    public var privateKeyHex: String {
        privateKey.map { String(format: "%02x", $0) }.joined()
    }
    
    public var ed25519PublicKeyHex: String {
        ed25519PublicKey.map { String(format: "%02x", $0) }.joined()
    }
    
    public var x25519PublicKeyHex: String {
        x25519PublicKey.map { String(format: "%02x", $0) }.joined()
    }
}

/// Session Handle
public struct SessionHandle {
    public let peerId: Data
    
    public var peerIdString: String {
        String(data: peerId, encoding: .utf8) ?? ""
    }
}

/// Group Handle
public struct GroupHandle {
    public let groupId: Data
}

/// Encrypted Message
public struct EncryptedMessage {
    public let senderId: Data
    public let ciphertext: Data
    public let timestamp: Date
}

/// Main Sibna SDK Class
public class Sibna {
    
    /// SDK Version
    public static let version = "7.0.0"
    
    private var contextPointer: OpaquePointer?
    private var identity: IdentityKeyPair?
    private let config: SibnaConfig
    
    /// Initialize SDK
    public init(config: SibnaConfig = SibnaConfig()) {
        self.config = config
        self.contextPointer = sibna_context_create(nil, nil, 0)
    }
    
    deinit {
        if let ptr = contextPointer {
            sibna_context_free(ptr)
        }
    }
    
    /// Generate new identity key pair
    public func generateIdentity() throws -> IdentityKeyPair {
        guard let ctx = contextPointer else {
            throw SibnaError.contextNotInitialized
        }
        
        var edPub = [UInt8](repeating: 0, count: 32)
        var xPub = [UInt8](repeating: 0, count: 32)
        var seed = [UInt8](repeating: 0, count: 32)
        
        let result = sibna_context_generate_identity(ctx, &edPub, &xPub, &seed)
        
        guard result == SIBNA_SUCCESS else {
            throw SibnaError.fromCode(result)
        }
        
        let keypair = IdentityKeyPair(
            privateKey: Data(seed),
            ed25519PublicKey: Data(edPub),
            x25519PublicKey: Data(xPub)
        )
        
        self.identity = keypair
        return keypair
    }
    
    /// Get current identity
    public func getIdentity() -> IdentityKeyPair? {
        return identity
    }
    
    /// Create a new session
    public func createSession(peerId: Data) throws -> SessionHandle {
        guard let ctx = contextPointer else {
            throw SibnaError.contextNotInitialized
        }
        
        let result = peerId.withUnsafeBytes { ptr in
            sibna_session_create(ctx, ptr.baseAddress?.assumingMemoryBound(to: UInt8.self), peerId.count)
        }
        
        guard result != nil else {
            throw SibnaError.sessionCreationFailed
        }
        
        return SessionHandle(peerId: peerId)
    }
    
    /// Perform X3DH handshake
    public func performHandshake(
        peerId: Data,
        initiator: Bool,
        peerIdentityKey: Data,
        peerSignedPrekey: Data,
        peerOnetimePrekey: Data
    ) throws -> Data {
        guard let ctx = contextPointer else {
            throw SibnaError.contextNotInitialized
        }
        
        var secretPtr: UnsafeMutablePointer<UInt8>?
        var secretLen: Int = 0
        
        let result = peerId.withUnsafeBytes { peerIdPtr in
            peerIdentityKey.withUnsafeBytes { ikPtr in
                peerSignedPrekey.withUnsafeBytes { spkPtr in
                    peerOnetimePrekey.withUnsafeBytes { opkPtr in
                        sibna_context_perform_handshake(
                            ctx,
                            peerIdPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                            peerId.count,
                            initiator ? 1 : 0,
                            ikPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                            spkPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                            opkPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                            &secretPtr,
                            &secretLen
                        )
                    }
                }
            }
        }
        
        guard result == SIBNA_SUCCESS, let ptr = secretPtr else {
            throw SibnaError.fromCode(result)
        }
        
        let secret = Data(bytes: ptr, count: secretLen)
        sibna_free_buffer(ptr, secretLen)
        
        return secret
    }
    
    /// Encrypt a message
    public func encrypt(peerId: Data, plaintext: Data) throws -> Data {
        guard let ctx = contextPointer else {
            throw SibnaError.contextNotInitialized
        }
        
        var cipherPtr: UnsafeMutablePointer<UInt8>?
        var cipherLen: Int = 0
        
        let result = peerId.withUnsafeBytes { peerIdPtr in
            plaintext.withUnsafeBytes { plaintextPtr in
                sibna_context_encrypt(
                    ctx,
                    peerIdPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    peerId.count,
                    plaintextPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    plaintext.count,
                    &cipherPtr,
                    &cipherLen
                )
            }
        }
        
        guard result == SIBNA_SUCCESS, let ptr = cipherPtr else {
            throw SibnaError.fromCode(result)
        }
        
        let ciphertext = Data(bytes: ptr, count: cipherLen)
        sibna_free_buffer(ptr, cipherLen)
        
        return ciphertext
    }
    
    /// Decrypt a message
    public func decrypt(peerId: Data, ciphertext: Data) throws -> Data {
        guard let ctx = contextPointer else {
            throw SibnaError.contextNotInitialized
        }
        
        var plainPtr: UnsafeMutablePointer<UInt8>?
        var plainLen: Int = 0
        
        let result = peerId.withUnsafeBytes { peerIdPtr in
            ciphertext.withUnsafeBytes { cipherPtr in
                sibna_context_decrypt(
                    ctx,
                    peerIdPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    peerId.count,
                    cipherPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    ciphertext.count,
                    &plainPtr,
                    &plainLen
                )
            }
        }
        
        guard result == SIBNA_SUCCESS, let ptr = plainPtr else {
            throw SibnaError.fromCode(result)
        }
        
        let plaintext = Data(bytes: ptr, count: plainLen)
        sibna_free_buffer(ptr, plainLen)
        
        return plaintext
    }
    
    /// Get device ID
    public func getDeviceId() -> Data {
        guard let ctx = contextPointer else {
            return Data(repeating: 0, count: 16)
        }
        
        var deviceId = [UInt8](repeating: 0, count: 16)
        sibna_context_get_device_id(ctx, &deviceId)
        
        return Data(deviceId)
    }
    
    /// Generate random bytes
    public static func randomBytes(count: Int) -> Data {
        var bytes = [UInt8](repeating: 0, count: count)
        _ = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
        return Data(bytes)
    }
}

/// Sibna Errors
public enum SibnaError: Error {
    case contextNotInitialized
    case sessionCreationFailed
    case encryptionFailed
    case decryptionFailed
    case invalidKey
    case unknownError(code: Int32)
    
    static func fromCode(_ code: Int32) -> SibnaError {
        switch code {
        case SIBNA_ENCRYPTION_FAILED:
            return .encryptionFailed
        case SIBNA_DECRYPTION_FAILED:
            return .decryptionFailed
        case SIBNA_INVALID_ARGUMENT:
            return .invalidKey
        default:
            return .unknownError(code: code)
        }
    }
}

// C FFI bindings
private let SIBNA_SUCCESS: Int32 = 0
private let SIBNA_ENCRYPTION_FAILED: Int32 = 3
private let SIBNA_DECRYPTION_FAILED: Int32 = 4
private let SIBNA_INVALID_ARGUMENT: Int32 = 2

@_silgen_name("sibna_context_create")
private func sibna_context_create(_ config: UnsafeRawPointer?, _ password: UnsafePointer<UInt8>?, _ len: Int) -> OpaquePointer?

@_silgen_name("sibna_context_free")
private func sibna_context_free(_ ctx: OpaquePointer)

@_silgen_name("sibna_context_generate_identity")
private func sibna_context_generate_identity(_ ctx: OpaquePointer, _ edPub: UnsafeMutablePointer<UInt8>, _ xPub: UnsafeMutablePointer<UInt8>, _ seed: UnsafeMutablePointer<UInt8>) -> Int32

@_silgen_name("sibna_session_create")
private func sibna_session_create(_ ctx: OpaquePointer, _ peerId: UnsafePointer<UInt8>?, _ len: Int) -> OpaquePointer?

@_silgen_name("sibna_context_perform_handshake")
private func sibna_context_perform_handshake(_ ctx: OpaquePointer, _ peerId: UnsafePointer<UInt8>?, _ peerIdLen: Int, _ initiator: Int32, _ ik: UnsafePointer<UInt8>?, _ spk: UnsafePointer<UInt8>?, _ opk: UnsafePointer<UInt8>?, _ secret: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?, _ secretLen: UnsafeMutablePointer<Int>?) -> Int32

@_silgen_name("sibna_context_encrypt")
private func sibna_context_encrypt(_ ctx: OpaquePointer, _ peerId: UnsafePointer<UInt8>?, _ peerIdLen: Int, _ plaintext: UnsafePointer<UInt8>?, _ plaintextLen: Int, _ ciphertext: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?, _ ciphertextLen: UnsafeMutablePointer<Int>?) -> Int32

@_silgen_name("sibna_context_decrypt")
private func sibna_context_decrypt(_ ctx: OpaquePointer, _ peerId: UnsafePointer<UInt8>?, _ peerIdLen: Int, _ ciphertext: UnsafePointer<UInt8>?, _ ciphertextLen: Int, _ plaintext: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?, _ plaintextLen: UnsafeMutablePointer<Int>?) -> Int32

@_silgen_name("sibna_context_get_device_id")
private func sibna_context_get_device_id(_ ctx: OpaquePointer, _ deviceId: UnsafeMutablePointer<UInt8>)

@_silgen_name("sibna_free_buffer")
private func sibna_free_buffer(_ ptr: UnsafeMutablePointer<UInt8>?, _ len: Int)
