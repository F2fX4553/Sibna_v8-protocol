package io.sibna.sdk

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.security.SecureRandom

/**
 * Sibna Secure Messaging SDK for Android
 * 
 * A production-ready implementation of the Signal Protocol for secure
 * end-to-end encrypted communication.
 * 
 * Version: 7.0.0
 */
object Sibna {

    init {
        System.loadLibrary("sibna")
    }

    /**
     * Get the SDK version
     */
    fun getVersion(): String = "7.0.0"

    /**
     * Initialize the SDK with configuration
     */
    fun initialize(config: SibnaConfig = SibnaConfig()): SibnaContext {
        return SibnaContext(config)
    }

    /**
     * Generate random bytes
     */
    fun randomBytes(length: Int): ByteArray {
        val bytes = ByteArray(length)
        SecureRandom().nextBytes(bytes)
        return bytes
    }

    /**
     * Convert bytes to hex string
     */
    fun bytesToHex(bytes: ByteArray): String {
        return bytes.joinToString("") { "%02x".format(it) }
    }

    /**
     * Convert hex string to bytes
     */
    fun hexToBytes(hex: String): ByteArray {
        return ByteArray(hex.length / 2) {
            hex.substring(it * 2, it * 2 + 2).toInt(16).toByte()
        }
    }
}

/**
 * SDK Configuration
 */
data class SibnaConfig(
    val enableForwardSecrecy: Boolean = true,
    val enablePostCompromiseSecurity: Boolean = true,
    val maxSkippedMessages: Int = 2000,
    val keyRotationInterval: Long = 86400L, // 24 hours
    val enableGroupMessaging: Boolean = true,
    val maxGroupSize: Int = 256
)

/**
 * Main context for Sibna operations
 */
class SibnaContext(private val config: SibnaConfig) {

    private val nativeContext: Long = nativeCreateContext(config)
    private var identity: IdentityKeyPair? = null

    /**
     * Generate a new identity key pair
     */
    suspend fun generateIdentity(): IdentityKeyPair = withContext(Dispatchers.IO) {
        val keypair = nativeGenerateIdentity(nativeContext)
        identity = keypair
        keypair
    }

    /**
     * Get the current identity
     */
    fun getIdentity(): IdentityKeyPair? = identity

    /**
     * Create a new session with a peer
     */
    suspend fun createSession(peerId: String): SessionHandle = withContext(Dispatchers.IO) {
        nativeCreateSession(nativeContext, peerId.toByteArray())
        SessionHandle(peerId)
    }

    /**
     * Perform X3DH handshake
     */
    suspend fun performHandshake(
        peerId: String,
        initiator: Boolean,
        peerIdentityKey: ByteArray,
        peerSignedPrekey: ByteArray,
        peerOnetimePrekey: ByteArray
    ): ByteArray = withContext(Dispatchers.IO) {
        nativePerformHandshake(
            nativeContext,
            peerId.toByteArray(),
            initiator,
            peerIdentityKey,
            peerSignedPrekey,
            peerOnetimePrekey
        )
    }

    /**
     * Encrypt a message
     */
    suspend fun encrypt(peerId: String, plaintext: ByteArray): ByteArray = 
        withContext(Dispatchers.IO) {
            nativeEncrypt(nativeContext, peerId.toByteArray(), plaintext)
        }

    /**
     * Decrypt a message
     */
    suspend fun decrypt(peerId: String, ciphertext: ByteArray): ByteArray = 
        withContext(Dispatchers.IO) {
            nativeDecrypt(nativeContext, peerId.toByteArray(), ciphertext)
        }

    /**
     * Create a new group
     */
    suspend fun createGroup(groupId: ByteArray): GroupHandle = withContext(Dispatchers.IO) {
        nativeCreateGroup(nativeContext, groupId)
        GroupHandle(groupId)
    }

    /**
     * Add member to group
     */
    suspend fun addGroupMember(groupId: ByteArray, publicKey: ByteArray) = 
        withContext(Dispatchers.IO) {
            nativeAddGroupMember(nativeContext, groupId, publicKey)
        }

    /**
     * Encrypt group message
     */
    suspend fun encryptGroupMessage(groupId: ByteArray, plaintext: ByteArray): ByteArray = 
        withContext(Dispatchers.IO) {
            nativeEncryptGroup(nativeContext, groupId, plaintext)
        }

    /**
     * Get device ID
     */
    fun getDeviceId(): ByteArray = nativeGetDeviceId(nativeContext)

    /**
     * List sessions
     */
    suspend fun listSessions(): List<String> = withContext(Dispatchers.IO) {
        nativeListSessions(nativeContext).map { String(it) }
    }

    /**
     * Delete session
     */
    suspend fun deleteSession(peerId: String) = withContext(Dispatchers.IO) {
        nativeDeleteSession(nativeContext, peerId.toByteArray())
    }

    protected fun finalize() {
        nativeFreeContext(nativeContext)
    }

    // Native methods
    private external fun nativeCreateContext(config: SibnaConfig): Long
    private external fun nativeFreeContext(context: Long)
    private external fun nativeGenerateIdentity(context: Long): IdentityKeyPair
    private external fun nativeCreateSession(context: Long, peerId: ByteArray)
    private external fun nativePerformHandshake(
        context: Long, peerId: ByteArray, initiator: Boolean,
        peerIdentityKey: ByteArray, peerSignedPrekey: ByteArray, peerOnetimePrekey: ByteArray
    ): ByteArray
    private external fun nativeEncrypt(context: Long, peerId: ByteArray, plaintext: ByteArray): ByteArray
    private external fun nativeDecrypt(context: Long, peerId: ByteArray, ciphertext: ByteArray): ByteArray
    private external fun nativeCreateGroup(context: Long, groupId: ByteArray)
    private external fun nativeAddGroupMember(context: Long, groupId: ByteArray, publicKey: ByteArray)
    private external fun nativeEncryptGroup(context: Long, groupId: ByteArray, plaintext: ByteArray): ByteArray
    private external fun nativeGetDeviceId(context: Long): ByteArray
    private external fun nativeListSessions(context: Long): Array<ByteArray>
    private external fun nativeDeleteSession(context: Long, peerId: ByteArray)
}

/**
 * Identity key pair
 */
data class IdentityKeyPair(
    val privateKey: ByteArray,
    val ed25519PublicKey: ByteArray,
    val x25519PublicKey: ByteArray
) {
    fun getPrivateKeyHex(): String = Sibna.bytesToHex(privateKey)
    fun getEd25519PublicKeyHex(): String = Sibna.bytesToHex(ed25519PublicKey)
    fun getX25519PublicKeyHex(): String = Sibna.bytesToHex(x25519PublicKey)
}

/**
 * Session handle
 */
data class SessionHandle(val peerId: String)

/**
 * Group handle
 */
data class GroupHandle(val groupId: ByteArray)

/**
 * Message representation
 */
data class Message(
    val senderId: String,
    val content: ByteArray,
    val timestamp: Long,
    val encrypted: Boolean = true
)
