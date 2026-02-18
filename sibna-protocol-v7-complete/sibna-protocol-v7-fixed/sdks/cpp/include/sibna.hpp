/**
 * Sibna Protocol C++ SDK
 * ======================
 *
 * A C++ wrapper for the Sibna secure communication protocol.
 *
 * @example
 * ```cpp
 * #include <sibna.hpp>
 *
 * int main() {
 *     sibna::Client client("alice", "http://localhost:8000");
 *     client.register();
 *     client.send("bob", "Hello!");
 *     return 0;
 * }
 * ```
 */

#ifndef SIBNA_HPP
#define SIBNA_HPP

#include <string>
#include <vector>
#include <functional>
#include <memory>
#include <cstdint>

namespace sibna {

/**
 * Represents a decrypted message.
 */
struct Message {
    std::string sender_id;
    std::string content;
    uint64_t timestamp;
};

/**
 * High-Level Sibna Client.
 *
 * Handles encryption, storage, queuing, and networking automatically.
 */
class Client {
public:
    /**
     * Create a new client instance.
     *
     * @param user_id Unique identifier for this user
     * @param server_url URL of the relay server
     */
    Client(const std::string& user_id, const std::string& server_url = "http://localhost:8000");

    /**
     * Destructor.
     */
    ~Client();

    /**
     * Register identity with the server.
     *
     * @return True if registration successful
     */
    bool register_identity();

    /**
     * Queue a message to be sent.
     *
     * @param recipient_id Recipient's user ID
     * @param message Message content
     * @return Message queue ID
     */
    int send(const std::string& recipient_id, const std::string& message);

    /**
     * Fetch new messages.
     *
     * @return List of new messages
     */
    std::vector<Message> receive();

    /**
     * Set callback for new messages.
     *
     * @param callback Function to call with new messages
     */
    void on_message(std::function<void(const Message&)> callback);

    /**
     * Start background processing.
     */
    void start();

    /**
     * Stop background processing.
     */
    void stop();

    /**
     * Get count of pending outgoing messages.
     */
    int pending_count() const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

/**
 * Configuration options.
 */
struct Config {
    bool enable_forward_secrecy = true;
    bool enable_post_compromise_security = true;
    int max_skipped_messages = 2000;
    uint64_t key_rotation_interval = 86400;
    uint64_t handshake_timeout = 30;
    int message_buffer_size = 1024;
};

/**
 * Secure context for advanced usage.
 */
class SecureContext {
public:
    /**
     * Create a new secure context.
     *
     * @param config Configuration options
     * @param password Optional master password
     */
    explicit SecureContext(const Config& config, const std::string& password = "");

    /**
     * Destructor.
     */
    ~SecureContext();

    /**
     * Create a new session.
     *
     * @param peer_id Peer identifier
     */
    void create_session(const std::string& peer_id);

    /**
     * Perform X3DH handshake.
     *
     * @param peer_id Peer identifier
     * @param initiator True if this side initiates
     * @param peer_identity_key Peer's identity key (hex)
     * @param peer_signed_prekey Peer's signed prekey (hex)
     * @param peer_onetime_prekey Peer's one-time prekey (hex)
     */
    std::vector<uint8_t> perform_handshake(
        const std::string& peer_id,
        bool initiator,
        const std::string& peer_identity_key,
        const std::string& peer_signed_prekey,
        const std::string& peer_onetime_prekey
    );

    /**
     * Encrypt a message.
     *
     * @param session_id Session identifier
     * @param plaintext Message to encrypt
     * @return Encrypted ciphertext
     */
    std::vector<uint8_t> encrypt(
        const std::string& session_id,
        const std::vector<uint8_t>& plaintext
    );

    /**
     * Decrypt a message.
     *
     * @param session_id Session identifier
     * @param ciphertext Encrypted message
     * @return Decrypted plaintext
     */
    std::vector<uint8_t> decrypt(
        const std::string& session_id,
        const std::vector<uint8_t>& ciphertext
    );

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace sibna

#endif // SIBNA_HPP
