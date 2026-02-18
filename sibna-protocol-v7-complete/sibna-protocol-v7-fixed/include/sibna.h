/**
 * Sibna Protocol C Header
 * =======================
 *
 * Auto-generated C bindings for the Sibna protocol.
 * Version: 7.0.0
 */

#ifndef SIBNA_H
#define SIBNA_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* FFI Error Codes */
typedef enum {
    SIBNA_SUCCESS = 0,
    SIBNA_NULL_POINTER = 1,
    SIBNA_INVALID_ARGUMENT = 2,
    SIBNA_ENCRYPTION_FAILED = 3,
    SIBNA_DECRYPTION_FAILED = 4,
    SIBNA_SESSION_NOT_FOUND = 5,
    SIBNA_OUT_OF_MEMORY = 6,
    SIBNA_PANIC = 7,
    SIBNA_KEY_DERIVATION_FAILED = 8,
    SIBNA_INVALID_STATE = 9,
    SIBNA_UNKNOWN_ERROR = 255
} sibna_error_t;

/* Opaque handle types */
typedef struct sibna_context sibna_context_t;
typedef struct sibna_session sibna_session_t;

/* Configuration */
typedef struct {
    uint8_t enable_forward_secrecy;
    uint8_t enable_post_compromise_security;
    size_t max_skipped_messages;
    uint64_t key_rotation_interval;
    uint64_t handshake_timeout;
    size_t message_buffer_size;
} sibna_config_t;

/**
 * Initialize the Sibna library.
 * Must be called before any other functions.
 *
 * @return SIBNA_SUCCESS on success
 */
sibna_error_t sibna_init(void);

/**
 * Create a new secure context.
 *
 * @param config Configuration options (NULL for defaults)
 * @param password Master password (optional)
 * @param password_len Password length
 * @return Context handle or NULL on failure
 */
sibna_context_t* sibna_context_create(
    const sibna_config_t* config,
    const uint8_t* password,
    size_t password_len
);

/**
 * Free a secure context.
 *
 * @param ctx Context to free
 * @return SIBNA_SUCCESS on success
 */
sibna_error_t sibna_context_free(sibna_context_t* ctx);

/**
 * Load identity keys into context.
 *
 * @param ctx Context handle
 * @param ed_pub Ed25519 public key (32 bytes)
 * @param x_pub X25519 public key (32 bytes)
 * @param seed Private key seed (32 bytes)
 * @return SIBNA_SUCCESS on success
 */
sibna_error_t sibna_context_load_identity(
    sibna_context_t* ctx,
    const uint8_t* ed_pub,
    const uint8_t* x_pub,
    const uint8_t* seed
);

/**
 * Create a new session.
 *
 * @param ctx Context handle
 * @param peer_id Peer identifier
 * @param peer_id_len Peer ID length
 * @return Session handle or NULL on failure
 */
sibna_session_t* sibna_session_create(
    sibna_context_t* ctx,
    const uint8_t* peer_id,
    size_t peer_id_len
);

/**
 * Free a session.
 *
 * @param session Session to free
 * @return SIBNA_SUCCESS on success
 */
sibna_error_t sibna_session_free(sibna_session_t* session);

/**
 * Perform X3DH handshake.
 *
 * @param ctx Context handle
 * @param peer_id Peer identifier
 * @param peer_id_len Peer ID length
 * @param initiator True if this side initiates
 * @param peer_ik Peer identity key (32 bytes)
 * @param peer_spk Peer signed prekey (32 bytes)
 * @param peer_opk Peer one-time prekey (32 bytes)
 * @param shared_secret Output buffer for shared secret
 * @param shared_secret_len Output length
 * @return SIBNA_SUCCESS on success
 */
sibna_error_t sibna_context_perform_handshake(
    sibna_context_t* ctx,
    const uint8_t* peer_id,
    size_t peer_id_len,
    uint8_t initiator,
    const uint8_t* peer_ik,
    const uint8_t* peer_spk,
    const uint8_t* peer_opk,
    uint8_t** shared_secret,
    size_t* shared_secret_len
);

/**
 * Encrypt a message.
 *
 * @param ctx Context handle
 * @param session_id Session identifier
 * @param session_id_len Session ID length
 * @param plaintext Message to encrypt
 * @param plaintext_len Plaintext length
 * @param ciphertext Output buffer
 * @param ciphertext_len Output length
 * @return SIBNA_SUCCESS on success
 */
sibna_error_t sibna_context_encrypt(
    sibna_context_t* ctx,
    const uint8_t* session_id,
    size_t session_id_len,
    const uint8_t* plaintext,
    size_t plaintext_len,
    uint8_t** ciphertext,
    size_t* ciphertext_len
);

/**
 * Decrypt a message.
 *
 * @param ctx Context handle
 * @param session_id Session identifier
 * @param session_id_len Session ID length
 * @param ciphertext Encrypted message
 * @param ciphertext_len Ciphertext length
 * @param plaintext Output buffer
 * @param plaintext_len Output length
 * @return SIBNA_SUCCESS on success
 */
sibna_error_t sibna_context_decrypt(
    sibna_context_t* ctx,
    const uint8_t* session_id,
    size_t session_id_len,
    const uint8_t* ciphertext,
    size_t ciphertext_len,
    uint8_t** plaintext,
    size_t* plaintext_len
);

/**
 * Generate a new X25519 key pair.
 *
 * @param public_key Output buffer for public key (32 bytes)
 * @param private_key Output buffer for private key (32 bytes)
 * @return SIBNA_SUCCESS on success
 */
sibna_error_t sibna_generate_keypair(
    uint8_t* public_key,
    uint8_t* private_key
);

/**
 * Generate random bytes.
 *
 * @param buffer Output buffer
 * @param len Number of bytes to generate
 * @return SIBNA_SUCCESS on success
 */
sibna_error_t sibna_random_bytes(
    uint8_t* buffer,
    size_t len
);

/**
 * Free a buffer allocated by Sibna.
 *
 * @param ptr Buffer pointer
 * @param len Buffer length
 * @return SIBNA_SUCCESS on success
 */
sibna_error_t sibna_free_buffer(
    uint8_t* ptr,
    size_t len
);

#ifdef __cplusplus
}
#endif

#endif /* SIBNA_H */
