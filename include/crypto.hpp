#pragma once

#include <string>
#include <vector>
#include <stdexcept>
#include <sodium.h>

namespace crypto {

// Sizes (bytes)
constexpr size_t SALT_SIZE    = crypto_pwhash_SALTBYTES;      // 16
constexpr size_t KEY_SIZE     = crypto_secretstream_xchacha20poly1305_KEYBYTES; // 32
constexpr size_t HEADER_SIZE  = crypto_secretstream_xchacha20poly1305_HEADERBYTES;
constexpr size_t CHUNK_SIZE   = 1 << 16; // 64 KiB

// File format:
//   [salt: 16 bytes][stream_header: 24 bytes][encrypted_chunks...]
// Each chunk produced by crypto_secretstream_xchacha20poly1305_push

/**
 * Securely zeroed key buffer — wraps a libsodium-allocated region so
 * it is zeroed on destruction and cannot be swapped to disk (mlock).
 */
class SecureKey {
public:
    SecureKey() {
        data_ = static_cast<uint8_t*>(sodium_malloc(KEY_SIZE));
        if (!data_) throw std::runtime_error("sodium_malloc failed");
        sodium_memzero(data_, KEY_SIZE);
    }
    ~SecureKey() { sodium_free(data_); }

    // Non-copyable, movable
    SecureKey(const SecureKey&) = delete;
    SecureKey& operator=(const SecureKey&) = delete;
    SecureKey(SecureKey&& o) noexcept : data_(o.data_) { o.data_ = nullptr; }

    uint8_t*       data()       noexcept { return data_; }
    const uint8_t* data() const noexcept { return data_; }
    static constexpr size_t size() noexcept { return KEY_SIZE; }

private:
    uint8_t* data_;
};

/**
 * Derive a KEY_SIZE key from password + salt using Argon2id
 * (crypto_pwhash default on libsodium >= 1.0.15).
 */
SecureKey derive_key(const std::string& password,
                     const uint8_t salt[SALT_SIZE]);

/**
 * Encrypt plaintext → ciphertext.
 * Generates a random salt each call.
 */
void encrypt_file(std::ifstream in,
                  std::ofstream out,
                  const std::string& password);

/**
 * Decrypt ciphertext → plaintext.
 */
void decrypt_file(std::ifstream in,
                  std::ofstream out,
                  const std::string& password);

/**
 * Read password from terminal without echo.
 * Prompts the user, then clears the password from memory on scope exit.
 */
std::string read_password(const std::string& prompt);

} // namespace crypto
