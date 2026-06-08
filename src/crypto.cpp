#include "crypto.hpp"

#include <sodium.h>
#ifdef _WIN32
    #include <windows.h>
#else
    #include <termios.h>
    #include <unistd.h>
#endif

#include <array>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>
#include "logging.hpp"

namespace crypto {

    // ---------------------------------------------------------------------------
    // Secure password input
    // ---------------------------------------------------------------------------

    std::string read_password(const std::string& prompt)
    {
        // Disable echo
        #ifdef _WIN32
            HANDLE h = GetStdHandle(STD_INPUT_HANDLE);
            DWORD mode = 0;
            GetConsoleMode(h, &mode);
            SetConsoleMode(h, mode & ~ENABLE_ECHO_INPUT);

            std::cerr << prompt << std::flush;
            std::string pw;
            std::getline(std::cin, pw);

            SetConsoleMode(h, mode);   // restore
            std::cerr << '\n';
            return pw;
        #else
            struct termios old_tty{}, new_tty{};
            const bool is_tty = (tcgetattr(STDIN_FILENO, &old_tty) == 0);
            if (is_tty) {
                new_tty = old_tty;
                new_tty.c_lflag &= ~static_cast<tcflag_t>(ECHO);
                tcsetattr(STDIN_FILENO, TCSANOW, &new_tty);
            }
        std::cerr << prompt << std::flush;

        // Use a libsodium-allocated buffer to prevent swapping
        constexpr size_t MAX_PW = 256;
        char* buf = static_cast<char*>(sodium_malloc(MAX_PW));
        if (!buf) throw std::runtime_error("sodium_malloc failed for password buffer");

        std::string pw;
        try {
            // Read char-by-char to avoid leaving a copy in istream internals
            char c = '\0';
            size_t i = 0;
            while (i < MAX_PW - 1 && std::cin.get(c) && c != '\n') {
                buf[i++] = c;
            }
            buf[i] = '\0';
            pw.assign(buf, i);
        } catch (...) {
            sodium_memzero(buf, MAX_PW);
            sodium_free(buf);
            if (is_tty) {
                tcsetattr(STDIN_FILENO, TCSANOW, &old_tty);
                std::cerr << '\n';
            }
            throw;
        }

        sodium_memzero(buf, MAX_PW);
        sodium_free(buf);

        if (is_tty) {
            tcsetattr(STDIN_FILENO, TCSANOW, &old_tty);
            std::cerr << '\n';
        }
        return pw;
        #endif
    }

SecureKey derive_key(const std::string& password,
                     const uint8_t salt[SALT_SIZE])
{
    SecureKey key;
    if (crypto_pwhash(
            key.data(), key.size(),
            password.data(), password.size(),
            salt,
            crypto_pwhash_OPSLIMIT_INTERACTIVE,
            crypto_pwhash_MEMLIMIT_INTERACTIVE,
            crypto_pwhash_argon2id_ALG_ARGON2ID13) != 0)
    {
        throw std::runtime_error("Key derivation (Argon2id) failed — out of memory?");
    }
    return key;
}


/**
 * ┌─────────────────────────────────────────────────────────────┐
 * │                        OUTPUT FILE                          │
 * ├──────────────────┬──────────────────┬───────────────────────┤
 * │      SALT        │  STREAM HEADER   │       CHUNKS          │
 * │   (SALT_SIZE B)  │  (HEADER_SIZE B) │                       │
 * │                  │                  │  ┌─────────────────┐  │
 * │  randombytes_buf │  xchacha20poly   │  │    CHUNK 1      │  │
 * │  (KDF input)     │  1305 init_push  │  │ ciphertext +    │  │
 * │                  │  output (nonce   │  │ ABYTES MAC      │  │
 * │                  │  + state seed)   │  │ TAG_MESSAGE     │  │
 * │                  │                  │  ├─────────────────┤  │
 * │                  │                  │  │    CHUNK 2      │  │
 * │                  │                  │  │ ciphertext +    │  │
 * │                  │                  │  │ ABYTES MAC      │  │
 * │                  │                  │  │ TAG_MESSAGE     │  │
 * │                  │                  │  ├─────────────────┤  │
 * │                  │                  │  │   CHUNK N       │  │
 * │                  │                  │  │ ciphertext +    │  │
 * │                  │                  │  │ ABYTES MAC      │  │
 * │                  │                  │  │ TAG_FINAL ◄──┐  │  │
 * │                  │                  │  └─────────────────┘  │
 * └──────────────────┴──────────────────┴───────────────────────┘
 * Byte offsets:
 * [0                .. SALT_SIZE)                  → salt
 * [SALT_SIZE        .. SALT_SIZE+HEADER_SIZE)      → stream header
 * [SALT_SIZE+HEADER_SIZE .. EOF)                   → chunks
 *     each chunk = plaintext_len + ABYTES bytes
 *     final chunk carries TAG_FINAL (signals EOF to decryptor)
 */
void encrypt_file(std::ifstream in,
                  std::ofstream out,
                  const std::string& password) {

    // Generate random salt and derive key
    std::array<uint8_t, SALT_SIZE> salt{};
    randombytes_buf(salt.data(), salt.size());

    SecureKey key = derive_key(password, salt.data());

    // Write salt
    out.write(reinterpret_cast<const char*>(salt.data()),
              SALT_SIZE);

    // Initialise secretstream
    crypto_secretstream_xchacha20poly1305_state st;
    std::array<uint8_t, HEADER_SIZE> header{};
    crypto_secretstream_xchacha20poly1305_init_push(&st, header.data(), key.data());

    // Write stream header
    out.write(reinterpret_cast<const char*>(header.data()),
              HEADER_SIZE);

    // Encrypt in chunks — always emit at least one chunk (handles empty files)
    std::vector<uint8_t> plain_buf(CHUNK_SIZE);
    std::vector<uint8_t> cipher_buf(CHUNK_SIZE +
        crypto_secretstream_xchacha20poly1305_ABYTES);

    bool first = true;
    while (true) {
        in.read(reinterpret_cast<char*>(plain_buf.data()),
                CHUNK_SIZE);
        const std::streamsize n = in.gcount();
        const bool eof = in.eof() || in.fail();

        // If nothing was read and this isn't the first iteration, we're done
        if (n == 0 && !first) break;

        const uint8_t tag = eof
            ? crypto_secretstream_xchacha20poly1305_TAG_FINAL
            : crypto_secretstream_xchacha20poly1305_TAG_MESSAGE;

        unsigned long long cipher_len = 0;
        crypto_secretstream_xchacha20poly1305_push(
            &st,
            cipher_buf.data(), &cipher_len,
            plain_buf.data(),  static_cast<unsigned long long>(n),
            nullptr, 0,        // no additional data
            tag);

        out.write(reinterpret_cast<const char*>(cipher_buf.data()),
                  static_cast<std::streamsize>(cipher_len));

        first = false;
        if (eof) break;
    }

    // Wipe stack buffers
    sodium_memzero(plain_buf.data(), plain_buf.size());
    sodium_memzero(&st, sizeof(st));

    if (!out) throw std::runtime_error("Write error on output file");
    LOG("Encryption complete");
}

// ---------------------------------------------------------------------------
// Decryption
// ---------------------------------------------------------------------------

void decrypt_file(std::ifstream in,
                  std::ofstream out,
                  const std::string& password)
{
    // Read salt
    std::array<uint8_t, SALT_SIZE> salt{};
    if (!in.read(reinterpret_cast<char*>(salt.data()),
                 SALT_SIZE))
        throw std::runtime_error("Corrupted file: cannot read salt");

    SecureKey key = derive_key(password, salt.data());

    // Read stream header
    std::array<uint8_t, HEADER_SIZE> header{};
    if (!in.read(reinterpret_cast<char*>(header.data()),
                 HEADER_SIZE))
        throw std::runtime_error("Corrupted file: cannot read stream header");

    crypto_secretstream_xchacha20poly1305_state st;
    if (crypto_secretstream_xchacha20poly1305_init_pull(&st, header.data(), key.data()) != 0)
        throw std::runtime_error("Invalid stream header — wrong password or corrupt file");

    // Decrypt in chunks
    constexpr size_t CIPHER_CHUNK = CHUNK_SIZE +
        crypto_secretstream_xchacha20poly1305_ABYTES;
    std::vector<uint8_t> cipher_buf(CIPHER_CHUNK);
    std::vector<uint8_t> plain_buf(CHUNK_SIZE);

    bool got_final = false;
    while (in) {
        in.read(reinterpret_cast<char*>(cipher_buf.data()),
                CIPHER_CHUNK);
        const std::streamsize n = in.gcount();
        if (n == 0) break;

        unsigned long long plain_len = 0;
        uint8_t tag = 0;
        if (crypto_secretstream_xchacha20poly1305_pull(
                &st,
                plain_buf.data(), &plain_len, &tag,
                cipher_buf.data(), static_cast<unsigned long long>(n),
                nullptr, 0) != 0)
        {
            sodium_memzero(plain_buf.data(), plain_buf.size());
            sodium_memzero(&st, sizeof(st));
            throw std::runtime_error("Decryption failed — wrong password or corrupt file");
        }

        out.write(reinterpret_cast<const char*>(plain_buf.data()),
                  plain_len);

        if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL) {
            got_final = true;
            break;
        }
    }

    sodium_memzero(plain_buf.data(), plain_buf.size());
    sodium_memzero(&st, sizeof(st));

    if (!got_final)
        throw std::runtime_error("Truncated ciphertext: final chunk tag not found");
    if (!out)
        throw std::runtime_error("Write error on output file");

    LOG("Decryption complete");
}


} // namespace crypto
