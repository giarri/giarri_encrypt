#include "crypto.hpp"

#include <gtest/gtest.h>
#include <sodium.h>

#include <array>
#include <filesystem>
#include <fstream>
#include <string>

#ifdef TARGET_OS_WINDOWS
#define NO_TERM
#else
#include <termios.h>
#endif
#include <fcntl.h>
#include <poll.h>
#include <chrono>
#include <cstring>

#ifdef __APPLE__
#  include <util.h>
#endif
#include <unistd.h>   // write, close
#include <thread>
#include <sstream>

namespace fs = std::filesystem;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static std::string tmp_path(const std::string& name) {
    return (fs::temp_directory_path() / ("giarri_encrypt_test_" + name)).string();
}

static void write_file(const std::string& path, const std::string& content) {
    std::ofstream f(path, std::ios::binary);
    f.write(content.data(), static_cast<std::streamsize>(content.size()));
}

static std::string read_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(f), {}};
}

// ---------------------------------------------------------------------------
// Key derivation tests
// ---------------------------------------------------------------------------

class KeyDerivationTest : public ::testing::Test {
protected:
    void SetUp() override { ASSERT_GE(sodium_init(), 0); }

    std::array<uint8_t, crypto::SALT_SIZE> make_salt(uint8_t fill = 0x42) {
        std::array<uint8_t, crypto::SALT_SIZE> s{};
        s.fill(fill);
        return s;
    }
};

TEST_F(KeyDerivationTest, DeterministicForSameInputs) {
    auto salt = make_salt();
    auto k1 = crypto::derive_key("hunter2", salt.data());
    auto k2 = crypto::derive_key("hunter2", salt.data());
    EXPECT_EQ(std::memcmp(k1.data(), k2.data(), crypto::KEY_SIZE), 0);
}

TEST_F(KeyDerivationTest, DifferentPasswordsDifferentKeys) {
    auto salt = make_salt();
    auto k1 = crypto::derive_key("password_a", salt.data());
    auto k2 = crypto::derive_key("password_b", salt.data());
    EXPECT_NE(std::memcmp(k1.data(), k2.data(), crypto::KEY_SIZE), 0);
}

// ---------------------------------------------------------------------------
// Password reading tests
// ---------------------------------------------------------------------------
// Drain the master fd for up to `timeout_ms`; returns whatever arrived.
static std::string drain(int master_fd, int timeout_ms = 200)
{
    std::string out;
    char buf[256];
    pollfd pfd{master_fd, POLLIN, 0};

    while (poll(&pfd, 1, timeout_ms) > 0 && (pfd.revents & POLLIN)) {
        ssize_t n = read(master_fd, buf, sizeof(buf));
        if (n <= 0) break;
        out.append(buf, n);
        timeout_ms = 50;   // shorter poll for subsequent chunks
    }
    return out;
}

class PtyEchoTest : public ::testing::Test {
protected:
    int master_fd = -1, slave_fd = -1;

    void SetUp() override {
        ASSERT_GE(sodium_init(), 0);
        ASSERT_EQ(openpty(&master_fd, &slave_fd, nullptr, nullptr, nullptr), 0)
            << "openpty failed: " << strerror(errno);

        // Make master non-blocking so drain() never hangs.
        int flags = fcntl(master_fd, F_GETFL);
        fcntl(master_fd, F_SETFL, flags | O_NONBLOCK);
    }

    void TearDown() override {
        if (master_fd >= 0) close(master_fd);
        if (slave_fd  >= 0) close(slave_fd);
    }
};

TEST_F(PtyEchoTest, SlaveHasEchoEnabledByDefault)
{
    // Sanity check: vanilla PTY slave echoes input back through master.
    const std::string input = "visible\n";
    write(master_fd, input.data(), input.size());

    std::string echoed = drain(master_fd);
    EXPECT_NE(echoed.find("visible"), std::string::npos)
        << "Expected default PTY to echo; got: " << echoed;
}

#ifndef NO_TERM
TEST_F(PtyEchoTest, ReadPasswordDisablesEcho)
{
    // ── 1. redirect STDIN_FILENO and std::cin to the slave ──────────────────
    int saved_stdin = dup(STDIN_FILENO);
    ASSERT_GE(saved_stdin, 0);
    ASSERT_EQ(dup2(slave_fd, STDIN_FILENO), STDIN_FILENO);

    // Sync std::cin's underlying fd with the new STDIN_FILENO.
    std::cin.sync_with_stdio(true);   // flush any buffered state

    // ── 2. feed a password through the master, then EOF ──────────────────
    const std::string password = "s3cr3t";
    // Run in a thread because read_password blocks until '\n'.
    std::thread writer([&]{
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        std::string line = password + "\n";
        write(master_fd, line.data(), line.size());
    });

    // ── 3. call the function under test ─────────────────────────────────
    std::string result = crypto::read_password("Password: ");
    writer.join();
    ASSERT_FALSE(std::cin.fail());

    // ── 4. restore STDIN_FILENO ─────────────────────────────────────────
    dup2(saved_stdin, STDIN_FILENO);
    close(saved_stdin);
    std::cin.clear();

    // ── 5. assertions ───────────────────────────────────────────────────
    EXPECT_EQ(result, password);

    // 5b. Nothing typed on slave should have been echoed back to master.
    std::string echoed = drain(master_fd);
    EXPECT_EQ(echoed.find(password), std::string::npos)
        << "Password was echoed back to master: " << echoed;

    // 5c. Directly verify ECHO flag is restored after the call.
    struct termios t{};
    ASSERT_EQ(tcgetattr(slave_fd, &t), 0);
    EXPECT_TRUE(t.c_lflag & ECHO)
        << "ECHO flag was not restored on the slave after read_password returned";
}
#endif

// ---------------------------------------------------------------------------
// Encrypt / Decrypt round-trip tests
// ---------------------------------------------------------------------------

class EncryptDecryptTest : public ::testing::Test {
protected:
    void SetUp() override {
        ASSERT_GE(sodium_init(), 0);
    }

    void TearDown() override {
        for (auto& p : paths_to_clean_) {
            fs::remove(p);
        }
    }

    std::string make_tmp(const std::string& tag) {
        auto p = tmp_path(tag);
        paths_to_clean_.push_back(p);
        return p;
    }

    std::vector<std::string> paths_to_clean_;
};

TEST_F(EncryptDecryptTest, RoundTripSmallFile) {
    const std::string plain_in  = make_tmp("plain_in");
    const std::string cipher    = make_tmp("cypher");
    const std::string plain_out = make_tmp("plain_out");
    const std::string password  = "correct_horse_battery_staple";
    const std::string content   = "Hello, giarri!";

    write_file(plain_in, content);
    std::ifstream in(plain_in, std::ios::binary);
    std::ofstream out(cipher, std::ios::binary);
    crypto::encrypt_file(std::move(in), std::move(out), password);
    in = std::ifstream(cipher, std::ios::binary);
    out = std::ofstream(plain_out, std::ios::binary);
    crypto::decrypt_file(std::move(in), std::move(out), password);

    EXPECT_EQ(read_file(plain_in), read_file(plain_out));
}

TEST_F(EncryptDecryptTest, RoundTripLargeFile) {
    // > 1 chunk (64 KiB) to exercise multi-chunk streaming
    const std::string plain_in  = make_tmp("large_in");
    const std::string cipher    = make_tmp("large_cipher");
    const std::string plain_out = make_tmp("large_out");
    const std::string password  = "large_file_pw";

    std::string big(200'000, '\xAB');
    write_file(plain_in, big);

    std::ifstream in(plain_in, std::ios::binary);
    std::ofstream out(cipher, std::ios::binary);
    crypto::encrypt_file(std::move(in), std::move(out), password);

    in = std::ifstream(cipher, std::ios::binary);
    out = std::ofstream(plain_out, std::ios::binary);
    crypto::decrypt_file(std::move(in), std::move(out), password);

    EXPECT_EQ(read_file(plain_out), big);
}

TEST_F(EncryptDecryptTest, RoundTripEmptyFile) {
    const std::string plain_in  = make_tmp("empty_in");
    const std::string cipher    = make_tmp("empty_cipher");
    const std::string plain_out = make_tmp("empty_out");

    write_file(plain_in, "");
    std::ifstream in(plain_in, std::ios::binary);
    std::ofstream out(cipher, std::ios::binary);
    crypto::encrypt_file(std::move(in), std::move(out), "pw");

    in = std::ifstream(cipher, std::ios::binary);
    out = std::ofstream(plain_out, std::ios::binary);
    crypto::decrypt_file(std::move(in), std::move(out), "pw");

    EXPECT_EQ(read_file(plain_out), "");
}

TEST_F(EncryptDecryptTest, WrongPasswordThrows) {
    const std::string plain_in  = make_tmp("wp_in");
    const std::string cipher    = make_tmp("wp_cipher");
    const std::string plain_out = make_tmp("wp_out");

    write_file(plain_in, "secret");
    std::ifstream in(plain_in, std::ios::binary);
    std::ofstream out(cipher, std::ios::binary);
    crypto::encrypt_file(std::move(in), std::move(out), "right_pw");

    in = std::ifstream(cipher, std::ios::binary);
    out = std::ofstream(plain_out, std::ios::binary);

    EXPECT_THROW(
         crypto::decrypt_file(std::move(in), std::move(out), "wrong_pw"),
         std::runtime_error);
}

TEST_F(EncryptDecryptTest, TamperedCiphertextThrows) {
    const std::string plain_in  = make_tmp("tc_in");
    const std::string cipher    = make_tmp("tc_cipher");
    const std::string plain_out = make_tmp("tc_out");

    write_file(plain_in, "tamper me");
    std::ifstream in(plain_in, std::ios::binary);
    std::ofstream out(cipher, std::ios::binary);
    crypto::encrypt_file(std::move(in), std::move(out), "pw");

    // Flip a byte in the ciphertext payload area (past salt+header)
    std::fstream f(cipher, std::ios::in | std::ios::out | std::ios::binary);
    f.seekp(crypto::SALT_SIZE + crypto::HEADER_SIZE + 10);
    char b = '\0';
    f.get(b);
    f.seekp(-1, std::ios::cur);
    f.put(static_cast<char>(b ^ 0xFF));
    f.flush();
    f.close();

    in = std::ifstream(cipher, std::ios::binary);
    out = std::ofstream(plain_out, std::ios::binary);
    EXPECT_THROW(crypto::decrypt_file(std::move(in), std::move(out), "pw"),
                 std::runtime_error);
}

TEST_F(EncryptDecryptTest, CiphertextDiffersFromPlaintext) {
    const std::string plain_in = make_tmp("diff_in");
    const std::string cipher   = make_tmp("diff_cipher");

    const std::string content = "plaintext should not appear in ciphertext";
    write_file(plain_in, content);

    std::ifstream in(plain_in, std::ios::binary);
    std::ofstream out(cipher, std::ios::binary);
    crypto::encrypt_file(std::move(in), std::move(out), "pw");

    // Ciphertext file must not contain the raw plaintext
    const std::string ct = read_file(cipher);
    EXPECT_EQ(ct.find(content), std::string::npos);
}

TEST_F(EncryptDecryptTest, UniqueNonceEachRun) {
    // Two encryptions of the same file should produce different ciphertexts
    // (different salt → different key + different stream header)
    const std::string plain_in = make_tmp("nonce_in");
    const std::string cipher1  = make_tmp("nonce_c1");
    const std::string cipher2  = make_tmp("nonce_c2");

    write_file(plain_in, "nonce test");
    std::ifstream in(plain_in, std::ios::binary);
    std::ofstream out(cipher1, std::ios::binary);
    crypto::encrypt_file(std::move(in), std::move(out), "pw");

    in =  std::ifstream(plain_in, std::ios::binary);
    out = std::ofstream(cipher2, std::ios::binary);
    crypto::encrypt_file(std::move(in), std::move(out), "pw");

    EXPECT_NE(read_file(cipher1), read_file(cipher2));
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
