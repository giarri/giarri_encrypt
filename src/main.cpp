#include <fstream>
#include <iostream>
#include <string>
#include <unistd.h>

#include "crypto.hpp"
#include "logging.hpp"


static void print_usage(const char* prog) {
    std::cout << "Usage:\n"
              << "  " << prog << " encrypt <input_file>\n"
              << "  " << prog << " decrypt <encrypted_input_file>\n";
}

int main(int argc, char* argv[]) {
    if (sodium_init() < 0) {
        LOG_ERR("libsodium initialisation failed. exiting\n");
        return 1;
    }

    // USAGE: ./program_name encrypt/decrypt input_file
    if (argc != 3) {
        print_usage(argv[0]);
        return 1;
    }

    const std::string mode(argv[1]);
    const std::string input_file(argv[2]);
    const std::string output_file{
        mode == "encrypt" ?
        std::string(argv[2]) + ".encrypted" :
        std::string(argv[2]) + ".decrypted"};

    if (mode != "encrypt" && mode != "decrypt") {
        LOG("Unknown mode: " << mode << '\n');
        print_usage(argv[0]);
        return 1;
    }

    std::string password = crypto::read_password("Password: ");

    std::ifstream in;
    std::ofstream out;
    //Errors during file handling are the most common. Hence, I decided to try catch this block. Files could throw exceptions in the rest of the code as well.
    try {
        in = std::ifstream(input_file, std::ios::binary);
        if (!in) throw std::runtime_error("Cannot open input file: " + input_file);
        out = std::ofstream(output_file, std::ios::binary);
        if (!out) throw std::runtime_error("Cannot open output file: " + output_file);
    } catch (const std::exception& e) {
        LOG_ERR(e.what());
        sodium_memzero(password.data(), password.size());
        return 1;
    }
    if (mode == "encrypt") {
        crypto::encrypt_file(std::move(in), std::move(out), password);
        LOG("Encrypted: " << input_file << " into " << output_file);
    } else {
        crypto::decrypt_file(std::move(in), std::move(out), password);
        LOG("Decrypted: " << input_file << " into " << output_file);
    }
    // Securely wipe password from memory
    sodium_memzero(password.data(), password.size());
    return 0;
}