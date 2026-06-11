# My encryption and decryption program.
This project has the objective of learning cpp as well as showing my coding abilities for an interview

## Project Requirements
Create a Linux C++ application able to:
- take a cleartext filename as an input
- take a password as an input
- produce the correct encrypted file as an output


- take an encrypted file as an input
- take a password as an input
- produce the correct decrypted file as an output

The filename must be retrieved using a command line argument.

The password must be retrieved using an interactive prompt that hides the user input.

The input file size can be arbitrary.

The application should log only non-sensitive information to the user in order to give useful debug or error information. It should never log sensitive information.

The application should be written carefully to avoid common attack vectors (like buffer overflows). Countermeasures to avoid RAM inspection to retrieve sensitive information would be appreciated.
It is required to:
- use a derivation function to retrieve the encryption key that will eventually be used to encrypt the file (e.g.: PBKDF2 or Argon2)
- use an encryption algorithm (e.g.: AES or CHACHA20)
- use a cryptographic library to perform the above mentioned operation (e.g.:
OpensSL or LibSodium)

It is also required to write some unit tests able to validate the correct functioning 
of the most critical operations (password reading, encryption and decryption operations). Usage of test libraries like Google Test or the Boost Test Library would be appreciated.

Effective usage of the latest C++ standards would be appreciated (at least C++11).

The C++ applications must be built using at least a basic Makefile, but using a CMake file would be appreciated.

## BUILD AND RUN
```shell
cmake -B build
cmake --build build
# example use
./build/giarri_encrypt encrypt CMakeLists.txt
```

## Issues I encountered
In some configurations (only test inside CLion) the read password test fails because of the following error:
```error
Password: Assertion failed: (_unprotected_ptr_from_user_ptr(user_ptr) == unprotected_ptr), function _sodium_malloc, file utils.c, line 630.
```
I think it's because the mock tries to incapsulate the read_password / stdin function...

This test was completely removed in the windows build because of the dependencies on pty.h
