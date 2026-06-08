cmake_minimum_required(VERSION 3.24) #version of FetchContent_Declare FIND_PACKAGE_ARGS 
project(giarri_encrypt VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
list(APPEND CMAKE_PREFIX_PATH "/opt/homebrew")

# Hardening flags
if(MSVC)
	add_compile_options(
		/GS /NXCOMPAT
	)
else()
    add_compile_options(
        -Wall -Wextra -Wpedantic
        -fstack-protector-strong
        -D_FORTIFY_SOURCE=2
        -Wformat -Wformat-security
    )
endif()

find_package(PkgConfig REQUIRED)
if(UNIX AND NOT APPLE)
    add_link_options(-Wl,-z,relro,-z,now)
elseif(APPLE)
    add_link_options(-Wl)
endif()

# -- Dependencies -------------------------------------------------------------
pkg_check_modules(SODIUM REQUIRED IMPORTED_TARGET libsodium)

# -- Library (shared between main and tests) -----------------------------------
add_library(giarri_encrypt_lib STATIC src/crypto.cpp)
target_include_directories(giarri_encrypt_lib PUBLIC include ${SODIUM_INCLUDE_DIRS})
target_link_libraries(giarri_encrypt_lib PUBLIC PkgConfig::SODIUM)

# ── Main executable ───────────────────────────────────────────────────────────
add_executable(giarri_encrypt
		src/main.cpp
		include/logging.hpp)
target_link_libraries(giarri_encrypt PRIVATE giarri_encrypt_lib)

# ── Test executable ───────────────────────────────────────────────────────────
include(FetchContent)
FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.tar.gz
	FIND_PACKAGE_ARGS NAMES GTest
)
# Prevent GTest from overriding your compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

add_executable(giarri_encrypt_tests tests/test_crypto.cpp)
target_link_libraries(giarri_encrypt_tests PRIVATE
	giarri_encrypt_lib
	GTest::gtest
	GTest::gtest_main
)
if(UNIX AND NOT APPLE)
    target_link_libraries(giarri_encrypt_tests PRIVATE util)
endif()

enable_testing()
include(GoogleTest)
gtest_discover_tests(giarri_encrypt_tests)
