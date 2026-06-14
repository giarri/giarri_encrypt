cmake_minimum_required(VERSION 3.24) #version of FetchContent_Declare FIND_PACKAGE_ARGS 
project(giarri_encrypt VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
list(APPEND CMAKE_PREFIX_PATH "/opt/homebrew")

# Hardening flags
if(MSVC)
	add_compile_options(/GS)
else()
    add_compile_options(
        -Wall -Wextra -Wpedantic
        -fstack-protector-strong
        -D_FORTIFY_SOURCE=2
        -Wformat -Wformat-security
    )
endif()

if(MSVC)
    add_link_options(/NXCOMPAT)
elseif(APPLE)
    add_link_options(-Wl, -pie)
elseif(UNIX)
    add_link_options(-Wl,-z,relro,-z,now)
endif()

# -- Dependencies -------------------------------------------------------------
find_package(PkgConfig REQUIRED)

pkg_check_modules(SODIUM REQUIRED IMPORTED_TARGET libsodium)
include(FetchContent)
FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.tar.gz
	FIND_PACKAGE_ARGS NAMES GTest
)
# Prevent GTest from overriding your compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

# Move executables to the root of the build directory
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})  # ← import libs (.lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})  # ← .so on Unix

# Add subdirectories
add_subdirectory(src)
add_subdirectory(tests)
