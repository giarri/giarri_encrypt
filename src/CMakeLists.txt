# Set the compiler flags on the Coverage build-type
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    set(CMAKE_C_FLAGS_COVERAGE "${CMAKE_C_FLAGS_DEBUG} --coverage")
    set(CMAKE_EXE_LINKER_FLAGS_COVERAGE "${CMAKE_EXE_LINKER_FLAGS_DEBUG} --coverage")
    set(CMAKE_SHARED_LINKER_FLAGS_COVERAGE "${CMAKE_SHARED_LINKER_FLAGS_DEBUG} --coverage")
    set(CMAKE_MODULE_LINKER_FLAGS_COVERAGE "${CMAKE_MODULE_LINKER_FLAGS_DEBUG} --coverage")
endif()

# Add target and source files
add_library(giarri_encrypt_lib SHARED crypto.cpp)
target_link_libraries(giarri_encrypt_lib PUBLIC PkgConfig::SODIUM)
target_include_directories(giarri_encrypt_lib PUBLIC include ${SODIUM_INCLUDE_DIRS})

# ── Main executable ───────────────────────────────────────────────────────────
add_executable(giarri_encrypt main.cpp)
target_link_libraries(giarri_encrypt PRIVATE giarri_encrypt_lib)

# Move executables to the root of the build directory
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

if ("${CMAKE_BUILD_TYPE}" STREQUAL "Coverage")
    target_compile_options(giarri_encrypt_lib PRIVATE --coverage)
    target_link_options(giarri_encrypt_lib PRIVATE --coverage)
endif()
