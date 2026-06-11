# Include subdirectories
include_directories(${GTEST_INCLUDE_DIRS} ${CMAKE_SOURCE_DIR}/include)

add_compile_definitions(BINDIR="${CMAKE_BINARY_DIR}")
add_executable(giarri_encrypt_tests test_crypto.cpp)
target_link_libraries(giarri_encrypt_tests PRIVATE
        giarri_encrypt_lib
        GTest::gtest
        GTest::gtest_main
)
if(UNIX AND NOT APPLE)
    target_link_libraries(giarri_encrypt_tests PRIVATE util)
endif()

gtest_discover_tests(giarri_encrypt_tests)
