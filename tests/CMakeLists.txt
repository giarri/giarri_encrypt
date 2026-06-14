# test/CMakeLists.txt
# Include subdirectories
include_directories(${GTEST_INCLUDE_DIRS} ${CMAKE_SOURCE_DIR}/include)
include(GenerateExportHeader)
generate_export_header(giarri_encrypt_lib)
target_include_directories(giarri_encrypt_lib PUBLIC ${CMAKE_CURRENT_BINARY_DIR})

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

# Tests
include(CTest)
include(GoogleTest)
enable_testing()

# Add a custom target for generating coverage-to-share reports
if ("${CMAKE_BUILD_TYPE}" STREQUAL "Coverage") # Check if the build type is 'Coverage'
    find_package(Python3 REQUIRED COMPONENTS Interpreter)  # Required for gcovr
    add_custom_target(coverage
            COMMAND ${CMAKE_COMMAND} -E make_directory coverage
            COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure
            COMMAND ${Python3_EXECUTABLE} -m gcovr -r ${CMAKE_SOURCE_DIR} --html --html-nested -o coverage/index.html
            WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
            COMMENT "Generating HTML coverage report..."
    )
endif()

gtest_discover_tests(giarri_encrypt_tests)
