cmake_minimum_required(VERSION 3.16)

project(vncpwd
    VERSION 2.0.0
    DESCRIPTION "VNC Credential & Security Inspector"
    LANGUAGES C)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

option(VNCPWD_BUILD_TESTS "Build the test suite" ON)
option(VNCPWD_WARNINGS_AS_ERRORS "Treat compiler warnings as errors" OFF)
option(VNCPWD_SANITIZERS "Build Debug with ASan and UBSan (GCC/Clang)" OFF)

add_library(vncpwd_core STATIC
    src/core/des.c
    src/core/encoding.c
    src/core/legacy_des.c
    src/core/format_validator.c
    src/core/auth_type.c
    src/core/detector.c
    src/core/util.c
    src/parsers/ini.c
    src/parsers/connection.c
    src/parsers/registry.c
    src/providers/provider.c
    src/providers/realvnc.c
    src/providers/tightvnc.c
    src/providers/tigervnc.c
    src/providers/ultravnc.c
    src/providers/passwdfile.c
    src/providers/connections.c
    src/reports/report.c
    src/inspector.c
)

target_include_directories(vncpwd_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

if(MSVC)
    target_compile_definitions(vncpwd_core PUBLIC _CRT_SECURE_NO_WARNINGS)
    target_compile_options(vncpwd_core PRIVATE /W4)
    if(VNCPWD_WARNINGS_AS_ERRORS)
        target_compile_options(vncpwd_core PRIVATE /WX)
    endif()
else()
    target_compile_options(vncpwd_core PRIVATE
        -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wno-sign-conversion)
    if(VNCPWD_WARNINGS_AS_ERRORS)
        target_compile_options(vncpwd_core PRIVATE -Werror)
    endif()
    if(VNCPWD_SANITIZERS)
        target_compile_options(vncpwd_core PUBLIC
            -fsanitize=address,undefined -fno-omit-frame-pointer)
        target_link_options(vncpwd_core INTERFACE -fsanitize=address,undefined)
    endif()
endif()

add_executable(vncpwd src/main.c)
target_link_libraries(vncpwd PRIVATE vncpwd_core)

if(WIN32)
    set_target_properties(vncpwd PROPERTIES WIN32_EXECUTABLE OFF)
endif()

install(TARGETS vncpwd RUNTIME DESTINATION bin)

if(VNCPWD_BUILD_TESTS)
    enable_testing()

    add_executable(vncpwd_tests
        tests/run_tests.c
        tests/test_main.c
        tests/test_des.c
        tests/test_encoding.c
        tests/test_validator.c
        tests/test_detector.c
        tests/test_ini.c
        tests/test_connection.c
        tests/test_report.c
    )
    target_include_directories(vncpwd_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/tests)
    target_link_libraries(vncpwd_tests PRIVATE vncpwd_core)
    set_target_properties(vncpwd_tests PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

    # Tests write fixture files such as test_ini_tmp.ini; run them somewhere
    # writable rather than next to the source tree.
    add_test(NAME unit COMMAND vncpwd_tests
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

    # Under a cross build the console tools are PE binaries.  When CMake is
    # told about an emulator (see cmake/mingw-w64-x86_64.cmake), it prefixes
    # these commands automatically, so the same test definitions verify a
    # Windows executable from a Linux host.

    # End-to-end checks drive the real binary.  They rely only on the command
    # line interface, so they also work when the core is exercised by a fuzzer.
    add_test(NAME cli_hex_password
        COMMAND vncpwd inspect --hex dbd83cfd727a1458 --show -q)
    set_tests_properties(cli_hex_password PROPERTIES
        PASS_REGULAR_EXPRESSION "password")

    add_test(NAME cli_rejects_odd_hex
        COMMAND vncpwd inspect --hex dbd83cfd727a145 -q)
    set_tests_properties(cli_rejects_odd_hex PROPERTIES WILL_FAIL TRUE)

    add_test(NAME cli_audit_exit_code
        COMMAND vncpwd audit -q)
    set_tests_properties(cli_audit_exit_code PROPERTIES
        PASS_REGULAR_EXPRESSION "max risk:")
endif()
