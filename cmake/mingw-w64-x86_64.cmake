# Cross-compile vncpwd for 64-bit Windows from a Linux host.
#
# Requires mingw-w64 (x86_64-w64-mingw32-gcc).  Usage:
#   cmake -S . -B build-win64 \
#     -DCMAKE_TOOLCHAIN_FILE=cmake/mingw-w64-x86_64.cmake \
#     -DCMAKE_BUILD_TYPE=Release
#
# The result is a self-contained PE32+ executable: libgcc and the C runtime
# are linked statically so the .exe has no MinGW DLL dependency.

set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR x86_64)

set(CMAKE_C_COMPILER x86_64-w64-mingw32-gcc)
set(CMAKE_RC_COMPILER x86_64-w64-mingw32-windres)

# Static libgcc and winpthread keep the binary portable.
set(CMAKE_EXE_LINKER_FLAGS_INIT "-static -static-libgcc")

# Do not let CMake pick up host libraries or headers for this target.
set(CMAKE_FIND_ROOT_PATH /usr/x86_64-w64-mingw32)
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

# Tests are not registered for cross builds: a PE binary cannot be exec'd on
# the build host.  An earlier revision tried CMAKE_CROSSCOMPILING_EMULATOR and
# CTest still ran the .exe through /bin/sh -- the tests "executed", produced
# MZ-header parse errors on stderr, and a WILL_FAIL test recorded that as a
# pass.  That failure mode is worse than not testing at all, so the Windows CI
# job now invokes the binaries under Wine itself, where exit status is
# unambiguous.

