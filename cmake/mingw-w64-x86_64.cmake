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

# A cross-compiled .exe cannot be executed on the build host.  When Wine is
# available, register it as the emulator so CTest runs every test binary
# through it instead of trying to exec() the PE directly.  Pass
#   -DVNCPWD_WINE_EMULATOR=wine
# on the CMake command line; leave it unset to build without running tests.
#
# Read the cache entry only if it was supplied: declaring it here would shadow
# a value the caller passed with -D and silently disable the emulator.
if(DEFINED NVCPWD_WINE_EMULATOR AND NVCPWD_WINE_EMULATOR)
    set(CMAKE_CROSSCOMPILING_EMULATOR "${NVCPWD_WINE_EMULATOR}")
endif()
