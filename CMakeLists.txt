cmake_minimum_required(VERSION 3.24)

project(1-patch VERSION 1.0.1 LANGUAGES C CXX)

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(FATAL_ERROR "1-patch rewrites Linux ELF binaries and must be built on Linux")
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(LIEF CONFIG REQUIRED)
find_package(ZLIB REQUIRED)
find_package(Threads REQUIRED)
find_path(LIBDWARF_INCLUDE_ROOT NAMES libdwarf/libdwarf.h REQUIRED)
find_library(LIBDWARF_LIBRARY NAMES dwarf REQUIRED)
find_library(LIBELF_LIBRARY NAMES elf REQUIRED)

option(PATCH_USE_SYSTEM_DISASM "Use installed Capstone and Keystone instead of building local copies" OFF)

if(PATCH_USE_SYSTEM_DISASM)
    find_path(CAPSTONE_INCLUDE_ROOT NAMES capstone/capstone.h REQUIRED)
    find_library(CAPSTONE_LIBRARY NAMES capstone REQUIRED)
    find_path(KEYSTONE_INCLUDE_ROOT NAMES keystone/keystone.h REQUIRED)
    find_library(KEYSTONE_LIBRARY NAMES keystone REQUIRED)
    add_library(patch_capstone UNKNOWN IMPORTED)
    set_target_properties(patch_capstone PROPERTIES
        IMPORTED_LOCATION "${CAPSTONE_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${CAPSTONE_INCLUDE_ROOT}")
    add_library(patch_keystone UNKNOWN IMPORTED)
    set_target_properties(patch_keystone PROPERTIES
        IMPORTED_LOCATION "${KEYSTONE_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${KEYSTONE_INCLUDE_ROOT}")
else()
    include(ExternalProject)
    set(CAPSTONE_PREFIX "${CMAKE_BINARY_DIR}/_deps/capstone")
    set(KEYSTONE_PREFIX "${CMAKE_BINARY_DIR}/_deps/keystone")
    file(MAKE_DIRECTORY "${CAPSTONE_PREFIX}/include" "${KEYSTONE_PREFIX}/include")

    ExternalProject_Add(patch_capstone_build
        GIT_REPOSITORY https://github.com/capstone-engine/capstone.git
        GIT_TAG 5.0.9
        GIT_SHALLOW TRUE
        UPDATE_DISCONNECTED TRUE
        INSTALL_DIR "${CAPSTONE_PREFIX}"
        CMAKE_ARGS
            -DCMAKE_INSTALL_PREFIX=<INSTALL_DIR>
            -DCMAKE_INSTALL_LIBDIR=lib
            -DCMAKE_BUILD_TYPE=Release
            -DBUILD_SHARED_LIBS=OFF
            -DBUILD_STATIC_LIBS=ON
            -DCAPSTONE_BUILD_TESTS=OFF
            -DCAPSTONE_BUILD_CSTOOL=OFF
            -DCAPSTONE_INSTALL=ON
            -DCAPSTONE_ARCHITECTURE_DEFAULT=OFF
            -DCAPSTONE_X86_SUPPORT=ON
        BUILD_BYPRODUCTS "${CAPSTONE_PREFIX}/lib/libcapstone.a")

    ExternalProject_Add(patch_keystone_build
        GIT_REPOSITORY https://github.com/keystone-engine/keystone.git
        GIT_TAG fb92f32391c6cced868252167509590319eeb58b
        UPDATE_DISCONNECTED TRUE
        INSTALL_DIR "${KEYSTONE_PREFIX}"
        CMAKE_ARGS
            -DCMAKE_INSTALL_PREFIX=<INSTALL_DIR>
            -DCMAKE_INSTALL_LIBDIR=lib
            -DCMAKE_BUILD_TYPE=Release
            -DBUILD_SHARED_LIBS=OFF
            -DBUILD_LIBS_ONLY=ON
            -DLLVM_TARGETS_TO_BUILD=X86
        BUILD_BYPRODUCTS "${KEYSTONE_PREFIX}/lib/libkeystone.a")

    add_library(patch_capstone STATIC IMPORTED)
    set_target_properties(patch_capstone PROPERTIES
        IMPORTED_LOCATION "${CAPSTONE_PREFIX}/lib/libcapstone.a"
        INTERFACE_INCLUDE_DIRECTORIES "${CAPSTONE_PREFIX}/include")
    add_dependencies(patch_capstone patch_capstone_build)

    add_library(patch_keystone STATIC IMPORTED)
    set_target_properties(patch_keystone PROPERTIES
        IMPORTED_LOCATION "${KEYSTONE_PREFIX}/lib/libkeystone.a"
        INTERFACE_INCLUDE_DIRECTORIES "${KEYSTONE_PREFIX}/include")
    add_dependencies(patch_keystone patch_keystone_build)
endif()

add_executable(1-patch src/main.cpp)
target_include_directories(1-patch PRIVATE
    "${LIBDWARF_INCLUDE_ROOT}"
    "${LIBDWARF_INCLUDE_ROOT}/libdwarf")
target_compile_options(1-patch PRIVATE -Wignored-attributes)
target_link_libraries(1-patch PRIVATE
    LIEF::LIEF
    patch_capstone
    patch_keystone
    "${LIBDWARF_LIBRARY}"
    ZLIB::ZLIB
    "${LIBELF_LIBRARY}"
    Threads::Threads
    m)

include(CTest)
if(BUILD_TESTING)
    add_executable(compiler tests/compiler.cpp)
    target_include_directories(compiler PRIVATE
        "${LIBDWARF_INCLUDE_ROOT}"
        "${LIBDWARF_INCLUDE_ROOT}/libdwarf")
    target_link_libraries(compiler PRIVATE
        patch_capstone patch_keystone "${LIBDWARF_LIBRARY}"
        ZLIB::ZLIB "${LIBELF_LIBRARY}" Threads::Threads m)
    add_test(NAME compiler COMMAND compiler)
    set_tests_properties(compiler PROPERTIES TIMEOUT 60)
    add_test(NAME patcher
        COMMAND sh "${CMAKE_CURRENT_SOURCE_DIR}/tests/patcher.sh" $<TARGET_FILE:1-patch>)
    set_tests_properties(patcher PROPERTIES TIMEOUT 90)
    add_test(NAME objdump
        COMMAND sh "${CMAKE_CURRENT_SOURCE_DIR}/tests/objdump.sh"
            $<TARGET_FILE:1-patch>
            "${CMAKE_CURRENT_SOURCE_DIR}/examples/objdump/objdump"
            "${CMAKE_CURRENT_SOURCE_DIR}/examples/objdump/objdump_patch.c")
    set_tests_properties(objdump PROPERTIES TIMEOUT 180)

    foreach(example IN ITEMS aura blind_test fmtstr heap_1 ld merger rao)
        add_test(NAME ${example}
            COMMAND sh "${CMAKE_CURRENT_SOURCE_DIR}/tests/${example}.sh"
                $<TARGET_FILE:1-patch> "${CMAKE_CURRENT_SOURCE_DIR}")
        set_tests_properties(${example} PROPERTIES SKIP_RETURN_CODE 77 TIMEOUT 180)
    endforeach()

endif()
