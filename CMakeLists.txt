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
    add_executable(general_compiler tests/general/compiler.cpp)
    target_include_directories(general_compiler PRIVATE
        "${LIBDWARF_INCLUDE_ROOT}"
        "${LIBDWARF_INCLUDE_ROOT}/libdwarf")
    target_link_libraries(general_compiler PRIVATE
        patch_capstone patch_keystone "${LIBDWARF_LIBRARY}"
        ZLIB::ZLIB "${LIBELF_LIBRARY}" Threads::Threads m)
    add_test(NAME general_compiler COMMAND general_compiler)
    set_tests_properties(general_compiler PROPERTIES TIMEOUT 60)

    foreach(general_case IN ITEMS patcher placement got_reuse)
        add_test(NAME general_${general_case}
            COMMAND sh "${CMAKE_CURRENT_SOURCE_DIR}/tests/general/${general_case}.sh" $<TARGET_FILE:1-patch>)
        set_tests_properties(general_${general_case} PROPERTIES TIMEOUT 90)
    endforeach()

    foreach(cpp_case IN ITEMS patcher virtual adjustor abi runtime runtime_abi
            runtime_refs runtime_tls runtime_variables)
        add_test(NAME cpp_${cpp_case}
            COMMAND sh "${CMAKE_CURRENT_SOURCE_DIR}/tests/cpp/${cpp_case}.sh" $<TARGET_FILE:1-patch>)
        set_tests_properties(cpp_${cpp_case} PROPERTIES TIMEOUT 90)
    endforeach()
    foreach(runtime_case IN ITEMS constructor original objects tls_fix tls_objects)
        add_test(NAME cpp_runtime_${runtime_case}
            COMMAND sh "${CMAKE_CURRENT_SOURCE_DIR}/tests/cpp/runtime_${runtime_case}.sh" $<TARGET_FILE:1-patch>)
        set_tests_properties(cpp_runtime_${runtime_case} PROPERTIES TIMEOUT 120)
    endforeach()
    add_test(NAME cpp_build_options
        COMMAND sh "${CMAKE_CURRENT_SOURCE_DIR}/tests/cpp/build_options.sh" $<TARGET_FILE:1-patch>)
    set_tests_properties(cpp_build_options PROPERTIES TIMEOUT 180)

    add_test(NAME c_objdump
        COMMAND sh "${CMAKE_CURRENT_SOURCE_DIR}/tests/c/objdump.sh"
            $<TARGET_FILE:1-patch>
            "${CMAKE_CURRENT_SOURCE_DIR}/examples/objdump/objdump"
            "${CMAKE_CURRENT_SOURCE_DIR}/examples/objdump/objdump_patch.c")
    set_tests_properties(c_objdump PROPERTIES TIMEOUT 180)

    foreach(example IN ITEMS aura blind_test fmtstr heap_1 ld merger rao)
        add_test(NAME c_${example}
            COMMAND sh "${CMAKE_CURRENT_SOURCE_DIR}/tests/c/${example}.sh"
                $<TARGET_FILE:1-patch> "${CMAKE_CURRENT_SOURCE_DIR}")
        set_tests_properties(c_${example} PROPERTIES SKIP_RETURN_CODE 77 TIMEOUT 180)
    endforeach()

endif()
