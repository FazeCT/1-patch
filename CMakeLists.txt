cmake_minimum_required(VERSION 3.24)
project(thesis)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(thesis src/main.cpp)

find_package(LIEF REQUIRED)

target_include_directories(thesis PRIVATE /usr/include/capstone)
target_include_directories(thesis PRIVATE /usr/include/libdwarf)
target_include_directories(thesis PRIVATE /usr/include/keystone)

target_compile_options(thesis PRIVATE -Wignored-attributes)

target_link_libraries(thesis PRIVATE 
    LIEF::LIEF 
    /usr/lib/x86_64-linux-gnu/libcapstone.so 
    /usr/lib/x86_64-linux-gnu/libdwarf.a 
    /usr/lib/x86_64-linux-gnu/libz.so 
    /usr/lib/x86_64-linux-gnu/libelf.so
    /usr/lib/x86_64-linux-gnu/libkeystone.so
)