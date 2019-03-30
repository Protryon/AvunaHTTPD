cmake_minimum_required(VERSION 3.12)
project(avuna-httpd C)

set(CMAKE_VERBOSE_MAKEFILE on)

set(CMAKE_C_STANDARD 11)

set(CMAKE_C_FLAGS  "${CMAKE_C_FLAGS} -Wno-discarded-qualifiers -DDEBUG")

include_directories(src include/)

file(GLOB httpd_src
    "src/*.h"
    "src/*.c"
    "include/avuna/*.h"
)

add_executable(avuna-httpd ${httpd_src})
target_link_libraries(avuna-httpd -lssl -lcrypto -lz -lpthread)
