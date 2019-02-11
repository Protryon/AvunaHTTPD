cmake_minimum_required(VERSION 3.12)
project(avuna-httpd C)

set(CMAKE_C_STANDARD 11)

set(CMAKE_STANDARD_LIBRARIES -lssl -lcrypto -lz -lpthread)

include_directories(src)

file(GLOB httpd_src
    "src/*.h"
    "src/*.c"
)

add_executable(avuna-httpd ${httpd_src})
