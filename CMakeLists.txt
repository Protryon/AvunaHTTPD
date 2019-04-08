cmake_minimum_required(VERSION 3.12)
project(avuna-httpd C)

set(CMAKE_VERBOSE_MAKEFILE on)

set(CMAKE_C_STANDARD 11)

set(CMAKE_C_FLAGS  "${CMAKE_C_FLAGS} -Wno-discarded-qualifiers")

set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -DDEBUG")

file(GLOB global_src
    "include/avuna/*.h"
)

file(GLOB httpd_src
    "src/*.h"
    "src/*.c"
)

file(GLOB fcgi_src
    "modules/fcgi/src/*.h"
    "modules/fcgi/src/*.c"
)

file(GLOB htdocs_src
    "modules/htdocs/src/*.h"
    "modules/htdocs/src/*.c"
)

file(GLOB mount_src
    "modules/mount/src/*.h"
    "modules/mount/src/*.c"
)

file(GLOB redirect_src
    "modules/redirect/src/*.h"
    "modules/redirect/src/*.c"
)

file(GLOB reverse_proxy_src
    "modules/reverse_proxy/src/*.h"
    "modules/reverse_proxy/src/*.c"
)

add_executable(avuna-httpd ${httpd_src} ${global_src})
target_include_directories(avuna-httpd PUBLIC include/)
target_include_directories(avuna-httpd PRIVATE src/)
target_link_libraries(avuna-httpd -lssl -lcrypto -lpthread -ldl -lavuna-util -export-dynamic)

set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "/etc/avuna/httpd/modules/")

add_library(mod_fcgi SHARED ${fcgi_src} ${global_src})
target_include_directories(mod_fcgi PRIVATE include/)
target_include_directories(mod_fcgi PRIVATE modules/htdocs/include/)
target_link_libraries(mod_fcgi -lavuna-util)
add_library(mod_htdocs SHARED ${htdocs_src} ${global_src})
target_include_directories(mod_htdocs PRIVATE include/)
target_include_directories(mod_htdocs PUBLIC modules/htdocs/include/)
target_link_libraries(mod_htdocs -lz -lavuna-util)
add_library(mod_mount SHARED ${mount_src} ${global_src})
target_include_directories(mod_mount PRIVATE include/)
target_link_libraries(mod_mount -lavuna-util)
add_library(mod_redirect SHARED ${redirect_src} ${global_src})
target_include_directories(mod_redirect PRIVATE include/)
target_link_libraries(mod_redirect -lavuna-util)
add_library(mod_reverse_proxy SHARED ${reverse_proxy_src} ${global_src})
target_include_directories(mod_reverse_proxy PRIVATE include/)
target_include_directories(mod_reverse_proxy PRIVATE modules/htdocs/include/)
target_link_libraries(mod_reverse_proxy -lavuna-util)
