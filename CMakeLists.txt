cmake_minimum_required(VERSION 2.8.9)
project(lightning)

#set(CMAKE_C_FLAGS "-Wall -O0 -g -DLOG_VERBOSE -std=c99 -D_GNU_SOURCE -Wno-deprecated-declarations -DNO_TERM_COLOR")
set(CMAKE_C_FLAGS "-O2 -DLOG_VERBOSE -std=c99 -D_GNU_SOURCE -Wno-deprecated-declarations -DNO_TERM_COLOR")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

set(SRCS_FOR_LOCAL alloc.c local.c socks5.c util.c encrypt.c cli.c)
set(SRCS_FOR_REMOTE alloc.c remote.c socks5.c util.c encrypt.c cli.c)

add_executable(lightning ${SRCS_FOR_LOCAL})
add_executable(lightning_remote ${SRCS_FOR_REMOTE})

target_link_libraries(lightning uv crypto ssl)
target_link_libraries(lightning_remote uv crypto ssl)
