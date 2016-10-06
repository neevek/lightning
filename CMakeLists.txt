cmake_minimum_required(VERSION 2.8.9)
set (CMAKE_INSTALL_PREFIX /usr/local)

#set(CMAKE_C_FLAGS "-Wall -O0 -g -DLOG_VERBOSE -std=c99 -D_GNU_SOURCE -Wno-deprecated-declarations -DNO_TERM_COLOR")
set(CMAKE_C_FLAGS "-O2 -DLOG_VERBOSE -std=c99 -D_GNU_SOURCE -Wno-deprecated-declarations -DNO_TERM_COLOR")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

set(SRCS_FOR_LOCAL alloc.c local.c socks5.c util.c encrypt.c cli.c sig_handler.c)
set(SRCS_FOR_REMOTE alloc.c remote.c socks5.c util.c encrypt.c cli.c)

IF(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
  MESSAGE("Building on MacOS, system proxy configuration feature is enabled.")
  set(SRCS_FOR_LOCAL ${SRCS_FOR_LOCAL} proxy_config.m)
  FIND_LIBRARY(FOUNDATION_LIB Foundation)
  FIND_LIBRARY(SYSTEM_CONFIGURATION_LIB SystemConfiguration)
  FIND_LIBRARY(CF_NETWORK_LIB CFNetwork)
  FIND_LIBRARY(SECURITY_LIB Security)
  MARK_AS_ADVANCED(FOUNDATION_LIB SYSTEM_CONFIGURATION_LIB CF_NETWORK_LIB SECURITY_LIB)
  SET(EXTRA_LIBS ${FOUNDATION_LIB} ${SYSTEM_CONFIGURATION_LIB} ${CF_NETWORK_LIB} ${SECURITY_LIB})
ENDIF()

add_executable(lightning_local ${SRCS_FOR_LOCAL})
add_executable(lightning_remote ${SRCS_FOR_REMOTE})

target_link_libraries(lightning_local uv crypto ssl ${EXTRA_LIBS})
target_link_libraries(lightning_remote uv crypto ssl)

install(TARGETS lightning_local lightning_remote DESTINATION /usr/local/bin)
