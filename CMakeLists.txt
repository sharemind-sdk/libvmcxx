#
# This file is a part of the Sharemind framework.
# Copyright (C) Cybernetica AS
#
# All rights are reserved. Reproduction in whole or part is prohibited
# without the written consent of the copyright owner. The usage of this
# code is subject to the appropriate license agreement.
#

CMAKE_MINIMUM_REQUIRED(VERSION "2.8.12")
PROJECT("SHAREMIND_LIBVMCXX" "CXX")

SET(LIBVMCXX_VERSION "0.3.0.0")
SET(LIBVMCXX_COMPAT_VERSION "0.3.0.0")

INCLUDE("${CMAKE_CURRENT_SOURCE_DIR}/config.local" OPTIONAL)
INCLUDE("${CMAKE_CURRENT_BINARY_DIR}/config.local" OPTIONAL)

FIND_PACKAGE(SharemindCxxHeaders REQUIRED)
FIND_PACKAGE(SharemindLibvm 0.3.0 REQUIRED)

SET(LIBVMCXX_INSTALL_DEFINITIONS ${SharemindCxxHeaders_DEFINITIONS}
                                 ${SharemindLibvm_DEFINITIONS})
SET(LIBVMCXX_INSTALL_LINK_LIBRARIES ${SharemindCxxHeaders_LIBRARIES}
                                    ${SharemindLibvm_LIBRARIES})
SET(LIBVMCXX_INSTALL_INCLUDE_DIRS "${CMAKE_INSTALL_PREFIX}/include"
                                  ${SharemindCxxHeaders_INCLUDE_DIRS}
                                  ${SharemindLibvm_INCLUDE_DIRS})

FILE(GLOB_RECURSE SHAREMIND_LIBVMCXX_HEADERS
     "${CMAKE_CURRENT_SOURCE_DIR}/src/*.h")
ADD_CUSTOM_TARGET("include_libvmcxx_headers_in_IDE"
                  SOURCES ${SHAREMIND_LIBVMCXX_HEADERS})
INSTALL(FILES ${SHAREMIND_LIBVMCXX_HEADERS}
        DESTINATION "include/sharemind/libvm")

# Install cmake files:
FILE(GLOB_RECURSE sharemind_libvm_in_files "${CMAKE_CURRENT_SOURCE_DIR}/*.in")
ADD_CUSTOM_TARGET("include_sharemind_libvm_in_files_in_IDE"
                  SOURCES ${sharemind_libvm_in_files})
CONFIGURE_FILE("${CMAKE_CURRENT_SOURCE_DIR}/SharemindLibvmCxxConfig.cmake.in"
               "${CMAKE_CURRENT_BINARY_DIR}/SharemindLibvmCxxConfig.cmake"
               @ONLY)
CONFIGURE_FILE(
    "${CMAKE_CURRENT_SOURCE_DIR}/SharemindLibvmCxxConfigVersion.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/SharemindLibvmCxxConfigVersion.cmake" @ONLY)
INSTALL(FILES "${CMAKE_CURRENT_BINARY_DIR}/SharemindLibvmCxxConfig.cmake"
              "${CMAKE_CURRENT_BINARY_DIR}/SharemindLibvmCxxConfigVersion.cmake"
        DESTINATION "lib/SharemindLibvmCxx")
