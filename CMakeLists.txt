#
# Copyright (C) 2015 Cybernetica
#
# Research/Commercial License Usage
# Licensees holding a valid Research License or Commercial License
# for the Software may use this file according to the written
# agreement between you and Cybernetica.
#
# GNU General Public License Usage
# Alternatively, this file may be used under the terms of the GNU
# General Public License version 3.0 as published by the Free Software
# Foundation and appearing in the file LICENSE.GPL included in the
# packaging of this file.  Please review the following information to
# ensure the GNU General Public License version 3.0 requirements will be
# met: http://www.gnu.org/copyleft/gpl-3.0.html.
#
# For further information, please contact us at sharemind@cyber.ee.
#

CMAKE_MINIMUM_REQUIRED(VERSION "3.0")
PROJECT(SharemindLibVmCxx VERSION "0.5.0" LANGUAGES "CXX")

INCLUDE("${CMAKE_CURRENT_SOURCE_DIR}/config.local" OPTIONAL)
INCLUDE("${CMAKE_CURRENT_BINARY_DIR}/config.local" OPTIONAL)

FIND_PACKAGE(SharemindCMakeHelpers REQUIRED)

SharemindSetProjectVersion()


FIND_PACKAGE(SharemindCxxHeaders REQUIRED)
FIND_PACKAGE(SharemindLibVm 0.5.0 REQUIRED)


FILE(GLOB_RECURSE SharemindLibVmCxx_HEADERS
     "${CMAKE_CURRENT_SOURCE_DIR}/src/*.h")
ADD_CUSTOM_TARGET("include_libvmcxx_headers_in_IDE"
                  SOURCES ${SharemindLibVmCxx_HEADERS})
INSTALL(FILES ${SharemindLibVmCxx_HEADERS}
        DESTINATION "include/sharemind/libvm"
        COMPONENT "dev")

# Install cmake files:
SharemindCreateCMakeFindFiles(
    INCLUDE_DIRS
        "${CMAKE_INSTALL_PREFIX}/include"
        ${SharemindCxxHeaders_INCLUDE_DIRS}
        ${SharemindLibVm_INCLUDE_DIRS}
    DEFINITIONS
        ${SharemindCxxHeaders_DEFINITIONS}
        ${SharemindLibVm_DEFINITIONS}
    LIBRARIES
        ${SharemindCxxHeaders_LIBRARIES}
        ${SharemindLibVm_LIBRARIES}
)


# Packaging:
SharemindSetupPackaging()
SharemindAddComponentPackage("dev"
    NAME "libsharemind-vm-cxx-dev"
    DESCRIPTION "Sharemind VM C++ wrapper development headers"
    DEB_SECTION "libdevel"
    DEB_DEPENDS
        "libsharemind-vm-dev (>= 0.3.0)"
        "libsharemind-cxxheaders-dev (>= 0.1.0)"
        "libstdc++-dev"
)
SharemindPackagingFinalize()
