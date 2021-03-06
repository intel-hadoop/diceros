#
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

cmake_minimum_required(VERSION 2.6 FATAL_ERROR)

# Default to release builds
set(CMAKE_BUILD_TYPE, Release)

include(JNIFlags.cmake NO_POLICY_SCOPE)

# Compile a library with both shared and static variants
function(add_dual_library LIBNAME)
    add_library(${LIBNAME} SHARED ${ARGN})
    add_library(${LIBNAME}_static STATIC ${ARGN})
    set_target_properties(${LIBNAME}_static PROPERTIES OUTPUT_NAME ${LIBNAME})
endfunction(add_dual_library)

# Link both a static and a dynamic target against some libraries
function(target_link_dual_libraries LIBNAME)
    target_link_libraries(${LIBNAME} ${ARGN})
    target_link_libraries(${LIBNAME}_static ${ARGN})
endfunction(target_link_dual_libraries)

function(output_directory TGT DIR)
    SET_TARGET_PROPERTIES(${TGT} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/${DIR}")
    SET_TARGET_PROPERTIES(${TGT} PROPERTIES
        ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/${DIR}")
    SET_TARGET_PROPERTIES(${TGT} PROPERTIES
        LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/${DIR}")
endfunction(output_directory TGT DIR)

function(dual_output_directory TGT DIR)
    output_directory(${TGT} "${DIR}")
    output_directory(${TGT}_static "${DIR}")
endfunction(dual_output_directory TGT DIR)

#
# This macro alters the behavior of find_package and find_library.
# It does this by setting the CMAKE_FIND_LIBRARY_SUFFIXES global variable. 
# You should save that variable before calling this function and restore it
# after you have accomplished your goal.
#
# The behavior is altered in two ways:
# 1. We always find shared libraries, never static;
# 2. We find shared libraries with the given version number.
#
# On Windows this function is a no-op.  Windows does not encode
# version number information information into library path names.
#
macro(set_find_shared_library_version LVERS)
    IF(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
        # Mac OS uses .dylib
        SET(CMAKE_FIND_LIBRARY_SUFFIXES ".${LVERS}.dylib")
    ELSEIF(${CMAKE_SYSTEM_NAME} MATCHES "FreeBSD")
        # FreeBSD has always .so installed.
        SET(CMAKE_FIND_LIBRARY_SUFFIXES ".so")
    ELSEIF(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
        # Windows doesn't support finding shared libraries by version.
        SET(CMAKE_FIND_LIBRARY_SUFFIXES ".dll")
    ELSE()
        # Most UNIX variants use .so
        SET(CMAKE_FIND_LIBRARY_SUFFIXES ".so.${LVERS}")
    ENDIF()
endmacro(set_find_shared_library_version LVERS)

macro(set_find_shared_library_without_version)
    IF(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
        # Mac OS uses .dylib
        SET(CMAKE_FIND_LIBRARY_SUFFIXES ".dylib")
    ELSEIF(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
        # No effect
    ELSE()
        # Most UNIX variants use .so
        SET(CMAKE_FIND_LIBRARY_SUFFIXES ".so")
    ENDIF()
endmacro(set_find_shared_library_without_version)

if (NOT GENERATED_JAVAH)
    # Must identify where the generated headers have been placed
    MESSAGE(FATAL_ERROR "You must set the cmake variable GENERATED_JAVAH")
endif (NOT GENERATED_JAVAH)
find_package(JNI REQUIRED)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -Wall -O2")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_REENTRANT -D_GNU_SOURCE")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64")
set(D main/native)

INCLUDE(CheckFunctionExists)
INCLUDE(CheckCSourceCompiles)
INCLUDE(CheckLibraryExists)
CHECK_FUNCTION_EXISTS(sync_file_range HAVE_SYNC_FILE_RANGE)
CHECK_FUNCTION_EXISTS(posix_fadvise HAVE_POSIX_FADVISE)
CHECK_LIBRARY_EXISTS(dl dlopen "" NEED_LINK_DL)

# AES Cipher
SET(STORED_CMAKE_FIND_LIBRARY_SUFFIXES CMAKE_FIND_LIBRARY_SUFFIXES)
set_find_shared_library_without_version()
SET(OPENSSL_NAME "crypto")
IF(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
    SET(OPENSSL_NAME "libeay32")
ENDIF()
find_library(CRYPTO_LIBRARY
    NAMES ${OPENSSL_NAME}
    PATHS ${CUSTOM_CRYPTO_PREFIX} ${CUSTOM_CRYPTO_PREFIX}/lib
        ${CUSTOM_CRYPTO_PREFIX}/lib64 ${CUSTOM_CRYPTO_LIB} NO_DEFAULT_PATH)
find_library(CRYPTO_LIBRARY
    NAMES ${OPENSSL_NAME})
SET(CMAKE_FIND_LIBRARY_SUFFIXES STORED_CMAKE_FIND_LIBRARY_SUFFIXES)
find_path(CRYPTO_INCLUDE_DIR
    NAMES openssl/evp.h
    PATHS ${CUSTOM_CRYPTO_PREFIX} ${CUSTOM_CRYPTO_PREFIX}/include
        ${CUSTOM_CRYPTO_INCLUDE} NO_DEFAULT_PATH)
find_path(CRYPTO_INCLUDE_DIR
    NAMES openssl/evp.h)
if (CRYPTO_LIBRARY AND CRYPTO_INCLUDE_DIR)
    GET_FILENAME_COMPONENT(HADOOP_CRYPTO_LIBRARY ${CRYPTO_LIBRARY} NAME)
    set(DICEROS_SOURCE_FILES
                "${D}/com/intel/diceros/crypto/engines/AESOpensslEngine.c"
                "${D}/com/intel/diceros/provider/securerandom/DrngSecureRandom.c"
                "${D}/com/intel/diceros/provider/securerandom/rdrand-api.c"
                "${D}/com/intel/diceros/crypto/engines/aes_utils.c")
else (CRYPTO_LIBRARY AND CRYPTO_INCLUDE_DIR)
    set(CRYPTO_INCLUDE_DIR "")
    set(DICEROS_SOURCE_FILES "")
    IF(REQUIRE_CRYPTO)
        MESSAGE(FATAL_ERROR "Required crypto library could not be found.
        CRYPTO_LIBRARY=${CRYPTO_LIBRARY},
        CRYPTO_INCLUDE_DIR=${CRYPTO_INCLUDE_DIR},
        CUSTOM_CRYPTO_INCLUDE_DIR=${CUSTOM_CRYPTO_INCLUDE_DIR},
        CUSTOM_CRYPTO_PREFIX=${CUSTOM_CRYPTO_PREFIX},
        CUSTOM_CRYPTO_INCLUDE=${CUSTOM_CRYPTO_INCLUDE}")
    ENDIF(REQUIRE_CRYPTO)
endif (CRYPTO_LIBRARY AND CRYPTO_INCLUDE_DIR)

# AES MB Cipher
SET(STORED_CMAKE_FIND_LIBRARY_SUFFIXES CMAKE_FIND_LIBRARY_SUFFIXES)
IF(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
    SET(CMAKE_FIND_LIBRARY_SUFFIXES ".dll")
ELSE()
    SET(CMAKE_FIND_LIBRARY_SUFFIXES ".so")
ENDIF()
find_library(AESMB_LIBRARY
    NAMES aesmb
    PATHS ${D}/aesmb
        ${D}/../../../target/native/target/usr/local/lib/
        ${CUSTOM_AESMB_PREFIX} ${CUSTOM_AESMB_PREFIX}/lib
        ${CUSTOM_AESMB_PREFIX}/lib64 ${CUSTOM_AESMB_LIB})
SET(CMAKE_FIND_LIBRARY_SUFFIXES STORED_CMAKE_FIND_LIBRARY_SUFFIXES)

find_path(AESMB_INCLUDE_DIR
    NAMES aes_api.h
    PATHS ${D}/aesmb
        ${CUSTOM_AESMB_PREFIX} ${CUSTOM_AESMB_PREFIX}/include
        ${CUSTOM_AESMB_INCLUDE})

if (CRYPTO_LIBRARY AND CRYPTO_INCLUDE_DIR AND AESMB_LIBRARY AND AESMB_INCLUDE_DIR)
    GET_FILENAME_COMPONENT(HADOOP_CRYPTO_LIBRARY ${CRYPTO_LIBRARY} NAME)
    GET_FILENAME_COMPONENT(HADOOP_AESMB_LIBRARY ${AESMB_LIBRARY} NAME)
    set(AESMB_SOURCE_FILES
        "${D}/com/intel/diceros/crypto/engines/AESMutliBufferEngine.c"
        "${D}/com/intel/diceros/crypto/engines/aes_multibuffer.c")
else (CRYPTO_LIBRARY AND CRYPTO_INCLUDE_DIR AND AESMB_LIBRARY AND AESMB_INCLUDE_DIR)
    set(AESMB_INCLUDE_DIR "")
    set(AESMB_SOURCE_FILES "")
    IF(REQUIRE_AESMB)
        MESSAGE(FATAL_ERROR "Required crypto or aesmb library could not be found.
        CRYPTO_LIBRARY=${CRYPTO_LIBRARY},
        AESMB_LIBRARY=${AESMB_LIBRARY},
        AESMB_INCLUDE_DIR=${AESMB_INCLUDE_DIR},
        CRYPTO_INCLUDE_DIR=${CRYPTO_INCLUDE_DIR},
        CUSTOM_CRYPTO_INCLUDE_DIR=${CUSTOM_CRYPTO_INCLUDE_DIR},
        CUSTOM_CRYPTO_PREFIX=${CUSTOM_CRYPTO_PREFIX},
        CUSTOM_CRYPTO_INCLUDE=${CUSTOM_CRYPTO_INCLUDE}")
    ENDIF(REQUIRE_AESMB)
endif (CRYPTO_LIBRARY AND CRYPTO_INCLUDE_DIR AND AESMB_LIBRARY AND AESMB_INCLUDE_DIR)

include_directories(
    ${GENERATED_JAVAH}
    ${D}
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_BINARY_DIR}
    ${JNI_INCLUDE_DIRS}
    ${CRYPTO_INCLUDE_DIR}
    ${AESMB_INCLUDE_DIR}
    ${D}/util
)
CONFIGURE_FILE(${CMAKE_SOURCE_DIR}/config.h.cmake ${CMAKE_BINARY_DIR}/config.h)

SET(CMAKE_BUILD_WITH_INSTALL_RPATH TRUE)
add_dual_library(diceros
       ${DICEROS_SOURCE_FILES}
        ${AESMB_SOURCE_FILES}
)
if (NEED_LINK_DL)
   set(LIB_DL dl)
endif (NEED_LINK_DL)

IF (${CMAKE_SYSTEM_NAME} MATCHES "Linux")
    #
    # By embedding '$ORIGIN' into the RPATH of libdiceros.so,
    # dlopen will look in the directory containing libdiceros.so.
    # However, $ORIGIN is not supported by all operating systems.
    #
    SET_TARGET_PROPERTIES(diceros
    PROPERTIES INSTALL_RPATH "\$ORIGIN/")
ENDIF()

target_link_dual_libraries(diceros
    ${LIB_DL}
    ${JAVA_JVM_LIBRARY}
)
SET(LIBDICEROS_VERSION "1.3.0")
SET_TARGET_PROPERTIES(diceros PROPERTIES
    SOVERSION ${LIBDICEROS_VERSION})
dual_output_directory(diceros target/usr/local/lib)
