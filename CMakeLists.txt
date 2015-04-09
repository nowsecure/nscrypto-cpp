cmake_minimum_required(VERSION 2.8)

project(nscrypto)
set(nscrypto_VERSION_MAJOR 1)
set(nscrypto_VERSION_MINOR 0)

include_directories(nscrypto include)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -pthread -Wall -Werror -Wno-unknown-pragmas")

add_library(nscrypto_libcrypto nscrypto/nscrypto_ecdh.cc)
add_library(nscrypto_mbedtls nscrypto/nscrypto_ecdh.cc)

target_compile_definitions(nscrypto_libcrypto PUBLIC "-DUSE_LIBCRYPTO -D_NSCRYPTO_TESTS")
target_compile_definitions(nscrypto_mbedtls PUBLIC "-DUSE_MBEDTLS -D_NSCRYPTO_TESTS")

add_executable(nscrypto_tests_libcrypto nscryptoTests/main.cc nscryptoTests/vp_ecdh.cc)
add_executable(nscrypto_tests_mbedtls nscryptoTests/main.cc nscryptoTests/vp_ecdh.cc)

target_link_libraries(nscrypto_tests_libcrypto nscrypto_libcrypto crypto bsd)
target_link_libraries(nscrypto_tests_mbedtls nscrypto_mbedtls mbedtls crypto bsd)
