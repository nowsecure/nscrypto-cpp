cmake_minimum_required(VERSION 2.8)

project(nscrypto)
set(nscrypto_VERSION_MAJOR 1)
set(nscrypto_VERSION_MINOR 0)

include_directories(nscrypto include)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -Wall -Werror -Wno-unknown-pragmas")

add_library(nscrypto nscrypto/nscrypto_ecdh.cc)
add_executable(nscrypto_tests nscryptoTests/main.cpp nscryptoTests/vp_ecdh.cpp)

target_link_libraries(nscrypto_tests nscrypto crypto bsd)
