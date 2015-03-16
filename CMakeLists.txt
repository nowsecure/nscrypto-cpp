cmake_minimum_required(VERSION 3.1)
project(nscryptoTests)

include_directories(nscrypto include)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

set(SOURCE_FILES
    nscryptoTests/main.cpp
    nscrypto/nscrypto_ecdh.cc
    nscryptoTests/vp_ecdh.cpp)

add_executable(nscryptoTests ${SOURCE_FILES})
target_link_libraries(nscryptoTests crypto bsd)
