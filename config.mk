LIBBSD_CF=$(shell pkg-config --cflags libbsd)
LIBBSD_LF=$(shell pkg-config --libs libbsd)

LDFLAGS+=-lssl -lcrypto -lc++ -lbsd
CXXFLAGS+=-I/usr/include/libressl
CXXFLAGS+=-I. -I../include -I../nscrypto -g
AR?=ar
RANLIB?=ranlib

# CLANG
CXX=clang++
CXXFLAGS+=-stdlib=libc++ -std=c++11

# G++ cannot compile this code
#CXX=g++
