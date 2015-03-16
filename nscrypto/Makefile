include ../config.mk

all: libnscrypto.a

libnscrypto.a: nscrypto_ecdh.o
	$(AR) -r libnscrypto.a nscrypto_ecdh.o
	$(RANLIB) libnscrypto.a

$(OBJS): %.o: %.cc
	$(CXX) -o $@ -c ${CXXFLAGS} $<

clean:
	rm -f libnscrypto.a nscrypto_ecdh.o
