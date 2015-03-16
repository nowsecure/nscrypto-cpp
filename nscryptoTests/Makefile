include ../config.mk

OBJS=main.o vp_ecdh.o
LIBS=../nscrypto/libnscrypto.a

all: main

main: $(OBJS) $(LIBS)
	$(CXX) -o $@ $(LDFLAGS) $(OBJS) $(LIBS)

$(OBJS): %.o: %.cpp
	${CXX} -o $@ -c ${CXXFLAGS} $<

../nscrypto/libnscrypto.a:
	$(MAKE) -C ../nscrypto

clean:
	rm -f $(OBJS)
