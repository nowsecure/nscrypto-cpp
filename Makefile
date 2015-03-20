SUBDIRS=nscrypto nscryptoTests

define MAKEALL
	$(foreach d,$(SUBDIRS),$(MAKE) -C $(d) $1;)
endef

all:
	$(call MAKEALL,all)

clean:
	$(call MAKEALL,clean)
