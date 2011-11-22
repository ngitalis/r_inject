#!/usr/bin/make -f

include ../Rules.mk

all: library binary

library: libinject.so
binary: inject

libinject.so.1.0.0: inject.o
	@$(CC) -o $@ -shared $(CFLAGS) $(LDFLAGS) $^
libinject.so.1.0: libinject.so.1.0.0
	@$(LN) -fs $< $@
libinject.so.1: libinject.so.1.0
	@$(LN) -fs $< $@
libinject.so: libinject.so.1
	@$(LN) -fs $< $@

inject: main.o libinject.so
	@$(CC) -o $@ -linject -L. $(CFLAGS) $(LDFLAGS) $<

install: binary library
	mkdir -p $(DESTDIR)/sbin
	mkdir -p $(DESTDIR)/lib64
	install -m 0755 -o root -g root inject $(DESTDIR)/sbin
	install -m 0755 -o root -g root libinject.so.1.0.0 $(DESTDIR)/lib64
	cd $(DESTDIR)/lib64 && $(LN) -fs libinject.so.1.0.0 libinject.so.1.0
	cd $(DESTDIR)/lib64 && $(LN) -fs libinject.so.1.0 libinject.so.1
	cd $(DESTDIR)/lib64 && $(LN) -fs libinject.so.1 libinject.so

clean:
	@$(RM) -f libinject.so* inject *.o

.PHONY: all clean library binary
