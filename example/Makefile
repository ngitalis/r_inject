#!/usr/bin/make -f

include ../Rules.mk

all: library binary

library: hammertime.so

binary: thetime

hammertime.so: hammertime.o
	@$(CC) -o $@ -shared -lpthread $(CFLAGS) $(LDFLAGS) $^

thetime: thetime.o
	@$(CC) -o $@ $(CFLAGS) $(LDFLAGS) $<

install:
	# Nothing installed for examples.

clean:
	@$(RM) -f hammertime.so thetime *.o

.PHONY: all clean library binary
