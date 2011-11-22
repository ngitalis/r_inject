#!/usr/bin/make -f

DEBUG   ?= n
CFLAGS  := -Wall -fPIC -I../include
ifeq ($(DEBUG),y)
CFLAGS  += -g
endif
LDFLAGS :=
RM      := rm
CC      := gcc
LN	:= ln
DESTDIR ?= /usr/local

%.o: %.c
	@$(CC) -o $@ $(CFLAGS) -c $^
