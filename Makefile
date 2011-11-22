#!/usr/bin/make -f

default:
	make -C src
	make -C example
	make -C include

install:
	make -C src install
	make -C example install
	make -C include install

clean:
	make -C src clean
	make -C example clean
	make -C include clean

.PHONY: default install clean
