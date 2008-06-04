CFLAGS=-Wall -g -O0
CFLAGS+=`pkg-config --cflags fuse`
LDLIBS=-lsmbclient -lfuse

all: foxtrot

clean:

distclean:
	rm -f foxtrot

.PHONY: all clean distclean
