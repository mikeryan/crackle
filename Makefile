CC          ?= gcc
INSTALL     ?= /usr/bin/install
DESTDIR     ?=
PREFIX      ?= /usr/local
INSTALL_DIR ?= $(DESTDIR)/$(PREFIX)/bin

OBJS = crackle.o aes.o aes-ccm.o aes-enc.o test.o

CFLAGS  ?= -O2 -Wall -Werror -g
LDFLAGS ?=

all: crackle

crackle: $(OBJS)
	$(CC) $(CFLAGS) -o crackle $(OBJS) -lpcap $(LDFLAGS)

install: crackle
	$(INSTALL) -d $(INSTALL_DIR)
	$(INSTALL) -m 0755 crackle $(INSTALL_DIR)

uninstall:
	rm -f $(INSTALL_DIR)/crackle

clean:
	rm -f crackle $(OBJS)

test: crackle
	cd tests && ./run_tests.pl ../crackle
