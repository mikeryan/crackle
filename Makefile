CC          ?= gcc
INSTALL     ?= /usr/bin/install
INSTALL_DIR ?= /usr/local/bin

OBJS = crackle.o aes.o aes-ccm.o aes-enc.o test.o

CFLAGS  = -Wall -Werror -O2
LDFLAGS = -lpcap

all: crackle

crackle: $(OBJS)
	$(CC) -o crackle $(OBJS) $(LDFLAGS)

install: crackle
	$(INSTALL) -m 0755 crackle $(INSTALL_DIR)

uninstall:
	rm -f $(INSTALL_DIR)/crackle

clean:
	rm -f crackle $(OBJS)
