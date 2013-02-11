OBJS = crackle.o aes.o aes-ccm.o aes-enc.o test.o

CFLAGS  = -Wall -Werror -O2
LDFLAGS = -lpcap

all: crackle

crackle: $(OBJS)
	$(CC) -o crackle $(OBJS) $(LDFLAGS)

clean:
	rm -f crackle $(OBJS)
