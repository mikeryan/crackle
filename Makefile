OBJS=crackle.o

CFLAGS  = -Wall -Werror
LDFLAGS = -lpcap

all: crackle

crackle: $(OBJS)
	$(CC) -o crackle $(OBJS) $(LDFLAGS)

clean:
	rm -f crackle $(OBJS)
