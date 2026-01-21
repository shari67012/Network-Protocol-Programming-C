CC = gcc
CFLAGS = -Wall -Wextra -O2
OBJS = main.o arp.o

all: arp

arp: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS)

main.o: main.c arp.h
arp.o: arp.c arp.h

clean:
	rm -f $(OBJS) arp
