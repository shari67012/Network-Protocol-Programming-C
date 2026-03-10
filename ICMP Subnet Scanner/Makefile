CC = gcc
CFLAGS = -Wall -g
LIBS = -lpcap

all: ipscanner

ipscanner: main.o fill_packet.o pcap.o
	$(CC) $(CFLAGS) -o ipscanner main.o fill_packet.o pcap.o $(LIBS)

main.o: main.c
	$(CC) $(CFLAGS) -c main.c

fill_packet.o: fill_packet.c
	$(CC) $(CFLAGS) -c fill_packet.c

pcap.o: pcap.c
	$(CC) $(CFLAGS) -c pcap.c

clean:
	rm -f *.o ipscanner



