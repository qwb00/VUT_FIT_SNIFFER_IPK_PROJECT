CC = gcc
CFLAGS = -g -Wall
TARGET = ipk-sniffer
LIBS = -lpcap

all: $(TARGET)

$(TARGET): main.o args.o capture_packet.o
	$(CC) $(CFLAGS) -o $(TARGET) main.o args.o capture_packet.o $(LIBS)

main.o: main.c main.h
	$(CC) $(CFLAGS) -c main.c

args.o: args.c args.h
	$(CC) $(CFLAGS) -c args.c

capture_packet.o: capture_packet.c capture_packet.h
	$(CC) $(CFLAGS) -c capture_packet.c

clean:
	rm -f *.o $(TARGET)
