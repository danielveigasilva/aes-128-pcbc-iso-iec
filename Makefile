all: aesMac

mac: aesMac

linux: aesLinux

aesLinux: aes-128-pcbc-iso-iec.o
	gcc -o aes-128-pcbc-iso-iec aes-128-pcbc-iso-iec.o aes.o && rm *.o

aesMac: aes-128-pcbc-iso-iec.o
	gcc -o aes-128-pcbc-iso-iec aes-128-pcbc-iso-iec.o aes.o && rm *.o

aes-128-pcbc-iso-iec.o: aes-128-pcbc-iso-iec.c
	gcc -c -g aes-128-pcbc-iso-iec.c aes.c

clean: 
	rm *.o