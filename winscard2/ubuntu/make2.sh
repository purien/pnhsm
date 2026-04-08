##!/bin/sh
##!/bin/sh
INCLUDE="-I/usr/include/PCSC -I./include -I."
#
rm *.o
rm  libwinscard.so.1.1
#
gcc -c -fPIC -O2 -Wall $INCLUDE ./ecc.c     -o  ./ecc.o 
gcc -c -fPIC -O2 -Wall $INCLUDE ./ecc2.c    -o  ./ecc2.o 
gcc -c -fPIC -O2 -Wall $INCLUDE ./hmac.c    -o  ./hmac.o 
gcc -c -fPIC -O2 -Wall $INCLUDE ./filecipher.c    -o  ./filecipher.o 
gcc -c -fPIC -O2 -Wall $INCLUDE ./imv.c    -o ./imv.o 
gcc -c -fPIC -O2 -Wall $INCLUDE ./socket.c    -o ./socket.o 
#gcc -c -fPIC -O2 -Wall $INCLUDE ./main.c    -o ./main.o 
gcc -c -fPIC -O2 -Wall $INCLUDE ./util.c      -o ./util.o 
gcc -c -fPIC -O2 -Wall $INCLUDE ./parse.c     -o ./parse.o 
gcc -c -fPIC -O2 -Wall $INCLUDE ./shell.c      -o ./shell.o 
gcc -c -fPIC -O2 -Wall $INCLUDE ./client.c    -o ./client.o 
gcc -c -fPIC -O2 -Wall $INCLUDE ./tls.c       -o ./tls.o 
gcc -c -fPIC -O2 -Wall $INCLUDE ./aead.c      -o  ./aead.o
gcc -c -fPIC -O2 -Wall $INCLUDE ./serial.c    -o ./serial.o 
gcc -c -fPIC -O2 -Wall $INCLUDE ./emulator.c  -o ./emulator.o 
gcc -c -fPIC -O2 -Wall $INCLUDE ./grid.c      -o ./grid.o 
gcc -c -fPIC -O2 -Wall $INCLUDE ./im.c        -o ./im.o 
gcc -c -fPIC -O2 -Wall $INCLUDE ./client3.c   -o ./client3.o 
gcc -c -fPIC -O2 -Wall $INCLUDE ./common2.c   -o ./common2.o 
gcc -c -fPIC -O2 -Wall $INCLUDE ./reentrant.c -o ./reentrant.o 
#
gcc -shared -o libwinscard.so.1.1 -Wl,-soname,libfoo.so.1  ./*.o  -lpthread -lssl -lcrypto -ldl
rm *.o
#