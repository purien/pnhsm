##!/bin/sh
INCLUDE="-I/usr/include/PCSC -I./include -I."
#
rm *.o
rm winscard
#
gcc -c -O2 -Wall $INCLUDE ./ecc.c     -o  ./ecc.o 
gcc -c -O2 -Wall $INCLUDE ./ecc2.c    -o  ./ecc2.o 
gcc -c -O2 -Wall $INCLUDE ./hmac.c    -o  ./hmac.o 
gcc -c -O2 -Wall $INCLUDE ./filecipher.c    -o  ./filecipher.o 
gcc -c -O2 -Wall $INCLUDE ./imv.c    -o ./imv.o 
gcc -c -O2 -Wall $INCLUDE ./socket.c    -o ./socket.o 
gcc -c -O2 -Wall $INCLUDE ./main.c    -o ./main.o 
gcc -c -O2 -Wall $INCLUDE ./util.c      -o ./util.o 
gcc -c -O2 -Wall $INCLUDE ./parse.c     -o ./parse.o 
gcc -c -O2 -Wall $INCLUDE ./shell.c      -o ./shell.o 
gcc -c -O2 -Wall $INCLUDE ./client.c    -o ./client.o 
gcc -c -O2 -Wall $INCLUDE ./tls.c       -o ./tls.o 
gcc -c -O2 -Wall $INCLUDE ./aead.c      -o  ./aead.o
gcc -c -O2 -Wall $INCLUDE ./serial.c    -o ./serial.o 
gcc -c -O2 -Wall $INCLUDE ./emulator.c  -o ./emulator.o 
gcc -c -O2 -Wall $INCLUDE ./grid.c      -o ./grid.o 
gcc -c -O2 -Wall $INCLUDE ./im.c        -o ./im.o 
#
gcc -o  winscard ./*.o   -lcrypto
rm ./*.o

