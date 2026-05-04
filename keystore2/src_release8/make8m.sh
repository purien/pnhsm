#!/bin/sh
INCLUDE="-I/usr/include/PCSC -I./include -I. -I./winscard1"
# in i2cmod.h uncomment #define NOI2C
# !!! in pcscemulator137.h  UNCOMMENT #define NOFAKE ...FOR NO USE OF PCSC 
rm *.o
rm racs8
rm racs8m
#
gcc -c -O2 -Wall $INCLUDE ./main.c         -o  ./main.o 
gcc -c -O2 -Wall $INCLUDE ./reentrant2.c   -o ./reentrant2.o 
gcc -c -O2 -Wall $INCLUDE ./common2.c      -o ./common2.o
gcc -c -O2 -Wall $INCLUDE ./pcsc.c         -o ./pcsc.o   
gcc -c -O2 -Wall $INCLUDE ./atr.c          -o ./atr.o    
gcc -c -O2 -Wall $INCLUDE ./pcscemulator.c -o ./pcscemulator.o 
gcc -c -O2 -Wall $INCLUDE ./grid137.c      -o ./grid137.o      
gcc -c -O2 -Wall $INCLUDE ./serverk.c      -o ./serverk.o   
gcc -c -O2 -Wall $INCLUDE ./server6.c      -o ./server6.o   
gcc -c -O2 -Wall $INCLUDE ./windowglue.c   -o ./windowglue.o 
gcc -c -O2 -Wall $INCLUDE ./i2c.c          -o ./i2c.o       
gcc -c -O2 -Wall $INCLUDE ./i2cmod.c       -o ./i2cmod.o    
#
gcc -c -O2 -Wall $INCLUDE ./winscard1/ecc.c         -o  ./ecc.o 
gcc -c -O2 -Wall $INCLUDE ./winscard1/ecc2.c        -o  ./ecc2.o 
gcc -c -O2 -Wall $INCLUDE ./winscard1/hmac.c        -o  ./hmac.o 
gcc -c -O2 -Wall $INCLUDE ./winscard1/filecipher.c  -o  ./filecipher.o 
gcc -c -O2 -Wall $INCLUDE ./winscard1/imv.c         -o ./imv.o 
gcc -c -O2 -Wall $INCLUDE ./winscard1/socket.c      -o ./socket.o 
gcc -c -O2 -Wall $INCLUDE ./winscard1/util.c        -o ./util.o 
gcc -c -O2 -Wall $INCLUDE ./winscard1/parse.c       -o ./parse.o 
gcc -c -O2 -Wall $INCLUDE ./winscard1/shell.c       -o ./shell.o 
gcc -c -O2 -Wall $INCLUDE ./winscard1/client.c      -o ./client.o 
gcc -c -O2 -Wall $INCLUDE ./winscard1/tls.c         -o ./tls.o 
gcc -c -O2 -Wall $INCLUDE ./winscard1/aead.c        -o  ./aead.o
gcc -c -O2 -Wall $INCLUDE ./winscard1/serial.c      -o ./serial.o 
gcc -c -O2 -Wall $INCLUDE ./winscard1/emulator.c    -o ./emulator.o 
gcc -c -O2 -Wall $INCLUDE ./winscard1/grid.c        -o ./grid.o 
gcc -c -O2 -Wall $INCLUDE ./winscard1/im.c          -o ./im.o 
#
gcc -o racs8m ./main.o ./ecc.o ./ecc2.o ./hmac.o ./filecipher.o ./imv.o ./socket.o ./util.o ./parse.o ./shell.o ./client.o ./tls.o ./aead.o ./serial.o ./emulator.o ./grid.o ./im.o ./pcsc.o ./atr.o ./pcscemulator.o ./grid137.o ./serverk.o ./windowglue.o  ./common2.o  ./reentrant2.o ./server6.o ./i2c.o ./i2cmod.o -lpthread -L. -lmssl -lmcrypto -ldl 
cp  ./racs8m  ./../racs8m
rm  ./*.o

