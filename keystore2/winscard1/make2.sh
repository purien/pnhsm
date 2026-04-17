##!/bin/sh
##!/bin/sh
INCLUDE="-I/usr/include/PCSC -I./include -I."
#
rm *.o
rm lwinscard
rm libwinscard.so.1.1
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
#
gcc -shared -o libwinscard.so.1.10 -Wl,-soname,libfoo.so.10  ./*.o   -lcrypto
#
rm ./*.o
cp      ./libwinscard.so.1.10  ./../src_release7/libwinscard.so.1.10.a
sudo cp ./libwinscard.so.1.10   /lib/libfoo.so.10




