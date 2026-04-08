CONFIG=##!/bin/sh
#
IP=pnhsm.dynalias.com 
PORT=8888
SEN=key31.com
IDENTITY=Client_identity
CONFIG=cardconfig2.txt
#
./winscard2 -c -H  cardconf$CONFIG  -H im -H aid010203040800 -H pin0000  -H *?00  -h $IP -p $PORT  -S $SEN -H identity$IDENTITY
