##!/bin/sh
#
IP=pnhsm.dynalias.com 
PORT=8888
SEN=key31.com
IDENTITY=Client_identity
#
./winscard2 -c  -H im -H aid010203040500 -H pin0000 -H *?00 -h $IP -p $PORT  -S $SEN -H identity$IDENTITY
