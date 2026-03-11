##!/bin/sh
#
IP=pnhsm.dynalias.com
PORT=8888
SEN=key7.com
IDENTITY=Client_identity
RIDENTITY=Client_identity
RPSK=0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20
RPORT=8888
RSEN=key2.com
RIP=pnhsm.dynalias.com
#
./tlsse -c -H *?00 -H rimtlsse -H ridentity$RIDENTITY -H rpsk$RPSK  -H rS$RSEN  -H rp$RPORT -H rh$RIP  -H identity$IDENTITY  -h $IP -p $PORT -S $SEN    
