REM
@echo off
set IP=pnhsm.dynalias.com 
set PORT=8888
set SEN=key31.com
set IDENTITY=Client_identity
set CONFIG=cardconfig2.txt
REM
winscard2 -c -H  cardconf%CONFIG%  -H im -H aid010203040800 -H pin0000  -H #?00  -h %IP% -p %PORT%  -S %SEN% -H identity%IDENTITY% 
PAUSE
