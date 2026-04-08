REM
@echo off
set IP=pnhsm.dynalias.com 
set PORT=8888
set SEN=key31.com
set IDENTITY=Client_identity
REM
winscard2 -c  -H im -H aid010203040500 -H pin0000 -H #?00 -h %IP% -p %PORT%  -S %SEN% -H  identity%IDENTITY%
PAUSE
