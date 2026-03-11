@echo off
set IP=pnhsm.dynalias.com
set PORT=8888
set SEN=key7.com
set IDENTITY=Client_identity
REM
set RIDENTITY=Client_identity
set RPSK=0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20
set RPORT=8888
set RSEN=key2.com
set RIP=pnhsm.dynalias.com
REM
tlsse.exe -c -H #?00 -H rimtlsse -H ridentity%RIDENTITY% -H rpsk%RPSK%  -H rS%RSEN%  -H rp%RPORT% -H rh%RIP%  -H identity%IDENTITY%  -h %IP% -p %PORT% -S %SEN%    
PAUSE
