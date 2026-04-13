@echo off
REM
set IP=pnhsm.dynalias.com
set PORT=8888
set SEN=key31.com
set guestID=guest
REM
set CAPub=046099836D971593AAA2C1C32B6DB9EF9521041795E21CF1E7511DF3BD358F97DF358B33A875E359CBE236163D6DBAEDFEC6C9393522C7EBC25A7CC85E1F0A7D67
REM
set KEY=02
set META=metadata
set FILE=afile.txt
REM
set RIP=pnhsm.dynalias.com
set RPORT=8888
set RSEN=key32.com
set RCOM=15
set guestID2=guest2
REM
tlsse -c  -H rimtlsse -H rhw101 -H com%RCOM% -H rpin0000 -H rh%RIP% -H rp%RPORT% -H rS%RSEN% -H ridentity%guestID2%  -H rlTLS13-AES128-CCM-SHA256 -H fkey%KEY% -H meta%META% -H Enc%FILE%  -H fkey%KEY% -H Dec%FILE%.bin  -H identity%guestID% -S %SEN% -p %PORT% -h  %IP%  -l TLS13-AES128-CCM-SHA256
PAUSE