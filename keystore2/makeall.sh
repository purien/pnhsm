#!/bin/bash
cd ./openssl
./make.sh
cd ..
cd ./winscard1
./make2.sh
cd ..
cd ./src_release8
# use PCSC library
# ./make8.sh
# no PCSC
./make8m.sh
cd ..




