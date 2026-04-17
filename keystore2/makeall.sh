#!/bin/bash
cd ./openssl
./make.sh
cd ..
cd ./winscard1
./make2.sh
cd ..
cd ./src_release7
./makeubuntu.sh
./makeubuntuf.sh
cd ..




