#!/bin/bash
v=3.0.20
wget https://www.openssl.org/source/openssl-$v.tar.gz
tar xzvf openssl-$v.tar.gz
cd openssl-$v
./config
make
rm                         ./../../src_release8/include/openssl/*.*
cp -L ./include/openssl/*  ./../../src_release8/include/openssl
cp ./libssl.a              ./../../src_release8/libmssl.a
cp ./libcrypto.a           ./../../src_release8/libmcrypto.a
cd ..
# rm -r  openssl-$v
# rm openssl-$v.tar.gz
