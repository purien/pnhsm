#!/bin/bash
wget https://www.openssl.org/source/openssl-1.0.2u.tar.gz
tar xzvf openssl-1.0.2u.tar.gz
cd openssl-1.0.2u
./config
make
rm ./../../src_release7/include/openssl/*.*
cp -L ./include/openssl/* ./../../src_release7/include/openssl
cp ./libssl.a           ./../../src_release7/libmssl.a
cp ./libcrypto.a  ./../../src_release7/libmcrypto.a
cd ..
rm -r  openssl-1.0.2u
rm openssl-1.0.2u.tar.gz






