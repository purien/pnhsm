##!/bin/sh
#
openssl s_server -debug -tlsextdebug -msg  -nocert -num_tickets 0  -no_ticket  -cipher DHE -ciphersuites  TLS_AES_128_CCM_SHA256   -groups P-256   -accept 8888 -tls1_3  -psk  0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20
 

