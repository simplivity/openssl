#!/bin/sh
#

cd fom
tar -xzvf openssl-fips*.tar.gz
cd openssl-fips*
./config fipscanisteronly --prefix=/tmp/$$/fips
make
make install
cd ../..

./config shared fips --with-fipsdir=/tmp/$$/fips no-idea no-mdc2 no-rc5 no-zlib enable-tlsext no-ssl2 enable-ec_nistp_64_gcc_128
make depend
make clean
make

