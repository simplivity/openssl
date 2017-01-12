#!/bin/sh
#
# Usage:
#   util/buildFom.sh [Shared|Static] [Debug|RelWithDebInfo]
#

echo "buildFOM..."
echo ${1}
echo ${2}

if [ "${2}" = "Debug" ]; then
	echo "Debug build requested"
	DEBUG=" -d"
fi

cd fom
tar -xzvf openssl-fips*.tar.gz
cd openssl-fips*
./config fipscanisteronly --prefix=/tmp/$$/fips
make
make install
cd ../..

./config shared fips --with-fipsdir=/tmp/$$/fips no-idea no-mdc2 no-rc5 no-zlib enable-tlsext no-ssl2 enable-ec_nistp_64_gcc_128 --prefix=$PWD/build/${1}/${2} ${DEBUG}
make depend
make clean
make

