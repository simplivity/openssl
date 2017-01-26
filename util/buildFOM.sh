#!/bin/sh
#
# Usage:
#   util/buildFom.sh [Shared|Static] [Debug|RelWithDebInfo]
#

echo "buildFOM..."
echo ${1}
echo ${2}

DEB_HOST_MULTIARCH=`dpkg-architecture -qDEB_HOST_MULTIARCH`

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

./config shared fips --with-fipsdir=/tmp/$$/fips no-idea no-mdc2 no-rc5 no-zlib enable-tlsext no-ssl2 enable-ec_nistp_64_gcc_128 --prefix=/usr --openssldir=/usr/lib/ssl --libdir=lib/${DEB_HOST_MULTIARCH} --enginesdir=/usr/lib/${DEB_HOST_MULTIARCH}/openssl-1.0.0/engines ${DEBUG}
make depend
make clean
make
make test
make INSTALL_PREFIX=$PWD/build/${1}/${2} install_sw

