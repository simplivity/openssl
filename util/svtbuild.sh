#!/bin/sh
#
# Usage:
#   util/svtbuild.sh [Debug|Release]
#
# Linux builds create both shared and static libraries from
# a single execution so we select just Debug/Release options.
#

echo "SVT Build..."
echo ${1}

INSTALL_BASE=${BUILD_DIR:-${PWD}}
FOMDIR=${INSTALL_BASE}/${1}/fips-install
SSLDIR=${INSTALL_BASE}/${1}/openssl-install

DEB_HOST_MULTIARCH=`dpkg-architecture -qDEB_HOST_MULTIARCH`

if [ "${1}" = "Debug" ]; then
    echo "Debug build requested"
    DEBUG=" -d"
fi

# If we ever get a FIPS module for 1.1, this is where we would add it
#cd fom
#tar -xzvf openssl-fips*.tar.gz
#cd openssl-fips*
#./config fipscanisteronly --prefix=$FOMDIR
#make clean
#make
#make install
#cd ../..

#./config fips shared --with-fipsdir=$FOMDIR no-idea no-mdc2 no-rc5 no-zlib enable-tlsext no-ssl2 enable-ec_nistp_64_gcc_128 --prefix=/usr --openssldir=/usr/lib/ssl --libdir=lib/${DEB_HOST_MULTIARCH} --enginesdir=/usr/lib/${DEB_HOST_MULTIARCH}/openssl-1.0.0/engines ${DEBUG}

HASHBANGPERL=/usr/bin/perl ./config shared \
               --prefix=/usr \
               --openssldir=/usr/lib/ssl \
               --libdir=lib/${DEB_HOST_MULTIARCH} \
               no-idea no-mdc2 no-rc5 no-zlib no-ssl3 enable-unit-test no-ssl3-method enable-rfc3779 enable-cms ${DEBUG}

make depend
make clean
make
make test
make INSTALL_PREFIX=$SSLDIR DESTDIR=${SSLDIR} install_sw install_docs
