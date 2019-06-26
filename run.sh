#!/usr/bin/bash

PWD=`pwd`

OPENSSL_DIR="${PWD}/../openssl/output"
OPENSSL_INCLUDE="${OPENSSL_DIR}/include"
OPENSSL_LIB="${OPENSSL_DIR}/lib"
export PATH="${OPENSSL_DIR}/bin":${PATH}

export LD_INCLUDE_PATH=${OPENSSL_INCLUDE}:${LD_INCLUDE_PATH}
export LD_LIBRARY_PATH=${OPENSSL_LIB}:${LD_LIBRARY_PATH}

rm -rf *.o *.so

gcc -fPIC -o cxdma.o -c xdma/cxdma.c
gcc -fPIC -o packet.o -c xdma/packet.c
gcc -fPIC -I ${OPENSSL_INCLUDE} -L ${OPENSSL_LIB} -o cryptEngine.o -c cryptEngine.c
gcc -shared -o libcryptHdl.so -lcrypto cryptEngine.o cxdma.o packet.o #cryptoSha256.o

### Install ###
cp ./libcryptHdl.so ${OPENSSL_LIB}/engines/libcryptHdl.so

### Test ###
#openssl engine dynamic -pre SO_PATH:${OPENSSL_LIB}/engines/libcryptHdl.so -pre ID:cryptHdl -pre LOAD
echo "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" | openssl dgst -sha256
echo "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" | openssl dgst -engine cryptHdl -sha256
