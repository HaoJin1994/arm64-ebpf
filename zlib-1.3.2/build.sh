CROSS=aarch64-linux-gnu-
CC=${CROSS}gcc \
AR=${CROSS}ar \
RANLIB=${CROSS}ranlib \
./configure --prefix=$PWD/release

make 
make install

