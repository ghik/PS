obj-m := psvfs.o

all:
	make -C /usr/src/linux-headers-`uname -r` M=`pwd` modules

reload:
	rmmod psvfs; insmod psvfs.ko
