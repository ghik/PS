obj-m := vfs_module.o gnKernel.o psvfs.o

all:
	make -C /usr/src/linux-headers-`uname -r` M=`pwd` modules

