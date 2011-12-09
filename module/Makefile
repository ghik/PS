obj-m := psvfs.o

all:
	make -C /usr/src/linux-headers-`uname -r` M=`pwd` modules

reload:
	rmmod psvfs; insmod psvfs.ko

clean:
	rm *.o *.ko Module.symvers modules.order .psvfs.ko.cmd .psvfs.mod.o.cmd .psvfs.o.cmd psvfs.mod.c
