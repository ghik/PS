all: mount-daemon

psvfsd.o: psvfsd.c psvfs_nl_defs.h
	gcc -c psvfsd.c

ssh.o: ssh.c ssh.h
	gcc -c ssh.c

mount-daemon: psvfsd.o ssh.o mount-daemon.c
	gcc -o mount-daemon psvfsd.o ssh.o mount-daemon.c -lssh -lnl -lnl-genl

clean:
	rm *.o mount-daemon
