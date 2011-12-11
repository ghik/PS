all: mount-daemon

psvfsd.o: psvfsd.c psvfs_nl_defs.h
	gcc -c psvfsd.c

ssh.o: ssh.c ssh.h
	gcc -c ssh.c

mount-daemon: mount-daemon.c ssh.o psvfsd.o
	gcc -o mount-daemon ssh.o psvfsd.o mount-daemon.c -lssh -lnl -lnl-genl

clean:
	rm *.o mount-daemon
