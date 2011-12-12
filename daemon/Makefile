all: mount-daemon

ssh.o: ssh.c ssh.h
	gcc -g -c ssh.c

mount-daemon: mount-daemon.c ssh.o
	gcc -g -o mount-daemon ssh.o mount-daemon.c -lssh -lnl -lnl-genl

clean:
	rm *.o mount-daemon
