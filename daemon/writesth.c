#include <unistd.h>
#include <fcntl.h>
#include <string.h>

int main(int argc, char** argv) {
	int fd = open(argv[1], O_WRONLY);
	write(fd, argv[2], strlen(argv[2]));
	close(fd);
	return 0;
}
