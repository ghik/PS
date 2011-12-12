#ifndef _SSH_H_
#define _SSH_H_

#include <libssh/libssh.h>
#include <libssh/sftp.h>
#include <sys/types.h>

ssh_session open_ssh_session(char* host, char* user, char* path);
void close_session(ssh_session session);
int sftp_read_file(ssh_session session, char* filepath, loff_t* offset, int size, char* buffer);
int sftp_write_file(ssh_session session, char* filepath, loff_t* offset, char* msg, int size);

#endif // _SSH_H_
