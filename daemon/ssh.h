#ifndef _SSH_H_
#define _SSH_H_

#include <libssh/libssh.h>
#include <libssh/sftp.h>

ssh_session open_ssh_session(char* host, char* user);
void close_session(ssh_session session);
int sftp_read_file(ssh_session session, char* filepath, int offset, int size);
int sftp_write_file(ssh_session session, char* filepath, int offset, char* msg);

#endif // _SSH_H_
