#ifndef SSH_H_
#define SSH_H_

int verify_knownhost(ssh_session session);
ssh_session open_ssh_session(char* host, char* user);
void close_session(ssh_session session);
int sftp_read_file(ssh_session session, char* filepath, int offset, int size);
int sftp_read_sync(ssh_session session, sftp_session sftp, char* filepath, int offset, int size);
int sftp_write_file(ssh_session session, char* filepath, int offset, char* msg);
int sftp_write_sync(ssh_session session, sftp_session sftp, char* filepath, int offset, char* msg);

#endif // SSH_H_
