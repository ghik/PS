#include <signal.h>
#include "psvfs_nl_defs.h"
#include "ssh.h"

ssh_session my_ssh_session;
char *user, *host;
int family;

struct nl_sock* init_nl() {
  struct nl_sock *sock;
  int i, res;

  struct msg_buf buffer;
  char* resp;

  char buf[1000];
  char* ptr = buf;
  int len = 0;

  // Allocate a new netlink socket
  sock = nl_socket_alloc();

  // Connect to generic netlink socket on kernel side
  genl_connect(sock);

  // Ask kernel to resolve family name to family id
  family = genl_ctrl_resolve(sock, PSVFS_FAMILY_NAME);

  /*
  strcpy(ptr, "somefile");
  ptr += strlen(ptr)+1;
  strcpy(ptr, "anotherfile");
  ptr += strlen(ptr)+1;
  strcpy(ptr, "somethingelse");
  ptr += strlen(ptr)+1;

  printf("Len is %i\n", ptr-buf);
  send_to_kernel(sock, family, PSVFS_C_INIT, NL_AUTO_SEQ, buf, ptr-buf);

  resp = receive_from_kernel(sock, &buffer);
  printf("Kernel says: %s\n", resp);
  */
  
  return sock;
}

void init_ssh(char* user, char* host) {

  // init 
  my_ssh_session = open_ssh_session(host, user);
  printf("Authentication succeeded!\n");
  printf("Connection to %s@%s established\n", user, host);
}

void session_close() {
  close_session(my_ssh_session);
  printf("Connection to %s@%s closed\n", user, host);
}

void INThandler(int sig) {
  printf("\nReceived SIGINT - closing..\n");
  session_close();
  exit(0);
}

struct file_op_msg* perform_read(struct file_op_msg* op) {
  char* buffer;
  if (sftp_read_file(my_ssh_session, op->filepath, op->offset, op->size, buffer) == SSH_OK) {
    strncpy(op->msg, buffer, MAX_BUF_SIZE);
    return op;
  }
  else {
    // TODO co gdy blad?
  }
}

struct file_op_msg* perform_write(struct file_op_msg* op) {
  if (sftp_write_file(my_ssh_session, op->filepath, op->offset, op->msg) == SSH_OK) {
    // TODO co return?
  }
  else {
    // TODO co gdy blad?
  }
}



int main(int argc, char** argv) {
  if (argc < 3) {
    printf("Za malo parametrow. Parametry: user host\n");
    exit(-1);
  }
  
  user = argv[1];
  host = argv[2];
  
  // inicjalizacja netlink'a
  struct nl_sock* socket = init_nl();
  
  // inicjalizacja sesji ssh
  init_ssh(user, host);

  // obsluge przerwania - zamyka sesje w razie przerwania
  signal(SIGINT, INThandler);
    
  struct msg_buf buffer;
  char buf[1000];
  struct file_op_msg* resp;
  struct file_op_msg* answer;

  // petla: receive i interpretacja komand
  while(1) {
    resp = (struct file_op_msg*) receive_from_kernel(socket, &buffer);
    if (resp->op == 0) {
      // read
      answer = perform_read(resp);
    }
    else {
      // write
      answer = perform_write(resp);
    }
    send_to_kernel(socket, family, PSVFS_C_INIT, NL_AUTO_SEQ, (char *) answer, sizeof(*answer));
  }

  // zamkniecie sesji
  session_close();
  return 0;
}
