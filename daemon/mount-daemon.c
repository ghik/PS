#include <signal.h>
#include "psvfs_nl_defs.h"
#include "ssh.h"

//#define DEBUG INT32_MAX
#define DEBUG 0

char *user, *host, *mount_path;
ssh_session my_ssh_session;
int family;
int mounted = -1;
int ires = 0;
void* pres;
void *data = NULL;
struct nl_sock* my_socket;
struct rw_request req;
struct rw_response resp;

struct nl_sock* init_nl() {
  struct nl_sock *sock;
  int i, res;

  char buf[4096];
  char* ptr = buf;

  nl_debug = DEBUG;

  // Allocate a new netlink socket
  sock = nl_socket_alloc();
  check(sock != NULL, "sock_alloc", 0, pres);

  nl_socket_disable_auto_ack(sock);
  nl_socket_disable_seq_check(sock);

  // Connect to generic netlink socket on kernel side
  ires = genl_connect(sock);
  check(ires == 0, "connect", ires, pres);

  // Ask kernel to resolve family name to family id
  family = genl_ctrl_resolve(sock, PSVFS_FAMILY_NAME);
  check(family != 0, "resolve", family, pres);

  ires = nl_socket_modify_cb(sock, NL_CB_VALID, NL_CB_CUSTOM, receive_from_kernel_cb, (void*)&data);
  check(ires == 0, "modify_cb", ires, pres);
  
  strcpy(ptr, "somefile");
  ptr += strlen(ptr)+1;
  strcpy(ptr, "anotherfile");
  ptr += strlen(ptr)+1;
  strcpy(ptr, "somethingelse");
  ptr += strlen(ptr)+1;
  
  printf("Len is %i\n", ptr-buf);
  
  send_to_kernel(sock, family, PSVFS_C_INIT, buf, ptr-buf);
  data = buf;
  
  ires = nl_recvmsgs_default(sock);
  check(ires == 0, "recvmsgs");
  
  printf("Kernel says: %s\n", buf);
  
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
  if(mounted == 0) {
    char command[512];
    sprintf(command, "umount %s", mount_path);
    system(command);
  }
  send_to_kernel(my_socket, family, PSVFS_C_DESTROY, NULL, 0);
}

void INThandler(int sig) {
  printf("\nReceived SIGINT - closing..\n");
  session_close();
  exit(0);
}

void perform_read() {
  resp.count = sftp_read_file(my_ssh_session, req.filename, req.offset, req.count, (char*) data);
  resp.offset = resp.count + req.offset;
}

void perform_write() {
  sftp_write_file(my_ssh_session, req.filename, req.offset, (char*) data);
  resp.count = req.count;
  resp.offset = req.offset + resp.count;
}

int mount_vfs() {
  char *mnt_cmd = "mount -t psvfs none";
  char command[512];
  sprintf(command, "%s %s", mnt_cmd, mount_path);
  return system(command);
}


int main(int argc, char** argv) {
  if (argc < 4) {
    printf("Za malo parametrow. Parametry: user host sciezka_do_montowania\n");
    exit(-1);
  }
  
  user = argv[1];
  host = argv[2];
  mount_path = argv[3];

  // inicjalizacja sesji ssh
  init_ssh(user, host);
  
  // inicjalizacja netlink'a
  my_socket = init_nl();
  
  // zamontuj
  mounted = mount_vfs();
  
  // obsluge przerwania - zamyka sesje w razie przerwania
  signal(SIGINT, INThandler);    

  // petla: receive i interpretacja komand
  while(1) {
    data = &req;
    ires = nl_recvmsgs_default(my_socket);
    check(ires == 0, "nl_recvmsgs_default1", ires, pres);

    resp.operation = req.operation;

    switch(req.operation) {
    case PSVFS_OP_READ:
      printf("Read %i bytes from offset %lli from file %s\n", req.count, req.offset, req.filename);

      data = malloc(req.count);

      perform_read();

      send_to_kernel(my_socket, family, PSVFS_C_RESPONSE, &resp, sizeof(resp));
      if(resp.count > 0) {
	send_to_kernel(my_socket, family, PSVFS_C_DATA, (void*)data, resp.count);
      }

      free((void*)data);

      break;
    case PSVFS_OP_WRITE:
      printf("Write %i bytes at offset %lli to file %s\n", req.count, req.offset, req.filename);

      data = malloc(req.count);
      ires = nl_recvmsgs_default(my_socket);
      check(ires == 0, "nl_recvmsgs_default2", ires, pres);      

      perform_write();
      
      printf("Write response: %i %lli\n", resp.count, resp.offset);

      send_to_kernel(my_socket, family, PSVFS_C_RESPONSE, &resp, sizeof(resp));

      free((void*)data);

      break;
    }
  }

  // zamkniecie sesji
  session_close();
  return 0;
}
