#include <signal.h>
#include "psvfs_nl_defs.h"
#include "ssh.h"

//#define DEBUG INT32_MAX
#define DEBUG 0

char *user, *host, *mount_path, *ssh_path;
ssh_session my_ssh_session;
int family;
int mounted = -1;
int ires = 0;
void* pres;
void *data = NULL;
struct nl_sock* my_socket;
struct rw_request req;
struct rw_response resp;

void session_close();

struct nla_policy psvfs_genl_policy[PSVFS_A_MAX + 1] = {
  [PSVFS_A_MSG] = { .type = NLA_UNSPEC }, // no policy, just a chunk of bytes
};

void check(int condition, const char* msg, int ires, void* pres) {
	if(!condition) {
		fprintf(stderr, "%s failed with results %i %i\n", msg, ires, (int)pres);
		perror("Fail is");
		session_close();
		exit(1);
	}
}

int receive_from_kernel_cb(struct nl_msg *msg, void *arg) {
	struct nlmsghdr* hdr = nlmsg_hdr(msg);
	struct nlattr* attrs[PSVFS_A_MAX+1];
	void** dest = (void**)arg;
	int len;

	check(hdr != NULL, "nlmsg_hdr", 0, NULL);

	ires = genlmsg_parse(hdr, 0, attrs, PSVFS_A_MAX, psvfs_genl_policy);
	check(ires == 0, "genlmsg_parse", ires, NULL);

	len = nla_len(attrs[PSVFS_A_MSG]);
	if(attrs[PSVFS_A_MSG] != NULL && len > 0) {
		memcpy(*dest, nla_data(attrs[PSVFS_A_MSG]), len);
	}

	return 0;
}

void send_to_kernel(struct nl_sock* sock, int family, int command, void* msg, int len) {
	// 36 was determined by binary search :) no idea how exactly do it
	struct nl_msg *nlmsg = nlmsg_alloc_size(GENL_HDRLEN+nla_total_size(len)+36);
	check(nlmsg != NULL, "alloc", 0, pres);

	pres = genlmsg_put(nlmsg, NL_AUTO_PID, NL_AUTO_SEQ, family, 0, NLM_F_ECHO, command, PSVFS_VERSION);
	check(pres != NULL, "genlmsg_put", 0, pres);

	ires = nla_put(nlmsg, PSVFS_A_MSG, len, msg);
	check(ires == 0, "nla_put", ires, pres);

	// Send message over netlink socket
	ires = nl_send_auto_complete(sock, nlmsg);
	check(ires >= 0, "nl_send", ires, pres);

	nlmsg_free(nlmsg);
}

struct nl_sock* init_nl() {
  struct nl_sock *sock;
  int i, res;

  char buf[65536];
  int buflen;

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
  
  buflen = sftp_list_dir(my_ssh_session, ssh_path, buf);
  
  send_to_kernel(sock, family, PSVFS_C_INIT, buf, buflen);
  data = buf;
  
  ires = nl_recvmsgs_default(sock);
  check(ires == 0, "recvmsgs", ires, NULL);
  
  printf("Kernel says: %s\n", buf);
  
  return sock;
}

void init_ssh(char* user, char* host, char* path) {

  // init 
  my_ssh_session = open_ssh_session(host, user, path);
  printf("Authentication succeeded!\n");
  printf("Connection to %s@%s:%s established\n", user, host, path);
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
  char* fullpath = malloc(strlen(ssh_path)+strlen(req.filename)+2);
  sprintf(fullpath, "%s/%s", ssh_path, req.filename);

  resp.offset = req.offset;
  resp.count = sftp_read_file(my_ssh_session, fullpath, &resp.offset, req.count, (char*) data);

  free(fullpath);
}

void perform_write() {
  char* fullpath = malloc(strlen(ssh_path)+strlen(req.filename)+2);
  sprintf(fullpath, "%s/%s", ssh_path, req.filename);

  resp.offset = req.offset;
  resp.count = sftp_write_file(my_ssh_session, fullpath, &resp.offset, (char*) data, req.count);

  free(fullpath);
}

int mount_vfs() {
  char *mnt_cmd = "mount -t psvfs none";
  char command[512];
  sprintf(command, "%s %s", mnt_cmd, mount_path);
  return system(command);
}


int main(int argc, char** argv) {
  if (argc < 5) {
    printf("Za malo parametrow. Parametry: user host sciezka_zdalna sciezka_do_montowania\n");
    exit(-1);
  }
  
  user = argv[1];
  host = argv[2];
  ssh_path = argv[3];
  mount_path = argv[4];

  // inicjalizacja sesji ssh
  init_ssh(user, host, ssh_path);
  
  // inicjalizacja netlink'a
  my_socket = init_nl();
  
  sleep(1);

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
