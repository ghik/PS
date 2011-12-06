/*
 * psvfsd.c
 *
 *  Created on: 02-12-2011
 *      Author: ghik
 */

#include "psvfs_nl_defs.h"

struct nla_policy psvfs_genl_policy[PSVFS_A_MAX + 1] = {
  [PSVFS_A_DATA] = { .type = NLA_UNSPEC },
  [PSVFS_A_MSG] = { .type = NLA_STRING },
};

void send_to_kernel(struct nl_sock* sock, int family, int command, int seq, const char* msg, int len) {
	// Construct a generic netlink by allocating a new message, fill in
	// the header and append a simple integer attribute.
	struct nl_msg *nlmsg = nlmsg_alloc();

	genlmsg_put(nlmsg, NL_AUTO_PID, seq, family, 0, NLM_F_ECHO, command, PSVFS_VERSION);
	nla_put(nlmsg, PSVFS_A_MSG, len, msg);

	// Send message over netlink socket
	nl_send_auto_complete(sock, nlmsg);

	// Free message
	nlmsg_free(nlmsg);
}

char* receive_from_kernel(struct nl_sock* sock, struct msg_buf* buf) {
	struct nlattr* na;

	int rep_len = recv(nl_socket_get_fd(sock), buf, sizeof(struct msg_buf), 0);
	/* Validate response message */
	if (buf->n.nlmsg_type == NLMSG_ERROR) { /* error */
		printf("error received NACK - leaving \n");
		return NULL;
	}
	if (rep_len < 0) {
		printf("error receiving reply message via Netlink \n");
		return NULL;
	}
	if (!NLMSG_OK((&buf->n), rep_len)) {
		printf("invalid reply message received via Netlink\n");
		return NULL;
	}

	rep_len = GENLMSG_PAYLOAD(&buf->n);

	na = (struct nlattr *) GENLMSG_DATA(buf);
	return (char *) NLA_DATA(na);
}

/*
int main(int argc, char** argv) {
	struct nl_sock *sock;
	int i, family, res;

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

	strcpy(ptr, "somefile");
	ptr += strlen(ptr)+1;
	strcpy(ptr, "anotherfile");
	ptr += strlen(ptr)+1;
	strcpy(ptr, "somethingelse");
	ptr += strlen(ptr)+1;

	printf("Len is %li\n", ptr-buf);
	send_to_kernel(sock, family, PSVFS_C_INIT, NL_AUTO_SEQ, buf, ptr-buf);

	resp = receive_from_kernel(sock, &buffer);
	printf("Kernel says: %s\n", resp);

	while(1) {
		resp = receive_from_kernel(sock, &buffer);
	}

	return 0;
}
*/
