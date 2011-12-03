/*
 * psvfsd.c
 *
 *  Created on: 02-12-2011
 *      Author: ghik
 */

#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>

#include "psvfs_nl_defs.h"

struct msg_buf {
	struct nlmsghdr n;
	struct genlmsghdr g;
	char buf[MAX_MSG_SIZE];
};

void send_to_kernel(struct nl_sock* sock, int family, int command, int seq, const char* msg) {
	// Construct a generic netlink by allocating a new message, fill in
	// the header and append a simple integer attribute.
	struct nl_msg *nlmsg = nlmsg_alloc();

	genlmsg_put(nlmsg, NL_AUTO_PID, seq, family, 0, NLM_F_ECHO,
			command, PSVFS_VERSION);
	nla_put_string(nlmsg, PSVFS_A_MSG, msg);

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

int main(int argc, char** argv) {
	struct nl_sock *sock;
	int family, res;

	struct msg_buf buffer;
	char* resp;

	// Allocate a new netlink socket
	sock = nl_socket_alloc();

	// Connect to generic netlink socket on kernel side
	genl_connect(sock);

	// Ask kernel to resolve family name to family id
	family = genl_ctrl_resolve(sock, PSVFS_FAMILY_NAME);

	send_to_kernel(sock, family, PSVFS_C_INIT, NL_AUTO_SEQ, "stuff here");

	resp = receive_from_kernel(sock, &buffer);
	printf("Kernel says: %s\n", resp);

	return 0;
}
