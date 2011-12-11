/*
 * psvfsd.c
 *
 *  Created on: 02-12-2011
 *      Author: ghik
 */

#include <stdlib.h>
#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>

#include "psvfs_nl_defs.h"

int ires = 0;
void* pres = NULL;

void check(int condition, const char* msg) {
	if(!condition) {
		fprintf(stderr, "%s failed with results %i %i\n", msg, ires, (int)pres);
		perror("Fail is");
		exit(1);
	}
}

struct msg_buf {
	struct nlmsghdr n;
	struct genlmsghdr g;
	char buf[sizeof(struct rw_request)];
};

int receive_from_kernel_cb(struct nl_msg *msg, void *dest) {
	struct nlmsghdr* hdr = nlmsg_hdr(msg);
	struct nlattr* attrs[PSVFS_A_MAX+1];

	printf("Callback\n");
	check(hdr != NULL, "nlmsg_hdr");

	ires = genlmsg_parse(hdr, 0, attrs, PSVFS_A_MAX, psvfs_genl_policy);
	check(ires == 0, "genlmsg_parse");

	if(attrs[PSVFS_A_MSG] != NULL) {
		memcpy(dest, nla_data(attrs[PSVFS_A_MSG]), nla_len(attrs[PSVFS_A_MSG]));
	}

	return 0;
}

void send_to_kernel(struct nl_sock* sock, int family, int command, void* msg, int len) {
	// 36 was determined by binary search :) no idea how exactly do it
	struct nl_msg *nlmsg = nlmsg_alloc_size(GENL_HDRLEN+nla_total_size(len)+36);
	check(nlmsg != NULL, "alloc");

	pres = genlmsg_put(nlmsg, NL_AUTO_PID, NL_AUTO_SEQ, family, 0, NLM_F_ECHO, command, PSVFS_VERSION);
	check(pres != NULL, "genlmsg_put");

	ires = nla_put(nlmsg, PSVFS_A_MSG, len, msg);
	check(ires == 0, "nla_put");

	// Send message over netlink socket
	ires = nl_send_auto_complete(sock, nlmsg);
	check(ires >= 0, "nl_send");

	nlmsg_free(nlmsg);

	printf("All sent.\n");
}

void* receive_from_kernel(struct nl_sock* sock, struct msg_buf* buf) {
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
	return NLA_DATA(na);
}

int main(int argc, char** argv) {
	struct nl_sock *sock;
	int family, res;

	struct msg_buf msgbuf;
	struct rw_request req = { .filename = "lol, srsly, wtf dude?" };
	struct rw_response resp;

	char buf[sizeof(struct rw_request)];
	char* ptr = buf;

	const char* data = NULL;
	FILE* f = fopen("afile", "r+");

	nl_debug = INT32_MAX;

	// Allocate a new netlink socket
	sock = nl_socket_alloc();
	check(sock != NULL, "sock_alloc");

	nl_socket_disable_auto_ack(sock);
	nl_socket_disable_seq_check(sock);

	// Connect to generic netlink socket on kernel side
	ires = genl_connect(sock);
	check(ires == 0, "connect");

	// Ask kernel to resolve family name to family id
	family = genl_ctrl_resolve(sock, PSVFS_FAMILY_NAME);
	check(family != 0, "resolve");

	ires = nl_socket_modify_cb(sock, NL_CB_VALID, NL_CB_CUSTOM, receive_from_kernel_cb, buf);
	check(ires == 0, "modify_cb");

	strcpy(ptr, "somefile");
	ptr += strlen(ptr)+1;
	strcpy(ptr, "anotherfile");
	ptr += strlen(ptr)+1;
	strcpy(ptr, "somethingelse");
	ptr += strlen(ptr)+1;

	printf("Len is %i\n", ptr-buf);
	send_to_kernel(sock, family, PSVFS_C_INIT, buf, ptr-buf);

	ires = nl_recvmsgs_default(sock);
	check(ires == 0, "recvmsgs");

	printf("Kernel says: %s\n", buf);

	ires = nl_socket_modify_cb(sock, NL_CB_VALID, NL_CB_CUSTOM, receive_from_kernel_cb, (void*)&req);
	check(ires == 0, "modify_cb");

	while(1) {
		ires = nl_recvmsgs_default(sock);
		check(ires == 0, "nl_recvmsgs_default");

		resp.operation = req.operation;

		switch(req.operation) {
		case PSVFS_OP_READ:
			printf("Read %i bytes from offset %lli from file %s\n", req.count, req.offset, req.filename);

			data = malloc(req.count);
			fseek(f, req.offset, SEEK_SET);
			resp.count = fread((void*)data, sizeof(unsigned char), req.count, f);
			resp.offset = ftell(f);

			send_to_kernel(sock, family, PSVFS_C_RESPONSE, &resp, sizeof(resp));
			send_to_kernel(sock, family, PSVFS_C_DATA, (void*)data, resp.count);

			free((void*)data);

			break;
		case PSVFS_OP_WRITE:

			break;
		}
	}

	fclose(f);

	return 0;
}
