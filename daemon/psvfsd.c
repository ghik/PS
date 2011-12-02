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

int main(int argc, char** argv) {
	struct nl_sock *sock;
	struct nl_msg *msg;
	int family;

	// Allocate a new netlink socket
	sock = nl_socket_alloc();

	// Connect to generic netlink socket on kernel side
	genl_connect(sock);

	// Ask kernel to resolve family name to family id
	family = genl_ctrl_resolve(sock, PSVFS_FAMILY_NAME);

	// Construct a generic netlink by allocating a new message, fill in
	// the header and append a simple integer attribute.
	msg = nlmsg_alloc();
	genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, family, 0, NLM_F_ECHO,
			PSVFS_C_INIT, PSVFS_VERSION);
	nla_put_string(msg, PSVFS_A_MSG, "Stuff happens.");

	// Send message over netlink socket
	nl_send_auto_complete(sock, msg);

	// Free message
	nlmsg_free(msg);

	return 0;
}
