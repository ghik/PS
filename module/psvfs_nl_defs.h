#ifndef PSVFS_NL_DEFS_H_
#define PSVFS_NL_DEFS_H_

/*
 * psvfs_nl_defs.h
 *
 *  Created on: 02-12-2011
 *      Author: ghik
 */

#ifdef __KERNEL__
#include <net/genetlink.h>
#else
#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
int receive_from_kernel_cb(struct nl_msg *msg, void *arg);
#endif

#define MAX_PATH_SIZE 256

/* Tutaj właściwie tylko PSVFS_A_MSG ma znaczenie - jest to oznaczenie atrybutu
 * (czyli kawałka danych wchodzącego w skład wiadomości), który
 * będzie trzymał stringa z wiadomością do/od kernela.
 */
enum {
	PSVFS_A_UNSPEC,
	PSVFS_A_MSG,
    __PSVFS_A_MAX,
};
#define PSVFS_A_MAX (__PSVFS_A_MAX - 1)

/*
 * Komendy. Każda z nich odpowiada osobnemu callbackowi po stronie kernela.
 */
enum {
	PSVFS_C_UNSPEC,
	PSVFS_C_INIT, // init filesystem (result of SSH/SCP login)
	PSVFS_C_DESTROY, // destroy filesystem (result of SSH/SCP logout)
	PSVFS_C_REQUEST, // filesystem operation request
	PSVFS_C_RESPONSE, // filesystem operation response
	PSVFS_C_DATA, // filesystem operation data
	__PSVFS_C_MAX,
};
#define PSVFS_C_MAX (__PSVFS_C_MAX - 1)

#define PSVFS_VERSION 1
#define PSVFS_FAMILY_NAME "PSVFS_FAMILY"

enum {
	PSVFS_OP_OPEN,
	PSVFS_OP_READ,
	PSVFS_OP_WRITE
};

struct rw_request {
	int operation; // PSVFS_OP_*
	size_t count;
	loff_t offset;
	char filename[MAX_PATH_SIZE];
};

struct rw_response {
	int operation; // PSVFS_OP_*, must be the same as for corresponding request
	size_t count;
	loff_t offset;
};

#endif /* PSVFS_NL_DEFS_H_ */
