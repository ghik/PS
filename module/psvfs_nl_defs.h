/*
 * psvfs_nl_defs.h
 *
 *  Created on: 02-12-2011
 *      Author: ghik
 */

#ifndef PSVFS_NL_DEFS_H_
#define PSVFS_NL_DEFS_H_

#ifdef __KERNEL__
#include <net/genetlink.h>
#else
#include <linux/genetlink.h>
#endif

#define GENLMSG_DATA(glh) ((void *)(NLMSG_DATA(glh) + GENL_HDRLEN))
#define GENLMSG_PAYLOAD(glh) (NLMSG_PAYLOAD(glh, 0) - GENL_HDRLEN)
#define NLA_DATA(na) ((void *)((char*)(na) + NLA_HDRLEN))

#define MAX_MSG_SIZE 1024

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
	PSVFS_C_REQUEST,
	PSVFS_C_RESPONSE,
	PSVFS_C_DATA,
	__PSVFS_C_MAX,
};
#define PSVFS_C_MAX (__PSVFS_C_MAX - 1)

struct nla_policy psvfs_genl_policy[PSVFS_A_MAX + 1] = {
	[PSVFS_A_MSG] = { .type = NLA_UNSPEC },
};

#define PSVFS_VERSION 1
#define PSVFS_FAMILY_NAME "PSVFS_FAMILY"

enum {
	PSVFS_OP_OPEN,
	PSVFS_OP_READ,
	PSVFS_OP_WRITE
};

struct rw_request {
	int operation;
	size_t count;
	loff_t offset;
	char filename[256];
};

struct rw_response {
	int operation;
	size_t count;
	loff_t offset;
};

#endif /* PSVFS_NL_DEFS_H_ */
