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
#endif

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
	__PSVFS_C_MAX,
};
#define PSVFS_C_MAX (__PSVFS_C_MAX - 1)

struct nla_policy psvfs_genl_policy[PSVFS_A_MAX + 1] = {
	[PSVFS_A_MSG] = { .type = NLA_STRING },
};

#define PSVFS_VERSION 1
#define PSVFS_FAMILY_NAME "PSVFS_FAMILY"

#endif /* PSVFS_NL_DEFS_H_ */
