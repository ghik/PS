/*
 * psvfs.h
 *
 *  Created on: 02-12-2011
 *      Author: ghik
 */

#ifndef PSVFS_H_
#define PSVFS_H_

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/proc_fs.h>
#include <linux/wait.h>
#include <linux/sched.h>

#include "psvfs_nl_defs.h"

/*
 * Functions
 */

/* Initializes module */
int psvfs_module_init(void);
/* Exits module */
void psvfs_module_exit(void);
/* Initializes virtual filesystem as a result of message from userspace daemon */
int psvfs_vfs_init(struct sk_buff *skb2, struct genl_info *info);
/* Destroys virtual filesystem as a resutl of message from userspace daemon */
int psvfs_vfs_destroy(struct sk_buff *skb2, struct genl_info *info);

/*
 * Module stuff
 */

MODULE_LICENSE("GPL");
module_init(psvfs_module_init);
module_exit(psvfs_module_exit);

/*
 * Netlink stuff
 */

static struct genl_family psvfs_gnl_family = {
    .id = GENL_ID_GENERATE,
    .hdrsize = 0,
    .name = PSVFS_FAMILY_NAME,
    .version = PSVFS_VERSION,
    .maxattr = PSVFS_A_MAX,
};

struct genl_ops psvfs_gnl_ops_init = {
	.cmd = PSVFS_C_INIT,
	.flags = 0,
	.policy = psvfs_genl_policy,
	.doit = psvfs_vfs_init,
	.dumpit = NULL,
};

struct genl_ops psvfs_gnl_ops_destroy = {
	.cmd = PSVFS_C_DESTROY,
	.flags = 0,
	.policy = psvfs_genl_policy,
	.doit = psvfs_vfs_destroy,
	.dumpit = NULL,
};

#endif /* PSVFS_H_ */
