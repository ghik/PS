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
#include <linux/wait.h>
#include <linux/sched.h>
#include <linux/pagemap.h>
#include <linux/fs.h>
#include <asm/atomic.h>
#include <asm/uaccess.h>

#include "psvfs_nl_defs.h"

/*
 * Functions
 */

struct nla_policy psvfs_genl_policy[PSVFS_A_MAX + 1] = {
  [PSVFS_A_DATA] = { .type = NLA_UNSPEC },
  [PSVFS_A_MSG] = { .type = NLA_STRING },
};

/* Initializes module */
int psvfs_module_init(void);
/* Exits module */
void psvfs_module_exit(void);
/* Initializes virtual filesystem as a result of message from userspace daemon */
int psvfs_vfs_init(struct sk_buff *skb2, struct genl_info *info);
/* Destroys virtual filesystem as a resutl of message from userspace daemon */
int psvfs_vfs_destroy(struct sk_buff *skb2, struct genl_info *info);
/* Sends a request to userspace daemon */
int send_to_daemon(char* msg, int command, int seq, u32 pid);

int psvfs_get_super(struct file_system_type *fst, int flags,
		const char *devname, void *data, struct vfsmount* mount);

int psvfs_open(struct inode *inode, struct file *filp);
ssize_t psvfs_read(struct file *filp, char *buf, size_t count, loff_t *offset);
ssize_t psvfs_write(struct file *filp, const char *buf, size_t count, loff_t *offset);

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


/*
 * VFS stuff
 */

#define LFS_MAGIC 0x19980122

static inline unsigned int blksize_bits(unsigned int size)
{
    unsigned int bits = 8;
    do {
        bits++;
        size >>= 1;
    } while (size > 256);
    return bits;
}

struct super_operations psvfs_super_ops = {
	.statfs		= simple_statfs,
	.drop_inode	= generic_delete_inode,
};

struct file_system_type psvfs_type = {
	.owner 		= THIS_MODULE,
	.name		= "psvfs",
	.get_sb		= psvfs_get_super,
	.kill_sb	= kill_litter_super,
};

struct file_operations psvfs_file_ops = {
	.open	= psvfs_open,
	.read 	= psvfs_read,
	.write  = psvfs_write,
};

/*
 * Other stuff
 */

atomic_t seq;
char* data = NULL;
int datalen = 0;
DEFINE_MUTEX(vfs_mutex);
DECLARE_WAIT_QUEUE_HEAD(vfs_queue);

#endif /* PSVFS_H_ */
