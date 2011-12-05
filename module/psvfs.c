#include "psvfs.h"

int psvfs_module_init(void) {
	printk(KERN_INFO "Initializing psvfs module.\n");

	data = kmalloc(MAX_MSG_SIZE, GFP_KERNEL);

	genl_register_family(&psvfs_gnl_family);
	genl_register_ops(&psvfs_gnl_family, &psvfs_gnl_ops_init);
	genl_register_ops(&psvfs_gnl_family, &psvfs_gnl_ops_destroy);

	return 0;
}

void psvfs_module_exit(void) {
	printk(KERN_INFO "Exiting psvfs module.\n");

	unregister_filesystem(&psvfs_type);

	genl_unregister_ops(&psvfs_gnl_family, &psvfs_gnl_ops_destroy);
	genl_unregister_ops(&psvfs_gnl_family, &psvfs_gnl_ops_init);
	genl_unregister_family(&psvfs_gnl_family);

	kfree(data);
}

int psvfs_vfs_init(struct sk_buff *skb2, struct genl_info *info) {
	int res = -1;
	struct nlattr* na;
	printk(KERN_INFO "Initializing virtual filesystem.\n");

	na = info->attrs[PSVFS_A_MSG];
	if (na) {
		datalen = nla_len(na);
		memcpy(data, nla_data(na), datalen);

		res = register_filesystem(&psvfs_type);
		send_to_daemon("VFS initialized.", PSVFS_C_INIT, info->snd_seq + 1,
				info->snd_pid);
	} else {
		datalen = 0;
	}

	return res;
}

int psvfs_vfs_destroy(struct sk_buff *skb2, struct genl_info *info) {
	printk(KERN_INFO "Destroying virtual filesystem.\n");

	unregister_filesystem(&psvfs_type);

	return 0;
}

int psvfs_recv_from_daemon(struct sk_buff* skb2, struct genl_info *info) {
	struct nlattr *na = info->attrs[PSVFS_A_MSG];
	if (na) {
		datalen = nla_len(na);
		memcpy(data, nla_data(na), datalen);
	} else {
		datalen = 0;
	}
	wake_up_interruptible(&vfs_queue);
	return 0;
}

int psvfs_open(struct inode *inode, struct file *filp) {
	mutex_lock(&vfs_mutex);

	mutex_unlock(&vfs_mutex);
	return 0;
}

ssize_t psvfs_read(struct file *filp, char *buf, size_t count, loff_t *offset) {
	mutex_lock(&vfs_mutex);

	mutex_unlock(&vfs_mutex);
	return 0;
}

ssize_t psvfs_write(struct file *filp, const char *buf, size_t count,
		loff_t *offset) {
	mutex_lock(&vfs_mutex);

	mutex_unlock(&vfs_mutex);
	return 0;
}

int send_to_daemon(char* msg, int command, int seq, u32 pid) {
	int res = 0;
	struct sk_buff* skb;
	void* msg_head;

	skb = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
	if (skb == NULL) {
		res = -ENOMEM;
		goto out;
	}

	msg_head = genlmsg_put(skb, 0, seq, &psvfs_gnl_family, 0, command);
	if (msg_head == NULL) {
		res = -ENOMEM;
		goto out;
	}

	res = nla_put(skb, PSVFS_A_DATA, strlen(msg) + 1, msg);
	if (res != 0)
		goto out;

	genlmsg_end(skb, msg_head);

	res = genlmsg_unicast(&init_net, skb, pid);
	if (res != 0)
		goto out;

	out: return res;
}

struct inode *make_inode(struct super_block *sb, int mode) {
	struct inode *ret = new_inode(sb);

	if (ret) {
		ret->i_mode = mode;
		ret->i_uid = ret->i_gid = 0;
		ret->i_blkbits = blksize_bits(PAGE_CACHE_SIZE);
		ret->i_blocks = 0;
		ret->i_atime = ret->i_mtime = ret->i_ctime = CURRENT_TIME;
	}
	return ret;
}

struct dentry *create_file(struct super_block *sb, struct dentry *dir,
		const char *name) {
	struct dentry *dentry;
	struct inode *inode;
	struct qstr qname;
	/*
	 * Make a hashed version of the name to go with the dentry.
	 */
	qname.name = name;
	qname.len = strlen(name);
	qname.hash = full_name_hash(name, qname.len);

	/*
	 * Now we can create our dentry and the inode to go with it.
	 */
	dentry = d_alloc(dir, &qname);
	if (!dentry)
		goto out;
	inode = make_inode(sb, S_IFREG | 0644);
	if (!inode)
		goto out_dput;
	inode->i_fop = &psvfs_file_ops;

	/*
	 * Put it all into the dentry cache and we're done.
	 */
	d_add(dentry, inode);
	return dentry;

	/*
	 * Then again, maybe it didn't work.
	 */
	out_dput: dput(dentry);
	out: return 0;
}

static void create_files(struct super_block *sb, struct dentry *root) {
	char* ptr = data;
	while (ptr < data + datalen) {
		create_file(sb, root, ptr);
		ptr += strlen(ptr) + 1;
	}
}

int fill_super(struct super_block *sb, void *data, int silent) {
	struct inode *root;
	struct dentry *root_dentry;

	sb->s_blocksize = PAGE_CACHE_SIZE;
	sb->s_blocksize_bits = PAGE_CACHE_SHIFT;
	sb->s_magic = LFS_MAGIC;
	sb->s_op = &psvfs_super_ops;

	root = make_inode(sb, S_IFDIR | 0755);
	if (!root)
		goto out;
	root->i_op = &simple_dir_inode_operations;
	root->i_fop = &simple_dir_operations;

	root_dentry = d_alloc_root(root);
	if (!root_dentry)
		goto out_iput;
	sb->s_root = root_dentry;

	create_files(sb, root_dentry);
	return 0;

	out_iput: iput(root);
	out: return -ENOMEM;
}

int psvfs_get_super(struct file_system_type *fst, int flags,
		const char *devname, void *data, struct vfsmount* mount) {
	return get_sb_single(fst, flags, data, fill_super, mount);
}
