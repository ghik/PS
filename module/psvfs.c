#include "psvfs.h"

struct nla_policy psvfs_genl_policy[PSVFS_A_MAX + 1] = {
  [PSVFS_A_MSG] = { .type = NLA_UNSPEC }, // no policy, just a chunk of bytes
};


int check(int condition, const char* msg) {
	if(!condition) {
		printk(KERN_INFO "%s failed\n", msg);
		return 0;
	}
	return 1;
}

#define ASSERT(condition, msg, target) if(!check((condition), (msg))) goto target;

int psvfs_module_init(void) {
	int res = 0;
	printk(KERN_INFO "Initializing psvfs module.\n");

	res = genl_register_family(&psvfs_gnl_family);
	ASSERT(res == 0, "register_family", out);
	res = genl_register_ops(&psvfs_gnl_family, &psvfs_gnl_ops_init);
	ASSERT(res == 0, "register_init_ops", out);
	res = genl_register_ops(&psvfs_gnl_family, &psvfs_gnl_ops_destroy);
	ASSERT(res == 0, "register_destroy_ops", out);
	res = genl_register_ops(&psvfs_gnl_family, &psvfs_gnl_ops_receive_response);
	ASSERT(res == 0, "register_resp_ops", out);
	res = genl_register_ops(&psvfs_gnl_family, &psvfs_gnl_ops_receive_data);
	ASSERT(res == 0, "register_data_ops", out);

	printk(KERN_INFO "Initialized psvfs module.\n");
  out:
	return 0;
}

void psvfs_module_exit(void) {
	printk(KERN_INFO "Exiting psvfs module.\n");

	if(daemon_pid > 0) {
		unregister_filesystem(&psvfs_type);

		if(filenames != NULL) {
			kfree((void*)filenames);
		}
	}

	genl_unregister_ops(&psvfs_gnl_family, &psvfs_gnl_ops_receive_data);
	genl_unregister_ops(&psvfs_gnl_family, &psvfs_gnl_ops_receive_response);
	genl_unregister_ops(&psvfs_gnl_family, &psvfs_gnl_ops_destroy);
	genl_unregister_ops(&psvfs_gnl_family, &psvfs_gnl_ops_init);
	genl_unregister_family(&psvfs_gnl_family);
}

int psvfs_vfs_init(struct sk_buff *skb2, struct genl_info *info) {
	int res = -1;
	struct nlattr* na;

	printk(KERN_INFO "Initializing virtual filesystem.\n");

	resp_ok = 0;

	if(daemon_pid > 0) {
		res = unregister_filesystem(&psvfs_type);
		ASSERT(res == 0, "unregister_filesystem", out);

		if(filenames != NULL) {
			kfree((void*)filenames);
		}
	}

	ASSERT(info != NULL && info->attrs != NULL, "genl_info", out);

	na = info->attrs[PSVFS_A_MSG];
	ASSERT(na != NULL, "info->attrs", out);

	fnlen = nla_len(na);

	filenames = kmalloc(fnlen, GFP_KERNEL);
	ASSERT(filenames != NULL, "kmalloc", out);

	memcpy((void*)filenames, nla_data(na), fnlen);

	daemon_pid = info->snd_pid;
	atomic_set(&seq, info->snd_seq);

	res = register_filesystem(&psvfs_type);
	ASSERT(res == 0, "register_filesystem", out);

	res = send_to_daemon("VFS initialized.", strlen("VFS initialized.")+1, PSVFS_C_INIT, atomic_read(&seq),
		info->snd_pid);
	ASSERT(res == 0, "send_to_daemon", out);

	resp_ok = 1;

  out:
    if(data != NULL) {
    	kfree((void*)data);
    	data = NULL;
    }

	return res;
}

int psvfs_vfs_destroy(struct sk_buff *skb2, struct genl_info *info) {
	printk(KERN_INFO "Destroying virtual filesystem.\n");

	unregister_filesystem(&psvfs_type);
	daemon_pid = -1;

	if(filenames != NULL) {
		kfree((void*)filenames);
	}

	return 0;
}

int psvfs_receive_response(struct sk_buff* skb2, struct genl_info *info) {
	struct nlattr *na;

	resp_ok = 0;

	ASSERT(info != NULL && info->attrs != NULL, "genl_info", out);

	na = info->attrs[PSVFS_A_MSG];
	ASSERT(na != NULL, "nlattr", out);
	ASSERT(nla_data(na) != NULL, "nla_data", out);

	memcpy((void*)&resp, nla_data(na), nla_len(na));

	if(resp.operation == PSVFS_OP_READ && resp.count > 0) {
		data = kmalloc(resp.count, GFP_KERNEL);
		ASSERT(data != NULL, "kmalloc", out);
		databytes = 0;
	}

	resp_ok = 1;

  out:
	responded = 1;
	wake_up_interruptible(&vfs_queue);
	return 0;
}

int psvfs_receive_data(struct sk_buff* skb2, struct genl_info *info) {
	struct nlattr *na;

	data_ok = 0;

	ASSERT(info != NULL && info->attrs != NULL, "genl_info", out);

	na = info->attrs[PSVFS_A_MSG];
	ASSERT(na != NULL, "nlattr", out);
	ASSERT(nla_data(na) != NULL, "nla_data", out);
	ASSERT(data != NULL, "data", out);

	memcpy(((char*)data)+databytes, nla_data(na), nla_len(na));
	databytes += nla_len(na);

	data_ok = 1;

	printk(KERN_INFO "We want %i, we have %i\n", resp.count, databytes);

  out:
    if(databytes >= resp.count) {
    	dataarrived = 1;
    	wake_up_interruptible(&vfs_queue);
    }
	return 0;
}

int psvfs_open(struct inode *inode, struct file *filp) {
	return 0;
}

ssize_t psvfs_read(struct file *filp, char *buf, size_t count, loff_t *offset) {
	ssize_t fres = -EIO;
	int res;

	if(daemon_pid == 0) {
		return -EIO;
	}

	if(mutex_lock_interruptible(&vfs_mutex) != 0) {
		return -EINTR;
	}

	printk(KERN_INFO "Read request to file %s at %lli size %i\n", filp->f_path.dentry->d_name.name, *offset, count);
	strcpy(req.filename, filp->f_path.dentry->d_name.name);

	printk(KERN_INFO "%s\n", req.filename);
	req.offset = *offset;
	req.count = count;
	req.operation = PSVFS_OP_READ;

	responded = 0;
	dataarrived = 0;

	res = send_to_daemon(&req, sizeof(req), PSVFS_C_REQUEST, atomic_add_return(1,&seq), daemon_pid);
	ASSERT(res == 0, "send_to_daemon", out);

	if(wait_event_interruptible(vfs_queue, responded == 1) != 0) {
		fres = -EINTR;
		goto out;
	}

	if(!resp_ok) {
		fres = -EIO;
		goto out;
	}

	if(resp.count > 0) {
		ASSERT(data != NULL, "kmalloc", out);

		printk(KERN_INFO "Waiting for data.\n");

		if(wait_event_interruptible(vfs_queue, dataarrived == 1) != 0) {
			fres = -EINTR;
			goto out;
		}

		if(!data_ok) {
			fres = -EIO;
			goto out;
		}

		copy_to_user(buf, (void*)data, resp.count);
	}

	*offset = resp.offset;
	fres = resp.count;

  out:
  	if(data != NULL) {
  		kfree((void*)data);
  		data = NULL;
  	}

	mutex_unlock(&vfs_mutex);
	return fres;
}

ssize_t psvfs_write(struct file *filp, const char *buf, size_t count,
		loff_t *offset) {
	ssize_t fres = -EIO;
	int res;

	if(daemon_pid == 0) {
		return -EIO;
	}

	if(mutex_lock_interruptible(&vfs_mutex) != 0) {
		return -EINTR;
	}

	printk(KERN_INFO "Write request to file %s at %lli size %i\n", filp->f_path.dentry->d_name.name, *offset, count);

	strcpy(req.filename, filp->f_path.dentry->d_name.name);
	req.operation = PSVFS_OP_WRITE;
	req.count = count;
	req.offset = *offset;

	if(count > 0) {
		data = kmalloc(count, GFP_KERNEL);
		ASSERT(data != NULL, "kmalloc", out);
		copy_from_user((void*)data, buf, count);
	}

	res = send_to_daemon(&req, sizeof(req), PSVFS_C_REQUEST, atomic_add_return(1,&seq), daemon_pid);
	ASSERT(res == 0, "send_to_daemon", out);

	printk(KERN_INFO "Write request sent.\n");

	if(count > 0) {
		res = send_to_daemon((void*)data, count, PSVFS_C_DATA, atomic_add_return(1,&seq), daemon_pid);
		ASSERT(res == 0, "send_to_daemon", out);
	}

	printk(KERN_INFO "Data sent.\n");

	if(wait_event_interruptible(vfs_queue, responded == 1) != 0) {
		fres = -EINTR;
		goto out;
	}

	if(!resp_ok) {
		fres = -EIO;
		goto out;
	}

	printk(KERN_INFO "Got response %i %lli\n", resp.count, resp.offset);

	*offset = resp.offset;
	fres = resp.count;

  out:
    if(data != NULL) {
    	kfree((void*)data);
    	data = NULL;
    }

	mutex_unlock(&vfs_mutex);
	return fres;
}

int send_to_daemon(void* msg, int len, int command, int seq, u32 pid) {
	struct sk_buff* skb;
	void* msg_head;
	int res;

	skb = genlmsg_new(GENL_HDRLEN+nla_total_size(len)+36, GFP_KERNEL);
	ASSERT(skb != NULL, "genlmsg_new", nomem);

	msg_head = genlmsg_put(skb, pid, seq, &psvfs_gnl_family, 0, command);
	ASSERT(msg_head != NULL, "genlmsg_put", nomem);

	res = nla_put(skb, PSVFS_A_MSG, len, msg);
	ASSERT(res == 0, "nla_put", out);

	res = genlmsg_end(skb, msg_head);
	ASSERT(res > 0, "genlmsg_end", out);

	res = genlmsg_unicast(&init_net, skb, pid);
	printk("If failed, it is %i\n", res);
	ASSERT(res == 0, "genlmsg_unicast", out);

  out:
    return res;

  nomem:
    return -ENOMEM;
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
	inode = make_inode(sb, S_IFREG | 0777);
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
	char* ptr = (char*)filenames;
	printk(KERN_INFO "fnlen is %i", fnlen);
	while (ptr < ((char*)filenames) + fnlen) {
		printk(KERN_INFO "Creating file %s\n", ptr);
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

	root = make_inode(sb, S_IFDIR | 0777);
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
