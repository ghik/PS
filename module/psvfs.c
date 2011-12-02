#include "psvfs.h"

int psvfs_module_init(void) {
    printk(KERN_INFO "Initializing psvfs module.\n");

    genl_register_family(&psvfs_gnl_family);
    genl_register_ops(&psvfs_gnl_family, &psvfs_gnl_ops_init);
    genl_register_ops(&psvfs_gnl_family, &psvfs_gnl_ops_destroy);

    return 0;
}

void psvfs_module_exit(void) {
    printk(KERN_INFO "Exiting psvfs module.\n");

    genl_unregister_ops(&psvfs_gnl_family, &psvfs_gnl_ops_destroy);
    genl_unregister_ops(&psvfs_gnl_family, &psvfs_gnl_ops_init);
    genl_unregister_family(&psvfs_gnl_family);
}

int psvfs_vfs_init(struct sk_buff *skb2, struct genl_info *info) {
    printk(KERN_INFO "Initializing virtual filesystem.\n");

    return 0;
}

int psvfs_vfs_destroy(struct sk_buff *skb2, struct genl_info *info) {
    printk(KERN_INFO "Destroying virtual filesystem.\n");

    return 0;
}
