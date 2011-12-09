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
#include <sys/socket.h>
#include <linux/genetlink.h>
#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#endif


#define GENLMSG_DATA(glh) ((void *)(NLMSG_DATA(glh) + GENL_HDRLEN))
#define GENLMSG_PAYLOAD(glh) (NLMSG_PAYLOAD(glh, 0) - GENL_HDRLEN)
#define NLA_DATA(na) ((void *)((char*)(na) + NLA_HDRLEN))

#define MAX_MSG_SIZE 1024

#define MAX_PATH_SIZE 256
#define MAX_BUF_SIZE 256

struct msg_buf {
  struct nlmsghdr n;
  struct genlmsghdr g;
  char buf[MAX_MSG_SIZE];
};

struct file_op_msg {
  int op; // 0 read, 1 write
  char filepath[MAX_PATH_SIZE]; // sciezka do pliku
  int offset; // offset w pliku
  int size; // rozmiar do odczytu/zapisu
  char msg[MAX_BUF_SIZE]; // odczytana wiadomosc / wiadomosc do zapisu
};


/* Tutaj właściwie tylko PSVFS_A_MSG ma znaczenie - jest to oznaczenie atrybutu
 * (czyli kawałka danych wchodzącego w skład wiadomości), który
 * będzie trzymał stringa z wiadomością do/od kernela.
 */
enum {
	PSVFS_A_DATA,
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
	PSVFS_C_READ,
	PSVFS_C_WRITE,
	__PSVFS_C_MAX,
};
#define PSVFS_C_MAX (__PSVFS_C_MAX - 1)

#define PSVFS_VERSION 1
#define PSVFS_FAMILY_NAME "PSVFS_FAMILY"

#endif /* PSVFS_NL_DEFS_H_ */
