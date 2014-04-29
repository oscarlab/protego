/*
 * ipt_raw_socket.h
 *
 *  Created on: Sep 13, 2012
 *      Author: bhushan
 */

#ifndef _LINUX_NETFILTER_XT_RAWSOCKET_H
#define _LINUX_NETFILTER_XT_RAWSOCKET_H
//#include <linux/in.h>
#include <stdbool.h>

struct xt_raw_socket_tg_info {
        bool allowed_raw_sock_proto[IPPROTO_MAX];
        long allowed_uid;
};

#endif /* _LINUX_NETFILTER_XT_RAWSOCKET_H */
