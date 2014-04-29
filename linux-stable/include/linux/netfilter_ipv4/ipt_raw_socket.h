/*
 * ipt_raw_socket.h
 *
 *  Created on: Sep 13, 2012
 *      Author: bhushan
 */

#ifndef _IPT_RAW_SOCKET_H
#define _IPT_RAW_SOCKET_H
#include <linux/in.h>


struct ipt_raw_socket_info {
	unsigned int allowed_raw_sock_proto[IPPROTO_MAX]={0};
};


#endif /* _IPT_RAW_SOCKET_H */
