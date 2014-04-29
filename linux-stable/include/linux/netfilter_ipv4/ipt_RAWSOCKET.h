/*
 * ipt_RAWSOCKET.h
 *
 *  Created on: Sep 18, 2012
 *      Author: bhushan
 */

#ifndef IPT_RAWSOCKET_H_
#define IPT_RAWSOCKET_H_
#include <stdbool.h>

struct xt_raw_socket_tg_info {
        bool allowed_raw_sock_proto[IPPROTO_MAX];
        long allowed_uid;
};


#endif /* IPT_RAWSOCKET_H_ */
