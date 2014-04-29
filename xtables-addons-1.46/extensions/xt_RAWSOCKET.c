/* Raw Sockets.  Allow registered non-tcp, non-udp protocols to use raw sockets. */
/* This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <net/icmp.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/route.h>
#include <net/dst.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include "xt_RAWSOCKET.h"

#if 1
# define DEBUG 1
#endif

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Bhushan Jain <bpjain@cs.stonybrook.edu>");
MODULE_DESCRIPTION("Xtables: raw sockets ");

static bool isProtoNull(const struct xt_raw_socket_tg_info *rsi)
{
	int i;
	for(i = 0; i < IPPROTO_MAX ; i++)
		if(rsi->allowed_raw_sock_proto[i])
			return false;
	return true;
}

static int raw_socket_tg_check(const struct xt_tgchk_param *par)
{
	const struct xt_raw_socket_tg_info *rsi = par->targinfo;

	if ((rsi->allowed_raw_sock_proto[IPPROTO_TCP]) || (rsi->allowed_raw_sock_proto[IPPROTO_UDP])) {
//		printk(KERN_INFO "\nXTABLES : TCP or UDP protocol not prefered.\n");
		return -EINVAL;
	}
	if(isProtoNull(rsi) && rsi->allowed_uid < 0)
	{
//		printk(KERN_INFO "\nXTABLES : At least one of protocol or uid needs to be mentioned.\n");
		return -EINVAL;
	}
	return 0;
}


static unsigned int
raw_socket_tg(struct sk_buff *skb, const struct xt_action_param *par)
{
	const struct xt_raw_socket_tg_info *rsi = par->targinfo;
	struct iphdr *iph;
	iph = ip_hdr(skb);
	if(skb->sk && skb->sk->sk_socket
			&& skb->sk->sk_socket->file
			&& skb->sk->sk_socket->file->f_cred
			&& skb->sk->sk_socket->file->f_cred->euid == 0)
	{
		/* Its root!!! Root can do anything :) */
		return NF_ACCEPT;
	}

	if(rsi->allowed_uid >= 0 && skb->sk && skb->sk->sk_socket
			&& skb->sk->sk_socket->file
			&& skb->sk->sk_socket->file->f_cred
			&& skb->sk->sk_socket->file->f_cred->euid == rsi->allowed_uid && isProtoNull(rsi))
	{
		return NF_ACCEPT;
	}

	if(skb->sk && skb->sk->sk_type == SOCK_RAW)
	{
//		printk(KERN_INFO "\nXTABLES : Found Raw Socket !!! Protocol is %d\n",skb->sk->sk_protocol);
		if(!rsi->allowed_raw_sock_proto[skb->sk->sk_protocol])
		{
//			printk(KERN_INFO "\nXTABLES : Dropping packet.\n");
			return NF_DROP;
		}
		else if(rsi->allowed_uid >= 0 && skb->sk && skb->sk->sk_socket
				&& skb->sk->sk_socket->file
				&& skb->sk->sk_socket->file->f_cred
				&& skb->sk->sk_socket->file->f_cred->euid != rsi->allowed_uid)
		{
//			printk(KERN_INFO "\nXTABLES : Dropping packet due to mismatched uid.\n");
			return NF_DROP;
		}
		else
		{
//			printk(KERN_INFO "\nXTABLES : Accepting packet.\n");
		}
	}
	return NF_ACCEPT;
}

static struct xt_target raw_socket_tg_reg __read_mostly = {
	.name		= "RAWSOCKET",
	.family		= NFPROTO_IPV4,
	.target		= raw_socket_tg,
	.targetsize	= sizeof(struct xt_raw_socket_tg_info),
	.table		= "rawsocket",
	.hooks		= (1 << NF_INET_LOCAL_OUT)| (1 << NF_INET_LOCAL_IN),
	.checkentry	= raw_socket_tg_check,
	.me		= THIS_MODULE,
};

static int __init raw_socket_tg_init(void)
{
	return xt_register_target(&raw_socket_tg_reg);
}

static void __exit raw_socket_tg_exit(void)
{
	xt_unregister_target(&raw_socket_tg_reg);
}

module_init(raw_socket_tg_init);
module_exit(raw_socket_tg_exit);
