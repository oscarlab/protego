/*
 *	"TEE" target extension for Xtables
 *	Copyright © Sebastian Claßen, 2007
 *	Jan Engelhardt, 2007-2010
 *
 *	based on ipt_ROUTE.c from Cédric de Launois
 *	<delaunois@info.ucl.be>
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	version 2 or later, as published by the Free Software Foundation.
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/module.h>
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
#include <linux/netfilter_ipv4/ipt_RAWSOCKET.h>

#if 1
# define DEBUG 1
#endif

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Bhushan Jain <bpjain@cs.stonybrook.edu>");
MODULE_DESCRIPTION("Xtables: raw sockets ");

static int raw_socket_tg_check(const struct xt_tgchk_param *par)
{
	const struct xt_raw_socket_tg_info *rsi = par->targinfo;
	pr_info("\nIn kernel xt_RAWSOCKET check.\n");

	if ((rsi->allowed_raw_sock_proto[IPPROTO_TCP]) || (rsi->allowed_raw_sock_proto[IPPROTO_UDP])) {
		pr_debug("TCP or UDP protocol not prefered.\n");
		return -EINVAL;
	}
	pr_info("\nkernel xt_RAWSOCKET check passed\n");
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

	if(skb->sk && skb->sk->sk_type == SOCK_RAW)
	{
		pr_info("Found Raw Socket !!!");
		if(!rsi->allowed_raw_sock_proto[skb->sk->sk_protocol])
		{
			pr_info("Dropping packet.");
			return NF_DROP;
		}
		else
		{
			pr_info("Accepting packet.");
		}
	}
	return NF_ACCEPT;
}

static struct xt_target raw_socket_tg_reg __read_mostly = {
	.name		= "RAWSOCKET",
	.family		= NFPROTO_IPV4,
	.target		= raw_socket_tg,
	.targetsize	= sizeof(struct xt_raw_socket_tg_info),
	.table		= "raw_sock",
	.hooks		= (1 << NF_INET_LOCAL_OUT) | (1 << NF_INET_LOCAL_IN),
	.checkentry	= raw_socket_tg_check,
	.me		= THIS_MODULE,
};

static int __init raw_socket_tg_init(void)
{
	pr_info("\nRegistering xt_RAW kernel target.\n");
	return xt_register_target(&raw_socket_tg_reg);
}

static void __exit raw_socket_tg_exit(void)
{
	xt_unregister_target(&raw_socket_tg_reg);
}

module_init(raw_socket_tg_init);
module_exit(raw_socket_tg_exit);
