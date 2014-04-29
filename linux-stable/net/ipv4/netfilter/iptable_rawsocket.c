/*
 * This is the 1999 rewrite of IP Firewalling, aiming for kernel 2.3.x.
 *
 * Copyright (C) 1999 Paul `Rusty' Russell & Michael J. Neuling
 * Copyright (C) 2000-2004 Netfilter Core Team <coreteam@netfilter.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/slab.h>
#include <net/ip.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Netfilter Core Team <coreteam@netfilter.org>");
MODULE_DESCRIPTION("iptables rawsocket table");

#define FILTER_VALID_HOOKS ((1 << NF_INET_LOCAL_IN) | \
			    (1 << NF_INET_FORWARD) | \
			    (1 << NF_INET_LOCAL_OUT))

static const struct xt_table packet_filter = {
	.name		= "rawsocket",
	.valid_hooks	= FILTER_VALID_HOOKS,
	.me		= THIS_MODULE,
	.af		= NFPROTO_IPV4,
	.priority	= NF_IP_PRI_RAWSOCKET,
};

static unsigned int
iptable_rawsocket_hook(unsigned int hook, struct sk_buff *skb,
		    const struct net_device *in, const struct net_device *out,
		    int (*okfn)(struct sk_buff *))
{
	const struct net *net;

	if (hook == NF_INET_LOCAL_OUT &&
	    (skb->len < sizeof(struct iphdr) ||
	     ip_hdrlen(skb) < sizeof(struct iphdr)))
		/* root is playing with raw sockets. */
		return NF_ACCEPT;

	if(in != NULL)
		return NF_ACCEPT;
	else
	{

		if(skb->sk && skb->sk->sk_type != SOCK_RAW)
		{
			return NF_ACCEPT;
		}
		if(skb->sk && skb->sk->sk_socket
				&& skb->sk->sk_socket->file
				&& skb->sk->sk_socket->file->f_cred
				&& skb->sk->sk_socket->file->f_cred->euid == 0)
		{
			/* Its root!!! Root can do anything :) */
			return NF_ACCEPT;
		}
		net = dev_net(out);
		return ipt_do_table(skb, hook, in, out, net->ipv4.iptable_rawsocket);
	}
}

static struct nf_hook_ops *rawsocket_ops __read_mostly;

/* Default to forward because I got too much mail already. */
//static bool forward = true;
//module_param(forward, bool, 0000);

static int __net_init iptable_rawsocket_net_init(struct net *net)
{
	struct ipt_replace *repl;

	repl = ipt_alloc_initial_table(&packet_filter);
	if (repl == NULL)
		return -ENOMEM;
//	/* Entry 1 is the FORWARD hook */
//	((struct ipt_standard *)repl->entries)[1].target.verdict =
//		forward ? -NF_ACCEPT - 1 : -NF_DROP - 1;

	net->ipv4.iptable_rawsocket =
		ipt_register_table(net, &packet_filter, repl);
	kfree(repl);
	if (IS_ERR(net->ipv4.iptable_rawsocket))
		return PTR_ERR(net->ipv4.iptable_rawsocket);
	return 0;
}

static void __net_exit iptable_rawsocket_net_exit(struct net *net)
{
	ipt_unregister_table(net, net->ipv4.iptable_rawsocket);
}

static struct pernet_operations iptable_rawsocket_net_ops = {
	.init = iptable_rawsocket_net_init,
	.exit = iptable_rawsocket_net_exit,
};

static int __init iptable_rawsocket_init(void)
{
	int ret;

	ret = register_pernet_subsys(&iptable_rawsocket_net_ops);
	if (ret < 0)
		return ret;

	/* Register hooks */
	rawsocket_ops = xt_hook_link(&packet_filter, iptable_rawsocket_hook);
	if (IS_ERR(rawsocket_ops)) {
		ret = PTR_ERR(rawsocket_ops);
		goto cleanup_table;
	}

	return ret;

 cleanup_table:
	unregister_pernet_subsys(&iptable_rawsocket_net_ops);
	return ret;
}

static void __exit iptable_rawsocket_fini(void)
{
	xt_hook_unlink(&packet_filter, rawsocket_ops);
	unregister_pernet_subsys(&iptable_rawsocket_net_ops);
}

module_init(iptable_rawsocket_init);
module_exit(iptable_rawsocket_fini);
