/*
 *	"RAWSOCKET" target extension for iptables
 *	Copyright Bhushan Jain <bpjain@cs.stonybrook.edu>, 2012
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License; either
 *	version 2 of the License, or any later version, as published by the
 *	Free Software Foundation.
 */
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <xtables.h>
#include "xt_RAWSOCKET.h"

enum {
	TCP_USED    	= 1 << 0,
	UDP_USED 		= 1 << 1,
	PROTO_PRESENT 	= 1 << 2,
	UID_PRESENT 	= 1 << 3
};

static const char *const proto_names[IPPROTO_MAX] = {
	[ 0] = "ip",
	[ 1] = "icmp",
	[ 2] = "igmp",
	[ 4] = "ipip",
	[ 6] = "tcp",
	[ 8] = "egp",
	[12] = "pup",
	[17] = "udp",
	[22] = "idp",
	[33] = "dccp",
	[41] = "ipv6",
	[46] = "rsvp",
	[47] = "gre",
	[50] = "esp",
	[51] = "ah",
	[94] = "beetph",
	[103] = "pim",
	[108] = "comp",
	[132] = "sctp",
	[136] = "udplite",
	[255] = "raw"
};

/* Function which prints out usage message. */
static void rawsock_tg_help(void)
{
	printf(
"RAWSOCKET target options:\n"
"  --allow value    Allow protocols indicated by value to use raw sockets\n"
"  --allow_uid value    Allow user indicated by value to use raw sockets\n"
"\n");
}

static const struct option rawsock_tg_opts[] = {
	{.name = "allow",     .has_arg = true, .val = 'a'},
	{.name = "allow_uid",     .has_arg = true, .val = 'i'},
	{NULL},
};

/* Initialize the target. */
static void rawsock_tg_init(struct xt_entry_target *t)
{
	int i;
	struct xt_raw_socket_tg_info *info = (void *)t->data;
	for(i = 0; i < IPPROTO_MAX ; i++)
		info->allowed_raw_sock_proto[i] = false;
	info->allowed_uid = -1;
}

static int rawsock_tg_parse(int c, char **argv, int invert, unsigned int *flags,
                           const void *entry, struct xt_entry_target **target)
{
//	printf("\n Reached parsing \n");
	struct xt_raw_socket_tg_info *info = (void *)(*target)->data;
	unsigned int n = -1;
	int i;
	bool isFound = false;
	unsigned int id;
	switch (c) {
		case 'a':
//			printf("\n Found allow \n");
//			xtables_param_act(XTF_NO_INVERT, "RAWSOCKET", "allow", invert);

			for (i = 0; i < IPPROTO_MAX; ++i)
				if (proto_names[i] != NULL &&
				    strcmp(proto_names[i], optarg) == 0) {
					n = i;
					isFound = true;
					break;
				}

			if (!isFound && (!xtables_strtoui(optarg, NULL, &n, 0, ~0U) || n >= IPPROTO_MAX ))
				xtables_param_act(XTF_BAD_VALUE, "RAWSOCKET", "allow", optarg);

			info->allowed_raw_sock_proto[n] = true;
			switch(n)
			{
				case IPPROTO_TCP:
					*flags |= TCP_USED;
				case IPPROTO_UDP:
					*flags |= UDP_USED;
			}
			*flags |= PROTO_PRESENT;
			break;
			
			case 'i':
//				printf("\n Found allow_uid \n");
	//			xtables_param_act(XTF_NO_INVERT, "RAWSOCKET", "allow", invert);


				if (!xtables_strtoui(optarg, NULL, &id, 0, ~0U))
					xtables_param_act(XTF_BAD_VALUE, "RAWSOCKET", "allow_uid", optarg);

				info->allowed_uid = id;
				*flags |= UID_PRESENT;
				break;
		default:
			printf("\n Parsing Failed \n");
			return false;	
	}
//	printf("\n Parsing successful \n");
	return true;
}

static void rawsock_tg_check(unsigned int flags)
{
	if ((flags & TCP_USED) || (flags & UDP_USED))
		xtables_error(PARAMETER_PROBLEM,
		           "RAWSOCKET target: raw sockets for tcp, udp should not be allowed.");
	if (!(flags & PROTO_PRESENT) && !(flags & UID_PRESENT))
		xtables_error(PARAMETER_PROBLEM,
		           "RAWSOCKET target: at least one of protocol or uid must be entered.");
}

static void
rawsock_tg_print(const void *entry, const struct xt_entry_target *target,
                int numeric)
{
	const struct xt_raw_socket_tg_info *info = (const void *)target->data;
	int i = 0;
	printf(" Allowed raw socket protocol : ");
	for(i = 0; i < IPPROTO_MAX ; i++)
		if(info->allowed_raw_sock_proto[i])
			printf(" %s ",proto_names[i]);
	if(info->allowed_uid >= 0)
	{
		printf(" Allowed user id : ");
		printf(" %ld ",info->allowed_uid);
	}
}

static void
rawsock_tg_save(const void *entry, const struct xt_entry_target *target)
{
	const struct xt_raw_socket_tg_info *info = (const void *)target->data;
	int i = 0;
	for(i = 0; i < IPPROTO_MAX ; i++)
		if(info->allowed_raw_sock_proto[i])
			printf(" --allow %d ",i);
	if(info->allowed_uid >= 0)
		printf(" --allow_uid %ld ",info->allowed_uid);
}

static struct xtables_target rawsock_tg_reg = {
	.version       = XTABLES_VERSION,
	.name          = "RAWSOCKET",
	.family        = NFPROTO_IPV4,
	.size          = XT_ALIGN(sizeof(struct xt_raw_socket_tg_info)),
	.userspacesize = XT_ALIGN(sizeof(struct xt_raw_socket_tg_info)),
	.help          = rawsock_tg_help,
	.init          = rawsock_tg_init,
	.parse         = rawsock_tg_parse,
	.final_check   = rawsock_tg_check,
	.print         = rawsock_tg_print,
	.save          = rawsock_tg_save,
	.extra_opts    = rawsock_tg_opts,
};

static __attribute__((constructor)) void rawsock_tg_ldr(void)
{
//	printf("\n Registering target \n");
	xtables_register_target(&rawsock_tg_reg);
}
