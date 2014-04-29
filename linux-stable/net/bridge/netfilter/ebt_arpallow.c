/*
 *  ebt_arpallow
 *
 *	Authors:
 *	Chia-Che Tsai <chitsai@cs.stonybrook.edu>
 *
 *  Nov, 2012
 *
 */
#include <linux/if_arp.h>
#include <net/arp.h>
#include <linux/module.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter_bridge/ebtables.h>

struct ebt_arpallow_info {
	unsigned short	allow_op;
	kuid_t		allow_user;
};

static unsigned int
ebt_arpallow_tg(struct sk_buff *skb, const struct xt_action_param *par)
{
	const struct ebt_arpallow_info *info = par->targinfo;
	const struct arphdr *ap;
	struct arphdr _ah;
	kuid_t cred;
	int known_cred = 0;

	printk(KERN_INFO "ebt_arpallow_tg\n");

	ap = skb_header_pointer(skb, 0, sizeof(_ah), &_ah);
	if (ap == NULL)
		return EBT_DROP;

	if (skb->sk && skb->sk->sk_socket &&
	    skb->sk->sk_socket->file->f_cred)
	{
		cred = skb->sk->sk_socket->file->f_cred->euid;
		known_cred = 1;
	}

	if (known_cred && cred == 0)
		return EBT_ACCEPT;

	if (ap->ar_op != info->allow_op ||
	    ap->ar_hln != ETH_ALEN ||
	    ap->ar_pro != htons(ETH_P_IP) ||
	    ap->ar_pln != 4)
		return EBT_CONTINUE;

	if (!info->allow_user || (known_cred && cred == info->allow_user))
		return EBT_ACCEPT;

	return EBT_CONTINUE;
}

static int ebt_arpallow_tg_check(const struct xt_tgchk_param *par)
{
	const struct ebt_arpallow_info *info = par->targinfo;

	printk(KERN_INFO "ebt_arpallow_tg_check: op = %u, user = %u\n",
	       ntohs(info->allow_op), info->allow_user);

	if (info->allow_op != htons(ARPOP_REQUEST)    &&
	    info->allow_op != htons(ARPOP_RREQUEST)   &&
	    info->allow_op != htons(ARPOP_InREQUEST))
		return -EINVAL;

	return 0;
}

static struct xt_target ebt_arpallow_tg_reg __read_mostly = {
	.name		= "ARPALLOW",
	.revision	= 0,
	.family		= NFPROTO_BRIDGE,
	.table		= "arpallow",
	.hooks		= (1 << NF_BR_NUMHOOKS) | (1 << NF_BR_LOCAL_OUT),
	.target		= ebt_arpallow_tg,
	.checkentry	= ebt_arpallow_tg_check,
	.targetsize	= sizeof(struct ebt_arpallow_info),
	.me		= THIS_MODULE,
};

static int __init ebt_arpallow_init(void)
{
	return xt_register_target(&ebt_arpallow_tg_reg);
}

static void __exit ebt_arpallow_fini(void)
{
	xt_unregister_target(&ebt_arpallow_tg_reg);
}

module_init(ebt_arpallow_init);
module_exit(ebt_arpallow_fini);
MODULE_DESCRIPTION("Ebtables: ARP allow target");
MODULE_LICENSE("GPL");
