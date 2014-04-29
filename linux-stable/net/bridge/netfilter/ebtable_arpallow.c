/*
 *  ebtable_nat
 *
 *	Authors:
 *	Bart De Schuymer <bdschuym@pandora.be>
 *
 *  April, 2002
 *
 */

#include <linux/netfilter_bridge/ebtables.h>
#include <linux/module.h>

#define ARPALLOW_VALID_HOOKS (1 << NF_BR_LOCAL_OUT)

static struct ebt_entries initial_chains[] =
{
	{
		.name	= "OUTPUT",
		.policy	= EBT_DROP,
	},
};

static struct ebt_replace_kernel initial_table =
{
	.name		= "arpallow",
	.valid_hooks	= ARPALLOW_VALID_HOOKS,
	.entries_size	= sizeof(struct ebt_entries),
	.hook_entry	= {
		[NF_BR_LOCAL_OUT]	= &initial_chains[0],
	},
	.entries	= (char *)initial_chains,
};

static int check(const struct ebt_table_info *info, unsigned int valid_hooks)
{
	if (valid_hooks & ~ARPALLOW_VALID_HOOKS)
		return -EINVAL;
	return 0;
}

static struct ebt_table frame_arpallow =
{
	.name		= "arpallow",
	.table		= &initial_table,
	.valid_hooks	= ARPALLOW_VALID_HOOKS,
	.check		= check,
	.me		= THIS_MODULE,
};

static unsigned int
ebt_arpallow_out(unsigned int hook, struct sk_buff *skb, const struct net_device *in,
   const struct net_device *out, int (*okfn)(struct sk_buff *))
{
	return ebt_do_table(hook, skb, in, out, &frame_arpallow);
}

static struct nf_hook_ops ebt_ops_arpallow[] __read_mostly = {
	{
		.hook		= ebt_arpallow_out,
		.owner		= THIS_MODULE,
		.pf		= NFPROTO_BRIDGE,
		.hooknum	= NF_BR_LOCAL_OUT,
		.priority	= NF_BR_PRI_FILTER_OTHER,
	},
};

static struct ebt_table *registered_table = NULL;

static int __net_init frame_arpallow_net_init(struct net *net)
{
	if (registered_table) {
		ebt_unregister_table(net, registered_table);
		registered_table = NULL;
	}
	registered_table = ebt_register_table(net, &frame_arpallow);
	if (IS_ERR(registered_table)) {
		int error = PTR_ERR(registered_table);
		registered_table = NULL;
		printk(KERN_INFO "failed registering arpallow table (%d)\n", error);
		return error;
	}
	return 0;
}

static void __net_exit frame_arpallow_net_exit(struct net *net)
{
	if (registered_table) {
		ebt_unregister_table(net, &frame_arpallow);
		registered_table = NULL;
	}
}

static struct pernet_operations frame_arpallow_net_ops = {
	.init = frame_arpallow_net_init,
	.exit = frame_arpallow_net_exit,
};

static int __init ebtable_arpallow_init(void)
{
	int ret;

	ret = register_pernet_subsys(&frame_arpallow_net_ops);
	if (ret < 0)
		return ret;
	ret = nf_register_hooks(ebt_ops_arpallow, ARRAY_SIZE(ebt_ops_arpallow));
	if (ret < 0)
		unregister_pernet_subsys(&frame_arpallow_net_ops);
	return ret;
}

static void __exit ebtable_arpallow_fini(void)
{
	nf_unregister_hooks(ebt_ops_arpallow, ARRAY_SIZE(ebt_ops_arpallow));
	unregister_pernet_subsys(&frame_arpallow_net_ops);
}

module_init(ebtable_arpallow_init);
module_exit(ebtable_arpallow_fini);
MODULE_LICENSE("GPL");
