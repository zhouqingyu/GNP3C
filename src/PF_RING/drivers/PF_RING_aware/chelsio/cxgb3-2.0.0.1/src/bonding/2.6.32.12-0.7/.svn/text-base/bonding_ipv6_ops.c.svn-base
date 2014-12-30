/*
 * This is an ugly hack. SLES turns off ipv6 by blacklisting the
 * ipv6 module. However, since bonding supports ipv6, it is built to
 * depend on ipv6. Thus, when ipv6 is blacklisted, bonding cannot be
 * loaded.
 *
 * This file provides a global structure bonding_ipv6_ops that
 * is initialized by ipv6 when it loads.
 * Instead of depending on ipv6, bonding calls the ipv6 functions
 * through bonding_ipv6_ops.
 */


#include "bonding_ipv6_ops.h"


static void bonding_ipv6_dummy_function(void)
{
};

struct bonding_ipv6_ops bonding_ipv6_ops_dummy = {
	.ndisc_build_skb = NULL,
	.ndisc_send_skb = NULL,
	.in6_dev_put = NULL,
	.register_inet6addr_notifier = (void *)bonding_ipv6_dummy_function,
	.unregister_inet6addr_notifier = (void *)bonding_ipv6_dummy_function,
};

struct bonding_ipv6_ops *bonding_ipv6_ops = &bonding_ipv6_ops_dummy;

DECLARE_RWSEM(bonding_ipv6_ops_sem);

EXPORT_SYMBOL(bonding_ipv6_ops);
EXPORT_SYMBOL(bonding_ipv6_ops_dummy);
EXPORT_SYMBOL(bonding_ipv6_ops_sem);

