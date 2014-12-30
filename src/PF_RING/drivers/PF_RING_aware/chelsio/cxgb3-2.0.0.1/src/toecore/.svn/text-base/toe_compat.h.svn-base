/*
 * Copyright (C) 2003-2009 Chelsio Communications.  All rights reserved.
 *
 * Written by Dimitris Michailidis (dm@chelsio.com),
 *	      Divy Le Ray (divy@chelsio.com)
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */
#ifndef __TOE_COMPAT_H
#define __TOE_COMPAT_H

#include <linux/version.h>

/*
 * Pull in either Linux 2.6 or earlier compatibility definitions.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
#include "toe_compat_2_6.h"
#else
#include "toe_compat_2_4.h"
#endif

#if !defined(for_each_netdev)
#define for_each_netdev(d) \
	for (d = dev_base; d; d = d->next)
#endif

#if !defined(NEW_SKB_OFFSET)
static inline void skb_reset_network_header(struct sk_buff *skb)
{
	skb->nh.raw = skb->data;
}
#endif

#if !defined(TRANSPORT_HEADER)
#define transport_header h.raw
#define network_header nh.raw
#endif

#if !defined(SEC_INET_CONN_ESTABLISHED)
static inline void security_inet_conn_established(struct sock *sk,
						  struct sk_buff *skb)
{}
#endif

#if defined(CONFIG_KPROBES) && defined(KPROBES_SYMBOL_NAME)
#define KPROBES_KALLSYMS
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
#define INET_PROC_DIR init_net.proc_net
#else
#define INET_PROC_DIR proc_net
#endif

#if !defined(VLAN_DEV_API)
#include <linux/if_vlan.h>
#if defined(VLAN_DEV_INFO)
static inline struct vlan_dev_info *vlan_dev_info(const struct net_device *dev)
{
	return VLAN_DEV_INFO(dev);
}
#endif

static inline u16 vlan_dev_vlan_id(const struct net_device *dev)
{
	return vlan_dev_info(dev)->vlan_id;
}

static inline struct net_device *vlan_dev_real_dev(const struct net_device *dev)
{
	return vlan_dev_info(dev)->real_dev;
}
#else /* VLAN_DEV_API */
#if defined(RHEL_RELEASE_CODE)
#if RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(5,7) && \
    RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(6,0)
#include <linux/if_vlan.h>
static inline u16 vlan_dev_vlan_id(const struct net_device *dev)
{
	return VLAN_DEV_INFO(dev)->vlan_id;
}
#endif
#endif /* RHEL_RELEASE_CODE */
#endif /* VLAN_DEV_API */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,30)
#define SET_PROC_NODE_OWNER(_p, _owner) \
	do { (_p)->owner = (_owner); } while (0)
#else
#define SET_PROC_NODE_OWNER(_p, _owner) \
	do { } while (0)
#endif

#if !defined(INET_PREFIX)
#define inet_daddr daddr
#define inet_rcv_saddr rcv_saddr
#define inet_dport dport
#define inet_saddr saddr
#define inet_sport sport
#define inet_id id
#endif

#if defined(RHEL_RELEASE_CODE)
#if RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(6,2)
#include <net/secure_seq.h>
#endif
#endif /* RHEL_RELEASE_CODE */

#if LINUX_VERSION_CODE == KERNEL_VERSION(2,6,32)
#if !defined(GFP_MEMALLOC)
static inline gfp_t sk_allocation(struct sock *sk, gfp_t gfp_mask)
{
        return gfp_mask;
}
#endif /* GFP_MEMALLOC */
#endif

#endif /* __TOE_COMPAT_H */
