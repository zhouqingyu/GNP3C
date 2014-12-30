/*
 * This file is part of the Chelsio T3 Ethernet driver for Linux.
 *
 * Copyright (C) 2003-2009 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

#ifndef _CHELSIO_L2T_H
#define _CHELSIO_L2T_H

#ifndef AUTOCONF_INCLUDED
#include <linux/autoconf.h>
#endif
#include <linux/spinlock.h>
#include "t3cdev.h"
#include <asm/atomic.h>

enum {
	L2T_STATE_VALID,      /* entry is up to date */
	L2T_STATE_STALE,      /* entry may be used but needs revalidation */
	L2T_STATE_RESOLVING,  /* entry needs address resolution */
	L2T_STATE_UNUSED      /* entry not in use */
};

struct neighbour;
struct sk_buff;

/*
 * Each L2T entry plays multiple roles.  First of all, it keeps state for the
 * corresponding entry of the HW L2 table and maintains a queue of offload
 * packets awaiting address resolution.  Second, it is a node of a hash table
 * chain, where the nodes of the chain are linked together through their next
 * pointer.  Finally, each node is a bucket of a hash table, pointing to the
 * first element in its chain through its first pointer.
 */
struct l2t_entry {
	u16 state;                  /* entry state */
	u16 idx;                    /* entry index */
	u32 addr;                   /* dest IP address */
	int ifindex;                /* neighbor's net_device's ifindex */
	u16 smt_idx;                /* SMT index */
	u16 vlan;                   /* VLAN TCI (id: bits 0-11, prio: 13-15 */
	struct neighbour *neigh;    /* associated neighbour */
	struct l2t_entry *first;    /* start of hash chain */
	struct l2t_entry *next;     /* next l2t_entry on chain */
	struct sk_buff *arpq_head;  /* queue of packets awaiting resolution */
	struct sk_buff *arpq_tail;
	spinlock_t lock;
	atomic_t refcnt;            /* entry reference count */
	u8 dmac[6];                 /* neighbour's MAC address */
	u8 chan_idx;                /* channel index */
	u16 orig_smt_idx;           /* original SMT index in a bond */
#ifndef NETEVENT
#ifdef OFLD_USE_KPROBES
	struct timer_list update_timer;
	struct t3cdev *tdev;
#endif
#endif
};

struct l2t_data {
	unsigned int nentries;      /* number of entries */
	struct l2t_entry *rover;    /* starting point for next allocation */
	atomic_t nfree;             /* number of free entries */
	rwlock_t lock;
	struct l2t_entry l2tab[0];
};

typedef void (*arp_failure_handler_func)(struct t3cdev *dev,
					 struct sk_buff *skb);

/*
 * Callback stored in an skb to handle address resolution failure.
 */
struct l2t_skb_cb {
	arp_failure_handler_func arp_failure_handler;
};

#define L2T_SKB_CB(skb) ((struct l2t_skb_cb *)(skb)->cb)

static inline void set_arp_failure_handler(struct sk_buff *skb,
					   arp_failure_handler_func hnd)
{
	L2T_SKB_CB(skb)->arp_failure_handler = hnd;
}

/*
 * Getting to the L2 data from an offload device.
 */
#define L2DATA(dev) ((dev)->l2opt)

void t3_l2e_free(struct l2t_data *d, struct l2t_entry *e);
void t3_l2t_update(struct t3cdev *dev, struct neighbour *neigh);
struct l2t_entry *t3_l2t_get(struct t3cdev *cdev, struct neighbour *neigh,
			     struct net_device *dev);
int t3_l2t_send_slow(struct t3cdev *dev, struct sk_buff *skb,
		     struct l2t_entry *e);
void t3_l2t_send_event(struct t3cdev *dev, struct l2t_entry *e);
struct l2t_data *t3_init_l2t(unsigned int l2t_capacity);
void t3_free_l2t(struct l2t_data *d);
int t3_l2t_update_l2e(struct t3cdev *dev, struct l2t_entry *e);

#ifdef CONFIG_PROC_FS
int t3_l2t_proc_setup(struct proc_dir_entry *dir, struct l2t_data *d);
void t3_l2t_proc_free(struct proc_dir_entry *dir);
#else
#define l2t_proc_setup(dir, d) 0
#define l2t_proc_free(dir)
#endif

int cxgb3_ofld_send(struct t3cdev *dev, struct sk_buff *skb);

static inline int l2t_send(struct t3cdev *dev, struct sk_buff *skb,
			   struct l2t_entry *e)
{
	if (likely(e->state == L2T_STATE_VALID))
		return cxgb3_ofld_send(dev, skb);
	return t3_l2t_send_slow(dev, skb, e);
}

static inline void l2t_release(struct l2t_data *d, struct l2t_entry *e)
{
	if (atomic_dec_and_test(&e->refcnt))
		t3_l2e_free(d, e);
}

static inline void l2t_hold(struct l2t_data *d, struct l2t_entry *e)
{
	if (atomic_add_return(1, &e->refcnt) == 1)  /* 0 -> 1 transition */
		atomic_dec(&d->nfree);
}

#endif
