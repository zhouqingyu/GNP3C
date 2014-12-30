/*
 * Copyright (c) 2005-2009 Chelsio, Inc. All rights reserved.
 * Copyright (c) 2005-2009 Open Grid Computing, Inc. All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */
#ifndef _CHELSIO_DEFS_H
#define _CHELSIO_DEFS_H

#include <linux/skbuff.h>
#include <net/tcp.h>

#include "t3cdev.h"

#include "cxgb3_offload.h"

#define VALIDATE_TID 1

void *cxgb_alloc_mem(unsigned long size);
void cxgb_free_mem(void *addr);
void cxgb_neigh_update(struct neighbour *neigh);
void cxgb_redirect(struct dst_entry *old, struct dst_entry *new);
#ifndef LINUX_2_4
int req_set_offload_policy(struct net_device *,
			   const struct ofld_policy_file *,
			   size_t);
#endif

/*
 * Map an ATID or STID to their entries in the corresponding TID tables.
 */
static inline union active_open_entry *atid2entry(const struct tid_info *t,
						  unsigned int atid)
{
	return &t->atid_tab[atid - t->atid_base];
}


static inline union listen_entry *stid2entry(const struct tid_info *t,
					     unsigned int stid)
{
	return &t->stid_tab[stid - t->stid_base];
}

/*
 * Find the connection corresponding to a TID.
 */
static inline struct t3c_tid_entry *lookup_tid(const struct tid_info *t,
					       unsigned int tid)
{
	struct t3c_tid_entry *t3c_tid = tid < t->ntids ?
					&(t->tid_tab[tid]) : NULL;

	return (t3c_tid && t3c_tid->client) ? t3c_tid : NULL;
}

/*
 * Find the connection corresponding to a server TID.
 */
static inline struct t3c_tid_entry *lookup_stid(const struct tid_info *t,
						unsigned int tid)
{
	union listen_entry *e;

	if (tid < t->stid_base || tid >= t->stid_base + t->nstids)
		return NULL;

	e = stid2entry(t, tid);
	if ((void *)e->next >= (void *)t->tid_tab &&
	    (void *)e->next < (void *)&t->atid_tab[t->natids])
		return NULL;

	return &e->t3c_tid;
}

/*
 * Find the connection corresponding to an active-open TID.
 */
static inline struct t3c_tid_entry *lookup_atid(const struct tid_info *t,
						unsigned int tid)
{
	union active_open_entry *e;

	if (tid < t->atid_base || tid >= t->atid_base + t->natids)
		return NULL;

	e = atid2entry(t, tid);
	if ((void *)e->next >= (void *)t->tid_tab &&
	    (void *)e->next < (void *)&t->atid_tab[t->natids])
		return NULL;

	return &e->t3c_tid;
}

int process_rx(struct t3cdev *dev, struct sk_buff **skbs, int n);
int attach_t3cdev(struct t3cdev *dev);
void detach_t3cdev(struct t3cdev *dev);
#endif
