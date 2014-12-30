/*
 * Copyright (C) 2003-2009 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */
#ifndef _T3CDEV_H_
#define _T3CDEV_H_

#include <linux/list.h>
#include <asm/atomic.h>
#include <linux/netdevice.h>
#include <linux/proc_fs.h>
#include <linux/skbuff.h>
#include <net/neighbour.h>

#define T3CNAMSIZ 16

struct cxgb3_client;

enum t3ctype {
	T3A = 0,
	T3B,
	T3C,
};

struct t3cdev {
	char name[T3CNAMSIZ];		    /* T3C device name */
	enum t3ctype type;
	struct list_head ofld_dev_list;	    /* for list linking */
	struct net_device *lldev;     /* LL dev associated with T3C messages */
	struct proc_dir_entry *proc_dir;    /* root of proc dir for this T3C */
	int (*send)(struct t3cdev *dev, struct sk_buff *skb);
	int (*recv)(struct t3cdev *dev, struct sk_buff **skb, int n);
	int (*ctl)(struct t3cdev *dev, unsigned int req, void *data);
	void (*neigh_update)(struct t3cdev *dev, struct neighbour *neigh);
	void *priv;                         /* driver private data */
	void *l2opt;                        /* optional layer 2 data */
	void *l3opt;                        /* optional layer 3 data */
	void *l4opt;                        /* optional layer 4 data */
	void *ulp;			    /* ulp stuff */
	void *ulp_iscsi;		    /* ulp iscsi */
};

#endif /* _T3CDEV_H_ */
