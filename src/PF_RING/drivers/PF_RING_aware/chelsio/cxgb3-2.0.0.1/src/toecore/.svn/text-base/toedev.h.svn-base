/*
 * Network offload device definitions.
 *
 * Copyright (C) 2003-2009 Chelsio Communications.  All rights reserved.
 *
 * Written by Dimitris Michailidis (dm@chelsio.com)
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

#ifndef _OFFLOAD_DEV_H_
#define _OFFLOAD_DEV_H_

struct neighbour;

/* Parameter values for offload_get_phys_egress() */
enum {
	TOE_OPEN,
	TOE_FAILOVER,
};

/* Parameter values for toe_failover() */
enum {
	TOE_ACTIVE_SLAVE,
	TOE_LINK_DOWN,
	TOE_LINK_UP,
	TOE_RELEASE,
	TOE_RELEASE_ALL,
	TOE_BOND_DOWN,
	TOE_BOND_UP,
};

#if defined(CONFIG_TCP_OFFLOAD) || defined(CONFIG_TCP_OFFLOAD_MODULE)
#include <linux/list.h>
#include <linux/netdevice.h>

#define TOENAMSIZ 16

/* belongs in linux/if.h */
#define IFF_OFFLOAD_TCPIP  (1 << 14)
#define IFF_OFFLOAD_TCPIP6 (1 << 15)

/* Get the toedev associated with a net_device */
#define TOEDEV(netdev) (*(struct toedev **)&(netdev)->ec_ptr)

/* offload type ids */
enum {
	TOE_ID_CHELSIO_T1 = 1,
	TOE_ID_CHELSIO_T1C,
	TOE_ID_CHELSIO_T2,
	TOE_ID_CHELSIO_T3,
	TOE_ID_CHELSIO_T3B,
	TOE_ID_CHELSIO_T3C,
};

struct offload_id {
	unsigned int id;
	unsigned long data;
};

struct net_device;
struct tom_info;
struct proc_dir_entry;
struct sock;
struct sk_buff;

struct toedev {
	char name[TOENAMSIZ];       /* TOE device name */
	struct list_head toe_list;  /* for list linking */
	unsigned int ttid;          /* TOE type id */
	unsigned long flags;        /* device flags */
	unsigned int mtu;           /* max size of TX offloaded data */
	unsigned int nconn;         /* max # of offloaded connections */
	unsigned int nlldev;        /* # of associated Ethernet devices */
	struct net_device **lldev;  /* associated LL devices */
	const struct tom_info *offload_mod; /* attached TCP offload module */
	struct offload_policy *policy;
	struct proc_dir_entry *proc_dir;    /* root of proc dir for this TOE */
	int (*open)(struct toedev *dev);
	int (*close)(struct toedev *dev);
	int (*can_offload)(struct toedev *dev, struct sock *sk);
	int (*connect)(struct toedev *dev, struct sock *sk,
		       struct net_device *egress_dev);
	int (*send)(struct toedev *dev, struct sk_buff *skb);
	int (*recv)(struct toedev *dev, struct sk_buff **skb, int n);
	int (*ctl)(struct toedev  *tdev, unsigned int req, void *data);
	void (*neigh_update)(struct toedev *dev, struct neighbour *neigh);
	void (*failover)(struct toedev *dev, struct net_device *bond_dev,
			 struct net_device *ndev, int event, struct net_device *last);
	void *priv;                 /* driver private data */
	void *l2opt;                /* optional layer 2 data */
	void *l3opt;                /* optional layer 3 data */
	void *l4opt;                /* optional layer 4 data */
	void *ulp;                  /* ulp stuff */
};

struct tom_info {
	int (*attach)(struct toedev *dev, const struct offload_id *entry);
	int (*detach)(struct toedev *dev);
	const char *name;
	const struct offload_id *id_table;
	struct list_head list_node;
};

static inline void init_offload_dev(struct toedev *dev)
{
	INIT_LIST_HEAD(&dev->toe_list);
}

static inline int netdev_is_offload(const struct net_device *dev)
{
	return dev->priv_flags & IFF_OFFLOAD_TCPIP;
}

static inline void netdev_set_offload(struct net_device *dev)
{
	dev->priv_flags |= IFF_OFFLOAD_TCPIP;
}

static inline void netdev_clear_offload(struct net_device *dev)
{
	dev->priv_flags &= ~IFF_OFFLOAD_TCPIP;
}

extern int tcp_sack_enabled(void);
extern int tcp_timestamps_enabled(void);
extern int tcp_win_scaling_enabled(void);
extern int tcp_ecn_enabled(void);
extern int register_tom(struct tom_info *t);
extern int unregister_tom(struct tom_info *t);
extern int register_toedev(struct toedev *dev, const char *name);
extern int unregister_toedev(struct toedev *dev);
extern int activate_offload(struct toedev *dev);
extern int deactivate_offload(struct toedev *dev);
extern int toe_send(struct toedev *dev, struct sk_buff *skb);
extern struct net_device *offload_get_phys_egress(struct net_device *dev,
						  struct sock *sk,
						  int context);
#endif

#if defined(CONFIG_TCP_OFFLOAD_MODULE)
extern int *sysctl_tcp_sack_p;
extern int *sysctl_tcp_timestamps_p;
extern int *sysctl_tcp_window_scaling_p;

static inline int toe_receive_skb(struct toedev *dev, struct sk_buff **skb,
				  int n)
{
	return dev->recv(dev, skb, n);
}

extern int  prepare_tcp_for_offload(void);
extern void restore_tcp_to_nonoffload(void);
#elif defined(CONFIG_TCP_OFFLOAD)
extern int toe_receive_skb(struct toedev *dev, struct sk_buff **skb, int n);
#endif

#if defined(CONFIG_TCP_OFFLOAD) || \
    (defined(CONFIG_TCP_OFFLOAD_MODULE) && defined(MODULE))
extern void toe_neigh_update(struct neighbour *neigh);
extern int toe_failover(struct net_device *bond_dev,
			 struct net_device *fail_dev, int event,
			 struct net_device *last_dev);
extern int toe_enslave(struct net_device *bond_dev,
		       struct net_device *slave_dev);
#else
static inline void toe_neigh_update(struct neighbour *neigh) {}
static inline int toe_failover(struct net_device *bond_dev,
				struct net_device *fail_dev, int event,
				struct net_device *last_dev);
{}
static inline int toe_enslave(struct net_device *bond_dev,
			      struct net_device *slave_dev)
{
	return 0;
}
#endif /* CONFIG_TCP_OFFLOAD */

#endif /* _OFFLOAD_DEV_H_ */
