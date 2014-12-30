/*
 * Copyright (C) 2003-2009 Chelsio Communications.  All rights reserved.
 *
 * Written by Divy Le Ray (divy@chelsio.com)
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */
#ifndef _TOE_BONDING_H
#define _TOE_BONDING_H

#if defined(BOND_SUPPORT)
#include "toe_compat.h"
#include <drivers/net/bonding/bonding.h>

static inline int is_bmode_supported(struct net_device *bond_dev)
{
	struct bonding *bond = (struct bonding *)netdev_priv(bond_dev);
	int ret = 0;

	switch (bond->params.mode) {
	case BOND_MODE_ACTIVEBACKUP:
	case BOND_MODE_8023AD:
	case BOND_MODE_XOR:
		ret = 1;
		break;
	case BOND_MODE_ROUNDROBIN:
	case BOND_MODE_TLB:
	case BOND_MODE_ALB:
		/* unsupported or not yet supported */
		break;
	}
	return ret;
}

static inline struct toedev * toe_bond_slave_toedev(struct net_device *bond_dev)
{
	struct bonding *bond = (struct bonding *)netdev_priv(bond_dev);
	struct slave *slave = bond->first_slave;
	struct net_device *slavedev;

	/* Do nothing if slaves are also bonding devices */
	if (slave && !(slave->dev->flags & IFF_MASTER)) {
		slavedev = slave->dev;
		if (slavedev->priv_flags & IFF_802_1Q_VLAN)
			slavedev = vlan_dev_real_dev(slavedev);
		return(TOEDEV(slavedev));
	}

	return NULL;
}

static inline int toe_bond_slavecnt(struct net_device *bond_dev)
{
	struct bonding *bond = (struct bonding *)netdev_priv(bond_dev);
	return bond->slave_cnt;
}

struct net_device * toe_bond_get_slave(struct net_device *dev,
				       struct sock *sk, int context);
void toe_bond_neigh_propagate(struct net_device *dev, struct neighbour *neigh);
#else
static inline int is_bmode_supported(struct net_device *bond_dev)
{
	return 0;
}

static inline struct toedev * toe_bond_slave_toedev(struct net_device *bond_dev)
{
	return NULL;
}

static inline struct net_device * toe_bond_get_slave(struct net_device *dev,
						     struct sock *sk,
						     int context)
{
	return NULL;
}

static inline int toe_bond_slavecnt(struct net_device *bond_dev)
{
	return 0;
}

void toe_bond_neigh_propagate(struct net_device *dev, struct neighbour *neigh)
{}
#endif
#endif /* _TOE_BONDING_H */
