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

#include <linux/netdevice.h>
#include <net/sock.h>
#include <linux/toedev.h>
#include <linux/if_vlan.h>
#include <linux/version.h>
#include <net/ip.h>

#include <drivers/net/bonding/bonding.h>
#include <drivers/net/bonding/bond_3ad.h>

#include "toe_bonding.h"

#include "toe_compat.h"

/*
 * Bonding for TOE.
 * Limitation(s):
 *	The slaves of a bonding device share the same TOEDEV:
 *	They are either ports of the same adapter,
 *	or bonding devices themselves.
 */

/* Adapted from drivers/net/bonding/bond_main.c:bond_xmit_activebackup() */
static struct net_device * toe_bond_acb_select(struct net_device *dev,
					       int context)
{
	struct bonding *bond = (struct bonding *)netdev_priv(dev);
	struct net_device *slave_dev = NULL;

	if (context == TOE_OPEN) {
		read_lock(&bond->lock);
		read_lock(&bond->curr_slave_lock);
	}

	if (!BOND_IS_OK(bond))
		goto out;

	if (!bond->curr_active_slave)
		goto out;

	slave_dev = bond->curr_active_slave->dev;

out:
	if (context == TOE_OPEN) {
		read_unlock(&bond->curr_slave_lock);
		read_unlock(&bond->lock);
	}
	return (slave_dev);
}

/* XXX */
static struct net_device * toe_bond_xor_select(struct net_device *dev, int context)
{
	struct bonding *bond = (struct bonding *)netdev_priv(dev);
	struct net_device *slave_dev = NULL;
	struct slave *slave, *start_at;
	int    slave_no, i;
	static int xor_select_cntr = 0;

	if (context == TOE_OPEN)
		read_lock(&bond->lock);

	if (!BOND_IS_OK(bond)) {
		goto out;
	}

	slave_no = xor_select_cntr++ % bond->slave_cnt;

	bond_for_each_slave(bond, slave, i) {
		slave_no--;
		if (slave_no < 0)
			break;
	}

	start_at = slave;

	bond_for_each_slave_from(bond, slave, i, start_at) {
		if (IS_UP(slave->dev) && (slave->link == BOND_LINK_UP) &&
		    (slave->state == BOND_STATE_ACTIVE)) {
			slave_dev = slave->dev;
			break;
		}
	}

out:
	if (context == TOE_OPEN)
		read_unlock(&bond->lock);
	return slave_dev;
}

/* Adapted from drivers/net/bonding/bond_3ad.c:__get_bond_by_port() */
static inline struct bonding *toe_bond_get_bond_by_port(struct port *port)
{
	if (port->slave == NULL) {
		return NULL;
	}

	return bond_get_bond_by_slave(port->slave);
}

/* Adapted from drivers/net/bonding/bond_3ad.c:__get_first_port() */
static inline struct port *toe_bond_get_first_port(struct bonding *bond)
{
	if (bond->slave_cnt == 0)
		return NULL;

	return &(SLAVE_AD_INFO(bond->first_slave).port);
}

/* Adapted from drivers/net/bonding/bond_3ad.c:__get_next_port() */
static inline struct port *toe_bond_get_next_port(struct port *port)
{
	struct bonding *bond = toe_bond_get_bond_by_port(port);
	struct slave *slave = port->slave;

	// If there's no bond for this port, or this is the last slave
	if ((bond == NULL) || (slave->next == bond->first_slave))
		return NULL;

	return &(SLAVE_AD_INFO(slave->next).port);
}

/* Adapted from
 * drivers/net/bonding/bond_3ad.c:bond_3ad_get_active_agg_info() */
static int toe_bond_3ad_get_active_agg_info(struct bonding *bond,
					    struct ad_info *ad_info)
{
	struct aggregator *aggregator = NULL;
	struct port *port;

	for (port = toe_bond_get_first_port(bond); port;
	     port = toe_bond_get_next_port(port))
	{
		if (port->aggregator && port->aggregator->is_active) {
			aggregator = port->aggregator;
			break;
		}
	}

	if (aggregator) {
		ad_info->aggregator_id = aggregator->aggregator_identifier;
		ad_info->ports = aggregator->num_of_ports;
		ad_info->actor_key = aggregator->actor_oper_aggregator_key;
		ad_info->partner_key = aggregator->partner_oper_aggregator_key;
		memcpy(ad_info->partner_system,
		       aggregator->partner_system.mac_addr_value, ETH_ALEN);
		return 0;
	}

	return -1;
}

/* Adapted from drivers/net/bonding/bond_3ad.c:bond_3ad_xmit_xor() */
static struct net_device * toe_bond_8023AD_select(struct net_device *dev,
					   	  int context)
{
	struct bonding *bond = (struct bonding *)netdev_priv(dev);
	struct net_device *slave_dev = NULL;
	struct slave *slave, *start_at;
	static int slave_counter = 0;
	int slave_agg_no;
	int slaves_in_agg;
	int agg_id;
	struct ad_info ad_info;
	int i, found = 0;

	if (context == TOE_OPEN)
		read_lock(&bond->lock);

	if (!BOND_IS_OK(bond)) {
		goto out;
	}

	if (toe_bond_3ad_get_active_agg_info(bond, &ad_info)) {
		printk("%s: %s: Error: bond_3ad_get_active_agg_info failed\n",
		       __func__, dev->name);
		goto out;
	}

	slaves_in_agg = ad_info.ports;
	agg_id = ad_info.aggregator_id;

	if (slaves_in_agg == 0) {
		/*the aggregator is empty*/
		printk("%s: %s: Error: active aggregator is empty\n",
		       __func__, dev->name);
		goto out;
	}

	slave_counter++;
	slave_agg_no = (slave_counter %= slaves_in_agg);
	
	bond_for_each_slave(bond, slave, i) {
		struct aggregator *agg = SLAVE_AD_INFO(slave).port.aggregator;

		if (agg && (agg->aggregator_identifier == agg_id)) {
			slave_agg_no--;
			if (slave_agg_no < 0) {
				break;
			}
		}
	}

	if (slave_agg_no >= 0) {
		printk(KERN_ERR DRV_NAME ": %s: Error: Couldn't find a slave "
		       "to tx on for aggregator ID %d\n", dev->name, agg_id);
		goto out;
	}

	start_at = slave;

	bond_for_each_slave_from(bond, slave, i, start_at) {
		int slave_agg_id = 0;
		struct aggregator *agg = SLAVE_AD_INFO(slave).port.aggregator;

		if (agg) {
			slave_agg_id = agg->aggregator_identifier;
		}

		found = (SLAVE_IS_OK(slave) && agg &&
			 (slave_agg_id == agg_id));
		if (found) {
			slave_dev = slave->dev;
			break;
		}
	}

out:
	if (context == TOE_OPEN)
		read_unlock(&bond->lock);

	return slave_dev;
}

/* XXX */
static struct net_device * toe_bond_tlb_select(struct net_device *dev,
					       int context)
{
	return NULL;
}

/* XXX */
static struct net_device * toe_bond_alb_select(struct net_device *dev,
					       int context)
{
	return NULL;
}

struct net_device * toe_bond_get_slave(struct net_device *dev,
				       struct sock *sk, int context)
{
	struct bonding *bond = (struct bonding *)netdev_priv(dev);

	switch (bond->params.mode) {
	case BOND_MODE_ROUNDROBIN:
		dev = NULL;
		break;
	case BOND_MODE_ACTIVEBACKUP:
		dev = toe_bond_acb_select(dev, context);
		break;
	case BOND_MODE_XOR:
		dev = toe_bond_xor_select(dev, context);
		break;
	case BOND_MODE_8023AD:
		dev = toe_bond_8023AD_select(dev, context);
		break;
	case BOND_MODE_TLB:
		dev = toe_bond_tlb_select(dev, context);
		break;
	case BOND_MODE_ALB:
		dev = toe_bond_alb_select(dev, context);
		break;
	}

	return dev;
}


void toe_bond_neigh_propagate(struct net_device *dev, struct neighbour *neigh)
{
	struct bonding *bond = (struct bonding *)netdev_priv(dev);
	struct slave *slave, *start_at;
	int i;

	slave = start_at = bond->first_slave;
	bond_for_each_slave_from(bond, slave, i, start_at) {
		struct toedev *tdev = TOEDEV(slave->dev);

		/* Slave is a bonding device */
		if (slave->dev->flags & IFF_MASTER)
			toe_bond_neigh_propagate(slave->dev, neigh);

		/* Slave is a physical device. */
		else if (netdev_is_offload(dev) && tdev)
			tdev->neigh_update(tdev, neigh);
	}
}
