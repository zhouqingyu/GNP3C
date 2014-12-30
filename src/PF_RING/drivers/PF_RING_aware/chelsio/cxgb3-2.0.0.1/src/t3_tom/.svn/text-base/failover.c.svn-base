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

#include "defs.h"
#include <linux/toedev.h>

#include "tom.h"
#include "cpl_io_state.h"
#include "t3_cpl.h"
#include "cxgb3_ctl_defs.h"
#include "firmware_exports.h"

#include <drivers/net/bonding/bonding.h>

/* Adapted from drivers/net/bonding/bond_3ad.c:__get_bond_by_port() */
static inline struct bonding *toe_bond_get_bond_by_port(struct port *port)
{
	if (port->slave == NULL)
		return NULL;

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

	/* If there's no bond for this port, or this is the last slave */
	if ((bond == NULL) || (slave->next == bond->first_slave))
		return NULL;

	return &(SLAVE_AD_INFO(slave->next).port);
}

static inline int total_ports(struct toedev *tdev)
{
	struct adap_ports *port_info = TOM_DATA(tdev)->ports;

	return port_info->nports;
}

static inline int lookup_port(struct net_device *slave_dev)
{
	int i, port = -1;
	struct toedev *tdev = TOEDEV(slave_dev);
	struct adap_ports *port_info = TOM_DATA(tdev)->ports;

	for (i = 0; i < port_info->nports; i++) {
		if (slave_dev != port_info->lldevs[i])
			continue;

		port = i;
		break;
	}
	return port;
}

static inline int lld_evt(int event)
{
	return event + FAILOVER_ACTIVE_SLAVE;
}

static void four_ports_failover(struct toedev *tdev,
				struct net_device *bond_dev,
				struct net_device *slave_dev,
				int event)
{
	struct bond_ports bond_ports;
	struct bonding *bond = (struct bonding *)netdev_priv(bond_dev);
	struct slave *slave = NULL;
	int port_idx,  idx = 0, i;
	struct port *port;

	if (!slave_dev) /* bond release all */
		return;

	switch (bond->params.mode) {
	case BOND_MODE_ACTIVEBACKUP:
		/*
		 * Ignore release events.
		 * A new active slave might be picked up
		 * soon after, we just care about this.
		 */
		if (event != TOE_ACTIVE_SLAVE)
			return;

		port_idx = lookup_port(slave_dev);
		bond_ports.port = port_idx;
		bond_ports.nports = 0;

		bond_for_each_slave(bond, slave, i) {
			if (slave->dev != slave_dev) {
				bond_ports.ports[idx++] =
					lookup_port(slave->dev);
				bond_ports.nports++;
			}
		}
		tdev->ctl(tdev, lld_evt(event), &bond_ports);
		break;

	case BOND_MODE_8023AD:
		if (event == TOE_ACTIVE_SLAVE)
			return;

		port_idx = lookup_port(slave_dev);
		bond_ports.port = port_idx;
		bond_ports.nports = 0;

		for (port = toe_bond_get_first_port(bond); port;
		     port = toe_bond_get_next_port(port)) {
			if (port->slave->dev != slave_dev &&
			    port->slave->state == BOND_STATE_ACTIVE) {
				bond_ports.ports[idx++] =
					lookup_port(port->slave->dev);
				bond_ports.nports++;
			}
		}
		tdev->ctl(tdev, lld_evt(event), &bond_ports);
		break;

	case BOND_MODE_XOR:
		port_idx = lookup_port(slave_dev);
		bond_ports.port = port_idx;
		bond_ports.nports = 0;

		bond_for_each_slave(bond, slave, i) {
			if (slave->dev != slave_dev &&
			    slave->state == BOND_STATE_ACTIVE) {
				bond_ports.ports[idx++] =
					lookup_port(slave->dev);
				bond_ports.nports++;
			}
		}
		tdev->ctl(tdev, lld_evt(event), &bond_ports);
		break;
	}
	return;
}

static void failover(struct toedev *tdev,
		     struct net_device *bond_dev,
		     struct net_device *slave_dev,
		     int event)
{
	int failed_port, if_port = 0;

	if (event == TOE_LINK_DOWN) {
		failed_port = lookup_port(slave_dev);
		if_port = !failed_port;
		tdev->ctl(tdev, FAILOVER, &if_port);

	} else if (event == TOE_LINK_UP) {
		if_port = lookup_port(slave_dev);
		tdev->ctl(tdev, FAILOVER, &if_port);
	}

	return;
}

/* Called under bonding locks (bond_mii_monitor) */
int t3_failover(struct toedev *tdev, struct net_device *bond_dev,
		struct net_device *slave_dev, int event, struct net_device *last_dev)
{
	struct bonding *bond = (struct bonding *)netdev_priv(bond_dev);
	int active_ports = 0;
	struct port *port;
	int if_port;

	/* differentiate 4 ports and 2 ports adapters */
	if (tdev->nlldev > 2) {
		four_ports_failover(tdev, bond_dev, slave_dev, event);
		return 0;
	}

	/* Last slave removed. Map the event to a complete release */
	if (event == TOE_RELEASE && bond->slave_cnt == 1)
		event = TOE_RELEASE_ALL;

	switch (bond->params.mode) {
	case BOND_MODE_ACTIVEBACKUP:
		if (event == TOE_ACTIVE_SLAVE) {
			if (!slave_dev || bond->slave_cnt == 1)
				tdev->ctl(tdev, FAILOVER_CLEAR, NULL);
			else {
				if_port = lookup_port(slave_dev);
				tdev->ctl(tdev, FAILOVER, &if_port);
			}
		} else if (event == TOE_RELEASE_ALL)
			tdev->ctl(tdev, FAILOVER_CLEAR, NULL);
		break;
	case BOND_MODE_8023AD:
		if (event == TOE_ACTIVE_SLAVE)
			return 0;

		for (port = toe_bond_get_first_port(bond); port;
		     port = toe_bond_get_next_port(port))
			active_ports +=
				(port->slave->state == BOND_STATE_ACTIVE);

		/* One port enslaved only. Ignore failover events */
		if (bond->slave_cnt == 1)
			return 0;

		/* No more active port */
		if ((event == TOE_LINK_DOWN || event == TOE_RELEASE) &&
		    !active_ports) {
			tdev->ctl(tdev, FAILOVER_CLEAR, NULL);
			return 0;
		}

		/* Dead port back alive in a already active bond device */
		if (event == TOE_LINK_UP && active_ports > 1) {
			if_port = lookup_port(slave_dev);
			tdev->ctl(tdev, FAILOVER_DONE, &if_port);
			return 0;
		}
		/* fall through */
	case BOND_MODE_XOR:
		/* One port enslaved only. Ignore failover events */
		if (bond->slave_cnt == 1)
			return 0;

		failover(tdev, bond_dev, slave_dev, event);
	}
	return 0;
}

void t3_update_master_devs(struct toedev *tdev)
{
	int i;

	for (i = 0; i < tdev->nlldev; i++) {
		struct net_device *dev = tdev->lldev[i];

		if (dev->flags & IFF_SLAVE) {
			struct net_device *bond_dev = dev->master;
			struct bonding *bond = (struct bonding *)netdev_priv(bond_dev);
			struct toedev *slave_tdev = NULL;
			struct slave *slave;
			int i, ofld_cnt = 0;

			if (netdev_is_offload(bond_dev))
				continue;

			read_lock_bh(&bond->lock);
			bond_for_each_slave(bond, slave, i) {
				ofld_cnt += !!netdev_is_offload(slave->dev);

				if (!slave_tdev)
					slave_tdev = TOEDEV(slave->dev);
				else if (slave_tdev != TOEDEV(slave->dev)) {
					slave_tdev = NULL;
					break;
				}
			}
			read_unlock_bh(&bond->lock);

			if (ofld_cnt == bond->slave_cnt && slave_tdev)
				netdev_set_offload(bond_dev);
		}
	}
}
