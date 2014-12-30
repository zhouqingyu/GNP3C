/*
 * Copyright(c) 2008 Hewlett-Packard Development Company, L.P.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 * The full GNU General Public License is included in this distribution in the
 * file called LICENSE.
 *
 */

#include <linux/types.h>
#include <linux/if_vlan.h>
#include <net/ipv6.h>
#include <net/ndisc.h>
#include <net/addrconf.h>
#include "bonding.h"
#include "bonding_ipv6_ops.h"

/*
 * Assign bond->master_ipv6 to the next IPv6 address in the list, or
 * zero it out if there are none.
 */
static void bond_glean_dev_ipv6(struct net_device *dev, struct in6_addr *addr)
{
	struct inet6_dev *idev;
	struct inet6_ifaddr *ifa;

	down_read(&bonding_ipv6_ops_sem);
	if (!bonding_ipv6_ops->in6_dev_put)
		goto out;

	if (!dev)
		goto out;

	idev = in6_dev_get(dev);
	if (!idev)
		goto out;

	read_lock_bh(&idev->lock);
	ifa = idev->addr_list;
	if (ifa)
		ipv6_addr_copy(addr, &ifa->addr);
	else
		ipv6_addr_set(addr, 0, 0, 0, 0);

	read_unlock_bh(&idev->lock);

	bonding_ipv6_ops->in6_dev_put(idev);

out:
	up_read(&bonding_ipv6_ops_sem);
}

static void bond_na_send(struct net_device *slave_dev,
			 struct in6_addr *daddr,
			 int router,
			 unsigned short vlan_id)
{
	struct in6_addr mcaddr;
	struct icmp6hdr icmp6h = {
		.icmp6_type = NDISC_NEIGHBOUR_ADVERTISEMENT,
	};
	struct sk_buff *skb;

	icmp6h.icmp6_router = router;
	icmp6h.icmp6_solicited = 0;
	icmp6h.icmp6_override = 1;

	addrconf_addr_solict_mult(daddr, &mcaddr);

	pr_debug("ipv6 na on slave %s: dest %pI6, src %pI6\n",
	       slave_dev->name, &mcaddr, daddr);

	skb = bonding_ipv6_ops->ndisc_build_skb(slave_dev, &mcaddr, daddr, &icmp6h, daddr,
			      ND_OPT_TARGET_LL_ADDR);

	if (!skb) {
		pr_err(DRV_NAME ": NA packet allocation failed\n");
		return;
	}

	if (vlan_id) {
		skb = vlan_put_tag(skb, vlan_id);
		if (!skb) {
			pr_err(DRV_NAME ": failed to insert VLAN tag\n");
			return;
		}
	}

	bonding_ipv6_ops->ndisc_send_skb(skb, slave_dev, NULL, &mcaddr, daddr, &icmp6h);
}

/*
 * Kick out an unsolicited Neighbor Advertisement for an IPv6 address on
 * the bonding master.  This will help the switch learn our address
 * if in active-backup mode.
 *
 * Caller must hold curr_slave_lock for read or better
 */
void bond_send_unsolicited_na(struct bonding *bond)
{
	struct slave *slave = bond->curr_active_slave;
	struct vlan_entry *vlan;
	struct inet6_dev *idev;
	int is_router;

	down_read(&bonding_ipv6_ops_sem);
	if (!bonding_ipv6_ops->in6_dev_put)
		goto out;

	pr_debug("bond_send_unsol_na: bond %s slave %s\n", bond->dev->name,
				slave ? slave->dev->name : "NULL");

	if (!slave || !bond->send_unsol_na ||
	    test_bit(__LINK_STATE_LINKWATCH_PENDING, &slave->dev->state))
		goto out;

	bond->send_unsol_na--;


	idev = in6_dev_get(bond->dev);
	if (!idev)
		goto out;

	is_router = !!idev->cnf.forwarding;

	bonding_ipv6_ops->in6_dev_put(idev);

	if (!ipv6_addr_any(&bond->master_ipv6))
		bond_na_send(slave->dev, &bond->master_ipv6, is_router, 0);

	list_for_each_entry(vlan, &bond->vlan_list, vlan_list) {
		if (!ipv6_addr_any(&vlan->vlan_ipv6)) {
			bond_na_send(slave->dev, &vlan->vlan_ipv6, is_router,
				     vlan->vlan_id);
		}
	}
out:
	up_read(&bonding_ipv6_ops_sem);
}

/*
 * bond_inet6addr_event: handle inet6addr notifier chain events.
 *
 * We keep track of device IPv6 addresses primarily to use as source
 * addresses in NS probes.
 *
 * We track one IPv6 for the main device (if it has one).
 */
static int bond_inet6addr_event(struct notifier_block *this,
				unsigned long event,
				void *ptr)
{
	struct inet6_ifaddr *ifa = ptr;
	struct net_device *vlan_dev, *event_dev = ifa->idev->dev;
	struct bonding *bond;
	struct vlan_entry *vlan;

	if (dev_net(event_dev) != &init_net)
		return NOTIFY_DONE;

	list_for_each_entry(bond, &bond_dev_list, bond_list) {
		if (bond->dev == event_dev) {
			switch (event) {
			case NETDEV_UP:
				if (ipv6_addr_any(&bond->master_ipv6))
					ipv6_addr_copy(&bond->master_ipv6,
						       &ifa->addr);
				return NOTIFY_OK;
			case NETDEV_DOWN:
				if (ipv6_addr_equal(&bond->master_ipv6,
						    &ifa->addr))
					bond_glean_dev_ipv6(bond->dev,
							    &bond->master_ipv6);
				return NOTIFY_OK;
			default:
				return NOTIFY_DONE;
			}
		}

		list_for_each_entry(vlan, &bond->vlan_list, vlan_list) {
			vlan_dev = vlan_group_get_device(bond->vlgrp,
							 vlan->vlan_id);
			if (vlan_dev == event_dev) {
				switch (event) {
				case NETDEV_UP:
					if (ipv6_addr_any(&vlan->vlan_ipv6))
						ipv6_addr_copy(&vlan->vlan_ipv6,
							       &ifa->addr);
					return NOTIFY_OK;
				case NETDEV_DOWN:
					if (ipv6_addr_equal(&vlan->vlan_ipv6,
							    &ifa->addr))
						bond_glean_dev_ipv6(vlan_dev,
								    &vlan->vlan_ipv6);
					return NOTIFY_OK;
				default:
					return NOTIFY_DONE;
				}
			}
		}
	}
	return NOTIFY_DONE;
}

static struct notifier_block bond_inet6addr_notifier = {
	.notifier_call = bond_inet6addr_event,
};

void bond_register_ipv6_notifier(void)
{
	down_read(&bonding_ipv6_ops_sem);
	bonding_ipv6_ops->register_inet6addr_notifier(&bond_inet6addr_notifier);
	up_read(&bonding_ipv6_ops_sem);
}

void bond_unregister_ipv6_notifier(void)
{
	down_read(&bonding_ipv6_ops_sem);
	bonding_ipv6_ops->unregister_inet6addr_notifier(&bond_inet6addr_notifier);
	up_read(&bonding_ipv6_ops_sem);
}

