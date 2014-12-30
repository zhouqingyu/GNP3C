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

#include <linux/list.h>
#include <linux/notifier.h>
#include <asm/atomic.h>
#include <linux/proc_fs.h>
#include <linux/if_vlan.h>
#include <linux/highmem.h>
#include <linux/vmalloc.h>
#include <linux/netdevice.h>
#include <net/neighbour.h>

#if defined(CONFIG_XEN) && defined(CONFIG_XEN_TOE)
#include <net/bridge/br_private.h>
#endif

#include "common.h"
#include "regs.h"
#include "cxgb3_ioctl.h"
#include "cxgb3_ctl_defs.h"
#include "cxgb3_defs.h"
#include "l2t.h"
#include "firmware_exports.h"
#include "cxgb3_offload.h"

#include "cxgb3_compat.h"
#if defined(NETEVENT)
#include <net/netevent.h>
#endif


#if defined(CONFIG_TCP_OFFLOAD_MODULE)
#if defined(BOND_SUPPORT)
#include <drivers/net/bonding/bonding.h>
#endif
#include <linux/toedev.h>
#endif

static LIST_HEAD(client_list);
static LIST_HEAD(ofld_dev_list);
static DEFINE_MUTEX(cxgb3_db_lock);

/* Track # of adapters registered for offload */
static atomic_t registered_ofld_adapters = ATOMIC_INIT(0);

#ifndef RAW_NOTIFIER_HEAD
# define RAW_NOTIFIER_HEAD(name) struct notifier_block *name
# define raw_notifier_call_chain notifier_call_chain
# define raw_notifier_chain_register notifier_chain_register
# define raw_notifier_chain_unregister notifier_chain_unregister
#endif

static RAW_NOTIFIER_HEAD(offload_error_notify_list);
static DEFINE_MUTEX(notify_mutex);

int register_offload_error_notifier(struct notifier_block *nb)
{
        int err;

        mutex_lock(&notify_mutex);
        err = raw_notifier_chain_register(&offload_error_notify_list, nb);
        mutex_unlock(&notify_mutex);
        return err;
}
EXPORT_SYMBOL(register_offload_error_notifier);

int unregister_offload_error_notifier(struct notifier_block *nb)
{
        int err;

        mutex_lock(&notify_mutex);
        err = raw_notifier_chain_unregister(&offload_error_notify_list, nb);
        mutex_unlock(&notify_mutex);
        return err;
}
EXPORT_SYMBOL(unregister_offload_error_notifier);

#ifdef  LINUX_2_4
static unsigned int MAX_ATIDS = 64 * 1024;
#else
static const unsigned int MAX_ATIDS = 64 * 1024;
#endif  /* LINUX_2_4 */
static const unsigned int ATID_BASE = 0x10000;

static inline int offload_activated(struct t3cdev *tdev)
{
	struct adapter *adapter = tdev2adap(tdev);

	if (!cxgb3_filter_toe_mode(adapter, CXGB3_FTM_TOE)) {
		int i;
		printk(KERN_WARNING "Offload services disabled for adapter %s:"
		       " filters in use; ports:\n", tdev->name);
		for_each_port(adapter, i) {
			struct net_device *dev = adapter->port[i];
			printk(KERN_WARNING "    %d: %s\n", i, dev->name);
		}
		return 0;
	}
	return (test_bit(OFFLOAD_DEVMAP_BIT, &adapter->open_device_map));
}

int offload_error_notification(struct net_device *netdev, unsigned long error)
{
        struct t3cdev *tdev = dev2t3cdev(netdev);

        if (offload_activated(tdev)) {
                mutex_lock(&notify_mutex);
                raw_notifier_call_chain(&offload_error_notify_list, error, tdev);
                mutex_unlock(&notify_mutex);
        }
        return 0;
}
EXPORT_SYMBOL(offload_error_notification);

/**
 *	cxgb3_register_client - register an offload client
 *	@client: the client
 *
 *	Add the client to the client list,
 *	and call backs the client for each activated offload device
 */
void cxgb3_register_client(struct cxgb3_client *client)
{
	struct t3cdev *tdev;

	mutex_lock(&cxgb3_db_lock);
	list_add_tail(&client->client_list, &client_list);

	if (client->add) {
		list_for_each_entry(tdev, &ofld_dev_list, ofld_dev_list) {
			if (offload_activated(tdev))
				client->add(tdev);
		}
	}
	mutex_unlock(&cxgb3_db_lock);
}
EXPORT_SYMBOL(cxgb3_register_client);

/**
 *	cxgb3_unregister_client - unregister an offload client
 *	@client: the client
 *
 *	Remove the client to the client list,
 *	and call backs the client for each activated offload device.
 */
void cxgb3_unregister_client(struct cxgb3_client *client)
{
	struct t3cdev *tdev;

	mutex_lock(&cxgb3_db_lock);
	list_del(&client->client_list);

	if (client->remove) {
		list_for_each_entry(tdev, &ofld_dev_list, ofld_dev_list) {
			if (offload_activated(tdev))
				client->remove(tdev);
		}
	}
	mutex_unlock(&cxgb3_db_lock);
}
EXPORT_SYMBOL(cxgb3_unregister_client);

/* Get the t3cdev associated with a net_device */
struct t3cdev *dev2t3cdev(struct net_device *dev)
{
	const struct port_info *pi = netdev_priv(dev);

	return (struct t3cdev *)pi->adapter;
}
EXPORT_SYMBOL(dev2t3cdev);

/**
 *	cxgb3_add_clients - activate register clients for an offload device
 *	@tdev: the offload device
 *
 *	Call backs all registered clients once a offload device is activated
 */
void cxgb3_add_clients(struct t3cdev *tdev)
{
	struct cxgb3_client *client;

	mutex_lock(&cxgb3_db_lock);
	list_for_each_entry(client, &client_list, client_list) {
		if (client->add)
			client->add(tdev);
	}
	mutex_unlock(&cxgb3_db_lock);
}

/**
 *	cxgb3_remove_clients - activate register clients for an offload device
 *	@tdev: the offload device
 *
 *	Call backs all registered clients once a offload device is deactivated
 */
void cxgb3_remove_clients(struct t3cdev *tdev)
{
	struct cxgb3_client *client;

	mutex_lock(&cxgb3_db_lock);
	list_for_each_entry(client, &client_list, client_list) {
		if (client->remove)
			client->remove(tdev);
	}
	mutex_unlock(&cxgb3_db_lock);
}

/**
 *	cxgb3_err_notify - notifies a device failure to the registered clients
 *	@tdev: the offload device
 *	@status: H/W status: up or down
 *	@error: error identifier
 *
 *	Call backs all registered clients if the ASIC gets reset on a fatal error
 */
void cxgb3_err_notify(struct t3cdev *tdev, u32 status, u32 error)
{
	struct cxgb3_client *client;

	mutex_lock(&cxgb3_db_lock);
	list_for_each_entry(client, &client_list, client_list) {
		/*
		 * restricted to TOM at this point,
		 * until iSCSI and iWARP catch up
		 */
		if (client->name && strcmp(client->name, "tom_cxgb3") == 0 &&
		    client->event_handler)
			client->event_handler(tdev, status, error);
	}
	mutex_unlock(&cxgb3_db_lock);
}

#if defined(CONFIG_XEN) && defined(CONFIG_XEN_TOE)
/**
 *	is_vif - return TRUE if a device is a Xen virtual interface (VIF)
 *	@dev: the device to test for VIF status ...
 *
 *	N.B. Xen virtual interfaces (VIFs) have a few distinguishing
 *	features that we can use to try to determine whether we're
 *	looking at one.  Unfortunately there's noting _really_ defined
 *	for them so this is just a hueristic and we probably ought to
 *	think about a better predicate.  For right now we look for a
 *	name of "vif*" and a MAC address of fe:ff:ff:ff:ff:ff ...
 */
static int is_vif(struct net_device *dev)
{
	const char vifname[3] = "vif";
	const char vifmac[ETH_ALEN] = { 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff };

	return (memcmp(dev->name, vifname, sizeof(vifname)) == 0 &&
		memcmp(dev->dev_addr, vifmac, ETH_ALEN) == 0);
}

/**
 *	is_xenbrpif - return TRUE if we have the pysical interface (PIF)
 *	for a Xen bridge (XENBR)
 *
 *	@xenbr: the Xen bridge net device
 *	@pif: the physical interface net device
 *
 *	Search a Xen bridge's port interface list for the specified
 *	physical interface (PIF).  Return TRUE if found, FALSE
 *	otherwise.  There should be only a single PIF in a Xen bridge;
 *	if we find more than one we're not looking at a standard Xen
 *	bridge used to proxy for a PIF and we return FALSE.
 */
static int is_xenbrpif(struct net_device *xenbr,
		       struct net_device *pif)
{
	struct net_bridge *br = netdev_priv(xenbr);
	struct net_bridge_port *port;
	
	list_for_each_entry(port, &br->port_list, list) {
		struct net_device *portdev = port->dev;
		if (!is_vif(portdev))
			return (portdev == pif);
	}
	return 0;
}

struct net_device *get_xenbrpif(struct net_device *xenbr) {

	struct net_bridge *br = netdev_priv(xenbr);
	struct net_device *pif = NULL;
	struct net_bridge_port *port;
	
	list_for_each_entry(port, &br->port_list, list) {
		struct net_device *portdev = port->dev;
		if (!is_vif(portdev)) {
			if (pif)
				return NULL;
			pif = portdev;
		}
	}
	return pif;
}
#endif

#if defined(NETEVENT) || defined(OFLD_USE_KPROBES)
static struct t3cdev * dev2tdev(struct net_device *root_dev)
{
#if defined(CONFIG_TCP_OFFLOAD_MODULE)
	struct adapter *adapter;
#if defined(BOND_SUPPORT)
	struct bonding *bond;
#endif
	int port;

	if (!root_dev)
		return NULL;

	while (root_dev) {
		if (root_dev->priv_flags & IFF_802_1Q_VLAN)
			root_dev = vlan_dev_real_dev(root_dev);
#if defined(BOND_SUPPORT)
		else if (root_dev->flags & IFF_MASTER) {
			bond = (struct bonding *)netdev_priv(root_dev);
			/* We select the first child since we can only bond
			 * offload devices belonging to the same adapter.
			 */
			read_lock(&bond->lock);
			if (bond->first_slave)
				root_dev = bond->first_slave->dev;
			else
				root_dev = NULL;
			read_unlock(&bond->lock);
		}
#endif
#if defined(CONFIG_XEN) && defined(CONFIG_XEN_TOE)
		else if (root_dev->priv_flags & IFF_EBRIDGE)
			root_dev = get_xenbrdpif(root_dev);
#endif
		else
			break;
	}

	read_lock(&adapter_list_lock);
	list_for_each_entry(adapter, &adapter_list, adapter_list) {
		if (!is_offload(adapter))
			continue;
		for_each_port(adapter, port)
			if (root_dev == adapter->port[port]) {
				read_unlock(&adapter_list_lock);
				return dev2t3cdev(root_dev);
			}
	}
	read_unlock(&adapter_list_lock);

	return NULL;
#else
	return NULL;
#endif
}
#endif

static struct net_device *get_iff_from_mac(adapter_t *adapter,
					   const unsigned char *mac,
					   unsigned int vlan)
{
	int i;

	for_each_port(adapter, i) {
		struct vlan_group *grp;
		struct net_device *dev = adapter->port[i];
		const struct port_info *p = netdev_priv(dev);

		if (!memcmp(dev->dev_addr, mac, ETH_ALEN)) {
			if (vlan && vlan != VLAN_VID_MASK) {
				grp = p->vlan_grp;
				dev = grp ? vlan_group_get_device(grp, vlan) :
					    NULL;
			}
#if defined(CONFIG_XEN) && defined(CONFIG_XEN_TOE)
			else if (dev->br_port)
				dev = dev->br_port->br->dev;
#endif
			else
				while (dev->master)
					dev = dev->master;
			return dev;
		}
	}
	return NULL;
}

static inline void failover_fixup(adapter_t *adapter, int port)
{
	struct net_device *dev = adapter->port[port];
	struct port_info *p = netdev_priv(dev);
	struct cmac *mac = &p->mac;

	if (!netif_running(dev)) {
		/* Failover triggered by the interface ifdown */
		t3_write_reg(adapter, A_XGM_TX_CTRL + mac->offset,
			     F_TXEN);
		t3_read_reg(adapter, A_XGM_TX_CTRL + mac->offset);
	} else {
		/* Failover triggered by the interface link down */
		t3_write_reg(adapter, A_XGM_RX_CTRL + mac->offset, 0);
		t3_read_reg(adapter, A_XGM_RX_CTRL + mac->offset);
		t3_write_reg(adapter, A_XGM_RX_CTRL + mac->offset,
			     F_RXEN);
	}
}

static inline int in_bond(int port, struct bond_ports *bond_ports)
{
	int i;

	for (i = 0; i < bond_ports->nports; i++)
		if (port ==  bond_ports->ports[i])
			break;
	
	return (i < bond_ports->nports);
}

static int t3_4ports_failover(struct adapter *adapter, int event,
			      struct bond_ports *bond_ports)
{
	int port = bond_ports->port;
	struct t3cdev *tdev = &adapter->tdev;
	struct l2t_data *d = L2DATA(tdev);
	struct l2t_entry *e, *end;
	int nports = 0, port_idx;

	/* Reassign L2T entries */
	switch (event) {
	case FAILOVER_PORT_RELEASE:
	case FAILOVER_PORT_DOWN:
		read_lock_bh(&d->lock);
		port_idx = 0;
		nports = bond_ports->nports;
		for (e = &d->l2tab[1], end = d->rover;
		     e != end; ++e) {
			int newport;

			if (e->smt_idx == port) {
				newport = bond_ports->ports[port_idx];
				spin_lock_bh(&e->lock);
				e->smt_idx = newport;
				if (e->state == L2T_STATE_VALID)
					t3_l2t_update_l2e(tdev, e);
				spin_unlock_bh(&e->lock);
				port_idx = port_idx < nports ?
					   port_idx + 1 : 0;
			}
			/*
			 * If the port is released, update orig_smt_idx
			 * to failed over port.
			 * There are 2 situations:
			 * 1. Port X is the original port and is released.
			 * {orig_smt_idx, smt_idx} follows these steps.
			 * {X, X} -> {X, Y} -> {Y, Y}
			 * 2. Port Z is released, a failover from port X
			 * had happened previously.
			 * {orig_smt_idx, smt_idx} follows these steps:
			 * {X, Z} -> {Z, Z}
			 */
			if (event == FAILOVER_PORT_RELEASE &&
			    e->orig_smt_idx == port) {
				spin_lock_bh(&e->lock);
				e->orig_smt_idx = e->smt_idx;
				spin_unlock_bh(&e->lock);
			}
		}
		read_unlock_bh(&d->lock);
		break;
	case FAILOVER_PORT_UP:
		read_lock_bh(&d->lock);
		for (e = &d->l2tab[1], end = d->rover;
		     e != end; ++e) {
			if (e->orig_smt_idx == port &&
			    in_bond(e->smt_idx, bond_ports)) {
				spin_lock_bh(&e->lock);
				e->smt_idx = port;
				if (e->state == L2T_STATE_VALID)
					t3_l2t_update_l2e(tdev, e);
				spin_unlock_bh(&e->lock);
			}
		}
		read_unlock_bh(&d->lock);
		break;
	case FAILOVER_ACTIVE_SLAVE:
		read_lock_bh(&d->lock);
		for (e = &d->l2tab[1], end = d->rover;
		     e != end; ++e) {
			if (e->smt_idx != port &&
			    in_bond(e->smt_idx, bond_ports)) {
				spin_lock_bh(&e->lock);
				e->smt_idx = port;
				if (e->state == L2T_STATE_VALID)
					t3_l2t_update_l2e(tdev, e);
				spin_unlock_bh(&e->lock);
			}
		}
		read_unlock_bh(&d->lock);
		break;
	}
	return 0;
}

static int cxgb_ulp_iscsi_ctl(adapter_t *adapter, unsigned int req, void *data)
{
	int i;
	int ret = 0;
	unsigned int val = 0;
	struct ulp_iscsi_info *uiip = data;

	switch (req) {
	case ULP_ISCSI_GET_PARAMS:
		uiip->pdev = adapter->pdev;
		uiip->llimit = t3_read_reg(adapter, A_ULPRX_ISCSI_LLIMIT);
		uiip->ulimit = t3_read_reg(adapter, A_ULPRX_ISCSI_ULIMIT);
		uiip->tagmask = t3_read_reg(adapter, A_ULPRX_ISCSI_TAGMASK);

		val = t3_read_reg(adapter, A_ULPRX_ISCSI_PSZ);
		for (i = 0; i < 4; i++, val >>= 8)
			uiip->pgsz_factor[i] = val & 0xFF;

		val = t3_read_reg(adapter, A_TP_PARA_REG7);
		uiip->max_txsz =
		uiip->max_rxsz = min((val >> S_PMMAXXFERLEN0)&M_PMMAXXFERLEN0,
				     (val >> S_PMMAXXFERLEN1)&M_PMMAXXFERLEN1);

		/*
		 * On tx, the iscsi pdu has to be <= tx page size and has to
		 * fit into the Tx PM FIFO.
		 */
		val = min(adapter->params.tp.tx_pg_size,
			  t3_read_reg(adapter, A_PM1_TX_CFG) >> 17);
		uiip->max_txsz = min(val, uiip->max_txsz);

		/* set max. pdu size (MaxRxData) to 16224 */
		val = t3_read_reg(adapter, A_TP_PARA_REG2);
		if ((val >> S_MAXRXDATA) != 0x3f60) {
			val &= (M_RXCOALESCESIZE << S_RXCOALESCESIZE);
			val |= V_MAXRXDATA(0x3f60);
			printk(KERN_INFO
				"%s, iscsi set MaxRxData to 16224 (0x%x).\n",
				adapter->name, val);
			t3_write_reg(adapter, A_TP_PARA_REG2, val);
		}

		/*
		 * on rx, the iscsi pdu has to be < rx page size and the
		 * the max rx data length programmed in TP
		 */
		val = min(adapter->params.tp.rx_pg_size,
			  ((t3_read_reg(adapter, A_TP_PARA_REG2)) >>
				S_MAXRXDATA) & M_MAXRXDATA);
		uiip->max_rxsz = min(val, uiip->max_rxsz);
		break;
	case ULP_ISCSI_SET_PARAMS:
		t3_write_reg(adapter, A_ULPRX_ISCSI_TAGMASK, uiip->tagmask);
		/* program the ddp page sizes */
		for (val = 0, i = 0; i < 4; i++)
			val |= (uiip->pgsz_factor[i] & 0xF) << (8 * i);
		if (val && (val != t3_read_reg(adapter, A_ULPRX_ISCSI_PSZ))) {
			printk(KERN_INFO
			       "%s, setting iscsi pgsz 0x%x, %u,%u,%u,%u.\n",
				adapter->name, val, uiip->pgsz_factor[0],
				uiip->pgsz_factor[1], uiip->pgsz_factor[2],
				uiip->pgsz_factor[3]);
			t3_write_reg(adapter, A_ULPRX_ISCSI_PSZ, val);
		}
		break;
	default:
		ret = -EOPNOTSUPP;
	}
	return ret;
}

/* Response queue used for RDMA events. */
#define ASYNC_NOTIF_RSPQ 0

static int cxgb_rdma_ctl(adapter_t *adapter, unsigned int req, void *data)
{
	int ret = 0;

	switch (req) {
	case RDMA_GET_PARAMS: {
		struct rdma_info *req = data;
		struct pci_dev *pdev = adapter->pdev;

		req->udbell_physbase = pci_resource_start(pdev, 2);
		req->udbell_len = pci_resource_len(pdev, 2);
		req->tpt_base = t3_read_reg(adapter, A_ULPTX_TPT_LLIMIT);
		req->tpt_top  = t3_read_reg(adapter, A_ULPTX_TPT_ULIMIT);
		req->pbl_base = t3_read_reg(adapter, A_ULPTX_PBL_LLIMIT);
		req->pbl_top  = t3_read_reg(adapter, A_ULPTX_PBL_ULIMIT);
		req->rqt_base = t3_read_reg(adapter, A_ULPRX_RQ_LLIMIT);
		req->rqt_top  = t3_read_reg(adapter, A_ULPRX_RQ_ULIMIT);
		req->kdb_addr = adapter->regs + A_SG_KDOORBELL;
		req->pdev     = pdev;
		break;
	}
	case RDMA_CQ_OP: {
		unsigned long flags;
		struct rdma_cq_op *req = data;

		/* may be called in any context */
		spin_lock_irqsave(&adapter->sge.reg_lock, flags);
		ret = t3_sge_cqcntxt_op(adapter, req->id, req->op,
					req->credits);
		spin_unlock_irqrestore(&adapter->sge.reg_lock, flags);
		break;
	}
	case RDMA_GET_MEM: {
		struct ch_mem_range *t = data;
		struct mc7 *mem;

		if ((t->addr & 7) || (t->len & 7))
			return -EINVAL;
		if (t->mem_id == MEM_CM)
			mem = &adapter->cm;
		else if (t->mem_id == MEM_PMRX)
			mem = &adapter->pmrx;
		else if (t->mem_id == MEM_PMTX)
			mem = &adapter->pmtx;
		else
			return -EINVAL;

		ret = t3_mc7_bd_read(mem, t->addr/8, t->len/8, (u64 *)t->buf);
		if (ret)
			return ret;
		break;
	}
	case RDMA_CQ_SETUP: {
		struct rdma_cq_setup *req = data;
		unsigned long flags;

		spin_lock_irqsave(&adapter->sge.reg_lock, flags);
		ret = t3_sge_init_cqcntxt(adapter, req->id, req->base_addr,
					  req->size, ASYNC_NOTIF_RSPQ,
					  req->ovfl_mode, req->credits,
					  req->credit_thres);
		spin_unlock_irqrestore(&adapter->sge.reg_lock, flags);
		break;
	}
	case RDMA_CQ_DISABLE: {
		unsigned long flags;

		spin_lock_irqsave(&adapter->sge.reg_lock, flags);
		ret = t3_sge_disable_cqcntxt(adapter, *(unsigned int *)data);
		spin_unlock_irqrestore(&adapter->sge.reg_lock, flags);
		break;
	}
	case RDMA_CTRL_QP_SETUP: {
		struct rdma_ctrlqp_setup *req = data;
		unsigned long flags;

		spin_lock_irqsave(&adapter->sge.reg_lock, flags);
		ret = t3_sge_init_ecntxt(adapter, FW_RI_SGEEC_START, 0,
					 SGE_CNTXT_RDMA, ASYNC_NOTIF_RSPQ,
					 req->base_addr, req->size,
					 FW_RI_TID_START, 1, 0);
		spin_unlock_irqrestore(&adapter->sge.reg_lock, flags);
		break;
	}
	case RDMA_GET_MIB: {
		spin_lock(&adapter->stats_lock);
		t3_tp_get_mib_stats(adapter, (struct tp_mib_stats *)data);
		spin_unlock(&adapter->stats_lock);
		break;
	}
	default:
		ret = -EOPNOTSUPP;
	}
	return ret;
}

static int cxgb_offload_ctl(struct t3cdev *tdev, unsigned int req, void *data)
{
	struct adapter *adapter = tdev2adap(tdev);
	struct tid_range *tid;
	struct mtutab *mtup;
	struct iff_mac *iffmacp;
	struct ddp_params *ddpp;
	struct adap_ports *ports;
	struct port_array *pap;
	struct ofld_page_info *rx_page_info;
	struct tp_params *tp = &adapter->params.tp;
	struct bond_ports *bond_ports;
	int port;

	switch (req) {
	case GET_MAX_OUTSTANDING_WR:
		*(unsigned int *)data = FW_WR_NUM;
		break;
	case GET_WR_LEN:
		*(unsigned int *)data = WR_FLITS;
		break;
	case GET_TX_MAX_CHUNK:
		*(unsigned int *)data = 1 << 20;  /* 1MB */
		break;
	case GET_TID_RANGE:
		tid = data;
		tid->num = t3_mc5_size(&adapter->mc5) -
			adapter->params.mc5.nroutes -
			adapter->params.mc5.nfilters -
			adapter->params.mc5.nservers;
		tid->base = 0;
		break;
	case GET_STID_RANGE:
		tid = data;
		tid->num = adapter->params.mc5.nservers;
		tid->base = t3_mc5_size(&adapter->mc5) - tid->num -
			adapter->params.mc5.nfilters -
			adapter->params.mc5.nroutes;
		break;
	case GET_L2T_CAPACITY:
		*(unsigned int *)data = 2048;
		break;
	case GET_CPUIDX_OF_QSET: {
		unsigned int qset = *(unsigned int *)data;

		if (qset >= SGE_QSETS ||
		    adapter->rrss_map[qset] >= RSS_TABLE_SIZE)
			return -EINVAL;
		*(unsigned int *)data = adapter->rrss_map[qset];
		break;
	}
	case GET_PORT_SCHED: {
		struct port_sched *p = data;

		if (adapter->params.nports > 2) {
			const struct port_info *pi = netdev_priv(p->dev);
			p->sched = pi->port_id;
		} else
			p->sched = -1;
		break;
	}
	case GET_NUM_QUEUES:
		*(unsigned int *)data = adapter->sge.nqsets;
		break;
	case GET_MTUS:
		mtup = data;
		mtup->size = NMTUS;
		mtup->mtus = adapter->params.mtus;
		break;
	case GET_IFF_FROM_MAC:
		iffmacp = data;
		iffmacp->dev = get_iff_from_mac(adapter, iffmacp->mac_addr,
					  iffmacp->vlan_tag & VLAN_VID_MASK);
		break;
	case GET_DDP_PARAMS:
		ddpp = data;
		ddpp->llimit = t3_read_reg(adapter, A_ULPRX_TDDP_LLIMIT);
		ddpp->ulimit = t3_read_reg(adapter, A_ULPRX_TDDP_ULIMIT);
		ddpp->tag_mask = t3_read_reg(adapter, A_ULPRX_TDDP_TAGMASK);
		ddpp->pdev = adapter->pdev;
		break;
	case GET_PORTS:
		ports = data;
		ports->nports   = adapter->params.nports;
		for_each_port(adapter, port)
			ports->lldevs[port] = adapter->port[port];
		break;
	case GET_PORT_ARRAY:
		pap = data;
		pap->nports = adapter->params.nports;
		pap->lldevs = adapter->port;
		break;
	case FAILOVER:
		port = *(int *)data;
		t3_port_failover(adapter, port);
		failover_fixup(adapter, !port);
		break;
	case FAILOVER_DONE:
		port = *(int *)data;
		t3_failover_done(adapter, port);
		break;
	case FAILOVER_CLEAR:
		t3_failover_clear(adapter);
		break;
	case FAILOVER_ACTIVE_SLAVE:
	case FAILOVER_PORT_DOWN:
	case FAILOVER_PORT_UP:
	case FAILOVER_PORT_RELEASE:
		bond_ports = data;
		t3_4ports_failover(adapter, req, bond_ports);
		break;	
	case GET_RX_PAGE_INFO:
		rx_page_info = data;
		rx_page_info->page_size = tp->rx_pg_size;
		rx_page_info->num = tp->rx_num_pgs;
		break;
	case GET_ISCSI_IPV4ADDR: {
		struct iscsi_ipv4addr *p = data;
		struct port_info *pi = netdev_priv(p->dev);
		p->ipv4addr = pi->iscsi_ipv4addr;
		break;
	}
	case SET_ISCSI_IPV4ADDR: {
		struct iscsi_ipv4addr *p = data;
		struct port_info *pi = netdev_priv(p->dev);
		pi->iscsi_ipv4addr = p->ipv4addr;
		break;
	}
	case ULP_ISCSI_GET_PARAMS:
	case ULP_ISCSI_SET_PARAMS:
		if (!offload_running(adapter))
			return -EAGAIN;
		return cxgb_ulp_iscsi_ctl(adapter, req, data);
	case RDMA_GET_PARAMS:
	case RDMA_CQ_OP:
	case RDMA_CQ_SETUP:
	case RDMA_CQ_DISABLE:
	case RDMA_CTRL_QP_SETUP:
	case RDMA_GET_MEM:
	case RDMA_GET_MIB:
		if (!offload_running(adapter))
			return -EAGAIN;
		return cxgb_rdma_ctl(adapter, req, data);
	case GET_EMBEDDED_INFO: {
	struct ch_embedded_info *e = data;

		spin_lock(&adapter->stats_lock);
		t3_get_fw_version(adapter, &e->fw_vers);
		t3_get_tp_version(adapter, &e->tp_vers);
		spin_unlock(&adapter->stats_lock);

		break;
}
	default:
		return -EOPNOTSUPP;
	}
	return 0;
}

/*
 * Dummy handler for Rx offload packets in case we get an offload packet before
 * proper processing is setup.  This complains and drops the packet as it isn't
 * normal to get offload packets at this stage.
 */
static int rx_offload_blackhole(struct t3cdev *dev, struct sk_buff **skbs,
				int n)
{
	while (n--)
		kfree_skb(skbs[n]);
	return 0;
}

static void dummy_neigh_update(struct t3cdev *dev, struct neighbour *neigh)
{
}

void cxgb3_set_dummy_ops(struct t3cdev *dev)
{
	dev->recv         = rx_offload_blackhole;
	dev->neigh_update = dummy_neigh_update;
}

/*
 * Free an active-open TID.
 */
void *cxgb3_free_atid(struct t3cdev *tdev, int atid)
{
	struct tid_info *t = &(T3C_DATA(tdev))->tid_maps;
	union active_open_entry *p = atid2entry(t, atid);
	void *ctx = p->t3c_tid.ctx;

	spin_lock_bh(&t->atid_lock);
	p->t3c_tid.ctx = NULL;
	p->t3c_tid.client = NULL;
	p->next = t->afree;
	t->afree = p;
	t->atids_in_use--;
	spin_unlock_bh(&t->atid_lock);

	return ctx;
}
EXPORT_SYMBOL(cxgb3_free_atid);

/*
 * Free a server TID and return it to the free pool.
 */
void cxgb3_free_stid(struct t3cdev *tdev, int stid)
{
	struct tid_info *t = &(T3C_DATA(tdev))->tid_maps;
	union listen_entry *p = stid2entry(t, stid);

	spin_lock_bh(&t->stid_lock);
	p->t3c_tid.ctx = NULL;
	p->t3c_tid.client = NULL;
	p->next = t->sfree;
	t->sfree = p;
	t->stids_in_use--;
	spin_unlock_bh(&t->stid_lock);
}
EXPORT_SYMBOL(cxgb3_free_stid);

void cxgb3_insert_tid(struct t3cdev *tdev, struct cxgb3_client *client,
	void *ctx, unsigned int tid)
{
	struct tid_info *t = &(T3C_DATA(tdev))->tid_maps;

	t->tid_tab[tid].client = client;
	t->tid_tab[tid].ctx = ctx;
	atomic_inc(&t->tids_in_use);
}
EXPORT_SYMBOL(cxgb3_insert_tid);

/*
 * Populate a TID_RELEASE WR.  The skb must be already propely sized.
 */
static inline void mk_tid_release(struct sk_buff *skb, unsigned int tid)
{
	struct cpl_tid_release *req;

	skb->priority = CPL_PRIORITY_SETUP;
	req = (struct cpl_tid_release *)__skb_put(skb, sizeof(*req));
	req->wr.wr_hi = htonl(V_WR_OP(FW_WROPCODE_FORWARD));
	OPCODE_TID(req) = htonl(MK_OPCODE_TID(CPL_TID_RELEASE, tid));
}

DECLARE_TASK_FUNC(t3_process_tid_release_list, task_param)
{
	struct sk_buff *skb;
	struct t3c_data *td = WORK2T3CDATA(task_param, tid_release_task);
	struct t3cdev *tdev = td->dev;

	spin_lock_bh(&td->tid_release_lock);
	while (td->tid_release_list) {
		struct t3c_tid_entry *p = td->tid_release_list;

		td->tid_release_list = (struct t3c_tid_entry *)p->ctx;
		spin_unlock_bh(&td->tid_release_lock);

		skb = alloc_skb(sizeof(struct cpl_tid_release),
				GFP_KERNEL | __GFP_NOFAIL);

		mk_tid_release(skb, p - td->tid_maps.tid_tab);
		cxgb3_ofld_send(tdev, skb);
		p->ctx = NULL;
		spin_lock_bh(&td->tid_release_lock);
	}
	spin_unlock_bh(&td->tid_release_lock);
}

/* use ctx as a next pointer in the tid release list */
void cxgb3_queue_tid_release(struct t3cdev *tdev, unsigned int tid)
{
	struct t3c_data *td = T3C_DATA(tdev);
	struct t3c_tid_entry *p = &td->tid_maps.tid_tab[tid];

	spin_lock_bh(&td->tid_release_lock);
	p->ctx = (void *)td->tid_release_list;
	p->client = NULL;
	td->tid_release_list = p;
	if (!p->ctx)
		schedule_work(&td->tid_release_task);
	spin_unlock_bh(&td->tid_release_lock);
}
EXPORT_SYMBOL(cxgb3_queue_tid_release);

/*
 * Remove a tid from the TID table.  A client may defer processing its last
 * CPL message if it is locked at the time it arrives, and while the message
 * sits in the client's backlog the TID may be reused for another connection.
 * To handle this we atomically switch the TID association if it still points
 * to the original client context.
 */
void cxgb3_remove_tid(struct t3cdev *tdev, void *ctx, unsigned int tid)
{
	struct tid_info *t = &(T3C_DATA(tdev))->tid_maps;

	BUG_ON(tid >= t->ntids);
	if (tdev->type == T3A)
		(void)cmpxchg(&t->tid_tab[tid].ctx, ctx, NULL);
	else {
		struct sk_buff *skb;

		skb = alloc_skb(sizeof(struct cpl_tid_release), GFP_ATOMIC);
		if (likely(skb != NULL)) {
			mk_tid_release(skb, tid);
			cxgb3_ofld_send(tdev, skb);
			t->tid_tab[tid].ctx = NULL;
		} else
			cxgb3_queue_tid_release(tdev, tid);
	}
	atomic_dec(&t->tids_in_use);
}
EXPORT_SYMBOL(cxgb3_remove_tid);

int cxgb3_alloc_atid(struct t3cdev *tdev, struct cxgb3_client *client,
		     void *ctx)
{
	int atid = -1;
	struct tid_info *t = &(T3C_DATA(tdev))->tid_maps;

	spin_lock_bh(&t->atid_lock);
	if (t->afree &&
	    t->atids_in_use + atomic_read(&t->tids_in_use) + MC5_MIN_TIDS <=
	    t->ntids) {
		union active_open_entry *p = t->afree;

		atid = (p - t->atid_tab) + t->atid_base;
		t->afree = p->next;
		p->t3c_tid.ctx = ctx;
		p->t3c_tid.client = client;
		t->atids_in_use++;
	}
	spin_unlock_bh(&t->atid_lock);
	return atid;
}
EXPORT_SYMBOL(cxgb3_alloc_atid);

int cxgb3_alloc_stid(struct t3cdev *tdev, struct cxgb3_client *client,
		     void *ctx)
{
	int stid = -1;
	struct tid_info *t = &(T3C_DATA(tdev))->tid_maps;

	spin_lock_bh(&t->stid_lock);
	if (t->sfree) {
		union listen_entry *p = t->sfree;

		stid = (p - t->stid_tab) + t->stid_base;
		t->sfree = p->next;
		p->t3c_tid.ctx = ctx;
		p->t3c_tid.client = client;
		t->stids_in_use++;
	}
	spin_unlock_bh(&t->stid_lock);
	return stid;
}
EXPORT_SYMBOL(cxgb3_alloc_stid);

static int do_smt_write_rpl(struct t3cdev *dev, struct sk_buff *skb)
{
	struct cpl_smt_write_rpl *rpl = cplhdr(skb);

	if (rpl->status != CPL_ERR_NONE)
		printk(KERN_ERR
		       "Unexpected SMT_WRITE_RPL status %u for entry %u\n",
		       rpl->status, GET_TID(rpl));

	return CPL_RET_BUF_DONE;
}

static int do_l2t_write_rpl(struct t3cdev *dev, struct sk_buff *skb)
{
	struct cpl_l2t_write_rpl *rpl = cplhdr(skb);

	if (rpl->status != CPL_ERR_NONE)
		printk(KERN_ERR
		       "Unexpected L2T_WRITE_RPL status %u for entry %u\n",
		       rpl->status, GET_TID(rpl));

	return CPL_RET_BUF_DONE;
}

static int do_rte_write_rpl(struct t3cdev *dev, struct sk_buff *skb)
{
	struct cpl_rte_write_rpl *rpl = cplhdr(skb);

	if (rpl->status != CPL_ERR_NONE)
		printk(KERN_ERR
		       "Unexpected RTE_WRITE_RPL status %u for entry %u\n",
		       rpl->status, GET_TID(rpl));

	return CPL_RET_BUF_DONE;
}

static int do_act_open_rpl(struct t3cdev *dev, struct sk_buff *skb)
{
	struct cpl_act_open_rpl *rpl = cplhdr(skb);
	unsigned int atid = G_TID(ntohl(rpl->atid));
	struct t3c_tid_entry *t3c_tid;

	t3c_tid = lookup_atid(&(T3C_DATA(dev))->tid_maps, atid);
	if (t3c_tid && t3c_tid->ctx && t3c_tid->client &&
	    t3c_tid->client->handlers &&
	    t3c_tid->client->handlers[CPL_ACT_OPEN_RPL]) {
		return t3c_tid->client->handlers[CPL_ACT_OPEN_RPL] (dev, skb,
			t3c_tid->ctx);
	} else {
		CH_MSG(tdev2adap(dev), DEBUG, OFLD,
		       "%s: received clientless CPL command 0x%x\n",
			dev->name, CPL_ACT_OPEN_RPL);
		return CPL_RET_BUF_DONE | CPL_RET_BAD_MSG;
	}
}

static int do_stid_rpl(struct t3cdev *dev, struct sk_buff *skb)
{
	union opcode_tid *p = cplhdr(skb);
	unsigned int stid = G_TID(ntohl(p->opcode_tid));
	struct t3c_tid_entry *t3c_tid;
	const struct tid_info *t = &(T3C_DATA(dev))->tid_maps;

	/*
	 * We get these messages also when setting up HW filters.  Throw
	 * those away silently.
	 */
	if (stid >= t->stid_base + t->nstids)
		return CPL_RET_BUF_DONE;

	t3c_tid = lookup_stid(t, stid);
	if (t3c_tid && t3c_tid->ctx && t3c_tid->client->handlers &&
	    t3c_tid->client->handlers[p->opcode]) {
		return t3c_tid->client->handlers[p->opcode] (dev, skb, t3c_tid->ctx);
	} else {
		CH_MSG(tdev2adap(dev), DEBUG, OFLD,
		       "%s: received clientless CPL command 0x%x\n",
			dev->name, p->opcode);
		return CPL_RET_BUF_DONE | CPL_RET_BAD_MSG;
	}
}

static int do_hwtid_rpl(struct t3cdev *dev, struct sk_buff *skb)
{
	union opcode_tid *p = cplhdr(skb);
	unsigned int hwtid = G_TID(ntohl(p->opcode_tid));
	struct t3c_tid_entry *t3c_tid;

	t3c_tid = lookup_tid(&(T3C_DATA(dev))->tid_maps, hwtid);
	if (t3c_tid && t3c_tid->ctx && t3c_tid->client->handlers &&
		t3c_tid->client->handlers[p->opcode]) {
		return t3c_tid->client->handlers[p->opcode]
						(dev, skb, t3c_tid->ctx);
	} else {
		CH_MSG(tdev2adap(dev), DEBUG, OFLD,
		       "%s: received clientless CPL command 0x%x\n",
			dev->name, p->opcode);
		return CPL_RET_BUF_DONE | CPL_RET_BAD_MSG;
	}
}

static int do_cr(struct t3cdev *dev, struct sk_buff *skb)
{
	struct cpl_pass_accept_req *req = cplhdr(skb);
	unsigned int stid = G_PASS_OPEN_TID(ntohl(req->tos_tid));
	struct tid_info *t = &(T3C_DATA(dev))->tid_maps;
	struct t3c_tid_entry *t3c_tid;
	unsigned int tid = GET_TID(req);

	if (unlikely(tid >= t->ntids)) {
		printk("%s: passive open TID %u too large\n",
		       dev->name, tid);
		t3_fatal_err(tdev2adap(dev));
		return CPL_RET_BUF_DONE;
	}

	t3c_tid = lookup_stid(t, stid);
	if (t3c_tid && t3c_tid->ctx && t3c_tid->client->handlers &&
	    t3c_tid->client->handlers[CPL_PASS_ACCEPT_REQ]) {
		return t3c_tid->client->handlers[CPL_PASS_ACCEPT_REQ]
						(dev, skb, t3c_tid->ctx);
	} else {
		CH_MSG(tdev2adap(dev), DEBUG, OFLD,
		       "%s: received clientless CPL command 0x%x\n",
			dev->name, CPL_PASS_ACCEPT_REQ);
		return CPL_RET_BUF_DONE | CPL_RET_BAD_MSG;
	}
}

/*
 * Returns an sk_buff for a reply CPL message of size len.  If the input
 * sk_buff has no other users it is trimmed and reused, otherwise a new buffer
 * is allocated.  The input skb must be of size at least len.  Note that this
 * operation does not destroy the original skb data even if it decides to reuse
 * the buffer.
 */
static struct sk_buff *cxgb3_get_cpl_reply_skb(struct sk_buff *skb, size_t len,
					       int gfp)
{
	if (likely(!skb_cloned(skb))) {
		BUG_ON(skb->len < len);
		__skb_trim(skb, len);
		skb_get(skb);
	} else {
		skb = alloc_skb(len, gfp);
		if (skb)
			__skb_put(skb, len);
	}
	return skb;
}

static int do_abort_req_rss(struct t3cdev *dev, struct sk_buff *skb)
{
	union opcode_tid *p = cplhdr(skb);
	unsigned int hwtid = G_TID(ntohl(p->opcode_tid));
	struct t3c_tid_entry *t3c_tid;

	t3c_tid = lookup_tid(&(T3C_DATA(dev))->tid_maps, hwtid);
	if (t3c_tid && t3c_tid->ctx && t3c_tid->client->handlers &&
		t3c_tid->client->handlers[p->opcode]) {
		return t3c_tid->client->handlers[p->opcode]
						(dev, skb, t3c_tid->ctx);
	} else {
		struct cpl_abort_req_rss *req = cplhdr(skb);
		struct cpl_abort_rpl *rpl;
		struct sk_buff *reply_skb;
		unsigned int tid = GET_TID(req);
		u8 cmd = req->status;

		WARN_ON(dev->type == T3B);

		if (req->status == CPL_ERR_RTX_NEG_ADVICE ||
		    req->status == CPL_ERR_PERSIST_NEG_ADVICE)
			goto out;

		reply_skb = cxgb3_get_cpl_reply_skb(skb,
						    sizeof(struct cpl_abort_rpl),
						    GFP_ATOMIC);

		if (!reply_skb) {
			printk("do_abort_req_rss: couldn't get skb!\n");
			goto out;
		}
		reply_skb->priority = CPL_PRIORITY_DATA;
		rpl = cplhdr(reply_skb);
		rpl->wr.wr_hi =
			htonl(V_WR_OP(FW_WROPCODE_OFLD_HOST_ABORT_CON_RPL));
		rpl->wr.wr_lo = htonl(V_WR_TID(tid));
		OPCODE_TID(rpl) =
			htonl(MK_OPCODE_TID(CPL_ABORT_RPL, tid));
		rpl->cmd = cmd;
		cxgb3_ofld_send(dev, reply_skb);
 out:
		return CPL_RET_BUF_DONE;
	}
}

static int do_act_establish(struct t3cdev *dev, struct sk_buff *skb)
{
	struct cpl_act_establish *req = cplhdr(skb);
	unsigned int atid = G_PASS_OPEN_TID(ntohl(req->tos_tid));
	struct tid_info *t = &(T3C_DATA(dev))->tid_maps;
	struct t3c_tid_entry *t3c_tid;
	unsigned int tid = GET_TID(req);

	if (unlikely(tid >= t->ntids)) {
		printk("%s: active establish TID %u too large\n",
		       dev->name, tid);
		t3_fatal_err(tdev2adap(dev));
		return CPL_RET_BUF_DONE;
	}

	t3c_tid = lookup_atid(t, atid);
	if (t3c_tid && t3c_tid->ctx && t3c_tid->client->handlers &&
	    t3c_tid->client->handlers[CPL_ACT_ESTABLISH]) {
		return t3c_tid->client->handlers[CPL_ACT_ESTABLISH]
						(dev, skb, t3c_tid->ctx);
	} else {
		CH_MSG(tdev2adap(dev), DEBUG, OFLD,
		       "%s: received clientless CPL command 0x%x\n",
			dev->name, CPL_ACT_ESTABLISH);
		return CPL_RET_BUF_DONE | CPL_RET_BAD_MSG;
	}
}

static int do_trace(struct t3cdev *dev, struct sk_buff *skb)
{
	struct cpl_trace_pkt *p = cplhdr(skb);
	struct adapter *adapter = tdev2adap(dev);

	skb->protocol = htons(0xffff);
	skb->dev = dev->lldev;
	if (adapter->params.nports > 2)
		skb_pull(skb, sizeof(*p) + 8); /* pull CPL + preamble */
	else
		skb_pull(skb, sizeof(*p));     /* pull CPL */
	skb_reset_mac_header(skb);
	netif_receive_skb(skb);
	return 0;
}

static int do_term(struct t3cdev *dev, struct sk_buff *skb)
{
	unsigned int hwtid = ntohl(skb->priority) >> 8 & 0xfffff;
	unsigned int opcode = G_OPCODE(ntohl(skb->csum));
	struct t3c_tid_entry *t3c_tid;

	t3c_tid = lookup_tid(&(T3C_DATA(dev))->tid_maps, hwtid);
	if (t3c_tid && t3c_tid->ctx && t3c_tid->client->handlers &&
		t3c_tid->client->handlers[opcode]) {
		return t3c_tid->client->handlers[opcode](dev,skb,t3c_tid->ctx);
	} else {
		CH_MSG(tdev2adap(dev), DEBUG, OFLD,
		       "%s: received clientless CPL command 0x%x\n",
			dev->name, opcode);
		return CPL_RET_BUF_DONE | CPL_RET_BAD_MSG;
	}
}

#if defined(NETEVENT)
static int nb_callback(struct notifier_block *self, unsigned long event,
	void *ctx)
{
	switch (event) {
		case (NETEVENT_NEIGH_UPDATE): {
			cxgb_neigh_update((struct neighbour *)ctx);
			break;
		}
#ifdef DIVY	/* XXX Divy no NETEVENT_ROUTE_UPDATE definition */
		case (NETEVENT_ROUTE_UPDATE):
			break;
#endif
		case (NETEVENT_PMTU_UPDATE):
			break;
		case (NETEVENT_REDIRECT): {
			struct netevent_redirect *nr = ctx;
			cxgb_redirect(nr->old, nr->new);
			cxgb_neigh_update(nr->new->neighbour);
			break;
		}
		default:
			break;
	}
	return 0;
}

#elif defined(OFLD_USE_KPROBES)

#ifndef AUTOCONF_INCLUDED
#include <linux/autoconf.h>
#endif
#include <linux/kallsyms.h>
#include <linux/kprobes.h>
#include <net/arp.h>

static int (*orig_arp_constructor)(struct neighbour *);

static void neigh_suspect(struct neighbour *neigh)
{
	struct hh_cache *hh;

	neigh->output = neigh->ops->output;

	for (hh = neigh->hh; hh; hh = hh->hh_next)
		hh->hh_output = neigh->ops->output;
}

static void neigh_connect(struct neighbour *neigh)
{
	struct hh_cache *hh;

	neigh->output = neigh->ops->connected_output;

	for (hh = neigh->hh; hh; hh = hh->hh_next)
		hh->hh_output = neigh->ops->hh_output;
}

static inline int neigh_max_probes(const struct neighbour *n)
{
	const struct neigh_parms *p = n->parms;
	return (n->nud_state & NUD_PROBE ?
		p->ucast_probes :
		p->ucast_probes + p->app_probes + p->mcast_probes);
}

static void neigh_timer_handler_offload(unsigned long arg)
{
	unsigned long now, next;
	struct neighbour *neigh = (struct neighbour *)arg;
	unsigned state;
	int notify = 0;

	write_lock(&neigh->lock);

	state = neigh->nud_state;
	now = jiffies;
	next = now + HZ;

	if (!(state & NUD_IN_TIMER)) {
#ifndef CONFIG_SMP
		printk(KERN_WARNING "neigh: timer & !nud_in_timer\n");
#endif
		goto out;
	}

	if (state & NUD_REACHABLE) {
		if (time_before_eq(now,
				   neigh->confirmed +
				   neigh->parms->reachable_time)) {
			next = neigh->confirmed + neigh->parms->reachable_time;
		} else if (time_before_eq(now,
					  neigh->used +
					  neigh->parms->delay_probe_time)) {
			neigh->nud_state = NUD_DELAY;
			neigh->updated = jiffies;
			neigh_suspect(neigh);
			next = now + neigh->parms->delay_probe_time;
		} else {
			neigh->nud_state = NUD_STALE;
			neigh->updated = jiffies;
			neigh_suspect(neigh);
			cxgb_neigh_update(neigh);
		}
	} else if (state & NUD_DELAY) {
		if (time_before_eq(now,
				   neigh->confirmed +
				   neigh->parms->delay_probe_time)) {
			neigh->nud_state = NUD_REACHABLE;
			neigh->updated = jiffies;
			neigh_connect(neigh);
			cxgb_neigh_update(neigh);
			next = neigh->confirmed + neigh->parms->reachable_time;
		} else {
			neigh->nud_state = NUD_PROBE;
			neigh->updated = jiffies;
			atomic_set(&neigh->probes, 0);
			next = now + neigh->parms->retrans_time;
		}
	} else {
		/* NUD_PROBE|NUD_INCOMPLETE */
		next = now + neigh->parms->retrans_time;
	}

	if ((neigh->nud_state & (NUD_INCOMPLETE | NUD_PROBE)) &&
	    atomic_read(&neigh->probes) >= neigh_max_probes(neigh)) {
		struct sk_buff *skb;

		neigh->nud_state = NUD_FAILED;
		neigh->updated = jiffies;
		notify = 1;
		cxgb_neigh_update(neigh);
		NEIGH_CACHE_STAT_INC(neigh->tbl, res_failed);

		/* It is very thin place. report_unreachable is very
		   complicated routine. Particularly, it can hit the same
		   neighbour entry!
		   So that, we try to be accurate and avoid dead loop. --ANK
		 */
		while (neigh->nud_state == NUD_FAILED &&
		       (skb = __skb_dequeue(&neigh->arp_queue)) != NULL) {
			write_unlock(&neigh->lock);
			neigh->ops->error_report(neigh, skb);
			write_lock(&neigh->lock);
		}
		skb_queue_purge(&neigh->arp_queue);
	}

	if (neigh->nud_state & NUD_IN_TIMER) {
		if (time_before(next, jiffies + HZ/2))
			next = jiffies + HZ/2;
		if (!mod_timer(&neigh->timer, next))
			neigh_hold(neigh);
	}
	if (neigh->nud_state & (NUD_INCOMPLETE | NUD_PROBE)) {
		struct sk_buff *skb = skb_peek(&neigh->arp_queue);
		/* keep skb alive even if arp_queue overflows */
		if (skb)
			skb_get(skb);
		write_unlock(&neigh->lock);
		neigh->ops->solicit(neigh, skb);
		atomic_inc(&neigh->probes);
		if (skb)
			kfree_skb(skb);
	} else {
out:
		write_unlock(&neigh->lock);
	}

#ifdef CONFIG_ARPD
	if (notify && neigh->parms->app_probes)
		neigh_app_notify(neigh);
#endif
	neigh_release(neigh);
}

static int arp_constructor_offload(struct neighbour *neigh)
{
	if (dev2tdev(neigh->dev))
		neigh->timer.function = neigh_timer_handler_offload;
	return orig_arp_constructor(neigh);
}

/*
 * This must match exactly the signature of neigh_update for jprobes to work.
 * It runs from a trap handler with interrupts off so don't disable BH.
 */
static int neigh_update_offload(struct neighbour *neigh, const u8 *lladdr,
				u8 new, u32 flags)
{
	write_lock(&neigh->lock);
	cxgb_neigh_update(neigh);
	write_unlock(&neigh->lock);
	jprobe_return();
	/* NOTREACHED */
	return 0;
}

static struct jprobe neigh_update_jprobe = {
	.entry = (kprobe_opcode_t *) neigh_update_offload,
	.kp.addr = (kprobe_opcode_t *) neigh_update
};

static int prepare_arp_with_t3core(void)
{
	int err;

	err = register_jprobe(&neigh_update_jprobe);
	if (err) {
		printk(KERN_ERR "Could not install neigh_update jprobe, "
				"error %d\n", err);
		return err;
	}

	orig_arp_constructor = arp_tbl.constructor;
	arp_tbl.constructor  = arp_constructor_offload;

	return 0;
}

static void restore_arp_sans_t3core(void)
{
	arp_tbl.constructor = orig_arp_constructor;
	unregister_jprobe(&neigh_update_jprobe);
}

#else /* Module suport */

static inline int prepare_arp_with_t3core(void)
{
	return 0;
}

static inline void restore_arp_sans_t3core(void)
{}
#endif

#if defined(NETEVENT)
static struct notifier_block nb = {
	.notifier_call = nb_callback
};
#endif

/*
 * Process a received packet with an unknown/unexpected CPL opcode.
 */
static int do_bad_cpl(struct t3cdev *dev, struct sk_buff *skb)
{
	printk(KERN_ERR "%s: received bad CPL command 0x%x\n", dev->name,
	       *skb->data);
	return CPL_RET_BUF_DONE | CPL_RET_BAD_MSG;
}

/*
 * Handlers for each CPL opcode
 */
static cpl_handler_func cpl_handlers[NUM_CPL_CMDS];

/*
 * Add a new handler to the CPL dispatch table.  A NULL handler may be supplied
 * to unregister an existing handler.
 */
void t3_register_cpl_handler(unsigned int opcode, cpl_handler_func h)
{
	if (opcode < NUM_CPL_CMDS)
		cpl_handlers[opcode] = h ? h : do_bad_cpl;
	else
		printk(KERN_ERR "T3C: handler registration for "
		       "opcode %x failed\n", opcode);
}
EXPORT_SYMBOL(t3_register_cpl_handler);

/*
 * T3CDEV's receive method.
 */
int process_rx(struct t3cdev *dev, struct sk_buff **skbs, int n)
{
	while (n--) {
		struct sk_buff *skb = *skbs++;
		unsigned int opcode = G_OPCODE(ntohl(skb->csum));
		int ret = cpl_handlers[opcode] (dev, skb);

#if VALIDATE_TID
		if (ret & CPL_RET_UNKNOWN_TID) {
			union opcode_tid *p = cplhdr(skb);

			printk(KERN_ERR "%s: CPL message (opcode %u) had "
			       "unknown TID %u\n", dev->name, opcode,
			       G_TID(ntohl(p->opcode_tid)));
		}
#endif
		if (ret & CPL_RET_BUF_DONE)
			kfree_skb(skb);
	}
	return 0;
}

/*
 * Sends an sk_buff to a T3C driver after dealing with any active network taps.
 */
int cxgb3_ofld_send(struct t3cdev *dev, struct sk_buff *skb)
{
	int r;

	local_bh_disable();
#if defined(CONFIG_CHELSIO_T3)
	if (unlikely(netdev_nit)) {      /* deal with active taps */
		skb->nh.raw = skb->data;
		if (!skb->dev)
			skb->dev = dev->lldev;
		dev_queue_xmit_nit(skb, skb->dev);
	}
#endif
	r = dev->send(dev, skb);

	local_bh_enable();
	return r;
}
EXPORT_SYMBOL(cxgb3_ofld_send);

/**
 * cxgb3_ofld_skb - process n received offload packets
 * @dev: the offload device
 * @skb: an array of offload packets
 * @n: the number of offload packets
 *
 * Process an array of ingress offload packets.  Each packet is forwarded
 * to any active network taps and then passed to the offload device's receive
 * method.  We optimize passing packets to the receive method by passing
 * it the whole array at once except when there are active taps.
 */
int cxgb3_ofld_recv(struct t3cdev *dev, struct sk_buff **skb, int n)
{
#if defined(CONFIG_CHELSIO_T3)
	if (likely(!netdev_nit))
		return dev->recv(dev, skb, n);

	for ( ; n; n--, skb++) {
		skb[0]->dev = dev->lldev;
		dev_queue_xmit_nit(skb[0], dev->lldev);
		skb[0]->dev = NULL;
		dev->recv(dev, skb, 1);
	}
	return 0;
#else
	return dev->recv(dev, skb, n);
#endif
}

#if defined(NETEVENT) || defined(OFLD_USE_KPROBES)
void cxgb_neigh_update(struct neighbour *neigh)
{
	struct t3cdev *tdev = dev2tdev(neigh->dev);

	if (tdev)
		t3_l2t_update(tdev, neigh);
}
#endif

#if defined(NETEVENT)
static void set_l2t_ix(struct t3cdev *tdev, u32 tid, struct l2t_entry *e)
{
	struct sk_buff *skb;
	struct cpl_set_tcb_field *req;

	skb = alloc_skb(sizeof(*req), GFP_ATOMIC);
	if (!skb) {
		printk(KERN_ERR "%s: cannot allocate skb!\n", __FUNCTION__);
		return;
	}
	skb->priority = CPL_PRIORITY_CONTROL;
	req = (struct cpl_set_tcb_field *)skb_put(skb, sizeof(*req));
	req->wr.wr_hi = htonl(V_WR_OP(FW_WROPCODE_FORWARD));
	OPCODE_TID(req) = htonl(MK_OPCODE_TID(CPL_SET_TCB_FIELD, tid));
	req->reply = V_NO_REPLY(1);
	req->cpu_idx = 0;
	req->word = htons(W_TCB_L2T_IX);
	req->mask = cpu_to_be64(V_TCB_L2T_IX(M_TCB_L2T_IX));
	req->val = cpu_to_be64(V_TCB_L2T_IX(e->idx));
	tdev->send(tdev, skb);
}

void cxgb_redirect(struct dst_entry *old, struct dst_entry *new)
{
	struct tid_info *ti;
	struct t3cdev *old_tdev, *new_tdev;
	u32 tid;
	int update_tcb;
	struct l2t_entry *e;
	struct t3c_tid_entry *te;

	old_tdev = dev2tdev(old->neighbour->dev);
	new_tdev = dev2tdev(new->neighbour->dev);

	if (!old_tdev)
		return;
	if (new_tdev) {
		printk(KERN_WARNING "%s: Redirect to non-offload"
		       "device ignored.\n", __FUNCTION__);
		return;
	}

	if (old_tdev != new_tdev) {
		printk(KERN_WARNING "%s: Redirect to different "
		       "offload device ignored.\n", __FUNCTION__);
		return;
	}

	/* Add new L2T entry */
	e = t3_l2t_get(new_tdev, new->neighbour, new->neighbour->dev);
	if (!e) {
		printk(KERN_ERR "%s: couldn't allocate new l2t entry!\n",
		       __FUNCTION__);
		return;
	}

	/* Walk tid table and notify clients of dst change. */
	ti = &(T3C_DATA(new_tdev))->tid_maps;
	for (tid = 0; tid < ti->ntids; tid++) {
		te = lookup_tid(ti, tid);
		BUG_ON(!te);
		if (te && te->ctx && te->client && te->client->redirect) {
			update_tcb = te->client->redirect(te->ctx, old, new,
							  e);
			if (update_tcb)  {
				l2t_hold(L2DATA(new_tdev), e);
				set_l2t_ix(new_tdev, tid, e);
			}
		}
	}
	l2t_release(L2DATA(new_tdev), e);
}
#endif

#ifndef LINUX_2_4
/*
 * An administrator has requested that a set of offload policies be attached
 * to the interface.  This functionality is actually managed by toecore and
 * the new policy will be hung off this net_device's corresponding toedev but
 * we don't have access to call toecore code.  Thus, we need to have one of
 * our clients -- which can call toecore code -- proxy the call for us.
 */
int req_set_offload_policy(struct net_device *dev,
			   const struct ofld_policy_file *opf,
			   size_t len)
{
	struct cxgb3_client *client;
	int found = 0;
	int ret = -EINVAL;

	/*
	 * Make sure we're dealing with a network device with offload
	 * activated ...
	 */
	if (!offload_activated(dev2t3cdev(dev)))
		return ret;

	mutex_lock(&cxgb3_db_lock);
	list_for_each_entry(client, &client_list, client_list) {
		/*
		 * We want to restrict ourself to t3_tom module in order to
		 * request our proxy service since A. it talks to toecore and
		 * B. it's the only module which supports the extended
		 * cxgb3_client data structure and has a set_offload_policy
		 * structure element.
		 */
		if (client->name && strcmp(client->name, "tom_cxgb3") == 0 &&
		    client->set_offload_policy) {
			found = 1;
			ret = client->set_offload_policy(dev, opf, len);
			break;
		}
	}
	mutex_unlock(&cxgb3_db_lock);
	if (!found)
		printk(KERN_ERR "req_set_offload_policy: no proxy found\n");
	return ret;
}
#endif /* !LINUX_2_4 */

/*
 * Allocate a chunk of memory using kmalloc or, if that fails, vmalloc.
 * The allocated memory is cleared.
 */
void *cxgb_alloc_mem(unsigned long size)
{
	void *p = kmalloc(size, GFP_KERNEL);

	if (!p)
		p = vmalloc(size);
	if (p)
		memset(p, 0, size);
	return p;
}

/*
 * Free memory allocated through cxgb3_alloc_mem().
 */
void cxgb_free_mem(void *addr)
{
	unsigned long p = (unsigned long) addr;

	if (p >= VMALLOC_START && p < VMALLOC_END)
		vfree(addr);
	else
		kfree(addr);
}

static int offload_info_read_proc(char *buf, char **start, off_t offset,
				  int length, int *eof, void *data)
{
	struct t3c_data *d = data;
	struct tid_info *t = &d->tid_maps;
	int len;

	len = sprintf(buf, "TID range: 0..%d, in use: %u\n"
		      "STID range: %d..%d, in use: %u\n"
		      "ATID range: %d..%d, in use: %u\n"
		      "MSS: %u\n",
		      t->ntids - 1, atomic_read(&t->tids_in_use), t->stid_base,
		      t->stid_base + t->nstids - 1, t->stids_in_use,
		      t->atid_base, t->atid_base + t->natids - 1,
		      t->atids_in_use, d->tx_max_chunk);
	if (len > length)
		len = length;
	*eof = 1;
	return len;
}

static int offload_info_proc_setup(struct proc_dir_entry *dir,
				   struct t3c_data *d)
{
	struct proc_dir_entry *p;

	if (!dir)
		return -EINVAL;

	p = create_proc_read_entry("info", 0, dir, offload_info_read_proc, d);
	if (!p)
		return -ENOMEM;

	SET_PROC_NODE_OWNER(p, THIS_MODULE);
	return 0;
}

static void offload_proc_dev_setup(struct t3cdev *dev)
{
	t3_l2t_proc_setup(dev->proc_dir, L2DATA(dev));
	offload_info_proc_setup(dev->proc_dir, T3C_DATA(dev));
}

static void offload_info_proc_free(struct proc_dir_entry *dir)
{
	if (dir)
		remove_proc_entry("info", dir);
}

static void offload_proc_dev_cleanup(struct t3cdev *dev)
{
	t3_l2t_proc_free(dev->proc_dir);
	offload_info_proc_free(dev->proc_dir);
}

/*
 * Allocate and initialize the TID tables.  Returns 0 on success.
 */
static int init_tid_tabs(struct tid_info *t, unsigned int ntids,
			 unsigned int natids, unsigned int nstids,
			 unsigned int atid_base, unsigned int stid_base)
{
	unsigned long size = ntids * sizeof(*t->tid_tab) +
	    natids * sizeof(*t->atid_tab) + nstids * sizeof(*t->stid_tab);

	t->tid_tab = cxgb_alloc_mem(size);
	if (!t->tid_tab)
		return -ENOMEM;

	t->stid_tab = (union listen_entry *)&t->tid_tab[ntids];
	t->atid_tab = (union active_open_entry *)&t->stid_tab[nstids];
	t->ntids = ntids;
	t->nstids = nstids;
	t->stid_base = stid_base;
	t->sfree = NULL;
	t->natids = natids;
	t->atid_base = atid_base;
	t->afree = NULL;
	t->stids_in_use = t->atids_in_use = 0;
	atomic_set(&t->tids_in_use, 0);
	spin_lock_init(&t->stid_lock);
	spin_lock_init(&t->atid_lock);

	/*
	 * Setup the free lists for stid_tab and atid_tab.
	 */
	if (nstids) {
		while (--nstids)
			t->stid_tab[nstids - 1].next = &t->stid_tab[nstids];
		t->sfree = t->stid_tab;
	}
	if (natids) {
		while (--natids)
			t->atid_tab[natids - 1].next = &t->atid_tab[natids];
		t->afree = t->atid_tab;
	}
	return 0;
}

static void free_tid_maps(struct tid_info *t)
{
	cxgb_free_mem(t->tid_tab);
}

int cxgb3_offload_activate(struct adapter *adapter)
{
	struct t3cdev *dev = &adapter->tdev;
	int natids, err;
	struct t3c_data *t;
	struct tid_range stid_range, tid_range;
	struct mtutab mtutab;
	unsigned int l2t_capacity;

	t = kcalloc(1, sizeof(*t), GFP_KERNEL);
	if (!t)
		return -ENOMEM;

	err = -EOPNOTSUPP;
	if (dev->ctl(dev, GET_TX_MAX_CHUNK, &t->tx_max_chunk) < 0 ||
	    dev->ctl(dev, GET_MAX_OUTSTANDING_WR, &t->max_wrs) < 0 ||
	    dev->ctl(dev, GET_L2T_CAPACITY, &l2t_capacity) < 0 ||
	    dev->ctl(dev, GET_MTUS, &mtutab) < 0 ||
	    dev->ctl(dev, GET_TID_RANGE, &tid_range) < 0 ||
	    dev->ctl(dev, GET_STID_RANGE, &stid_range) < 0)
		goto out_free;

	err = -ENOMEM;
	L2DATA(dev) = t3_init_l2t(l2t_capacity);
	if (!L2DATA(dev))
		goto out_free;

	natids = min(tid_range.num / 2, MAX_ATIDS);
	err = init_tid_tabs(&t->tid_maps, tid_range.num, natids,
			    stid_range.num, ATID_BASE, stid_range.base);
	if (err)
		goto out_free_l2t;

	t->mtus = mtutab.mtus;
	t->nmtus = mtutab.size;

	spin_lock_init(&t->tid_release_lock);
	INIT_LIST_HEAD(&t->list_node);
	t->dev = dev;

	T3C_DATA(dev) = t;
	dev->recv = process_rx;
#if defined(NETEVENT)
	dev->neigh_update = t3_l2t_update;
#endif

	T3_INIT_WORK(&t->tid_release_task, t3_process_tid_release_list, t);

	offload_proc_dev_setup(dev);

	/* Register netevent handler once */
	if (!atomic_read(&registered_ofld_adapters)) {
#if defined(NETEVENT)
		register_netevent_notifier(&nb);
#elif defined(OFLD_USE_KPROBES)
		if (prepare_arp_with_t3core())
			printk(KERN_ERR "Unable to set offload capabilities\n");
#endif
	}
	atomic_inc(&registered_ofld_adapters);

	return 0;

out_free_l2t:
	t3_free_l2t(L2DATA(dev));
	L2DATA(dev) = NULL;
out_free:
	kfree(t);
	return err;
}

void cxgb3_offload_deactivate(struct adapter *adapter)
{
	struct t3cdev *tdev = &adapter->tdev;
	struct t3c_data *t = T3C_DATA(tdev);

	offload_proc_dev_cleanup(tdev);

	atomic_dec(&registered_ofld_adapters);
	if (!atomic_read(&registered_ofld_adapters)) {
#if defined(NETEVENT)
		unregister_netevent_notifier(&nb);
#else
#if defined(OFLD_USE_KPROBES)
		restore_arp_sans_t3core();
#endif
#endif
	}
	free_tid_maps(&t->tid_maps);
	T3C_DATA(tdev) = NULL;
	t3_free_l2t(L2DATA(tdev));
	L2DATA(tdev) = NULL;
	kfree(t);
}

static inline void register_tdev(struct t3cdev *tdev)
{
	mutex_lock(&cxgb3_db_lock);
	list_add_tail(&tdev->ofld_dev_list, &ofld_dev_list);
	mutex_unlock(&cxgb3_db_lock);
}

static inline void unregister_tdev(struct t3cdev *tdev)
{
	mutex_lock(&cxgb3_db_lock);
	list_del(&tdev->ofld_dev_list);
	mutex_unlock(&cxgb3_db_lock);
}

static inline int adap2type(struct adapter *adapter)
{
	int type = 0;

	switch (adapter->params.rev) {
	case T3_REV_A:
		type = T3A;
		break;
	case T3_REV_B:
	case T3_REV_B2:
		type = T3B;
		break;
	case T3_REV_C:
		type = T3C;
		break;
	}
	return type;
}
		
void __devinit cxgb3_adapter_ofld(struct adapter *adapter)
{
	struct t3cdev *tdev = &adapter->tdev;

	INIT_LIST_HEAD(&tdev->ofld_dev_list);

	cxgb3_set_dummy_ops(tdev);
	tdev->send = t3_offload_tx;
	tdev->ctl = cxgb_offload_ctl;
	tdev->type = adap2type(adapter);

	register_tdev(tdev);
}

void __devexit cxgb3_adapter_unofld(struct adapter *adapter)
{
	struct t3cdev *tdev = &adapter->tdev;

	cxgb3_set_dummy_ops(tdev);

	unregister_tdev(tdev);
}

int offload_devices_read_proc(char *buf, char **start, off_t offset,
				     int length, int *eof, void *data)
{
	int i, len = 0;
	struct t3cdev *tdev;
	struct net_device *ndev;
	struct adapter *adapter;

	len += sprintf(buf, "Device           Interfaces\n");

	mutex_lock(&cxgb3_db_lock);
	list_for_each_entry(tdev, &ofld_dev_list, ofld_dev_list) {
		len += sprintf(buf + len, "%-16s", tdev->name);
		adapter = tdev2adap(tdev);
		for (i = 0; i < adapter->params.nports; i++) {
			ndev = adapter->port[i];
			len += sprintf(buf + len, " %s", ndev->name);
		}
		len += sprintf(buf + len, "\n");
		if (len >= length)
			break;
	}
	mutex_unlock(&cxgb3_db_lock);

	if (len > length)
		len = length;
	*eof = 1;
	return len;
}

void __init cxgb3_offload_init(void)
{
	int i;

	for (i = 0; i < NUM_CPL_CMDS; ++i)
		cpl_handlers[i] = do_bad_cpl;

	t3_register_cpl_handler(CPL_SMT_WRITE_RPL, do_smt_write_rpl);
	t3_register_cpl_handler(CPL_L2T_WRITE_RPL, do_l2t_write_rpl);
	t3_register_cpl_handler(CPL_RTE_WRITE_RPL, do_rte_write_rpl);
	t3_register_cpl_handler(CPL_PASS_OPEN_RPL, do_stid_rpl);
	t3_register_cpl_handler(CPL_CLOSE_LISTSRV_RPL, do_stid_rpl);
	t3_register_cpl_handler(CPL_PASS_ACCEPT_REQ, do_cr);
	t3_register_cpl_handler(CPL_PASS_ESTABLISH, do_hwtid_rpl);
	t3_register_cpl_handler(CPL_ABORT_RPL_RSS, do_hwtid_rpl);
	t3_register_cpl_handler(CPL_ABORT_RPL, do_hwtid_rpl);
	t3_register_cpl_handler(CPL_RX_URG_NOTIFY, do_hwtid_rpl);
	t3_register_cpl_handler(CPL_RX_DATA, do_hwtid_rpl);
	t3_register_cpl_handler(CPL_TX_DATA_ACK, do_hwtid_rpl);
	t3_register_cpl_handler(CPL_TX_DMA_ACK, do_hwtid_rpl);
	t3_register_cpl_handler(CPL_ACT_OPEN_RPL, do_act_open_rpl);
	t3_register_cpl_handler(CPL_PEER_CLOSE, do_hwtid_rpl);
	t3_register_cpl_handler(CPL_CLOSE_CON_RPL, do_hwtid_rpl);
	t3_register_cpl_handler(CPL_ABORT_REQ_RSS, do_abort_req_rss);
	t3_register_cpl_handler(CPL_ACT_ESTABLISH, do_act_establish);
	t3_register_cpl_handler(CPL_RDMA_TERMINATE, do_term);
	t3_register_cpl_handler(CPL_RDMA_EC_STATUS, do_hwtid_rpl);
	t3_register_cpl_handler(CPL_TRACE_PKT, do_trace);
	t3_register_cpl_handler(CPL_RX_DATA_DDP, do_hwtid_rpl);
	t3_register_cpl_handler(CPL_RX_DDP_COMPLETE, do_hwtid_rpl);
	/* for iSCSI */
	t3_register_cpl_handler(CPL_ISCSI_HDR, do_hwtid_rpl);
	t3_register_cpl_handler(CPL_GET_TCB_RPL, do_hwtid_rpl);
	t3_register_cpl_handler(CPL_SET_TCB_RPL, do_hwtid_rpl);

}

void __exit cxgb3_offload_exit(void)
{
	//offload_proc_cleanup();
}
