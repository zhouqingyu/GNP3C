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

#include <linux/module.h>
#ifndef	LINUX_2_4
#include <linux/moduleparam.h>
#endif	/* LINUX_2_4 */
#include <linux/init.h>
#include <linux/pci.h>
#ifndef	LINUX_2_4
#include <linux/dma-mapping.h>
#endif	/* LINUX_2_4 */
#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/if_vlan.h>
#include <linux/mii.h>
#include <linux/sockios.h>
#include <linux/workqueue.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/rtnetlink.h>
#include <linux/highmem.h>
#include <linux/vmalloc.h>
#include <linux/sched.h>
#include <asm/uaccess.h>
#include <linux/notifier.h>

#include "common.h"
#include "cxgb3_ioctl.h"
#include "regs.h"
#include "cxgb3_offload.h"
#include "version.h"

#include "cxgb3_defs.h"
#include "cxgb3_ctl_defs.h"
#include "t3_cpl.h"
#include "t3_firmware.h"
#include "firmware_exports.h"

enum {
	MAX_TXQ_ENTRIES      = 16384,
	MAX_CTRL_TXQ_ENTRIES = 1024,
	MAX_RSPQ_ENTRIES     = 16384,
	MAX_RX_BUFFERS       = 16384,
	MAX_RX_JUMBO_BUFFERS = 16384,
	MIN_TXQ_ENTRIES      = 4,
	MIN_CTRL_TXQ_ENTRIES = 4,
	MIN_RSPQ_ENTRIES     = 32,
	MIN_FL_ENTRIES       = 32,
	MIN_FL_JUMBO_ENTRIES = 32
};

/*
 * Local host copy of filter information.  This is used to program the
 * hardware filters.  In general, non-zero fields indicate that the associated
 * packet element should be compared for a match with the value.
 */
struct filter_info {
	u32 sip;		/* Source IP address */
	u32 sip_mask;		/* Source IP mask */
	u32 dip;		/* Destination IP address */
	u16 sport;		/* Source port */
	u16 dport;		/* Desination port */
	u32 vlan:12;		/* VLAN ID */
	u32 vlan_prio:3;	/* VLAN Priority: FILTER_NO_VLAN_PRI => none */
	u32 mac_hit:1;		/* Match MAC address at MAC Index */
	u32 mac_idx:4;		/* Index of Exact MAC Address entry */
				/*   (Port ID << 3) | MAC Index */
	u32 mac_vld:1;		/* Port ID and MAC Index are valid */
	u32 pkt_type:2;		/* Packet type: */
				/*   {0..3} => {Any, TCP, UDP, IP Fragment} */
	u32 report_filter_id:1;	/* Report filter ID in CPL Response Message */
	u32 pass:1;		/* Pass packet: 0 => drop, 1 => pass */
	u32 rss:1;		/* Use RSS: 0 => use Qset, 1 => RSS */
	u32 qset:3;		/* Qset to which packet should be appended */
	u32 locked:1;		/* filter used by software; unavailable to user */
	u32 valid:1;		/* filter is valid */
};

enum { FILTER_NO_VLAN_PRI = 7 };

#define PORT_MASK ((1 << MAX_NPORTS) - 1)

#define DFLT_MSG_ENABLE (NETIF_MSG_DRV | NETIF_MSG_PROBE | NETIF_MSG_LINK | \
			 NETIF_MSG_TIMER | NETIF_MSG_IFDOWN | NETIF_MSG_IFUP |\
			 NETIF_MSG_RX_ERR | NETIF_MSG_TX_ERR)

#define EEPROM_MAGIC 0x38E2F10C

#define CH_DEVICE(devid, idx) \
	{ \
		.vendor = PCI_VENDOR_ID_CHELSIO, \
		.device = (devid), \
		.subvendor = PCI_ANY_ID, \
		.subdevice = PCI_ANY_ID, \
		.driver_data = (idx) \
	}

static struct pci_device_id cxgb3_pci_tbl[] = {
	CH_DEVICE(0x20, 0),  /* PE9000 */
	CH_DEVICE(0x21, 1),  /* T302E */
	CH_DEVICE(0x22, 2),  /* T310E */
	CH_DEVICE(0x23, 3),  /* T320X */
	CH_DEVICE(0x24, 1),  /* T302X */
	CH_DEVICE(0x25, 3),  /* T320E */
	CH_DEVICE(0x26, 2),  /* T310X */
	CH_DEVICE(0x30, 2),  /* T3B10 */
	CH_DEVICE(0x31, 3),  /* T3B20 */
	CH_DEVICE(0x32, 1),  /* T3B02 */
	CH_DEVICE(0x33, 4),  /* T3B04 */
	CH_DEVICE(0x35, 6),  /* T3C20-derived T3C10 */
	CH_DEVICE(0x36, 3),  /* S320E-CR */
	CH_DEVICE(0x37, 7),  /* N320E-G2 */
	{ 0, }
};

MODULE_DESCRIPTION(DRIVER_DESC);
MODULE_AUTHOR("Chelsio Communications");
MODULE_LICENSE("GPL");
MODULE_VERSION(DRIVER_VERSION);
MODULE_DEVICE_TABLE(pci, cxgb3_pci_tbl);

static int dflt_msg_enable = DFLT_MSG_ENABLE;

module_param(dflt_msg_enable, int, 0644);
MODULE_PARM_DESC(dflt_msg_enable, "Chelsio T3 default message enable bitmap");

static int drv_wd_en = 0;

module_param(drv_wd_en, int, 0644);
MODULE_PARM_DESC(drv_wd_en, "Enable driver watchdog");

static int drv_wd_ac = 1;

module_param(drv_wd_ac, int, 0644);
MODULE_PARM_DESC(drv_wd_ac, "Action to take if driver watchdog fires. Bring "
		"down PHY's(1), PCIE linkdown(2) or FW exception(3)");

static int fw_wd_en = 0;

module_param(fw_wd_en, int, 0644);
MODULE_PARM_DESC(fw_wd_en, "Enable firmware watchdog");

/*
 * The driver uses the best interrupt scheme available on a platform in the
 * order MSI-X, MSI, legacy pin interrupts.  This parameter determines which
 * of these schemes the driver may consider as follows:
 *
 * msi = 2: choose from among all three options
 * msi = 1: only consider MSI and pin interrupts
 * msi = 0: force pin interrupts
 */
static int msi = 2;

module_param(msi, int, 0644);
MODULE_PARM_DESC(msi, "whether to use MSI-X (2), MSI (1) or Legacy INTx (0)");

/*
 * The driver enables offload as a default.
 * To disable it, use ofld_disable = 1.
 */

static int ofld_disable = 0;

module_param(ofld_disable, int, 0644);
MODULE_PARM_DESC(ofld_disable, "whether to enable offload at init time or not");

/*
 * The driver uses an auto-queue algorithm by default.
 * To disable it and force a single queue-set per port, use singleq = 1.
 */

static int singleq = 0;

module_param(singleq, int, 0644);
MODULE_PARM_DESC(singleq, "use a single queue-set per port");

/*
 * We have work elements that we need to cancel when an interface is taken
 * down.  Normally the work elements would be executed by keventd but that
 * can deadlock because of linkwatch.  If our close method takes the rtnl
 * lock and linkwatch is ahead of our work elements in keventd, linkwatch
 * will block keventd as it needs the rtnl lock, and we'll deadlock waiting
 * for our work to complete.  Get our own work queue to solve this.
 */
struct workqueue_struct *cxgb3_wq;

#ifndef	LINUX_2_4
static struct dentry *cxgb3_debugfs_root;
#endif	/* LINUX_2_4 */

static void cxgb_set_rxmode(struct net_device *dev);

DEFINE_RWLOCK(adapter_list_lock);
LIST_HEAD(adapter_list);

static inline void add_adapter(adapter_t *adap)
{
	write_lock_bh(&adapter_list_lock);
	list_add_tail(&adap->adapter_list, &adapter_list);
	write_unlock_bh(&adapter_list_lock);
}

static inline void remove_adapter(adapter_t *adap)
{
	write_lock_bh(&adapter_list_lock);
	list_del(&adap->adapter_list);
	write_unlock_bh(&adapter_list_lock);
}

/**
 *	link_report - show link status and link speed/duplex
 *	@dev: the port whose settings are to be reported
 *
 *	Shows the link status, speed, and duplex of a port.
 */
static void link_report(struct net_device *dev)
{
	if (!netif_carrier_ok(dev))
		printk(KERN_INFO "%s: link down\n", dev->name);
	else {
		static const char *fc[] = { "no", "Rx", "Tx", "Tx/Rx" };

		const char *s = "10Mbps";
		const struct port_info *p = netdev_priv(dev);

		switch (p->link_config.speed) {
		case SPEED_10000:
			s = "10Gbps";
			break;
		case SPEED_1000:
			s = "1000Mbps";
			break;
		case SPEED_100:
			s = "100Mbps";
			break;
		}

		printk(KERN_INFO "%s: link up, %s, %s-duplex, %s PAUSE\n",
		       dev->name, s,
		       p->link_config.duplex == DUPLEX_FULL ? "full" : "half",
		       fc[p->link_config.fc]);
	}
}

/**
 *	t3_os_link_changed - handle link status changes
 *	@adapter: the adapter associated with the link change
 *	@port_id: the port index whose link status has changed
 *	@link_stat: the new status of the link
 *	@speed: the new speed setting
 *	@duplex: the new duplex setting
 *	@pause: the new flow-control setting
 *
 *	This is the OS-dependent handler for link status changes.  The OS
 *	neutral handler takes care of most of the processing for these events,
 *	then calls this handler for any OS-specific processing.
 */
void t3_os_link_changed(struct adapter *adapter, int port_id, int link_stat,
			int speed, int duplex, int pause, int mac_was_reset)
{
	struct net_device *dev = adapter->port[port_id];
	struct port_info *pi = netdev_priv(dev);

	if (mac_was_reset) {
		struct cmac *mac = &pi->mac;
		rtnl_lock();
		t3_mac_set_mtu(mac, dev->mtu);
		t3_mac_set_address(mac, 0, dev->dev_addr);
		cxgb_set_rxmode(dev);
		rtnl_unlock();
	}

	/* Skip changes from disabled ports. */
	if (!netif_running(dev))
		return;

	if (link_stat != netif_carrier_ok(dev)) {
		if (link_stat)
			netif_carrier_on(dev);
		else
			netif_carrier_off(dev);

		link_report(dev);
	}
}

/**
 *	t3_os_phymod_changed - handle PHY module changes
 *	@phy: the PHY reporting the module change
 *	@mod_type: new module type
 *
 *	This is the OS-dependent handler for PHY module changes.  It is
 *	invoked when a PHY module is removed or inserted for any OS-specific
 *	processing.
 */
void t3_os_phymod_changed(struct adapter *adap, int port_id)
{
	static const char *mod_str[] = {
		NULL, "SR", "LR", "LRM", "TWINAX", "TWINAX", "unknown"
	};

	struct net_device *dev = adap->port[port_id];
	struct port_info *pi = netdev_priv(dev);

	if (pi->phy.modtype == phy_modtype_none)
		printk(KERN_INFO "%s: PHY module unplugged\n", dev->name);
	else
		printk(KERN_INFO "%s: %s PHY module inserted\n", dev->name,
		       mod_str[pi->phy.modtype]);
}

#ifndef LINUX_2_4
static ssize_t cxgb_set_nfilters(struct net_device *dev, unsigned int nfilters)
{
	struct port_info *pi = netdev_priv(dev);
	struct adapter *adap = pi->adapter;
	int min_tids = is_offload(adap) ? MC5_MIN_TIDS : 0;

	if (adap->flags & FULL_INIT_DONE)
		return -EBUSY;
	if (nfilters && adap->params.rev == 0)
		return -EINVAL;
	if (nfilters > t3_mc5_size(&adap->mc5) - adap->params.mc5.nservers -
	    min_tids)
		return -EINVAL;
	adap->params.mc5.nfilters = nfilters;
	return 0;
}
#endif

static void cxgb_set_rxmode(struct net_device *dev)
{
	struct t3_rx_mode rm;
	struct port_info *pi = netdev_priv(dev);
	struct cmac *mac = &pi->mac;

	init_rx_mode(&rm, dev);
	t3_mac_set_rx_mode(mac, &rm);

}

/**
 *	link_start - enable a port
 *	@dev: the port to enable
 *
 *	Performs the MAC and PHY actions needed to enable a port.
 */
static void link_start(struct net_device *dev)
{
	struct port_info *pi = netdev_priv(dev);
	struct cmac *mac = &pi->mac;

	if (!mac->multiport)
		t3_mac_init(mac);
	t3_mac_set_mtu(mac, dev->mtu);
	t3_mac_set_address(mac, 0, dev->dev_addr);
	cxgb_set_rxmode(dev);
	t3_link_start(&pi->phy, mac, &pi->link_config);
}

static void cxgb_disable_msi(struct adapter *adapter)
{
	if (adapter->flags & USING_MSIX) {
		pci_disable_msix(adapter->pdev);
		adapter->flags &= ~USING_MSIX;
	} else if (adapter->flags & USING_MSI) {
		pci_disable_msi(adapter->pdev);
		adapter->flags &= ~USING_MSI;
	}
}

/*
 * Interrupt handler for asynchronous events used with MSI-X.
 */
DECLARE_INTR_HANDLER(t3_async_intr_handler, irq, cookie, regs)
{
	t3_slow_intr_handler(cookie);
	return IRQ_HANDLED;
}

/*
 * Name the MSI-X interrupts.
 */
static void name_msix_vecs(struct adapter *adap)
{
	int i, j, msi_idx = 1, n = sizeof(adap->msix_info[0].desc) - 1;

	snprintf(adap->msix_info[0].desc, n, "%s", adap->name);
	adap->msix_info[0].desc[n] = 0;

	for_each_port(adap, j) {
		struct net_device *d = adap->port[j];
		const struct port_info *pi = netdev_priv(d);

		for (i = 0; i < pi->nqsets; i++, msi_idx++) {
			snprintf(adap->msix_info[msi_idx].desc, n,
				 "%s (queue %d)", d->name,
				 pi->first_qset + i);
			adap->msix_info[msi_idx].desc[n] = 0;
		}
 	}
}

static int request_msix_data_irqs(adapter_t *adap)
{
	int err, qidx;

	for (qidx = 0; qidx < adap->sge.nqsets; ++qidx) {
		err = request_irq(adap->msix_info[qidx + 1].vec,
				  t3_intr_handler(adap,
					adap->sge.qs[qidx].rspq.flags & USING_POLLING),
				  0, adap->msix_info[qidx + 1].desc,
				  &adap->sge.qs[qidx]);
		if (err) {
			while (--qidx >= 0)
				free_irq(adap->msix_info[qidx + 1].vec,
					 &adap->sge.qs[qidx]);
			return err;
		}
	}
	return 0;
}

static void free_irq_resources(struct adapter *adapter)
{
	if (adapter->flags & USING_MSIX) {
		int i;

		free_irq(adapter->msix_info[0].vec, adapter);
		for (i = 0; i < adapter->sge.nqsets; ++i)
			free_irq(adapter->msix_info[i + 1].vec,
				 &adapter->sge.qs[i]);
	} else
		free_irq(adapter->pdev->irq, adapter);
}

static int await_mgmt_replies(struct adapter *adap, unsigned long init_cnt,
			      unsigned long n)
{
	int attempts = 5;

	while (adap->sge.qs[0].rspq.offload_pkts < init_cnt + n) {
		if (!--attempts)
			return -ETIMEDOUT;
		msleep(10);
	}
	return 0;
}

static int init_tp_parity(struct adapter *adap)
{
	int i;
	struct sk_buff *skb;
	struct cpl_set_tcb_field *greq;
	unsigned long cnt = adap->sge.qs[0].rspq.offload_pkts;

	t3_tp_set_offload_mode(adap, 1);

	for (i = 0; i < 16; i++) {
		struct cpl_smt_write_req *req;

		skb = alloc_skb(sizeof(*req), GFP_KERNEL | __GFP_NOFAIL);
		req = (struct cpl_smt_write_req *)__skb_put(skb, sizeof(*req));
		memset(req, 0, sizeof(*req));
		req->wr.wr_hi = htonl(V_WR_OP(FW_WROPCODE_FORWARD));
		OPCODE_TID(req) = htonl(MK_OPCODE_TID(CPL_SMT_WRITE_REQ, i));
		req->mtu_idx = NMTUS - 1;
		req->iff = i;
		t3_mgmt_tx(adap, skb);
	}

	for (i = 0; i < 2048; i++) {
		struct cpl_l2t_write_req *req;

		skb = alloc_skb(sizeof(*req), GFP_KERNEL | __GFP_NOFAIL);
		req = (struct cpl_l2t_write_req *)__skb_put(skb, sizeof(*req));
		memset(req, 0, sizeof(*req));
		req->wr.wr_hi = htonl(V_WR_OP(FW_WROPCODE_FORWARD));
		OPCODE_TID(req) = htonl(MK_OPCODE_TID(CPL_L2T_WRITE_REQ, i));
		req->params = htonl(V_L2T_W_IDX(i));
		t3_mgmt_tx(adap, skb);
	}

	for (i = 0; i < 2048; i++) {
		struct cpl_rte_write_req *req;

		skb = alloc_skb(sizeof(*req), GFP_KERNEL | __GFP_NOFAIL);
		req = (struct cpl_rte_write_req *)__skb_put(skb, sizeof(*req));
		memset(req, 0, sizeof(*req));
		req->wr.wr_hi = htonl(V_WR_OP(FW_WROPCODE_FORWARD));
		OPCODE_TID(req) = htonl(MK_OPCODE_TID(CPL_RTE_WRITE_REQ, i));
		req->l2t_idx = htonl(V_L2T_W_IDX(i));
		t3_mgmt_tx(adap, skb);
	}

	skb = alloc_skb(sizeof(*greq), GFP_KERNEL | __GFP_NOFAIL);
	greq = (struct cpl_set_tcb_field *)__skb_put(skb, sizeof(*greq));
	memset(greq, 0, sizeof(*greq));
	greq->wr.wr_hi = htonl(V_WR_OP(FW_WROPCODE_FORWARD));
	OPCODE_TID(greq) = htonl(MK_OPCODE_TID(CPL_SET_TCB_FIELD, 0));
	greq->mask = cpu_to_be64(1);
	t3_mgmt_tx(adap, skb);

	i = await_mgmt_replies(adap, cnt, 16 + 2048 + 2048 + 1);
	t3_tp_set_offload_mode(adap, 0);
	return i;
}

/**
 *	setup_rss - configure RSS
 *	@adap: the adapter
 *
 *	Sets up RSS to distribute packets to multiple receive queues.  We
 *	configure the RSS CPU lookup table to distribute to the number of HW
 *	receive queues, and the response queue lookup table to narrow that
 *	down to the response queues actually configured for each port.
 *	We always configure the RSS mapping for two ports since the mapping
 *	table has plenty of entries.
 */
static void setup_rss(adapter_t *adap)
{
	int i;
	unsigned int nq[2];
	u8 cpus[SGE_QSETS + 1];
	u16 rspq_map[RSS_TABLE_SIZE];

	for (i = 0; i < SGE_QSETS; ++i)
		cpus[i] = i;
	cpus[SGE_QSETS] = 0xff;                     /* terminator */

	nq[0] = nq[1] = 0;
	for_each_port(adap, i) {
		const struct port_info *pi = adap2pinfo(adap, i);

		nq[pi->tx_chan] += pi->nqsets;
	}

	for (i = 0; i < RSS_TABLE_SIZE / 2; ++i) {
		rspq_map[i] = nq[0] ? i % nq[0] : 0;
		rspq_map[i + RSS_TABLE_SIZE / 2] = nq[1] ? i % nq[1] + nq[0] : 0;
	}

	/* Calculate the reverse RSS map table */
	for (i = 0; i < RSS_TABLE_SIZE; ++i)
		if (adap->rrss_map[rspq_map[i]] == 0xff)
			adap->rrss_map[rspq_map[i]] = i;

	t3_config_rss(adap, F_RQFEEDBACKENABLE | F_TNLLKPEN | F_TNLMAPEN |
		      F_TNLPRTEN | F_TNL2TUPEN | F_TNL4TUPEN | F_OFDMAPEN |
		      F_RRCPLMAPEN | V_RRCPLCPUSIZE(6) | F_HASHTOEPLITZ,
		      cpus, rspq_map);
}

static void ring_dbs(struct adapter *adap)
{
	int i, j;

	for (i = 0; i < SGE_QSETS; i++) {
		struct sge_qset *qs = &adap->sge.qs[i];

		if (qs->adap)
			for (j = 0; j < SGE_TXQ_PER_SET; j++)
				t3_write_reg(adap, A_SG_KDOORBELL,
					     F_SELEGRCNTX |
					     V_EGRCNTX(qs->txq[j].cntxt_id));
	}
}

#if !defined(NAPI_UPDATE)
/*
 * If we have multiple receive queues per port serviced by NAPI we need one
 * netdevice per queue as NAPI operates on netdevices.  We already have one
 * netdevice, namely the one associated with the interface, so we use dummy
 * ones for any additional queues.  Note that these netdevices exist purely
 * so that NAPI has something to work with, they do not represent network
 * ports and are not registered.
 */
static int init_dummy_netdevs(struct adapter *adap)
{
	int i, j, dummy_idx = 0;
	struct net_device *nd;

	for_each_port(adap, i) {
		struct net_device *dev = adap->port[i];
		const struct port_info *pi = netdev_priv(dev);

		for (j = 0; j < pi->nqsets - 1; j++) {
			if (!adap->dummy_netdev[dummy_idx]) {
				struct port_info *p;

				nd = alloc_netdev(sizeof(*p), "", ether_setup);
				if (!nd)
					goto free_all;

				p = netdev_priv(nd);
				p->adapter = adap;
				nd->weight = 64;
				set_bit(__LINK_STATE_START, &nd->state);
				adap->dummy_netdev[dummy_idx] = nd;
			}
			strcpy(adap->dummy_netdev[dummy_idx]->name, dev->name);
			dummy_idx++;
		}
	}
	return 0;

free_all:
	while (--dummy_idx >= 0) {
		free_netdev(adap->dummy_netdev[dummy_idx]);
		adap->dummy_netdev[dummy_idx] = NULL;
	}
	return -ENOMEM;
}
#endif

#if defined(NAPI_UPDATE)
static void init_napi(struct adapter *adap)
{
	int i;

	for (i = 0; i < SGE_QSETS; i++) {
		struct sge_qset *qs = &adap->sge.qs[i];

		if (qs->adap)
			netif_napi_add(qs->netdev, &qs->napi, qs->napi.poll,
				       64);
	}

	/*
	 * netif_napi_add() can be called only once per napi_struct because it
	 * adds each new napi_struct to a list.  Be careful not to call it a
	 * second time, e.g., during EEH recovery, by making a note of it.
	 */
        adap->flags |= NAPI_INIT;

}
#endif

/*
 * Wait until all NAPI handlers are descheduled.  This includes the handlers of
 * both netdevices representing interfaces and the dummy ones for the extra
 * queues.
 */
static void quiesce_rx(adapter_t *adap)
{
	int i;

#if defined(NAPI_UPDATE)
	for (i = 0; i < SGE_QSETS; i++) {
		struct sge_qset *qs = &adap->sge.qs[i];

		if (qs->adap)
			napi_disable(&qs->napi);
	}
#else
	struct net_device *dev;

	for_each_port(adap, i) {
		dev = adap->port[i];
		while (test_bit(__LINK_STATE_RX_SCHED, &dev->state))
			msleep(1);
	}

	for (i = 0; i < ARRAY_SIZE(adap->dummy_netdev); i++) {
		dev = adap->dummy_netdev[i];
		if (dev)
			while (test_bit(__LINK_STATE_RX_SCHED, &dev->state))
				msleep(1);
	}
#endif
}

static void enable_all_napi(struct adapter *adap)
{
#if defined(NAPI_UPDATE)
	int i;
	for (i = 0; i < SGE_QSETS; i++)
		if (adap->sge.qs[i].adap)
			napi_enable(&adap->sge.qs[i].napi);
#endif
}

/*
 * Allocate a chunk of memory using kmalloc or, if that fails, vmalloc.
 * The allocated memory is cleared.
 */
static void *alloc_mem(unsigned long size)
{
	void *p = kmalloc(size, GFP_KERNEL);

	if (!p)
		p = vmalloc(size);
	if (p)
		memset(p, 0, size);
	return p;
}

/*
 * Free memory allocated through alloc_mem().
 */
static void free_mem(void *addr)
{
	unsigned long p = (unsigned long) addr;

	if (p >= VMALLOC_START && p < VMALLOC_END)
		vfree(addr);
	else
		kfree(addr);
}

static int alloc_filters(struct adapter *adap)
{
	struct filter_info *p;

	if (!adap->params.mc5.nfilters)     /* no filters requested */
		return 0;

	adap->filters = alloc_mem(adap->params.mc5.nfilters * sizeof(*p));
	if (!adap->filters)
		return -ENOMEM;

	/* Set the default filters, only need to set non-0 fields here. */
	p = &adap->filters[adap->params.mc5.nfilters - 1];
	p->vlan = 0xfff;
	p->vlan_prio = FILTER_NO_VLAN_PRI;
	p->pass = p->rss = p->valid = p->locked = 1;

	return 0;
}

static void mk_set_tcb_field(struct cpl_set_tcb_field *req, unsigned int tid,
			     unsigned int word, u64 mask, u64 val)
{
	OPCODE_TID(req) = htonl(MK_OPCODE_TID(CPL_SET_TCB_FIELD, tid));
	req->reply = V_NO_REPLY(1);
	req->cpu_idx = 0;
	req->word = htons(word);
	req->mask = cpu_to_be64(mask);
	req->val = cpu_to_be64(val);
}

static inline void set_tcb_field_ulp(struct cpl_set_tcb_field *req,
				     unsigned int tid, unsigned int word,
				     u64 mask, u64 val)
{
	struct ulp_txpkt *txpkt = (struct ulp_txpkt *)req;

	txpkt->cmd_dest = htonl(V_ULPTX_CMD(ULP_TXPKT));
	txpkt->len = htonl(V_ULPTX_NFLITS(sizeof(*req) / 8));
	mk_set_tcb_field(req, tid, word, mask, val);
}

static int set_filter(struct adapter *adap, int id, const struct filter_info *f)
{
	int len;
	struct sk_buff *skb;
	struct ulp_txpkt *txpkt;
	struct work_request_hdr *wr;
	struct cpl_pass_open_req *oreq;
	struct cpl_set_tcb_field *sreq;

	len = sizeof(*wr) + sizeof(*oreq) + 2 * sizeof(*sreq);
	id += t3_mc5_size(&adap->mc5) - adap->params.mc5.nroutes -
	      adap->params.mc5.nfilters;

	skb = alloc_skb(len, GFP_KERNEL | __GFP_NOFAIL);

	wr = (struct work_request_hdr *)__skb_put(skb, len);
	wr->wr_hi = htonl(V_WR_OP(FW_WROPCODE_BYPASS) | F_WR_ATOMIC);

	oreq = (struct cpl_pass_open_req *)(wr + 1);
	txpkt = (struct ulp_txpkt *)oreq;
	txpkt->cmd_dest = htonl(V_ULPTX_CMD(ULP_TXPKT));
	txpkt->len = htonl(V_ULPTX_NFLITS(sizeof(*oreq) / 8));
	OPCODE_TID(oreq) = htonl(MK_OPCODE_TID(CPL_PASS_OPEN_REQ, id));
	oreq->local_port = htons(f->dport);
	oreq->peer_port = htons(f->sport);
	oreq->local_ip = htonl(f->dip);
	oreq->peer_ip = htonl(f->sip);
	oreq->peer_netmask = htonl(f->sip_mask);
	oreq->opt0h = 0;
	oreq->opt0l = htonl(F_NO_OFFLOAD);
	oreq->opt1 = htonl(V_MAC_MATCH_VALID(f->mac_vld) |
			 V_CONN_POLICY(CPL_CONN_POLICY_FILTER) |
			 V_VLAN_PRI(f->vlan_prio >> 1) |
			 V_VLAN_PRI_VALID(f->vlan_prio != FILTER_NO_VLAN_PRI) |
			 V_PKT_TYPE(f->pkt_type) | V_OPT1_VLAN(f->vlan) |
			 V_MAC_MATCH(f->mac_idx | (f->mac_hit << 4)));

	sreq = (struct cpl_set_tcb_field *)(oreq + 1);
	set_tcb_field_ulp(sreq, id, 1, 0x1800808000ULL,
			  (f->report_filter_id << 15) | (1 << 23) |
			  ((u64)f->pass << 35) | ((u64)!f->rss << 36));
	set_tcb_field_ulp(sreq + 1, id, 0, 0xffffffff, (2 << 19) | 1);
	t3_mgmt_tx(adap, skb);

	if (f->pass && !f->rss) {
		len = sizeof(*sreq);
		skb = alloc_skb(len, GFP_KERNEL | __GFP_NOFAIL);

		sreq = (struct cpl_set_tcb_field *)__skb_put(skb, len);
		sreq->wr.wr_hi = htonl(V_WR_OP(FW_WROPCODE_FORWARD));
		mk_set_tcb_field(sreq, id, 25, 0x3f80000,
				 (u64)adap->rrss_map[f->qset] << 19);
		t3_mgmt_tx(adap, skb);
	}
	return 0;
}

static int setup_hw_filters(struct adapter *adap)
{
	int i, err = 0;

	if (!adap->filters ||
	    atomic_read(&adap->filter_toe_mode) == CXGB3_FTM_TOE)
		return 0;

	t3_enable_filters(adap);

	for (i = err = 0; i < adap->params.mc5.nfilters && !err; i++)
		if (adap->filters[i].locked) {
			int ret = set_filter(adap, i, &adap->filters[i]);
			if (ret)
				err = ret;
		}
	return err;
}

/*
 * Atomically determine/set the filter/TOE mode exclusion switch to the
 * desired mode and return the success state.  The first time this is called
 * the filter/TOE mode of the adapter will be set permanently to the selected
 * mode.
 */
int cxgb3_filter_toe_mode(struct adapter *adapter, int mode)
{
	static spinlock_t cxgb3_filter_toe_lock = SPIN_LOCK_UNLOCKED;
	int cur_mode;

	/*
	 * It would be much easier to do all of this if we could use
	 * atomic_cmpxchg() but that primitive isn't available on all
	 * platforms so we're essentially faking it here via a spinlock.  We
	 * do an optimization here of reading the interlock without taking the
	 * spinlock and returning success/failure if the interlock has already
	 * been set.  We can do this because the interlock is one-shot and
	 * once set is never changed.  With this optimization, a single global
	 * spinlock is fine for protecting the critical section.
	 */
	cur_mode = atomic_read(&adapter->filter_toe_mode);
	if (cur_mode != CXGB3_FTM_NONE)
		return cur_mode == mode;

	spin_lock(&cxgb3_filter_toe_lock);

	cur_mode = atomic_read(&adapter->filter_toe_mode);
	if (cur_mode != CXGB3_FTM_NONE) {
		/* got changed while we were taking the lock ... */
		spin_unlock(&cxgb3_filter_toe_lock);
		return cur_mode == mode;
	}

	/*
	 * If we're successfully setting TOE mode for the adapter, disable
	 * the adapter's filter capabilities.
	 */
	if (mode == CXGB3_FTM_TOE)
		t3_disable_filters(adapter);

	atomic_set(&adapter->filter_toe_mode, mode);
	spin_unlock(&cxgb3_filter_toe_lock);

	return 1;
}


/**
 *	setup_sge_qsets - configure SGE Tx/Rx/response queues
 *	@adap: the adapter
 *
 *	Determines how many sets of SGE queues to use and initializes them.
 *	We support multiple queue sets per port if we have MSI-X, otherwise
 *	just one queue set per port.
 */
static int setup_sge_qsets(struct adapter *adap)
{
	int i, j, err, irq_idx = 0, qset_idx = 0, dummy_dev_idx;
	unsigned int ntxq = SGE_TXQ_PER_SET;

	if (adap->params.rev > 0 && !(adap->flags & USING_MSI))
		irq_idx = -1;

	dummy_dev_idx = 0;
	for_each_port(adap, i) {
		struct net_device *dev = adap->port[i];
		struct port_info *pi = netdev_priv(dev);

		pi->qs = &adap->sge.qs[pi->first_qset];
		for (j = 0; j < pi->nqsets; ++j, ++qset_idx) {
			if (!pi->rx_csum_offload)
				adap->params.sge.qset[qset_idx].lro = 0;
			err = t3_sge_alloc_qset(adap, qset_idx, 1,
				(adap->flags & USING_MSIX) ? qset_idx + 1 :
							     irq_idx,
				&adap->params.sge.qset[qset_idx], ntxq,
#if defined(NAPI_UPDATE)
				dev,
				netdev_get_tx_queue(dev, j));
#else
				j == 0 ? dev :
					 adap->dummy_netdev[dummy_dev_idx++],
				NULL);
#endif

			if (err) {
				t3_free_sge_resources(adap);
				return err;
			}
		}
	}

	return 0;
}

#ifndef	LINUX_2_4
static ssize_t attr_show(struct cxgb3_compat_device *d, char *buf,
			 ssize_t (*format)(struct net_device *, char *))
{
	ssize_t len;

	/* Synchronize with ioctls that may shut down the device */
	rtnl_lock();
	len = (*format)(to_net_dev(d), buf);
	rtnl_unlock();
	return len;
}

static ssize_t attr_store(struct cxgb3_compat_device *d,
			  const char *buf, size_t len,
			  ssize_t (*set)(struct net_device *, unsigned int),
			  unsigned int min_val, unsigned int max_val)
{
	char *endp;
	ssize_t ret;
	unsigned int val;

	if (!capable(CAP_NET_ADMIN))
		return -EPERM;

	val = simple_strtoul(buf, &endp, 0);
	if (endp == buf || val < min_val || val > max_val)
		return -EINVAL;

	rtnl_lock();
	ret = (*set)(to_net_dev(d), val);
	if (!ret)
		ret = len;
	rtnl_unlock();
	return ret;
}

#define CXGB3_SHOW(name, val_expr) \
static ssize_t format_##name(struct net_device *dev, char *buf) \
{ \
	struct port_info *pi = netdev_priv(dev); \
	struct adapter *adap = pi->adapter; \
	return sprintf(buf, "%u\n", val_expr); \
} \
CXGB3_SHOW_FUNC(show_##name, d, attr, buf) \
{ \
	return attr_show(d, buf, format_##name); \
}

static ssize_t set_nfilters(struct net_device *dev, unsigned int val)
{
	return cxgb_set_nfilters(dev, val);
}

CXGB3_STORE_FUNC(store_nfilters, d, attr, buf, len)
{
	return attr_store(d, buf, len, set_nfilters, 0, ~0);
}

static ssize_t set_nservers(struct net_device *dev, unsigned int val)
{
	struct port_info *pi = netdev_priv(dev);
	struct adapter *adap = pi->adapter;

	if (adap->flags & FULL_INIT_DONE)
		return -EBUSY;
	if (val > t3_mc5_size(&adap->mc5) - adap->params.mc5.nfilters -
	    MC5_MIN_TIDS)
		return -EINVAL;
	adap->params.mc5.nservers = val;
	return 0;
}

CXGB3_STORE_FUNC(store_nservers, d, attr, buf, len)
{
	return attr_store(d, buf, len, set_nservers, 0, ~0);
}

#define CXGB3_ATTR_R(name, val_expr) \
CXGB3_SHOW(name, val_expr) \
static CXGB3_DEVICE_ATTR(name, S_IRUGO, show_##name, NULL)

#define CXGB3_ATTR_RW(name, val_expr, store_method) \
CXGB3_SHOW(name, val_expr) \
static CXGB3_DEVICE_ATTR(name, S_IRUGO | S_IWUSR, show_##name, store_method)

CXGB3_ATTR_R(cam_size, t3_mc5_size(&adap->mc5));
CXGB3_ATTR_RW(nfilters, adap->params.mc5.nfilters, store_nfilters);
CXGB3_ATTR_RW(nservers, adap->params.mc5.nservers, store_nservers);

static struct attribute *cxgb3_attrs[] = {
	&dev_attr_cam_size.attr,
	&dev_attr_nfilters.attr,
	&dev_attr_nservers.attr,
	NULL
};

static struct attribute_group cxgb3_attr_group = { .attrs = cxgb3_attrs };

static ssize_t reg_attr_show(struct cxgb3_compat_device *d, char *buf, int reg,
			     int shift, unsigned int mask)
{
	struct port_info *pi = netdev_priv(to_net_dev(d));
	struct adapter *adap = pi->adapter;
	ssize_t len;
	unsigned int v;

	/* Synchronize with ioctls that may shut down the device */
	rtnl_lock();
	v = t3_read_reg(adap, reg);
	len = sprintf(buf, "%u\n", (v >> shift) & mask);
	rtnl_unlock();
	return len;
}

static ssize_t reg_attr_store(struct cxgb3_compat_device *d, const char *buf,
			      size_t len, int reg, int shift,
			      unsigned int mask, unsigned int min_val,
			      unsigned int max_val)
{
	struct port_info *pi = netdev_priv(to_net_dev(d));
	struct adapter *adap = pi->adapter;
	char *endp;
	unsigned int val;

	if (!capable(CAP_NET_ADMIN))
		return -EPERM;

	val = simple_strtoul(buf, &endp, 0);
	if (endp == buf || val < min_val || val > max_val)
		return -EINVAL;

	rtnl_lock();
	t3_set_reg_field(adap, reg, mask << shift,
			 val << shift);
	rtnl_unlock();
	return len;
}

#define T3_REG_SHOW(name, reg, shift, mask) \
CXGB3_SHOW_FUNC(show_##name, d, attr, buf) \
{ \
	return reg_attr_show(d, buf, reg, shift, mask); \
}

#define T3_REG_STORE(name, reg, shift, mask, min_val, max_val) \
CXGB3_STORE_FUNC(store_##name, d, attr, buf, len) \
{ \
	return reg_attr_store(d, buf, len, reg, shift, mask, min_val, max_val); \
}

#define T3_ATTR(name, reg, shift, mask, min_val, max_val) \
T3_REG_SHOW(name, reg, shift, mask) \
T3_REG_STORE(name, reg, shift, mask, min_val, max_val) \
static CXGB3_DEVICE_ATTR(name, S_IRUGO | S_IWUSR, show_##name, store_##name)

T3_ATTR(tcp_retries1, A_TP_SHIFT_CNT, S_RXTSHIFTMAXR1, M_RXTSHIFTMAXR1, 3, 15);
T3_ATTR(tcp_retries2, A_TP_SHIFT_CNT, S_RXTSHIFTMAXR2, M_RXTSHIFTMAXR2, 0, 15);
T3_ATTR(tcp_syn_retries, A_TP_SHIFT_CNT, S_SYNSHIFTMAX, M_SYNSHIFTMAX, 0, 15);
T3_ATTR(tcp_keepalive_probes, A_TP_SHIFT_CNT, S_KEEPALIVEMAX, M_KEEPALIVEMAX,
	1, 15);
T3_ATTR(tcp_sack, A_TP_TCP_OPTIONS, S_SACKMODE, M_SACKMODE, 0, 1);
T3_ATTR(tcp_timestamps, A_TP_TCP_OPTIONS, S_TIMESTAMPSMODE, M_TIMESTAMPSMODE,
	0, 1);

static ssize_t timer_attr_show(struct cxgb3_compat_device *d, char *buf, int reg)
{
	struct port_info *pi = netdev_priv(to_net_dev(d));
	struct adapter *adap = pi->adapter;
	unsigned int v, tps;
	ssize_t len;

	/* Synchronize with ioctls that may shut down the device */
	rtnl_lock();
	v = t3_read_reg(adap, reg);
	tps = (adap->params.vpd.cclk * 1000) >> adap->params.tp.tre;
	len = sprintf(buf, "%u\n", v / tps);
	rtnl_unlock();
	return len;
}

static ssize_t timer_attr_store(struct cxgb3_compat_device *d, const char *buf,
				size_t len, int reg, unsigned int min_val,
				unsigned int max_val)
{
	struct port_info *pi = netdev_priv(to_net_dev(d));
	struct adapter *adap = pi->adapter;
	char *endp;
	unsigned int val, tps;

	if (!capable(CAP_NET_ADMIN))
		return -EPERM;

	tps = (adap->params.vpd.cclk * 1000) >> adap->params.tp.tre;
	val = simple_strtoul(buf, &endp, 0);
	if (endp == buf || val * tps < min_val || val * tps > max_val)
		return -EINVAL;

	rtnl_lock();
	t3_write_reg(adap, reg, val * tps);
	rtnl_unlock();
	return len;
}

#define T3_TIMER_REG_SHOW(name, reg) \
CXGB3_SHOW_FUNC(show_##name, d, attr, buf) \
{ \
	return timer_attr_show(d, buf, reg); \
}

#define T3_TIMER_REG_STORE(name, reg, min_val, max_val) \
CXGB3_STORE_FUNC(store_##name, d, attr, buf, len) \
{ \
	return timer_attr_store(d, buf, len, reg, min_val, max_val); \
}

#define T3_TIMER_ATTR(name, reg, min_val, max_val) \
T3_TIMER_REG_SHOW(name, reg) \
T3_TIMER_REG_STORE(name, reg, min_val, max_val) \
static CXGB3_DEVICE_ATTR(name, S_IRUGO | S_IWUSR, show_##name, store_##name)

T3_TIMER_ATTR(tcp_keepalive_time, A_TP_KEEP_IDLE, 0, M_KEEPALIVEIDLE);
T3_TIMER_ATTR(tcp_keepalive_intvl, A_TP_KEEP_INTVL, 0, M_KEEPALIVEINTVL);
T3_TIMER_ATTR(tcp_finwait2_timeout, A_TP_FINWAIT2_TIMER, 0, M_FINWAIT2TIME);

static ssize_t tm_attr_show(struct cxgb3_compat_device *d, char *buf, int sched)
{
	struct port_info *pi = netdev_priv(to_net_dev(d));
	struct adapter *adap = pi->adapter;
	ssize_t len;
	unsigned int rate;

	rtnl_lock();
	t3_get_tx_sched(adap, sched, &rate, NULL);
	if (!rate)
		len = sprintf(buf, "disabled\n");
	else
		len = sprintf(buf, "%u Kbps\n", rate);
	rtnl_unlock();
	return len;
}

static ssize_t tm_attr_store(struct cxgb3_compat_device *d, const char *buf,
			     size_t len, int sched)
{
	struct port_info *pi = netdev_priv(to_net_dev(d));
	struct adapter *adap = pi->adapter;
	char *endp;
	ssize_t ret;
	unsigned int val;

	if (!capable(CAP_NET_ADMIN))
		return -EPERM;

	val = simple_strtoul(buf, &endp, 0);
	if (endp == buf || val > 10000000)
		return -EINVAL;

	rtnl_lock();
	ret = t3_config_sched(adap, val, sched);
	if (!ret)
		ret = len;
	rtnl_unlock();
	return ret;
}

#define TM_ATTR(name, sched) \
CXGB3_SHOW_FUNC(show_##name, d, attr, buf) \
{ \
	return tm_attr_show(d, buf, sched); \
} \
CXGB3_STORE_FUNC(store_##name, d, attr, buf, len) \
{ \
	return tm_attr_store(d, buf, len, sched); \
} \
static CXGB3_DEVICE_ATTR(name, S_IRUGO | S_IWUSR, show_##name, store_##name)

TM_ATTR(sched0, 0);
TM_ATTR(sched1, 1);
TM_ATTR(sched2, 2);
TM_ATTR(sched3, 3);
TM_ATTR(sched4, 4);
TM_ATTR(sched5, 5);
TM_ATTR(sched6, 6);
TM_ATTR(sched7, 7);

static struct attribute *offload_attrs[] = {
	&dev_attr_tcp_retries1.attr,
	&dev_attr_tcp_retries2.attr,
	&dev_attr_tcp_syn_retries.attr,
	&dev_attr_tcp_keepalive_probes.attr,
	&dev_attr_tcp_sack.attr,
	&dev_attr_tcp_timestamps.attr,
	&dev_attr_tcp_keepalive_time.attr,
	&dev_attr_tcp_keepalive_intvl.attr,
	&dev_attr_tcp_finwait2_timeout.attr,
	&dev_attr_sched0.attr,
	&dev_attr_sched1.attr,
	&dev_attr_sched2.attr,
	&dev_attr_sched3.attr,
	&dev_attr_sched4.attr,
	&dev_attr_sched5.attr,
	&dev_attr_sched6.attr,
	&dev_attr_sched7.attr,
	NULL
};

static struct attribute_group offload_attr_group = { .attrs = offload_attrs };

static ssize_t iscsi_ipv4addr_attr_show(struct cxgb3_compat_device *d, char *buf)
{
	struct port_info *pi = netdev_priv(to_net_dev(d));
	__be32 a = pi->iscsi_ipv4addr;

	return sprintf(buf, NIPQUAD_FMT "\n", NIPQUAD(a));
}

static ssize_t iscsi_ipv4addr_attr_store(struct cxgb3_compat_device *d,
				       const char *buf, size_t len)
{
	struct port_info *pi = netdev_priv(to_net_dev(d));

	pi->iscsi_ipv4addr = in_aton(buf);
	return len;
}

#define ISCSI_IPADDR_ATTR(name) \
CXGB3_SHOW_FUNC(show_##name, d, attr, buf) \
{ \
	return iscsi_ipv4addr_attr_show(d, buf); \
} \
CXGB3_STORE_FUNC(store_##name, d, attr, buf, len) \
{ \
	return iscsi_ipv4addr_attr_store(d, buf, len); \
} \
static CXGB3_DEVICE_ATTR(name, S_IRUGO | S_IWUSR, show_##name, store_##name)

ISCSI_IPADDR_ATTR(iscsi_ipv4addr);

static struct attribute *iscsi_offload_attrs[] = {
	&dev_attr_iscsi_ipv4addr.attr,
	NULL
};

static struct attribute_group iscsi_offload_attr_group = {
	.attrs = iscsi_offload_attrs
};
#endif	/* ! LINUX_2_4 */

/*
 * Sends an sk_buff to an offload queue driver
 * after dealing with any active network taps.
 */
static inline int offload_tx(struct t3cdev *tdev, struct sk_buff *skb)
{
	int ret;

	local_bh_disable();
	ret = t3_offload_tx(tdev, skb);
	local_bh_enable();
	return ret;
}

static int write_smt_entry(struct adapter *adapter, int idx)
{
	struct cpl_smt_write_req *req;
	struct sk_buff *skb = alloc_skb(sizeof(*req), GFP_KERNEL);

	if (!skb) return -ENOMEM;

	req = (struct cpl_smt_write_req *)__skb_put(skb, sizeof(*req));
	req->wr.wr_hi = htonl(V_WR_OP(FW_WROPCODE_FORWARD));
	OPCODE_TID(req) = htonl(MK_OPCODE_TID(CPL_SMT_WRITE_REQ, idx));
	req->mtu_idx = NMTUS - 1;  /* should be 0 but there's a T3 bug */
	req->iff = idx;
	memset(req->src_mac1, 0, sizeof(req->src_mac1));
	memcpy(req->src_mac0, adapter->port[idx]->dev_addr, ETH_ALEN);
	skb->priority = 1;
	offload_tx(&adapter->tdev, skb);
	return 0;
}

static int init_smt(struct adapter *adapter)
{
	int i;

	for_each_port(adapter, i)
		write_smt_entry(adapter, i);
	return 0;
}

static void init_port_mtus(struct adapter *adapter)
{
	unsigned int mtus = adapter->port[0]->mtu;

	if (adapter->port[1])
		mtus |= adapter->port[1]->mtu << 16;
	t3_write_reg(adapter, A_TP_MTU_PORT_TABLE, mtus);
}

static int send_pktsched_cmd(struct adapter *adap, int sched, int qidx, int lo,
			      int hi, int port)
{
	struct sk_buff *skb;
	struct mngt_pktsched_wr *req;

	skb = alloc_skb(sizeof(*req), GFP_KERNEL | __GFP_NOFAIL);
	req = (struct mngt_pktsched_wr *)skb_put(skb, sizeof(*req));
	req->wr_hi = htonl(V_WR_OP(FW_WROPCODE_MNGT));
	req->mngt_opcode = FW_MNGTOPCODE_PKTSCHED_SET;
	req->sched = sched;
	req->idx = qidx;
	req->min = lo;
	req->max = hi;
	req->binding = port;
	t3_mgmt_tx(adap, skb);

	return 0;
}

static int send_watchdog_cmd(struct adapter *adap, int wd, __u16 en,
      		__u16 ac, __u32 tval)
{
  	struct sk_buff *skb;
 	struct mngt_watchdog_wr *req;
 	int ret;
 
	skb = alloc_skb(sizeof(*req), GFP_KERNEL | __GFP_NOFAIL);
 	req = (struct mngt_watchdog_wr *)skb_put(skb, sizeof(*req));
 	memset(req, 0, sizeof(*req));
 	req->wr_hi = htonl(V_WR_OP(FW_WROPCODE_MNGT));
 	req->mngt_opcode = (__u8)wd;
 	req->enable = htons(en ? V_FW_WR_WD_EN(1) : V_FW_WR_WD_EN(0));
 	req->ac_or_rsvd1 = htons(ac);
	req->tval_or_rsvd2 = htonl(tval);
 	ret = t3_mgmt_tx(adap, skb);
 
	return ret;
}

static int bind_qsets(struct adapter *adap)
{
	int i, j, err = 0;

	for_each_port(adap, i) {
		const struct port_info *pi = adap2pinfo(adap, i);

		for (j = 0; j < pi->nqsets; ++j) {
			int ret = send_pktsched_cmd(adap, 1,
						    pi->first_qset + j, -1, -1,
						    pi->tx_chan);
			if (ret)
				err = ret;
		}
	}

	return err;
}

static void t3_release_firmware(const struct firmware *fw)
{
	if (!t3_local_firmware_free(fw))
		return;
	release_firmware(fw);
}	

static int t3_request_firmware(const struct firmware **firmware, const char *name,
                 struct device *dev)
{
	/* first check if there is firmware on the filesystem */
	if (!request_firmware(firmware, name, dev)) {
		return 0;
	}

	return t3_local_firmware_load(firmware, name);
}

#if !defined(LINUX_2_4)
#define FW_FNAME "cxgb3/t3fw-%d.%d.%d.bin"
#define TPEEPROM_NAME "cxgb3/t3%c_tp_eeprom-%d.%d.%d.bin"
#define TPSRAM_NAME "cxgb3/t3%c_protocol_sram-%d.%d.%d.bin"
#define AEL2005_OPT_EDC_NAME "cxgb3/ael2005_opt_edc.bin"
#define AEL2005_TWX_EDC_NAME "cxgb3/ael2005_twx_edc.bin"
#define AEL2020_TWX_EDC_NAME "cxgb3/ael2020_twx_edc.bin"

static inline const char *get_edc_fw_name(int edc_idx)
{
	const char *fw_name = NULL;

	switch (edc_idx) {
	case EDC_OPT_AEL2005:
		fw_name = AEL2005_OPT_EDC_NAME;
		break;
	case EDC_TWX_AEL2005:
		fw_name = AEL2005_TWX_EDC_NAME;
		break;
	case EDC_TWX_AEL2020:
		fw_name = AEL2020_TWX_EDC_NAME;
		break;
	}
	return fw_name;
}

/**
 *	t3_get_edc_fw - load specified PHY EDC code
 *	@phy: pointer to PHY state (and associated EDC cache)
 *	@edc_idx: ID of EDC code to load
 *
 *	Load the PHY Electronic Dispersion Control (EDC) Firmware indicated
 *	by edc_index into the PHY's EDC Cache.  If no errors occur, then the
 *	EDC size (in bytes) will be returned.  Otherwise a standard negative
 *	error number with be returned.
 */
int t3_get_edc_fw(struct cphy *phy, int edc_idx)
{
	struct adapter *adapter = phy->adapter;
	const struct firmware *fw;
	char buf[64];
	u32 csum;
	const __be32 *p;
	u16 *cache = phy->phy_cache;
	int i, ret;

	snprintf(buf, sizeof(buf), get_edc_fw_name(edc_idx));

	ret = t3_request_firmware(&fw, buf, &adapter->pdev->dev);
	if (ret < 0) {
		dev_err(&adapter->pdev->dev,
			"could not upgrade firmware: unable to load %s\n",
			buf);
		return ret;
	}

	/* check size, take checksum in account */
	if (fw->size > sizeof(phy->phy_cache) + 4) {
		CH_ERR(adapter, "firmware image too large %u, max supported %u\n",
		       (unsigned int)fw->size-4,
		       (unsigned int)sizeof(phy->phy_cache));
		ret = -EINVAL;
	}

	/* compute checksum */
	p = (const __be32 *)fw->data;
	for (csum = 0, i = 0; i < fw->size / sizeof(csum); i++)
		csum += ntohl(p[i]);

	if (csum != 0xffffffff) {
		CH_ERR(adapter, "corrupted firmware image, checksum %u\n",
			csum);
		ret = -EINVAL;
	}

	for (i = 0; i < fw->size / 4 ; i++) {
		*cache++ = (be32_to_cpu(p[i]) & 0xffff0000) >> 16;
		*cache++ = be32_to_cpu(p[i]) & 0xffff;
	}
	ret = fw->size;

	t3_release_firmware(fw);

	return ret;
}

static int upgrade_fw(struct adapter *adap)
{
	int ret;
	char buf[64];
	const struct firmware *fw;
	struct device *dev = &adap->pdev->dev;

	snprintf(buf, sizeof(buf), FW_FNAME, FW_VERSION_MAJOR,
		 FW_VERSION_MINOR, FW_VERSION_MICRO);
	ret = request_firmware(&fw, buf, dev);
	if (ret < 0) {
		dev_err(dev, "could not upgrade firmware: unable to load %s\n",
			buf);
		return ret;
	}
	ret = t3_load_fw(adap, fw->data, fw->size);
	release_firmware(fw);

	if (ret == 0)
		dev_warn(dev, "successful upgrade to firmware %d.%d.%d\n",
			FW_VERSION_MAJOR, FW_VERSION_MINOR, FW_VERSION_MICRO);
	else
		dev_err(dev, "failed to upgrade to firmware %d.%d.%d\n",
			FW_VERSION_MAJOR, FW_VERSION_MINOR, FW_VERSION_MICRO);

	return ret;
}

static int set_eeprom(struct net_device *dev, struct ethtool_eeprom *eeprom,
		      u8 *data);

static inline char t3rev2char(struct adapter *adapter)
{
	char rev = 'z';

	switch(adapter->params.rev) {
	case T3_REV_A:
		rev = 'a';
		break;
	case T3_REV_B:
	case T3_REV_B2:
		rev = 'b';
		break;
	case T3_REV_C:
		rev = 'c';
		break;
	}
	return rev;
}

static int update_tpsram(struct adapter *adap)
{
	const struct firmware *tpsram;
	char buf[64];
	struct device *dev = &adap->pdev->dev;
	int ret, major, minor, micro;
	char rev;

	rev = t3rev2char(adap);
	if (!rev)
		return 0;

	if (rev == 'c') {
		major = TP_VERSION_MAJOR;
		minor = TP_VERSION_MINOR;
		micro = TP_VERSION_MICRO;
	} else {
		major = TP_VERSION_MAJOR_T3B;
		minor = TP_VERSION_MINOR_T3B;
		micro = TP_VERSION_MICRO_T3B;
	}

	snprintf(buf, sizeof(buf), TPSRAM_NAME, rev, major, minor, micro);

	ret = request_firmware(&tpsram, buf, dev);
	if (ret < 0) {
		dev_err(dev, "could not load TP SRAM: unable to load %s\n",
			buf);
		return ret;
	}

	ret = t3_check_tpsram(adap, tpsram->data, tpsram->size);
	if (ret)
		goto release_tpsram;

	ret = t3_set_proto_sram(adap, tpsram->data);
	if (ret == 0)
		dev_warn(dev,
			 "successful update of protocol engine "
			 "to %d.%d.%d\n", major, minor, micro);
	else
		dev_err(dev, "failed to update of protocol engine %d.%d.%d\n",
			major, minor, micro);
	if (ret)
		dev_err(dev, "loading protocol SRAM failed\n");

release_tpsram:
	release_firmware(tpsram);

	return ret;
}
#endif /* ! LINUX_2_4 */

static inline int is_in_filter_mode(struct adapter *adapter)
{
	return adapter->params.mc5.nfilters;
}

static void kick_watchdog_timer(unsigned long data)
{
	struct adapter *adap = (struct adapter *)data;
	u32 glbtimer;

	t3_cim_hac_read(adap, (A_CIM_CTL_BASE + A_CIM_CTL_GLB_TIMER),
			&glbtimer);
	t3_cim_hac_write(adap, (A_CIM_CTL_BASE + A_CIM_CTL_TIMER0),
			(glbtimer + (10 * adap->params.vpd.cclk * 1000)));
	setup_timer(&adap->watchdog_timer, kick_watchdog_timer,
			(unsigned long)adap);
	mod_timer(&adap->watchdog_timer, jiffies + msecs_to_jiffies(1000));
}

/*
 *	fw_supports_watchdog - Check whether the firmware supports watchdog
 *	feature or not.
 *	@adap - Adapter whose firmware is to be checked for watchdog
 *	feature support.
 *
 *	Read adapter firmware version to find out whether it supports
 *	watchdog feature or not. T3 firmware v7.12.0 onwards includes
 *	support for watchdogs.
 */
static int fw_supports_watchdog(struct adapter *adap)
{
	u32 fw_ver;
	t3_get_fw_version(adap, &fw_ver);

	return fw_ver >= (G_FW_VERSION_MAJOR(7) | G_FW_VERSION_MINOR(12));
}

static int setup_watchdog(struct adapter *adap, int wd, __u16 en,
		__u16 ac, __u32 tval)
{
	u32 val;
	__u16 action = 0;

	/*
	 * Check whether firmware supports watchdogs.
	 */
	if (!fw_supports_watchdog(adap)) {
		printk(KERN_INFO "cxgb3: Firmware doesn't support watchdogs\n");
		return 1;
	}

	if (wd == FW_MNGTOPCODE_DRIVERWATCHDOG) {
		if ((ac == 0) || (ac == 1))
			action = GPIO_EN_0;
		else if (ac == 2)
			action = PCIE_LINKDOWN;
		else if (ac == 3)
			action = FW_EXCEPTION;
		else {
			printk(KERN_WARNING "cxgb3: Invalid action for driver "
					"watchdog\n");
			return 1;
		}

		t3_cim_hac_read(adap, (A_CIM_CTL_BASE + A_CIM_CTL_GLB_TIMER),
				&val);
		t3_cim_hac_write(adap, (A_CIM_CTL_BASE + A_CIM_CTL_TIMER0),
				(val + (10 * adap->params.vpd.cclk * 1000)));
		setup_timer(&adap->watchdog_timer, kick_watchdog_timer,
				(unsigned long)adap);
		mod_timer(&adap->watchdog_timer, 
				jiffies + msecs_to_jiffies(1000));
	} else if (wd == FW_MNGTOPCODE_FIRMWAREWATCHDOG) {
		val = t3_read_reg(adap, A_CIM_HOST_INT_ENABLE);
		val = val | (1 << 15);
		t3_write_reg(adap, A_CIM_HOST_INT_ENABLE, val);

		val = t3_read_reg(adap, A_CIM_HOST_INT_ENABLE);
		val = val & ~(1 << 15);
		t3_write_reg(adap, A_CIM_HOST_INT_CAUSE, val);
	}

	return send_watchdog_cmd(adap, wd, en, action, tval);
}

/**
 *	cxgb_up - enable the adapter
 *	@adap: adapter being enabled
 *
 *	Called when the first port is enabled, this function performs the
 *	actions necessary to make an adapter operational, such as completing
 *	the initialization of HW modules, and enabling interrupts.
 *
 *	Must be called with the rtnl lock held.
 */
static int cxgb_up(struct adapter *adap)
{
	int err = 0;

	if (!(adap->flags & FULL_INIT_DONE)) {
		err = t3_check_fw_version(adap);
#if !defined(LINUX_2_4)
		if (err == -EINVAL) {
			err = upgrade_fw(adap);
			CH_WARN(adap, "FW upgrade to %d.%d.%d %s\n",
				FW_VERSION_MAJOR, FW_VERSION_MINOR,
				FW_VERSION_MICRO, err ? "failed" : "succeeded");
		}
#endif

		err = t3_check_tpsram_version(adap);
#if !defined(LINUX_2_4)
		if (err == -EINVAL) {
			err = update_tpsram(adap);
			if (adap->params.rev == T3_REV_C) {
				CH_WARN(adap, "TP upgrade to %d.%d.%d %s\n",
					TP_VERSION_MAJOR, TP_VERSION_MINOR,
					TP_VERSION_MICRO,
					err ? "failed" :"succeeded");
			} else {
				CH_WARN(adap, "TP upgrade to %d.%d.%d %s\n",
					TP_VERSION_MAJOR_T3B,
					TP_VERSION_MINOR_T3B,
					TP_VERSION_MICRO_T3B,
					err ? "failed" : "succeeded");
			}
		}
#endif

		/* PR 6487. TOE and filtering are mutually exclusive */
		cxgb3_filter_toe_mode(adap, is_in_filter_mode(adap) ?
				      CXGB3_FTM_FILTER : CXGB3_FTM_TOE);

#if !defined(NAPI_UPDATE)
		err = init_dummy_netdevs(adap);
		if (err)
			goto out;
#endif
		/*
		 * Clear interrupts now to catch errors if t3_init_hw fails.
		 * We clear them again later as initialization may trigger
		 * conditions that can interrupt.
		 */
		t3_intr_clear(adap);

		err = t3_init_hw(adap, 0);
		if (err)
			goto out;

		t3_set_reg_field(adap, A_TP_PARA_REG5, 0, F_RXDDPOFFINIT);

/* T3 has a lookup table for 4 different page sizes with the default 4K page size using HPZ0
 * Use the upper register HPZ3 for TCP DPP to support huge pages
 */

#if defined(CONFIG_T3_ZCOPY_HUGEPAGES) && defined(CONFIG_HUGETLB_PAGE)
#define T3_HPAGE_SHIFT (HPAGE_SHIFT > 27 ? 27 : HPAGE_SHIFT)
		t3_write_reg(adap, A_ULPRX_TDDP_PSZ,
			     V_HPZ0(PAGE_SHIFT - 12) |
			     V_HPZ3(T3_HPAGE_SHIFT - 12));
#else
		t3_write_reg(adap, A_ULPRX_TDDP_PSZ, V_HPZ0(PAGE_SHIFT - 12));
#endif

		err = setup_sge_qsets(adap);
		if (err)
			goto out;

		alloc_filters(adap);
		setup_rss(adap);
#if defined(NAPI_UPDATE)
		if (!(adap->flags & NAPI_INIT))
			init_napi(adap);
#endif
		t3_start_sge_timers(adap);
		
		if (drv_wd_en) {
			if (setup_watchdog(adap, FW_MNGTOPCODE_DRIVERWATCHDOG,
						1, drv_wd_ac, 0))
				printk(KERN_WARNING "cxgb3: Failure to setup "
						"driver watchdog\n");
		}

		if (fw_wd_en) {
			if (setup_watchdog(adap, FW_MNGTOPCODE_FIRMWAREWATCHDOG, 1,
					0, (10 * adap->params.vpd.cclk * 1000)))
				printk(KERN_WARNING "cxgb3: Failure to setup "
						"firmware watchdog");
		}

		adap->flags |= FULL_INIT_DONE;
	}

	t3_intr_clear(adap);

	if (adap->flags & USING_MSIX) {
		name_msix_vecs(adap);
		err = request_irq(adap->msix_info[0].vec,
				  t3_async_intr_handler, 0,
				  adap->msix_info[0].desc, adap);
		if (err)
			goto irq_err;

		err = request_msix_data_irqs(adap);
		if (err) {
			free_irq(adap->msix_info[0].vec, adap);
			goto irq_err;
		}
	} else if ((err = request_irq(adap->pdev->irq,
				t3_intr_handler(adap,
						adap->sge.qs[0].rspq.flags & USING_POLLING),
				(adap->flags & USING_MSI) ? 0 : IRQF_SHARED,
				adap->name, adap)))
		goto irq_err;

	enable_all_napi(adap);
	t3_sge_start(adap);
	t3_intr_enable(adap);

	if (adap->params.rev >= T3_REV_C && is_offload(adap) &&
	    !(adap->flags & TP_PARITY_INIT)) {
		t3_set_reg_field(adap, A_PCIE_CFG,
			F_PCIE_DMASTOPEN, V_PCIE_DMASTOPEN(0));

		if (init_tp_parity(adap) == 0)
			adap->flags |= TP_PARITY_INIT;
	}

	if (adap->flags & TP_PARITY_INIT) {
		t3_write_reg(adap, A_TP_INT_CAUSE,
				F_CMCACHEPERR | F_ARPLUTPERR);
		t3_write_reg(adap, A_TP_INT_ENABLE, 0x7fbfffff);
	}
	t3_set_reg_field(adap, A_PCIE_CFG,
			F_PCIE_DMASTOPEN, F_PCIE_DMASTOPEN);

	if (!(adap->flags & QUEUES_BOUND)) {
		err = bind_qsets(adap);
		if (err) {
			CH_ERR(adap, "failed to bind qsets, err %d\n", err);
			t3_intr_disable(adap);
			free_irq_resources(adap);
			goto out;
		}
		setup_hw_filters(adap);
		adap->flags |= QUEUES_BOUND;
	}
out:
	return err;
irq_err:
	CH_ERR(adap, "request_irq failed, err %d\n", err);
	goto out;
}

/*
 * Release resources when all the ports and offloading have been stopped.
 */
static void cxgb_down(struct adapter *adapter, int on_wq)
{
	unsigned long flags;

	t3_sge_stop(adapter);

	/* sync with PHY intr task */
	spin_lock_irqsave(&adapter->work_lock, flags);
	t3_intr_disable(adapter);
	spin_unlock_irqrestore(&adapter->work_lock, flags);

	free_irq_resources(adapter);
	if (!on_wq)
		flush_workqueue(cxgb3_wq);/* wait for external IRQ handler */
	quiesce_rx(adapter);
}

static void schedule_chk_task(struct adapter *adap)
{
	unsigned int timeo;

	timeo = adap->params.linkpoll_period ?
		(HZ * adap->params.linkpoll_period) / 10 :
		adap->params.stats_update_period * HZ;
	if (timeo)
		queue_delayed_work(cxgb3_wq, &adap->adap_check_task, timeo);
}

static int offload_open(struct net_device *dev)
{
	struct port_info *pi = netdev_priv(dev);
	struct adapter *adapter = pi->adapter;
	struct t3cdev *tdev = dev2t3cdev(dev);
	int adap_up = adapter->open_device_map & PORT_MASK;
	int err = 0;

	if (test_and_set_bit(OFFLOAD_DEVMAP_BIT, &adapter->open_device_map))
		return 0;

	/* PR 6487. Filtering and TOE mutually exclusive */
	if (!cxgb3_filter_toe_mode(adapter, CXGB3_FTM_TOE)) {
		printk(KERN_WARNING
		       "%s: filtering on. Offload disabled\n", dev->name);
		err = -1;
		goto out;
	}

	if (!adap_up && (err = cxgb_up(adapter)) < 0)
		goto out;

	t3_tp_set_offload_mode(adapter, 1);
	tdev->lldev = adapter->port[0];
	err = cxgb3_offload_activate(adapter);
	if (err)
		goto out;

	init_port_mtus(adapter);
	t3_load_mtus(adapter, adapter->params.mtus, adapter->params.a_wnd,
		     adapter->params.b_wnd,
		     adapter->params.rev == 0 ?
		       adapter->port[0]->mtu : 0xffff);
	init_smt(adapter);

#ifndef	LINUX_2_4
	/* Never mind if the next step fails */
	if (sysfs_create_group(net2kobj(tdev->lldev), &offload_attr_group))
		printk(KERN_INFO
		       "%s: cannot create sysfs offload_attr_group\n",
		       dev->name);
#endif	/* LINUX_2_4 */

	/* Call back all registered clients */
	cxgb3_add_clients(tdev);

out:
	/* restore them in case the offload module has changed them */
	if (err) {
		t3_tp_set_offload_mode(adapter, 0);
		clear_bit(OFFLOAD_DEVMAP_BIT, &adapter->open_device_map);
		cxgb3_set_dummy_ops(tdev);
	}
	return err;
}

static int offload_close(struct t3cdev *tdev)
{
	struct adapter *adapter = tdev2adap(tdev);

	if (!test_bit(OFFLOAD_DEVMAP_BIT, &adapter->open_device_map))
		return 0;

	/* Call back all registered clients */
	cxgb3_remove_clients(tdev);
#ifndef LINUX_2_4
	sysfs_remove_group(net2kobj(tdev->lldev), &offload_attr_group);
#endif
	tdev->lldev = NULL;
	cxgb3_set_dummy_ops(tdev);
	t3_tp_set_offload_mode(adapter, 0);
	clear_bit(OFFLOAD_DEVMAP_BIT, &adapter->open_device_map);

	if (!adapter->open_device_map)
		cxgb_down(adapter, 0);

	cxgb3_offload_deactivate(adapter);
	return 0;
}

static int cxgb_open(struct net_device *dev)
{
	struct port_info *pi = netdev_priv(dev);
	struct adapter *adapter = pi->adapter;
	int other_ports = adapter->open_device_map & PORT_MASK;
	int err;

	if (!adapter->open_device_map && (err = cxgb_up(adapter)) < 0)
		return err;

	set_bit(pi->port_id, &adapter->open_device_map);

	if (is_offload(adapter) && !ofld_disable) {
		err = offload_open(dev);
		if (err)
			printk(KERN_WARNING
			       "Could not initialize offload capabilities\n");
#ifndef LINUX_2_4
		if (sysfs_create_group(net2kobj(dev), &iscsi_offload_attr_group))
			printk(KERN_INFO
			       "%s: cannot create sysfs iscsi_offload_attr_group\n",
			       dev->name);
#endif
	}

	t3_compat_set_num_tx_queues(dev, pi->nqsets);
	link_start(dev);
	t3_port_intr_enable(adapter, pi->port_id);
	netif_tx_start_all_queues(dev);
	if (!other_ports)
		schedule_chk_task(adapter);

	return 0;
}

static int __cxgb_close(struct net_device *dev, int on_wq)
{
	struct port_info *pi = netdev_priv(dev);
	struct adapter *adapter = pi->adapter;

	/* Stop link fault interrupts */
	t3_xgm_intr_disable(adapter, pi->port_id);
	t3_read_reg(adapter, A_XGM_INT_STATUS + pi->mac.offset);

	t3_port_intr_disable(adapter, pi->port_id);
	netif_tx_stop_all_queues(dev);
	netif_carrier_off(dev);

	/* disable pause frames */
	t3_set_reg_field(adapter, A_XGM_TX_CFG + pi->mac.offset,
			 F_TXPAUSEEN, 0);

	/* Reset RX FIFO HWM */
        t3_set_reg_field(adapter, A_XGM_RXFIFO_CFG +  pi->mac.offset,
			 V_RXFIFOPAUSEHWM(M_RXFIFOPAUSEHWM), 0);

#ifndef LINUX_2_4
	if (is_offload(adapter) && !ofld_disable)
		sysfs_remove_group(net2kobj(dev), &iscsi_offload_attr_group);
#endif

	spin_lock_irq(&adapter->work_lock);	/* sync with update task */
	clear_bit(pi->port_id, &adapter->open_device_map);
	spin_unlock_irq(&adapter->work_lock);

	if (!(adapter->open_device_map & PORT_MASK))
		cancel_rearming_delayed_workqueue(cxgb3_wq,
						  &adapter->adap_check_task);

	if (!adapter->open_device_map)
		cxgb_down(adapter, on_wq);

	msleep(100);

	/* Wait for TXFIFO empty */
	t3_wait_op_done(adapter, A_XGM_TXFIFO_CFG + pi->mac.offset,
			F_TXFIFO_EMPTY, 1, 20, 5);

	msleep(100);
	t3_mac_disable(&pi->mac, MAC_DIRECTION_RX);

	pi->phy.ops->power_down(&pi->phy, 1);

	return 0;
}

static int cxgb_close(struct net_device *dev)
{
	return __cxgb_close(dev, 0);
}

static struct net_device_stats *cxgb_get_stats(struct net_device *dev)
{
	struct port_info *pi = netdev_priv(dev);
	struct adapter *adapter = pi->adapter;
	struct net_device_stats *ns = &pi->netstats;
	const struct mac_stats *pstats = &pi->mac.stats;

	if (adapter->flags & FULL_INIT_DONE) {
		spin_lock(&adapter->stats_lock);
		t3_mac_update_stats(&pi->mac);
		spin_unlock(&adapter->stats_lock);
	}

	ns->tx_bytes = pstats->tx_octets;
	ns->tx_packets = pstats->tx_frames;
	ns->rx_bytes = pstats->rx_octets;
	ns->rx_packets = pstats->rx_frames;
	ns->multicast = pstats->rx_mcast_frames;

	ns->tx_errors = pstats->tx_underrun;
	ns->rx_errors = pstats->rx_symbol_errs + pstats->rx_fcs_errs +
		pstats->rx_too_long + pstats->rx_jabber + pstats->rx_short +
		pstats->rx_fifo_ovfl;

	/* detailed rx_errors */
	ns->rx_length_errors = pstats->rx_jabber + pstats->rx_too_long;
	ns->rx_over_errors = 0;
	ns->rx_crc_errors = pstats->rx_fcs_errs;
	ns->rx_frame_errors = pstats->rx_symbol_errs;
	ns->rx_fifo_errors = pstats->rx_fifo_ovfl;
	ns->rx_missed_errors = pstats->rx_cong_drops;

	/* detailed tx_errors */
	ns->tx_aborted_errors = 0;
	ns->tx_carrier_errors = 0;
	ns->tx_fifo_errors = pstats->tx_underrun;
	ns->tx_heartbeat_errors = 0;
	ns->tx_window_errors = 0;
	return ns;
}

static u32 get_msglevel(struct net_device *dev)
{
	struct port_info *pi = netdev_priv(dev);
	struct adapter *adapter = pi->adapter;

	return adapter->msg_enable;
}

static void set_msglevel(struct net_device *dev, u32 val)
{
	struct port_info *pi = netdev_priv(dev);
	struct adapter *adapter = pi->adapter;

	adapter->msg_enable = val;
}

static const char test_strings[][ETH_GSTRING_LEN] = {
	"Register test         (offline)",
	"Interrupt test        (offline)",
	"PMA/PMD loopback test (offline)",
	"PCS loopback test     (offline)",
	"Link test             (online)"
};

static char stats_strings[][ETH_GSTRING_LEN] = {
	"TxOctetsOK         ",
	"TxFramesOK         ",
	"TxMulticastFramesOK",
	"TxBroadcastFramesOK",
	"TxPauseFrames      ",
	"TxUnderrun         ",
	"TxExtUnderrun      ",

	"TxFrames64         ",
	"TxFrames65To127    ",
	"TxFrames128To255   ",
	"TxFrames256To511   ",
	"TxFrames512To1023  ",
	"TxFrames1024To1518 ",
	"TxFrames1519ToMax  ",

	"RxOctetsOK         ",
	"RxFramesOK         ",
	"RxMulticastFramesOK",
	"RxBroadcastFramesOK",
	"RxPauseFrames      ",
	"RxFCSErrors        ",
	"RxSymbolErrors     ",
	"RxShortErrors      ",
	"RxJabberErrors     ",
	"RxLengthErrors     ",
	"RxFIFOoverflow     ",

	"RxFrames64         ",
	"RxFrames65To127    ",
	"RxFrames128To255   ",
	"RxFrames256To511   ",
	"RxFrames512To1023  ",
	"RxFrames1024To1518 ",
	"RxFrames1519ToMax  ",

	"PhyFIFOErrors      ",
	"TSO                ",
	"VLANextractions    ",
	"VLANinsertions     ",
	"TxCsumOffload      ",
	"TXCoalesceWR       ",
	"TXCoalescePkt      ",
	"RxCsumGood         ",
	"RxDrops            ",

	"LroQueued          ",
	"LroFlushed         ",
	"LroExceededSessions",

	"CheckTXEnToggled   ",
	"CheckResets        ",

	"LinkFaults         ",
};

#if defined(GET_STATS_COUNT)
static int get_stats_count(struct net_device *dev)
{
	return ARRAY_SIZE(stats_strings);
}

static int self_test_count(struct net_device *dev)
{
	return ARRAY_SIZE(test_strings);
}
#else
static int get_sset_count(struct net_device *netdev, int sset)
{
	switch (sset) {
	case ETH_SS_TEST:
		return ARRAY_SIZE(test_strings);
	case ETH_SS_STATS:
		return ARRAY_SIZE(stats_strings);
	default:
		return -EOPNOTSUPP;
	}
}
#endif

#define T3_REGMAP_SIZE (3 * 1024)

static int get_regs_len(struct net_device *dev)
{
	return T3_REGMAP_SIZE;
}

#ifndef	LINUX_2_4
static int get_eeprom_len(struct net_device *dev)
{
	return EEPROMSIZE;
}
#endif	/* LINUX_2_4 */

static void get_drvinfo(struct net_device *dev, struct ethtool_drvinfo *info)
{
	struct port_info *pi = netdev_priv(dev);
	struct adapter *adapter = pi->adapter;
	u32 fw_vers = 0, tp_vers = 0;

	spin_lock(&adapter->stats_lock);
	t3_get_fw_version(adapter, &fw_vers);
	t3_get_tp_version(adapter, &tp_vers);
	spin_unlock(&adapter->stats_lock);

	strcpy(info->driver, DRIVER_NAME);
	strcpy(info->version, DRIVER_VERSION);
	strcpy(info->bus_info, pci_name(adapter->pdev));
	if (!fw_vers)
		strcpy(info->fw_version, "N/A");
	else {
		snprintf(info->fw_version, sizeof(info->fw_version),
			 "%s %u.%u.%u TP %u.%u.%u",
			 G_FW_VERSION_TYPE(fw_vers) ? "T" : "N",
			 G_FW_VERSION_MAJOR(fw_vers),
			 G_FW_VERSION_MINOR(fw_vers),
			 G_FW_VERSION_MICRO(fw_vers),
			 G_TP_VERSION_MAJOR(tp_vers),
			 G_TP_VERSION_MINOR(tp_vers),
			 G_TP_VERSION_MICRO(tp_vers));
	}
}

static void get_strings(struct net_device *dev, u32 stringset, u8 *data)
{
	if (stringset == ETH_SS_STATS)
		memcpy(data, stats_strings, sizeof(stats_strings));
	else
		memcpy(data, test_strings, sizeof(test_strings));
}

static unsigned long collect_sge_port_stats(struct adapter *adapter,
					    struct port_info *p, int idx)
{
	int i;
	unsigned long tot = 0;

	for (i = p->first_qset; i < p->first_qset + p->nqsets; ++i)
		tot += adapter->sge.qs[i].port_stats[idx];
	return tot;
}

static void clear_sge_port_stats(struct adapter *adapter, struct port_info *p)
{
	int i;
	struct sge_qset *qs = &adapter->sge.qs[p->first_qset];

	for (i = 0; i < p->nqsets; i++, qs++)
		memset(qs->port_stats, 0, sizeof(qs->port_stats));
}

static void get_stats(struct net_device *dev, struct ethtool_stats *stats,
		      u64 *data)
{
	struct port_info *pi = netdev_priv(dev);
	struct adapter *adapter = pi->adapter;
	const struct mac_stats *s = &pi->mac.stats;

	if (adapter->flags & FULL_INIT_DONE) {
		spin_lock(&adapter->stats_lock);
		t3_mac_update_stats(&pi->mac);
		spin_unlock(&adapter->stats_lock);
	}

	*data++ = s->tx_octets;
	*data++ = s->tx_frames;
	*data++ = s->tx_mcast_frames;
	*data++ = s->tx_bcast_frames;
	*data++ = s->tx_pause;
	*data++ = s->tx_underrun;
	*data++ = s->tx_fifo_urun;

	*data++ = s->tx_frames_64;
	*data++ = s->tx_frames_65_127;
	*data++ = s->tx_frames_128_255;
	*data++ = s->tx_frames_256_511;
	*data++ = s->tx_frames_512_1023;
	*data++ = s->tx_frames_1024_1518;
	*data++ = s->tx_frames_1519_max;

	*data++ = s->rx_octets;
	*data++ = s->rx_frames;
	*data++ = s->rx_mcast_frames;
	*data++ = s->rx_bcast_frames;
	*data++ = s->rx_pause;
	*data++ = s->rx_fcs_errs;
	*data++ = s->rx_symbol_errs;
	*data++ = s->rx_short;
	*data++ = s->rx_jabber;
	*data++ = s->rx_too_long;
	*data++ = s->rx_fifo_ovfl;

	*data++ = s->rx_frames_64;
	*data++ = s->rx_frames_65_127;
	*data++ = s->rx_frames_128_255;
	*data++ = s->rx_frames_256_511;
	*data++ = s->rx_frames_512_1023;
	*data++ = s->rx_frames_1024_1518;
	*data++ = s->rx_frames_1519_max;

	*data++ = pi->phy.fifo_errors;

	*data++ = collect_sge_port_stats(adapter, pi, SGE_PSTAT_TSO);
	*data++ = collect_sge_port_stats(adapter, pi, SGE_PSTAT_VLANEX);
	*data++ = collect_sge_port_stats(adapter, pi, SGE_PSTAT_VLANINS);
	*data++ = collect_sge_port_stats(adapter, pi, SGE_PSTAT_TX_CSUM);
	*data++ = collect_sge_port_stats(adapter, pi, SGE_PSTAT_TX_COALESCE_WR);
        *data++ = collect_sge_port_stats(adapter, pi, SGE_PSTAT_TX_COALESCE_PKT);
	*data++ = collect_sge_port_stats(adapter, pi, SGE_PSTAT_RX_CSUM_GOOD);
	*data++ = s->rx_cong_drops;
	*data++ = collect_sge_port_stats(adapter, pi, SGE_PSTAT_LRO_SKB) +
		  collect_sge_port_stats(adapter, pi, SGE_PSTAT_LRO_PG) +
		  collect_sge_port_stats(adapter, pi, SGE_PSTAT_LRO_ACK);
	*data++ = collect_sge_port_stats(adapter, pi, SGE_PSTAT_LRO);
	*data++ = collect_sge_port_stats(adapter, pi, SGE_PSTAT_LRO_OVFLOW);

	*data++ = s->num_toggled;
	*data++ = s->num_resets;

	*data++ = s->link_faults;
}

static int test_regs(struct net_device *dev, struct ethtool_test *eth_test)
{
	struct port_info *pi = netdev_priv(dev);
	int val;

	CH_WARN(pi->adapter, "register self test\n");

	t3_write_reg(pi->adapter, A_CIM_HOST_ACC_DATA, 0xdeadbeef);

	val = t3_read_reg(pi->adapter, A_CIM_HOST_ACC_DATA);
	return val == 0xdeadbeef ? 0 : -1;
}

/*
 * Interrupt handler used to check if MSI/MSI-X works on this platform.
 */
DECLARE_INTR_HANDLER(check_intr_handler, irq, adap, regs)
{
	t3_set_reg_field(adap, A_PL_INT_ENABLE0, F_MI1, 0);
	return IRQ_HANDLED;
}

static int check_intr(struct adapter *adap)
{
	int mi1, ret;

	ret = t3_read_reg(adap, A_PL_INT_CAUSE0) & F_MI1;
	if (!ret)
		return !ret;

	free_irq(adap->pdev->irq, adap);
	ret = request_irq(adap->pdev->irq, check_intr_handler,
			  IRQF_SHARED, adap->name, adap);
	if (ret)
		return ret;

	t3_set_reg_field(adap, A_PL_INT_ENABLE0, 0, F_MI1);
	msleep(100);
	mi1 = t3_read_reg(adap, A_PL_INT_ENABLE0) & F_MI1;
	if (mi1)
		t3_set_reg_field(adap, A_PL_INT_ENABLE0, F_MI1, 0);
	free_irq(adap->pdev->irq, adap);
	ret = request_irq(adap->pdev->irq,
			  t3_intr_handler(adap,
					  adap->sge.qs[0].rspq.flags &
					  USING_POLLING),
			  IRQF_SHARED,
			  adap->name, adap);
	if (ret)
		return ret;
	
	return mi1;
}

static int test_intr(struct net_device *dev, struct ethtool_test *eth_test)
{
	struct port_info *pi = netdev_priv(dev);
	struct adapter *adapter = pi->adapter;
	int ret = 0;

	CH_WARN(adapter, "interrupt self test\n");
	
	/*
	 * The driver checks MSI/MSI-X interrupts at load time.
	 * Take care of line intrs only here.
	 */
	
	if (!(adapter->flags & (USING_MSIX | USING_MSI)))
		ret = check_intr(adapter);

	if (ret)
		CH_ERR(adapter, "Interrupt test failed\n");
		
	return ret;
}

static struct sk_buff * loopback_fill(struct net_device *dev)
{
	struct sk_buff *skb;
	struct ethhdr *ethhdr;
	const char str[] = "cxgb3 loopback test";
	char *p;
	int len;

	len = sizeof(*ethhdr) + sizeof(str);
	skb = alloc_skb(len, GFP_KERNEL);
	if (!skb)
		return NULL;

	skb_reset_mac_header(skb);
	ethhdr = (struct ethhdr *)skb_mac_header(skb);
	skb_put(skb, sizeof(*ethhdr));

	memcpy(ethhdr->h_dest, dev->dev_addr, ETH_ALEN);
	memcpy(ethhdr->h_source, dev->dev_addr, ETH_ALEN);
	ethhdr->h_proto = htons(ETH_P_LOOP);

	skb_put(skb, sizeof(str));
	p = (char *)(ethhdr + 1);
	memcpy(p, str, sizeof(str));

	return skb;
}

static int get_rx_eth_pkts(struct port_info *pi)
{
	struct sge_qset *qs = pi->qs;
	int i, n = 0;

	for (i = pi->first_qset; i < pi->nqsets; i++) {
		n += qs->rspq.eth_pkts;
		qs++;
	}

	return n;
}

typedef void (*t3_set_loopback_t)(struct port_info *);
typedef void (*t3_reset_loopback_t)(struct port_info *);

static int test_loopback(struct net_device *dev, int loopback_mode,
			 t3_set_loopback_t set_loopback,
			 t3_reset_loopback_t reset_loopback)
{
	struct port_info *pi = netdev_priv(dev);
	struct cmac *mac = &pi->mac;
	struct adapter *adapter = pi->adapter;
	struct sk_buff *skb;
	int i, npkts = 10, rx_before, rx_after;
	u32 rx_cfg, rx_hash_high, rx_hash_low;
	
	
	if (!test_bit(pi->port_id, &adapter->open_device_map)) {
		CH_WARN(adapter, "Port not fully initialized, "
			"loopback test will fail\n");
		return -ENOTSUPP;
	}

	pi->loopback = loopback_mode;

	/* set the phy in loopback mode */
	netif_carrier_off(dev);
	
	/* Filter Rx traffic */
	t3_gate_rx_traffic(mac, &rx_cfg, &rx_hash_high, &rx_hash_low);
	t3_mac_enable_exact_filters(mac);
	
	set_loopback(pi);
	msleep(100);

	rx_before = get_rx_eth_pkts(pi);
	
	skb = loopback_fill(dev);
	for (i = 0; i < npkts; i++) {
		skb_get(skb);
		t3_eth_xmit(skb, dev);
	}

	msleep(100);
	rx_after = get_rx_eth_pkts(pi);

	/* Reset loopback mode */
	reset_loopback(pi);
	msleep(100);

	t3_open_rx_traffic(mac, rx_cfg, rx_hash_high, rx_hash_low);
	
	pi->loopback = LOOPBACK_NONE;

	/* Re-start the link */
	link_start(dev);

	return rx_after - rx_before != npkts;
}

/* Set spcified MMD block in loopback mode */
static void t3_set_loopback_mmd(struct port_info *pi,
				int mmd_addr, int reg_addr, u32 bit)
{
	struct cphy *phy = &pi->phy;
	u32 val;
	
	/* reset the phy */
	phy->ops->reset(phy, 0);
	mdio_read(phy, mmd_addr, reg_addr, &val);
	val |= (1 << bit);
	mdio_write(phy, mmd_addr, reg_addr, val);
}	
	
/* Set spcified MMD block out of loopback mode */
static void t3_reset_loopback_mmd(struct port_info *pi,
				  int mmd_addr, int reg_addr, u32 bit)
{
	struct cphy *phy = &pi->phy;
	u32 val;
	
	mdio_read(phy, mmd_addr, reg_addr, &val);
	val &= ~(1 << bit);
	mdio_write(phy, mmd_addr, reg_addr, val);
	phy->ops->reset(phy, 0);
}	

static void t3_set_loopback_pma_pmd(struct port_info *pi)
{
	t3_set_loopback_mmd(pi, MDIO_DEV_PMA_PMD, 0, 0);	
}	

static void t3_reset_loopback_pma_pmd(struct port_info *pi)
{
	t3_reset_loopback_mmd(pi, MDIO_DEV_PMA_PMD, 0, 0);	
}

static int test_loopback_pma_pmd(struct net_device *dev,
				 struct ethtool_test *eth_test)
{
	struct port_info *pi = netdev_priv(dev);

	CH_WARN(pi->adapter, "PHY PMA/PMD loopback test\n");
	return test_loopback(dev, LOOPBACK_PHY_PMA_PMD,
			     t3_set_loopback_pma_pmd,
			     t3_reset_loopback_pma_pmd);
}	

static void t3_set_loopback_pcs(struct port_info *pi)
{
	t3_set_loopback_mmd(pi, MDIO_DEV_PCS, 0, 14);	
}	

static void t3_reset_loopback_pcs(struct port_info *pi)
{
	t3_reset_loopback_mmd(pi, MDIO_DEV_PCS, 0, 14);	
}	

static int test_loopback_pcs(struct net_device *dev,
			     struct ethtool_test *eth_test)
{
	struct port_info *pi = netdev_priv(dev);

	CH_WARN(pi->adapter, "PHY PCS loopback test\n");
	return test_loopback(dev, LOOPBACK_PHY_PCS,
			     t3_set_loopback_pcs,
			     t3_reset_loopback_pcs);
}

static int test_link(struct net_device *dev, struct ethtool_test *eth_test)
{
	struct port_info *pi = netdev_priv(dev);
	int link_ok, speed, duplex, fc;
	struct cphy *phy = &pi->phy;
	struct link_config *lc = &pi->link_config;

	CH_WARN(pi->adapter, "link self test\n");

	link_ok = lc->link_ok;
	speed = lc->speed;
	duplex = lc->duplex;
	fc = lc->fc;
	phy->ops->get_link_status(phy, &link_ok, &speed, &duplex, &fc);

	return !link_ok;
}

typedef int (*t3_diag_func)(struct net_device *dev,
			    struct ethtool_test *eth_test);

enum {
	ONLINE = 0,
	OFFLINE,
};

struct t3_test_info {
	t3_diag_func test;
	int type;
};

static void self_tests(struct net_device *dev, struct ethtool_test *eth_test,
		       u64 *data)
{
	int offline = eth_test->flags & ETH_TEST_FL_OFFLINE, i;

	static const struct t3_test_info diags_matrix[] = {
		{ test_regs,			OFFLINE },
 		{ test_intr,			OFFLINE },
		{ test_loopback_pma_pmd,	OFFLINE },
		{ test_loopback_pcs,		OFFLINE },
		{ test_link,			 ONLINE }
	};
	
	for (i = 0; i < ARRAY_SIZE(diags_matrix); i++) {
		const struct t3_test_info *info = diags_matrix + i;
		int run = info->type == offline, val;

		val = run ? info->test(dev, eth_test) : 0;
		*data++ = val;
		if (val)
			eth_test->flags |= ETH_TEST_FL_FAILED;
	}
}

static inline void reg_block_dump(struct adapter *ap, void *buf,
				  unsigned int start, unsigned int end)
{
	u32 *p = buf + start;

	for ( ; start <= end; start += sizeof(u32))
		*p++ = t3_read_reg(ap, start);
}

static void get_regs(struct net_device *dev, struct ethtool_regs *regs,
		     void *buf)
{
	struct port_info *pi = netdev_priv(dev);
	struct adapter *ap = pi->adapter;
	/*
	 * Version scheme:
	 * bits 0..9: chip version
	 * bits 10..15: chip revision
	 * bit 31: set for PCIe cards
	 */
	regs->version = 3 | (ap->params.rev << 10) | (is_pcie(ap) << 31);

	/*
	 * We skip the MAC statistics registers because they are clear-on-read.
	 * Also reading multi-register stats would need to synchronize with the
	 * periodic mac stats accumulation.  Hard to justify the complexity.
	 */
	memset(buf, 0, T3_REGMAP_SIZE);
	reg_block_dump(ap, buf, 0, A_SG_RSPQ_CREDIT_RETURN);
	reg_block_dump(ap, buf, A_SG_HI_DRB_HI_THRSH, A_ULPRX_PBL_ULIMIT);
	reg_block_dump(ap, buf, A_ULPTX_CONFIG, A_MPS_INT_CAUSE);
	reg_block_dump(ap, buf, A_CPL_SWITCH_CNTRL, A_CPL_MAP_TBL_DATA);
	reg_block_dump(ap, buf, A_SMB_GLOBAL_TIME_CFG, A_XGM_SERDES_STAT3);
	reg_block_dump(ap, buf, A_XGM_SERDES_STATUS0,
		       XGM_REG(A_XGM_SERDES_STAT3, 1));
	reg_block_dump(ap, buf, XGM_REG(A_XGM_SERDES_STATUS0, 1),
		       XGM_REG(A_XGM_RX_SPI4_SOP_EOP_CNT, 1));
}

static int restart_autoneg(struct net_device *dev)
{
	struct port_info *p = netdev_priv(dev);

	if (!netif_running(dev))
		return -EAGAIN;
	if (p->link_config.autoneg != AUTONEG_ENABLE)
		return -EINVAL;
	p->phy.ops->autoneg_restart(&p->phy);
	return 0;
}

static int cxgb3_phys_id(struct net_device *dev, u32 data)
{
	struct port_info *pi = netdev_priv(dev);
	struct adapter *adapter = pi->adapter;
	int i;

	if (data == 0)
		data = 2;

	for (i = 0; i < data * 2; i++) {
		t3_set_reg_field(adapter, A_T3DBG_GPIO_EN, F_GPIO0_OUT_VAL,
				 (i & 1) ? F_GPIO0_OUT_VAL : 0);
		if (msleep_interruptible(500))
			break;
	}
	t3_set_reg_field(adapter, A_T3DBG_GPIO_EN, F_GPIO0_OUT_VAL,
			 F_GPIO0_OUT_VAL);
	return 0;
}

static int get_settings(struct net_device *dev, struct ethtool_cmd *cmd)
{
	struct port_info *p = netdev_priv(dev);

	cmd->supported = p->link_config.supported;
	cmd->advertising = p->link_config.advertising;

	if (netif_carrier_ok(dev)) {
		cmd->speed = p->link_config.speed;
		cmd->duplex = p->link_config.duplex;
	} else {
		cmd->speed = -1;
		cmd->duplex = -1;
	}

	cmd->port = (cmd->supported & SUPPORTED_TP) ? PORT_TP : PORT_FIBRE;
	cmd->phy_address = p->phy.addr;
	cmd->transceiver = XCVR_EXTERNAL;
	cmd->autoneg = p->link_config.autoneg;
	cmd->maxtxpkt = 0;
	cmd->maxrxpkt = 0;
	return 0;
}

static int speed_duplex_to_caps(int speed, int duplex)
{
	int cap = 0;

	switch (speed) {
	case SPEED_10:
		if (duplex == DUPLEX_FULL)
			cap = SUPPORTED_10baseT_Full;
		else
			cap = SUPPORTED_10baseT_Half;
		break;
	case SPEED_100:
		if (duplex == DUPLEX_FULL)
			cap = SUPPORTED_100baseT_Full;
		else
			cap = SUPPORTED_100baseT_Half;
		break;
	case SPEED_1000:
		if (duplex == DUPLEX_FULL)
			cap = SUPPORTED_1000baseT_Full;
		else
			cap = SUPPORTED_1000baseT_Half;
		break;
	case SPEED_10000:
		if (duplex == DUPLEX_FULL)
			cap = SUPPORTED_10000baseT_Full;
	}
	return cap;
}

#define ADVERTISED_MASK (ADVERTISED_10baseT_Half | ADVERTISED_10baseT_Full | \
		      ADVERTISED_100baseT_Half | ADVERTISED_100baseT_Full | \
		      ADVERTISED_1000baseT_Half | ADVERTISED_1000baseT_Full | \
		      ADVERTISED_10000baseT_Full)

static int set_settings(struct net_device *dev, struct ethtool_cmd *cmd)
{
	int cap;
	struct port_info *p = netdev_priv(dev);
	struct link_config *lc = &p->link_config;

	if (!(lc->supported & SUPPORTED_Autoneg)) {
		/*
		 * PHY offers a single speed/duplex.  See if that's what's
		 * being requested.
		 */
		if (cmd->autoneg == AUTONEG_DISABLE) {
			cap = speed_duplex_to_caps(cmd->speed, cmd->duplex);
			if (lc->supported & cap)
				return 0;
		}
		return -EINVAL;
	}

	if (cmd->autoneg == AUTONEG_DISABLE) {
		cap = speed_duplex_to_caps(cmd->speed, cmd->duplex);

		if (!(lc->supported & cap) || cmd->speed == SPEED_1000 ||
		    cmd->speed == SPEED_10000)
			return -EINVAL;
		lc->requested_speed = cmd->speed;
		lc->requested_duplex = cmd->duplex;
		lc->advertising = 0;
	} else {
		cmd->advertising &= ADVERTISED_MASK;
		cmd->advertising &= lc->supported;
		if (!cmd->advertising)
			return -EINVAL;
		lc->requested_speed = SPEED_INVALID;
		lc->requested_duplex = DUPLEX_INVALID;
		lc->advertising = cmd->advertising | ADVERTISED_Autoneg;
	}
	lc->autoneg = cmd->autoneg;
	if (netif_running(dev))
		t3_link_start(&p->phy, &p->mac, lc);
	return 0;
}

static void get_pauseparam(struct net_device *dev,
			   struct ethtool_pauseparam *epause)
{
	struct port_info *p = netdev_priv(dev);

	epause->autoneg = (p->link_config.requested_fc & PAUSE_AUTONEG) != 0;
	epause->rx_pause = (p->link_config.fc & PAUSE_RX) != 0;
	epause->tx_pause = (p->link_config.fc & PAUSE_TX) != 0;
}

static int set_pauseparam(struct net_device *dev,
			  struct ethtool_pauseparam *epause)
{
	struct port_info *p = netdev_priv(dev);
	struct link_config *lc = &p->link_config;

	if (epause->autoneg == AUTONEG_DISABLE)
		lc->requested_fc = 0;
	else if (lc->supported & SUPPORTED_Autoneg)
		lc->requested_fc = PAUSE_AUTONEG;
	else
		return -EINVAL;

	if (epause->rx_pause)
		lc->requested_fc |= PAUSE_RX;
	if (epause->tx_pause)
		lc->requested_fc |= PAUSE_TX;
	if (lc->autoneg == AUTONEG_ENABLE) {
		if (netif_running(dev))
			t3_link_start(&p->phy, &p->mac, lc);
	} else {
		lc->fc = lc->requested_fc & (PAUSE_RX | PAUSE_TX);
		if (netif_running(dev))
			t3_mac_set_speed_duplex_fc(&p->mac, -1, -1, lc->fc);
	}
	return 0;
}

static u32 get_rx_csum(struct net_device *dev)
{
	struct port_info *p = netdev_priv(dev);

	return p->rx_csum_offload;
}

static int set_rx_csum(struct net_device *dev, u32 data)
{
	struct port_info *p = netdev_priv(dev);

	p->rx_csum_offload = data;
	if (!data) {
		struct adapter *adap = p->adapter;
		int i;

		for (i = p->first_qset; i < p->first_qset + p->nqsets; i++) {
			adap->params.sge.qset[i].lro = 0;
			adap->sge.qs[i].lro.enabled = 0;
		}
	}
	return 0;
}

static void get_sge_param(struct net_device *dev, struct ethtool_ringparam *e)
{
	const struct port_info *pi = netdev_priv(dev);
	const struct adapter *adapter = pi->adapter;
	const struct qset_params *q = &adapter->params.sge.qset[pi->first_qset];

	e->rx_max_pending = MAX_RX_BUFFERS;
	e->rx_mini_max_pending = 0;
	e->rx_jumbo_max_pending = MAX_RX_JUMBO_BUFFERS;
	e->tx_max_pending = MAX_TXQ_ENTRIES;

	e->rx_pending = q->fl_size;
	e->rx_mini_pending = q->rspq_size;
	e->rx_jumbo_pending = q->jumbo_size;
	e->tx_pending = q->txq_size[0];
}

static int set_sge_param(struct net_device *dev, struct ethtool_ringparam *e)
{
	struct port_info *pi = netdev_priv(dev);
	struct adapter *adapter = pi->adapter;
	struct qset_params *q;
	int i;

	if (e->rx_pending > MAX_RX_BUFFERS ||
	    e->rx_jumbo_pending > MAX_RX_JUMBO_BUFFERS ||
	    e->tx_pending > MAX_TXQ_ENTRIES ||
	    e->rx_mini_pending > MAX_RSPQ_ENTRIES ||
	    e->rx_mini_pending < MIN_RSPQ_ENTRIES ||
	    e->rx_pending < MIN_FL_ENTRIES ||
	    e->rx_jumbo_pending < MIN_FL_JUMBO_ENTRIES ||
	    e->tx_pending < adapter->params.nports * MIN_TXQ_ENTRIES)
		return -EINVAL;

	if (adapter->flags & FULL_INIT_DONE)
		return -EBUSY;

	q = &adapter->params.sge.qset[pi->first_qset];
	for (i = 0; i < pi->nqsets; ++i, ++q) {
		q->rspq_size = e->rx_mini_pending;
		q->fl_size = e->rx_pending;
		q->jumbo_size = e->rx_jumbo_pending;
		q->txq_size[0] = e->tx_pending;
		q->txq_size[1] = e->tx_pending;
		q->txq_size[2] = e->tx_pending;
	}
	return 0;
}

static int set_coalesce(struct net_device *dev, struct ethtool_coalesce *c)
{
	struct port_info *pi = netdev_priv(dev);
	struct adapter *adapter = pi->adapter;
	struct qset_params *qsp = &adapter->params.sge.qset[0];
	struct sge_qset *qs = &adapter->sge.qs[0];

	if (c->rx_coalesce_usecs * 10 > M_NEWTIMER)
		return -EINVAL;

	qsp->coalesce_usecs = c->rx_coalesce_usecs;
	t3_update_qset_coalesce(qs, qsp);
	return 0;
}

static int get_coalesce(struct net_device *dev, struct ethtool_coalesce *c)
{
	struct port_info *pi = netdev_priv(dev);
	struct adapter *adapter = pi->adapter;
	struct qset_params *q = adapter->params.sge.qset;

	c->rx_coalesce_usecs = q->coalesce_usecs;
	return 0;
}

static int get_eeprom(struct net_device *dev, struct ethtool_eeprom *e,
		      u8 *data)
{
	struct port_info *pi = netdev_priv(dev);
	struct adapter *adapter = pi->adapter;
	int i, err = 0;

	u8 *buf = kmalloc(EEPROMSIZE, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	e->magic = EEPROM_MAGIC;
	for (i = e->offset & ~3; !err && i < e->offset + e->len; i += 4)
		err = t3_seeprom_read(adapter, i, (u32 *)&buf[i]);

	if (!err)
		memcpy(data, buf + e->offset, e->len);
	kfree(buf);
	return err;
}

static int set_eeprom(struct net_device *dev, struct ethtool_eeprom *eeprom,
		      u8 *data)
{
	struct port_info *pi = netdev_priv(dev);
	struct adapter *adapter = pi->adapter;
	u32 aligned_offset, aligned_len, *p;
	u8 *buf;
	int err = 0;


	if (eeprom->magic != EEPROM_MAGIC)
		return -EINVAL;

	aligned_offset = eeprom->offset & ~3;
	aligned_len = (eeprom->len + (eeprom->offset & 3) + 3) & ~3;

	if (aligned_offset != eeprom->offset || aligned_len != eeprom->len) {
		buf = kmalloc(aligned_len, GFP_KERNEL);
		if (!buf)
			return -ENOMEM;
		err = t3_seeprom_read(adapter, aligned_offset, (u32 *)buf);
		if (!err && aligned_len > 4)
			err = t3_seeprom_read(adapter,
					      aligned_offset + aligned_len - 4,
					      (u32 *)&buf[aligned_len - 4]);
		if (err)
			goto out;
		memcpy(buf + (eeprom->offset & 3), data, eeprom->len);
	} else
		buf = data;

	err = t3_seeprom_wp(adapter, 0);
	if (err)
		goto out;

	for (p = (u32 *)buf; !err && aligned_len; aligned_len -= 4, p++) {
		err = t3_seeprom_write(adapter, aligned_offset, *p);
		aligned_offset += 4;
	}

	if (!err)
		err = t3_seeprom_wp(adapter, 1);
out:
	if (buf != data)
		kfree(buf);
	return err;
}

static void get_wol(struct net_device *dev, struct ethtool_wolinfo *wol)
{
	wol->supported = 0;
	wol->wolopts = 0;
	memset(&wol->sopass, 0, sizeof(wol->sopass));
}

static struct ethtool_ops cxgb_ethtool_ops = {
	.get_settings      = get_settings,
	.set_settings      = set_settings,
	.get_drvinfo       = get_drvinfo,
	.get_msglevel      = get_msglevel,
	.set_msglevel      = set_msglevel,
	.get_ringparam     = get_sge_param,
	.set_ringparam     = set_sge_param,
	.get_coalesce      = get_coalesce,
	.set_coalesce      = set_coalesce,
#ifndef	LINUX_2_4
	.get_eeprom_len    = get_eeprom_len,
#endif	/* LINUX_2_4 */
	.get_eeprom        = get_eeprom,
	.set_eeprom        = set_eeprom,
	.get_pauseparam    = get_pauseparam,
	.set_pauseparam    = set_pauseparam,
	.get_rx_csum       = get_rx_csum,
	.set_rx_csum       = set_rx_csum,
	.get_tx_csum       = ethtool_op_get_tx_csum,
#ifndef	LINUX_2_4
	.set_tx_csum       = ethtool_op_set_tx_csum,
#endif	/* LINUX_2_4 */
	.get_sg            = ethtool_op_get_sg,
	.set_sg            = ethtool_op_set_sg,
	.get_link          = ethtool_op_get_link,
	.get_strings       = get_strings,
	.phys_id           = cxgb3_phys_id,
	.nway_reset        = restart_autoneg,
#if defined(GET_STATS_COUNT)
	.get_stats_count   = get_stats_count,
	.self_test_count   = self_test_count,
#else
	.get_sset_count    = get_sset_count,
#endif
	.get_ethtool_stats = get_stats,
	.get_regs_len      = get_regs_len,
	.get_regs          = get_regs,
	.get_wol           = get_wol,
#ifndef	LINUX_2_4
	.get_tso           = ethtool_op_get_tso,
	.set_tso           = ethtool_op_set_tso,
#endif	/* LINUX_2_4 */
#ifdef CXGB3_ETHTOOL_GPERMADDR
	.get_perm_addr     = ethtool_op_get_perm_addr,
#endif
	.self_test         = self_tests,
};


#define adjust_proc_metrics() \
	if (len <= offset + count) *eof = 1; \
	*start = buf + offset; \
	len -= offset; \
	if (len > count) len = count; \
	if (len < 0) len = 0;

static int snmp_read_proc(char *buf, char **start, off_t offset, int count,
			  int *eof, void *data)
{
	struct adapter *adapter = data;
	struct tp_mib_stats m;
	int len = 0;

	spin_lock(&adapter->stats_lock);
	t3_tp_get_mib_stats(adapter, &m);
	spin_unlock(&adapter->stats_lock);

#define MIB32(s, field) len += sprintf(buf + len, "%-18s %u\n", s, m.field)
#define MIB64(s, hi, lo) \
	len += sprintf(buf + len, "%-18s %llu\n", s, \
		       ((unsigned long long)m.hi << 32) + m.lo)

	MIB64("IPInReceives:", ipInReceive_hi, ipInReceive_lo);
	MIB64("IPInHdrErrors:", ipInHdrErrors_hi, ipInHdrErrors_lo);
	MIB64("IPInAddrErrors:", ipInAddrErrors_hi, ipInAddrErrors_lo);
	MIB64("IPInUnknownProtos:", ipInUnknownProtos_hi,
	      ipInUnknownProtos_lo);
	MIB64("IPInDiscards:", ipInDiscards_hi, ipInDiscards_lo);
	MIB64("IPInDelivers:", ipInDelivers_hi, ipInDelivers_lo);
	MIB64("IPOutRequests:", ipOutRequests_hi, ipOutRequests_lo);
	MIB64("IPOutDiscards:", ipOutDiscards_hi, ipOutDiscards_lo);
	MIB64("IPOutNoRoutes:", ipOutNoRoutes_hi, ipOutNoRoutes_lo);
	MIB32("IPReasmTimeout:", ipReasmTimeout);
	MIB32("IPReasmReqds:", ipReasmReqds);
	MIB32("IPReasmOKs:", ipReasmOKs);
	MIB32("IPReasmFails:", ipReasmFails);
	MIB32("TCPActiveOpens:", tcpActiveOpens);
	MIB32("TCPPassiveOpens:", tcpPassiveOpens);
	MIB32("TCPAttemptFails:", tcpAttemptFails);
	MIB32("TCPEstabResets:", tcpEstabResets);
	MIB32("TCPOutRsts:", tcpOutRsts);
	MIB32("TCPCurrEstab:", tcpCurrEstab);
	MIB64("TCPInSegs:", tcpInSegs_hi, tcpInSegs_lo);
	MIB64("TCPOutSegs:", tcpOutSegs_hi, tcpOutSegs_lo);
	MIB64("TCPRetransSeg:", tcpRetransSeg_hi, tcpRetransSeg_lo);
	MIB64("TCPInErrs:", tcpInErrs_hi, tcpInErrs_lo);
	MIB32("TCPRtoMin:", tcpRtoMin);
	MIB32("TCPRtoMax:", tcpRtoMax);

#undef MIB32
#undef MIB64

	adjust_proc_metrics();
	return len;
}

static int mtus_read_proc(char *buf, char **start, off_t offset, int count,
			  int *eof, void *data)
{
	struct adapter *adapter = data;
	unsigned short hw_mtus[NMTUS];
	int i, len = 0;

	spin_lock(&adapter->stats_lock);
	t3_read_hw_mtus(adapter, hw_mtus);
	spin_unlock(&adapter->stats_lock);

	len += sprintf(buf, "Soft MTU\tEffective MTU\n");
	for (i = 0; i < NMTUS; ++i)
		len += sprintf(buf + len, "%8u\t\t%5u\n",
			       adapter->params.mtus[i], hw_mtus[i]);

	adjust_proc_metrics();
	return len;
}

static int cong_ctrl_read_proc(char *buf, char **start, off_t offset,
			       int count, int *eof, void *data)
{
	static const char *dec_fac[] = {
		"0.5", "0.5625", "0.625", "0.6875", "0.75", "0.8125", "0.875",
		"0.9375" };

	unsigned short incr[NMTUS][NCCTRL_WIN];
	struct adapter *adapter = data;
	int i, len = 0;

	t3_get_cong_cntl_tab(adapter, incr);

	for (i = 0; i < NCCTRL_WIN; ++i) {
		int j;

		for (j = 0; j < NMTUS; ++j)
			len += sprintf(buf + len, "%5u ", incr[j][i]);

		len += sprintf(buf + len, "%5u %s\n", adapter->params.a_wnd[i],
			       dec_fac[adapter->params.b_wnd[i]]);
	}

	adjust_proc_metrics();
	return len;
}

static int rss_read_proc(char *buf, char **start, off_t offset, int count,
			 int *eof, void *data)
{
	u8 lkup_tab[2 * RSS_TABLE_SIZE];
	u16 map_tab[RSS_TABLE_SIZE];
	struct adapter *adapter = data;
	int i, len;

	i = t3_read_rss(adapter, lkup_tab, map_tab);
	if (i < 0)
		return i;

	len = sprintf(buf, "Idx\tLookup\tMap\n");
	for (i = 0; i < RSS_TABLE_SIZE; ++i)
		len += sprintf(buf + len, "%3u\t %3u\t %u\n", i, lkup_tab[i],
			       map_tab[i]);
	for (; i < 2 * RSS_TABLE_SIZE; ++i)
		len += sprintf(buf + len, "%3u\t %3u\n", i, lkup_tab[i]);

	adjust_proc_metrics();
	return len;
}

static int sched_read_proc(char *buf, char **start, off_t offset, int count,
			   int *eof, void *data)
{
	int i, len;
	unsigned int map, kbps, ipg;
	unsigned int pace_tab[NTX_SCHED];
	struct adapter *adap = data;

	map = t3_read_reg(adap, A_TP_TX_MOD_QUEUE_REQ_MAP);
	t3_read_pace_tbl(adap, pace_tab);

	len = sprintf(buf, "Scheduler  Mode   Channel  Rate (Kbps)   "
		      "Class IPG (0.1 ns)   Flow IPG (us)\n");
	for (i = 0; i < NTX_SCHED; ++i) {
		t3_get_tx_sched(adap, i, &kbps, &ipg);
		len += sprintf(buf + len, "    %u      %-5s     %u     ", i,
			       (map & (1 << (S_TX_MOD_TIMER_MODE + i))) ?
				"flow" : "class", !!(map & (1 << i)));
		if (kbps)
			len += sprintf(buf + len, "%9u     ", kbps);
		else
			len += sprintf(buf + len, " disabled     ");

		if (ipg)
			len += sprintf(buf + len, "%13u        ", ipg);
		else
			len += sprintf(buf + len, "     disabled        ");

		if (pace_tab[i])
			len += sprintf(buf + len, "%10u\n", pace_tab[i] / 1000);
		else
			len += sprintf(buf + len, "  disabled\n");
	}

	adjust_proc_metrics();
	return len;
}

static int stats_read_proc(char *buf, char **start, off_t offset,
			   int count, int *eof, void *data)
{
	int i, len = 0;
	struct adapter *adapter = data;

	len += sprintf(buf + len, "Interface:        ");
	for (i = 0; i < SGE_QSETS; ++i)
		len += sprintf(buf + len, " %10s",
			       adapter->sge.qs[i].netdev ?
			           adapter->sge.qs[i].netdev->name : "N/A");

#define C(s, v) \
	len += sprintf(buf + len, "\n%-18s", s); \
	for (i = 0; i < SGE_QSETS; ++i) \
		len += sprintf(buf + len, " %10lu", adapter->sge.qs[i].v); \

	C("RspQEmpty:", rspq.empty);
	C("FL0Empty:", fl[0].empty);
	C("FL0AllocFailed:", fl[0].alloc_failed);
	C("FL1Empty:", fl[1].empty);
	C("FL1AllocFailed:", fl[1].alloc_failed);
	C("TxQ0TunnelPkts:", txq[0].tx_pkts);
	C("TxQ0Full:", txq[0].stops);
	C("TxQ0Restarts:", txq[0].restarts);
	C("TxQ1OffloadPkts:", txq[1].tx_pkts);
	C("TxQ1Full:", txq[1].stops);
	C("TxQ1Restarts:", txq[1].restarts);
	C("TxQ2Full:", txq[2].stops);
	C("TxQ2Restarts:", txq[2].restarts);
	C("RxEthPackets:", rspq.eth_pkts);
	C("TXCoalesceWR:", port_stats[SGE_PSTAT_TX_COALESCE_WR]);
	C("TXCoalescePkt:", port_stats[SGE_PSTAT_TX_COALESCE_PKT]);
	C("LROcompleted:", port_stats[SGE_PSTAT_LRO]);
	C("LROpages:", port_stats[SGE_PSTAT_LRO_PG]);
	C("LROpackets:", port_stats[SGE_PSTAT_LRO_SKB]);
	C("LROmergedACKs:", port_stats[SGE_PSTAT_LRO_ACK]);
	C("LROoverflow:", port_stats[SGE_PSTAT_LRO_OVFLOW]);
	C("LROcollisions:", port_stats[SGE_PSTAT_LRO_COLSN]);
	C("RxOffloadPackets:", rspq.offload_pkts);
	C("RxOffloadBundles:", rspq.offload_bundles);
	C("PureRepsonses:", rspq.pure_rsps);
	C("RxImmediateData:", rspq.imm_data);
	C("ANE:", rspq.async_notif);
	C("RxDrops:", rspq.rx_drops);
	C("RspDeferred:", rspq.nomem);
	C("UnhandledIntr:", rspq.unhandled_irqs);
	C("RspStarved:", rspq.starved);
	C("RspRestarted:", rspq.restarted);
#undef C

	len += sprintf(buf + len, "\n%-18s %lu\n", "RxCorrectableErr:",
		       adapter->pmrx.stats.corr_err);
	len += sprintf(buf + len, "%-18s %lu\n", "TxCorrectableErr:",
		       adapter->pmtx.stats.corr_err);
	len += sprintf(buf + len, "%-18s %lu\n", "CMCorrectableErr:",
		       adapter->cm.stats.corr_err);

	len += sprintf(buf + len, "\n%-18s %lu\n", "ActiveRegionFull:",
		       adapter->mc5.stats.active_rgn_full);
	len += sprintf(buf + len, "%-18s %lu\n", "NFASearchErr:",
		       adapter->mc5.stats.nfa_srch_err);
	len += sprintf(buf + len, "%-18s %lu\n", "MC5UnknownCmd:",
		       adapter->mc5.stats.unknown_cmd);
	len += sprintf(buf + len, "%-18s %lu\n", "MC5DelActEmpty:",
		       adapter->mc5.stats.del_act_empty);

	len += sprintf(buf + len, "\n%-18s %lu\n", "ULPCh0PBLOOB:",
		       adapter->irq_stats[STAT_ULP_CH0_PBL_OOB]);
	len += sprintf(buf + len, "%-18s %lu\n", "ULPCh1PBLOOB:",
		       adapter->irq_stats[STAT_ULP_CH1_PBL_OOB]);
	len += sprintf(buf + len, "%-18s %lu\n", "PCICorrectableErr:",
		       adapter->irq_stats[STAT_PCI_CORR_ECC]);

	adjust_proc_metrics();
	return len;
}

static void *filter_get_idx(struct seq_file *seq, loff_t pos)
{
	int i;
	struct adapter *adap = seq->private;
	struct filter_info *p = adap->filters;

	if (!p)
		return NULL;

	for (i = 0; i < adap->params.mc5.nfilters; i++, p++)
		if (p->valid) {
			if (!pos)
				return p;
			pos--;
		}
	return NULL;
}

static void *filter_get_nxt_idx(struct seq_file *seq, struct filter_info *p)
{
	struct adapter *adap = seq->private;
	struct filter_info *end = &adap->filters[adap->params.mc5.nfilters];

	while (++p < end && !p->valid)
		;
	return p < end ? p : NULL;
}

static void *filter_seq_start(struct seq_file *seq, loff_t *pos)
{
	return *pos ? filter_get_idx(seq, *pos - 1) : SEQ_START_TOKEN;
}

static void *filter_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	v = *pos ? filter_get_nxt_idx(seq, v) : filter_get_idx(seq, 0);
	if (v)
		++*pos;
	return v;
}

static void filter_seq_stop(struct seq_file *seq, void *v)
{
}

static int filter_seq_show(struct seq_file *seq, void *v)
{
	static const char *pkt_type[] = { "*", "tcp", "udp", "frag" };

	if (v == SEQ_START_TOKEN)
		seq_puts(seq, "index         SIP                DIP     sport "
			      "dport VLAN PRI P/MAC type Q\n");
	else {
		char sip[20], dip[20];
		struct filter_info *f = v;
		struct adapter *adap = seq->private;
		u32 nsip = htonl(f->sip);
		u32 ndip = htonl(f->dip);

		sprintf(sip, NIPQUAD_FMT "/%-2u", NIPQUAD(nsip),
			f->sip_mask ? 33 - ffs(f->sip_mask) : 0);
		sprintf(dip, NIPQUAD_FMT, NIPQUAD(ndip));
		seq_printf(seq, "%5zu %18s %15s ", f - adap->filters, sip, dip);
		seq_printf(seq, f->sport ? "%5u " : "    * ", f->sport);
		seq_printf(seq, f->dport ? "%5u " : "    * ", f->dport);
		seq_printf(seq, f->vlan != 0xfff ? "%4u " : "   * ", f->vlan);
		seq_printf(seq, f->vlan_prio == FILTER_NO_VLAN_PRI ?
			   "  * " : "%1u/%1u ", f->vlan_prio, f->vlan_prio | 1);
		if (!f->mac_vld)
			seq_printf(seq, "*/*   ");
		else if (f->mac_hit)
			seq_printf(seq, "%1u/%3u ",
				       (f->mac_idx >> 3) & 0x1,
				       (f->mac_idx) & 0x7);
		else
			seq_printf(seq, "%1u/  * ",
				       (f->mac_idx >> 3) & 0x1);
		seq_printf(seq, "%4s ", pkt_type[f->pkt_type]);
		if (!f->pass)
			seq_printf(seq, "-\n");
		else if (f->rss)
			seq_printf(seq, "*\n");
		else
			seq_printf(seq, "%1u\n", f->qset);
	}
	return 0;
}

static struct seq_operations filter_seq_ops = {
	.start = filter_seq_start,
	.next = filter_seq_next,
	.stop = filter_seq_stop,
	.show = filter_seq_show
};

static int filter_seq_open(struct inode *inode, struct file *file)
{
	int rc = seq_open(file, &filter_seq_ops);

	if (!rc) {
		struct proc_dir_entry *dp = PDE(inode);
		struct seq_file *seq = file->private_data;

		seq->private = dp->data;
	}
	return rc;
}

static struct file_operations filter_seq_fops = {
	.owner = THIS_MODULE,
	.open = filter_seq_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release
};

struct cxgb3_proc_entry {
	const char *name;
	read_proc_t *fn;
};

static struct cxgb3_proc_entry proc_files[] = {
	{ "snmp", snmp_read_proc },
	{ "congestion_control", cong_ctrl_read_proc },
	{ "mtus", mtus_read_proc },
	{ "rss", rss_read_proc },
	{ "sched", sched_read_proc },
	{ "stats", stats_read_proc },
};

static int __devinit cxgb_proc_setup(struct adapter *adapter,
				     struct proc_dir_entry *dir)
{
	int i, created;
	struct proc_dir_entry *p;

	if (!dir)
		return -EINVAL;

	/* If we can create any of the entries we do. */
	for (created = i = 0; i < ARRAY_SIZE(proc_files); ++i) {
		p = create_proc_read_entry(proc_files[i].name, 0, dir,
					   proc_files[i].fn, adapter);
		if (p) {
			SET_PROC_NODE_OWNER(p, THIS_MODULE);
			created++;
		}
	}
	p = create_proc_entry("filters", S_IRUGO, dir);
	if (p) {
		p->proc_fops = &filter_seq_fops;
		p->data = adapter;
		created++;
	}

	return created ? 0 : -ENOMEM;
}

static void cxgb_proc_cleanup(struct proc_dir_entry *dir)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(proc_files); ++i)
		remove_proc_entry(proc_files[i].name, dir);
	remove_proc_entry("filters", dir);
}

static void clear_qset_stats(struct sge_qset *qs)
{
	qs->rspq.empty = 0;
	qs->fl[0].empty = 0;
	qs->fl[1].empty = 0;
	qs->txq[0].stops = 0;
	qs->txq[0].restarts = 0;
	qs->txq[1].stops = 0;
	qs->txq[1].restarts = 0;
	qs->txq[2].stops = 0;
	qs->txq[2].restarts = 0;
	qs->rspq.eth_pkts = 0;
	qs->port_stats[SGE_PSTAT_TX_COALESCE_WR] = 0;
	qs->port_stats[SGE_PSTAT_TX_COALESCE_PKT] = 0;
	qs->port_stats[SGE_PSTAT_LRO] = 0;
	qs->port_stats[SGE_PSTAT_LRO_PG] = 0;
	qs->port_stats[SGE_PSTAT_LRO_SKB] = 0;
	qs->port_stats[SGE_PSTAT_LRO_ACK] = 0;
	qs->port_stats[SGE_PSTAT_LRO_OVFLOW] = 0;
	qs->port_stats[SGE_PSTAT_LRO_COLSN] = 0;
	qs->rspq.offload_pkts = 0;
	qs->rspq.offload_bundles = 0;
	qs->rspq.pure_rsps = 0;
	qs->rspq.imm_data = 0;
	qs->rspq.async_notif = 0;
	qs->rspq.rx_drops = 0;
	qs->rspq.nomem = 0;
	qs->fl[0].alloc_failed = 0;
	qs->fl[1].alloc_failed = 0;
	qs->rspq.unhandled_irqs = 0;
	qs->rspq.starved = 0;
	qs->rspq.restarted = 0;
}

static void clear_port_qset_stats(struct adapter *adap,
				  const struct port_info *pi)
{
	int i;
	struct sge_qset *qs = &adap->sge.qs[pi->first_qset];

	for (i = 0; i < pi->nqsets; i++)
		clear_qset_stats(qs++);
}

#ifndef LINUX_2_4

#define ERR(fmt, ...) do {\
	printk(KERN_ERR "%s: " fmt "\n", dev->name, ## __VA_ARGS__); \
	return -EINVAL; \
} while (0)

/*
 * Perform device independent validation of offload policy.
 */
static int validate_offload_policy(const struct net_device *dev,
				   const struct ofld_policy_file *f,
				   size_t len)
{
	int i, inst;
	const u32 *p;
	const struct ofld_prog_inst *pi;

	/*
	 * We validate the following:
	 * - Program sizes match what's in the header
	 * - Branch targets are within the program
	 * - Offsets do not step outside struct offload_req
	 * - Outputs are valid
	 */
	printk(KERN_DEBUG "version %u, program length %zu bytes, alternate "
	       "program length %zu bytes\n", f->vers,
	       f->prog_size * sizeof(*pi), f->opt_prog_size * sizeof(*p));

	if (sizeof(*f) + (f->nrules + 1) * sizeof(struct offload_settings) +
	    f->prog_size * sizeof(*pi) + f->opt_prog_size * sizeof(*p) != len)
		ERR("bad offload policy length %zu", len);

	if (f->output_everything >= 0 && f->output_everything > f->nrules)
		ERR("illegal output_everything %d in header",
		    f->output_everything);

	pi = f->prog;

	for (i = 0; i < f->prog_size; i++, pi++) {
		if (pi->offset < 0 ||
		    pi->offset >= sizeof(struct offload_req) / 4)
			ERR("illegal offset %d at instruction %d", pi->offset,
			    i);
		if (pi->next[0] < 0 && -pi->next[0] > f->nrules)
			ERR("illegal output %d at instruction %d",
			    -pi->next[0], i);
		if (pi->next[1] < 0 && -pi->next[1] > f->nrules)
			ERR("illegal output %d at instruction %d",
			    -pi->next[1], i);
		if (pi->next[0] > 0 && pi->next[0] >= f->prog_size)
			ERR("illegal branch target %d at instruction %d",
			    pi->next[0], i);
		if (pi->next[1] > 0 && pi->next[1] >= f->prog_size)
			ERR("illegal branch target %d at instruction %d",
			    pi->next[1], i);
	}

	p = (const u32 *)pi;

	for (inst = i = 0; i < f->opt_prog_size; inst++) {
		unsigned int off = *p & 0xffff, nvals = *p >> 16;

		if (off >= sizeof(struct offload_req) / 4)
			ERR("illegal offset %u at opt instruction %d",
			    off, inst);
		if ((int32_t)p[1] < 0 && -p[1] > f->nrules)
			ERR("illegal output %d at opt instruction %d",
			    -p[1], inst);
		if ((int32_t)p[2] < 0 && -p[2] > f->nrules)
			ERR("illegal output %d at opt instruction %d",
			    -p[2], inst);
		if ((int32_t)p[1] > 0 && p[1] >= f->opt_prog_size)
			ERR("illegal branch target %d at opt instruction %d",
			    p[1], inst);
		if ((int32_t)p[2] > 0 && p[2] >= f->opt_prog_size)
			ERR("illegal branch target %d at opt instruction %d",
			    p[2], inst);
		p += 4 + nvals;
		i += 4 + nvals;
		if (i > f->opt_prog_size)
			ERR("too many values %u for opt instruction %d",
			    nvals, inst);
	}

	return 0;
}

#undef ERR

/*
 * Perform T3-specific validation of offload policy settings.
 */
static int validate_policy_settings(const struct net_device *dev,
				    struct adapter *adap,
				    const struct ofld_policy_file *f)
{
	int i, nqsets = 0, nclasses = 8 / adap->params.tp.nchan;
	const u32 *op = (const u32 *)&f->prog[f->prog_size];
	const struct offload_settings *s = (void *)&op[f->opt_prog_size];

	for_each_port(adap, i)
		nqsets += adap2pinfo(adap, i)->nqsets;

	for (i = 0; i <= f->nrules; i++, s++) {
		if (s->cong_algo > 3) {
			printk(KERN_ERR "%s: illegal congestion algorithm %d\n",
			       dev->name, s->cong_algo);
			return -EINVAL;
		}
		if (s->rssq >= nqsets) {
			printk(KERN_ERR "%s: illegal RSS queue %d\n", dev->name,
			       s->rssq);
			return -EINVAL;
		}
		if (s->sched_class >= nclasses) {
			printk(KERN_ERR "%s: illegal scheduling class %d\n",
			       dev->name, s->sched_class);
			return -EINVAL;
		}
		if (s->tstamp >= 0) {
			printk(KERN_ERR "%s: policy rules specifying timestamps"
			       " not supported\n", dev->name);
			return -EINVAL;
		}
		if (s->sack >= 0) {
			printk(KERN_ERR "%s: policy rules specifying SACK not "
			       "supported\n", dev->name);
			return -EINVAL;
		}
	}
	return 0;
}

#endif /* !LINUX_2_4 */

static int in_range(int val, int lo, int hi)
{
	return val < 0 || (val <= hi && val >= lo);
}

static int cxgb_extension_ioctl(struct net_device *dev, void __user *useraddr)
{
	struct port_info *pi = netdev_priv(dev);
	struct adapter *adapter = pi->adapter;
	u32 cmd;
	int ret;

	if (copy_from_user(&cmd, useraddr, sizeof(cmd)))
		return -EFAULT;

	switch (cmd) {
	case CHELSIO_SETREG: {
		struct ch_reg edata;

		if (!capable(CAP_NET_ADMIN))
			return -EPERM;
		if (copy_from_user(&edata, useraddr, sizeof(edata)))
			return -EFAULT;
		if ((edata.addr & 3) != 0 || edata.addr >= adapter->mmio_len)
			return -EINVAL;
		writel(edata.val, adapter->regs + edata.addr);
		break;
	}
	case CHELSIO_GETREG: {
		struct ch_reg edata;

		if (copy_from_user(&edata, useraddr, sizeof(edata)))
			return -EFAULT;
		if ((edata.addr & 3) != 0 || edata.addr >= adapter->mmio_len)
			return -EINVAL;
		edata.val = readl(adapter->regs + edata.addr);
		if (copy_to_user(useraddr, &edata, sizeof(edata)))
			return -EFAULT;
		break;
	}
	case CHELSIO_GETTPI: {
		struct ch_reg edata;

		if (copy_from_user(&edata, useraddr, sizeof(edata)))
			return -EFAULT;
		ret = t3_elmr_blk_read(adapter, edata.addr, &edata.val, 1);
		if (ret)
			return ret;
		if (copy_to_user(useraddr, &edata, sizeof(edata)))
			return -EFAULT;
		break;
	}
	case CHELSIO_SETTPI: {
		struct ch_reg edata;

		if (!capable(CAP_NET_ADMIN))
			return -EPERM;
		if (copy_from_user(&edata, useraddr, sizeof(edata)))
			return -EFAULT;
		ret = t3_elmr_blk_write(adapter, edata.addr, &edata.val, 1);
		if (ret)
			return ret;
		break;
	}
	case CHELSIO_GET_SGE_CONTEXT: {
		struct ch_cntxt ecntxt;

		if (copy_from_user(&ecntxt, useraddr, sizeof(ecntxt)))
			return -EFAULT;

		spin_lock_irq(&adapter->sge.reg_lock);
		if (ecntxt.cntxt_type == CNTXT_TYPE_EGRESS)
			ret = t3_sge_read_ecntxt(adapter, ecntxt.cntxt_id,
						 ecntxt.data);
		else if (ecntxt.cntxt_type == CNTXT_TYPE_FL)
			ret = t3_sge_read_fl(adapter, ecntxt.cntxt_id,
					     ecntxt.data);
		else if (ecntxt.cntxt_type == CNTXT_TYPE_RSP)
			ret = t3_sge_read_rspq(adapter, ecntxt.cntxt_id,
					       ecntxt.data);
		else if (ecntxt.cntxt_type == CNTXT_TYPE_CQ)
			ret = t3_sge_read_cq(adapter, ecntxt.cntxt_id,
					     ecntxt.data);
		else
			ret = -EINVAL;
		spin_unlock_irq(&adapter->sge.reg_lock);

		if (ret)
			return ret;
		if (copy_to_user(useraddr, &ecntxt, sizeof(ecntxt)))
			return -EFAULT;
		break;
	}
	case CHELSIO_GET_SGE_DESC: {
		struct ch_desc edesc;

		if (copy_from_user(&edesc, useraddr, sizeof(edesc)))
			return -EFAULT;

		if (edesc.queue_num >= SGE_QSETS * 6)
			return -EINVAL;

		ret = t3_get_desc(&adapter->sge.qs[edesc.queue_num / 6],
				  edesc.queue_num % 6, edesc.idx, edesc.data);
		if (ret < 0)
			return ret;
		edesc.size = ret;

		if (copy_to_user(useraddr, &edesc, sizeof(edesc)))
			return -EFAULT;
		break;
	}
	case CHELSIO_SET_QSET_PARAMS: {
		int i;
		struct qset_params *q;
		struct ch_qset_params t;
		int q1 = pi->first_qset;
		int nqsets = pi->nqsets;

		if (!capable(CAP_NET_ADMIN))
			return -EPERM;
		if (copy_from_user(&t, useraddr, sizeof(t)))
			return -EFAULT;
		if (t.qset_idx >= SGE_QSETS)
			return -EINVAL;
		if (!in_range(t.intr_lat, 0, M_NEWTIMER) ||
		    !in_range(t.cong_thres, 0, 255) ||
		    !in_range(t.txq_size[0], MIN_TXQ_ENTRIES,
			      MAX_TXQ_ENTRIES) ||
		    !in_range(t.txq_size[1], MIN_TXQ_ENTRIES,
			      MAX_TXQ_ENTRIES) ||
		    !in_range(t.txq_size[2], MIN_CTRL_TXQ_ENTRIES,
			      MAX_CTRL_TXQ_ENTRIES) ||
		    !in_range(t.fl_size[0], MIN_FL_ENTRIES, MAX_RX_BUFFERS) ||
		    !in_range(t.fl_size[1], MIN_FL_ENTRIES,
			      MAX_RX_JUMBO_BUFFERS) ||
		    !in_range(t.rspq_size, MIN_RSPQ_ENTRIES, MAX_RSPQ_ENTRIES))
		       return -EINVAL;

		if ((adapter->flags & FULL_INIT_DONE) && t.lro > 0)
			for_each_port(adapter, i) {
				pi = adap2pinfo(adapter, i);
				if (t.qset_idx >= pi->first_qset &&
				    t.qset_idx < pi->first_qset + pi->nqsets &&
				    !pi->rx_csum_offload)
					return -EINVAL;
			}

		if ((adapter->flags & FULL_INIT_DONE) &&
		    (t.rspq_size >= 0 || t.fl_size[0] >= 0 ||
		     t.fl_size[1] >= 0 || t.txq_size[0] >= 0 ||
		     t.txq_size[1] >= 0 || t.txq_size[2] >= 0 ||
		     t.polling >= 0 || t.cong_thres >= 0))
			return -EBUSY;

		/* Allow setting of any available qset when offload enabled */
		if (test_bit(OFFLOAD_DEVMAP_BIT, &adapter->open_device_map)) {
			q1 = 0;
			for_each_port(adapter, i) {
				pi = adap2pinfo(adapter, i);
				nqsets = pi->first_qset + pi->nqsets;
			}
		}

		if (t.qset_idx < q1)
			return -EINVAL;
		if (t.qset_idx > q1 + nqsets - 1)
			return -EINVAL;

		q = &adapter->params.sge.qset[t.qset_idx];

		if (t.rspq_size >= 0)
			q->rspq_size = t.rspq_size;
		if (t.fl_size[0] >= 0)
			q->fl_size = t.fl_size[0];
		if (t.fl_size[1] >= 0)
			q->jumbo_size = t.fl_size[1];
		if (t.txq_size[0] >= 0)
			q->txq_size[0] = t.txq_size[0];
		if (t.txq_size[1] >= 0)
			q->txq_size[1] = t.txq_size[1];
		if (t.txq_size[2] >= 0)
			q->txq_size[2] = t.txq_size[2];
		if (t.cong_thres >= 0)
			q->cong_thres = t.cong_thres;
		if (t.intr_lat >= 0) {
			struct sge_qset *qs = &adapter->sge.qs[t.qset_idx];

			q->coalesce_usecs = t.intr_lat;
			t3_update_qset_coalesce(qs, q);
		}
		if (t.polling >= 0) {
			if (adapter->flags & USING_MSIX)
				q->polling = t.polling;
			else {
				/* No polling with INTx for T3A */
				if (adapter->params.rev == 0 &&
				    !(adapter->flags & USING_MSI))
					t.polling = 0;

				for (i = 0; i < SGE_QSETS; i++) {
					q = &adapter->params.sge.qset[i];
					q->polling = t.polling;
				}
			}
		}
		if (t.lro >= 0) {
			struct sge_qset *qs = &adapter->sge.qs[t.qset_idx];

			q->lro = t.lro;
			qs->lro.enabled = t.lro;
		}
		break;
	}
	case CHELSIO_GET_QSET_PARAMS: {
		struct qset_params *q;
		struct ch_qset_params t;
		int q1 = pi->first_qset;
		int nqsets = pi->nqsets;
		int i;

		if (copy_from_user(&t, useraddr, sizeof(t)))
			return -EFAULT;

		/* Display qsets for all ports when offload enabled */
		if (test_bit(OFFLOAD_DEVMAP_BIT, &adapter->open_device_map)) {
			q1 = 0;
			for_each_port(adapter, i) {
				pi = adap2pinfo(adapter, i);
				nqsets = pi->first_qset + pi->nqsets;
			}
		}

		if (t.qset_idx >= nqsets)
			return -EINVAL;

		q = &adapter->params.sge.qset[q1 + t.qset_idx];
		t.rspq_size   = q->rspq_size;
		t.txq_size[0] = q->txq_size[0];
		t.txq_size[1] = q->txq_size[1];
		t.txq_size[2] = q->txq_size[2];
		t.fl_size[0]  = q->fl_size;
		t.fl_size[1]  = q->jumbo_size;
		t.polling     = q->polling;
		t.lro         = q->lro;
		t.intr_lat    = q->coalesce_usecs;
		t.cong_thres  = q->cong_thres;
		t.qnum        = q1;

		if (adapter->flags & USING_MSIX)
			t.vector = adapter->msix_info[q1 + t.qset_idx + 1].vec;
		else
			t.vector = adapter->pdev->irq;

		if (copy_to_user(useraddr, &t, sizeof(t)))
			return -EFAULT;
		break;
	}
	case CHELSIO_SET_QSET_NUM: {
		struct ch_reg edata;
		unsigned int i, first_qset = 0, other_qsets;

		if (!capable(CAP_NET_ADMIN))
			return -EPERM;
		if (adapter->flags & FULL_INIT_DONE)
			return -EBUSY;
		if (copy_from_user(&edata, useraddr, sizeof(edata)))
			return -EFAULT;
		if (edata.val < 1 ||
		    (edata.val > 1 && !(adapter->flags & USING_MSIX)))
			return -EINVAL;

		other_qsets = adapter->sge.nqsets - pi->nqsets;
		if (edata.val + other_qsets > SGE_QSETS)
			return -EINVAL;

		pi->nqsets = edata.val;
		t3_compat_set_num_tx_queues(dev, edata.val);
		adapter->sge.nqsets = other_qsets + pi->nqsets;

		for_each_port(adapter, i)
			if (adapter->port[i]) {
				pi = adap2pinfo(adapter, i);
				pi->first_qset = first_qset;
				first_qset += pi->nqsets;
			}
		break;
	}
	case CHELSIO_GET_QSET_NUM: {
		struct ch_reg edata;

		edata.cmd = CHELSIO_GET_QSET_NUM;
		edata.val = pi->nqsets;
		if (copy_to_user(useraddr, &edata, sizeof(edata)))
			return -EFAULT;
		break;
	}
	case CHELSIO_LOAD_FW: {
		u8 *fw_data;
		struct ch_mem_range t;

		if (!capable(CAP_NET_ADMIN))
			return -EPERM;
		if (copy_from_user(&t, useraddr, sizeof(t)))
			return -EFAULT;
		if (!t.len)
			return -EINVAL;

		fw_data = kmalloc(t.len, GFP_KERNEL);
		if (!fw_data)
			return -ENOMEM;

		if (copy_from_user(fw_data, useraddr + sizeof(t), t.len)) {
			kfree(fw_data);
			return -EFAULT;
		}

		ret = t3_load_fw(adapter, fw_data, t.len);
		kfree(fw_data);
		if (ret)
			return ret;
		break;
	}
	case CHELSIO_LOAD_BOOT: {
		u8 *boot_data;
		struct ch_mem_range t;

		if (!capable(CAP_NET_ADMIN))
			return -EPERM;
		if (copy_from_user(&t, useraddr, sizeof(t)))
			return -EFAULT;

		boot_data = kmalloc(t.len, GFP_KERNEL);
		if (!boot_data)
			return -ENOMEM;

		if (copy_from_user(boot_data, useraddr + sizeof(t), t.len)) {
			kfree(boot_data);
			return -EFAULT;
		}

		ret = t3_load_boot(adapter, boot_data, t.len);
		kfree(boot_data);
		if (ret)
			return ret;
		break;
	}
	case CHELSIO_SET_FILTER: {
		struct ch_filter f;
		struct filter_info *p;

		if (!adapter->params.mc5.nfilters)
			return -EOPNOTSUPP;
		if (!capable(CAP_NET_ADMIN))
			return -EPERM;
		if (!(adapter->flags & FULL_INIT_DONE))
			return -EAGAIN;  /* can still change nfilters */
		if (!adapter->filters)
			return -ENOMEM;
		if (!cxgb3_filter_toe_mode(adapter, CXGB3_FTM_FILTER))
			return -EBUSY;
		if (copy_from_user(&f, useraddr, sizeof(f)))
			return -EFAULT;

		if (f.filter_id >= adapter->params.mc5.nfilters ||
		    (f.val.dip && f.mask.dip != 0xffffffff) ||
		    (f.val.sport && f.mask.sport != 0xffff) ||
		    (f.val.dport && f.mask.dport != 0xffff) ||
		    (f.mask.vlan && f.mask.vlan != 0xfff) ||
		    (f.mask.vlan_prio && f.mask.vlan_prio != FILTER_NO_VLAN_PRI) ||
		    (f.mac_addr_idx != 0xffff && f.mac_addr_idx > 15) ||
		    f.qset >= SGE_QSETS ||
		    adapter->rrss_map[f.qset] >= RSS_TABLE_SIZE)
			return -EINVAL;

		p = &adapter->filters[f.filter_id];
		if (p->locked)
			return -EPERM;

		p->sip = f.val.sip;
		p->sip_mask = f.mask.sip;
		p->dip = f.val.dip;
		p->sport = f.val.sport;
		p->dport = f.val.dport;
		p->vlan = f.mask.vlan ? f.val.vlan : 0xfff;
		p->vlan_prio = f.mask.vlan_prio ? (f.val.vlan_prio & 6) :
						  FILTER_NO_VLAN_PRI;
		p->mac_hit = f.mac_hit;
		p->mac_vld = f.mac_addr_idx != 0xffff;
		p->mac_idx = f.mac_addr_idx;
		p->pkt_type = f.proto;
		p->report_filter_id = f.want_filter_id;
		p->pass = f.pass;
		p->rss = f.rss;
		p->qset = f.qset;

		ret = set_filter(adapter, f.filter_id, p);
		if (ret)
			return ret;
		p->valid = 1;
		break;
	}
	case CHELSIO_DEL_FILTER: {
		struct ch_filter f;
		struct filter_info *p;

		if (!adapter->params.mc5.nfilters)
			return -EOPNOTSUPP;
		if (!capable(CAP_NET_ADMIN))
			return -EPERM;
		if (!(adapter->flags & FULL_INIT_DONE))
			return -EAGAIN;  /* can still change nfilters */
		if (!adapter->filters)
			return -ENOMEM;
		if (!cxgb3_filter_toe_mode(adapter, CXGB3_FTM_FILTER))
			return -EBUSY;
		if (copy_from_user(&f, useraddr, sizeof(f)))
			return -EFAULT;
		if (f.filter_id >= adapter->params.mc5.nfilters)
		       return -EINVAL;

		p = &adapter->filters[f.filter_id];
		if (p->locked)
			return -EPERM;
		memset(p, 0, sizeof(*p));
		p->sip = p->sip_mask = 0xffffffff;
		p->vlan = 0xfff;
		p->vlan_prio = FILTER_NO_VLAN_PRI;
		p->pkt_type = 1;
		return set_filter(adapter, f.filter_id, p);
	}

	case CHELSIO_CLEAR_STATS: {
		struct ch_reg edata;
		struct port_info *pi = netdev_priv(dev);

		if (!capable(CAP_NET_ADMIN))
			return -EPERM;
		if (!(adapter->flags & FULL_INIT_DONE))
			return -EAGAIN;
		if (copy_from_user(&edata, useraddr, sizeof(edata)))
			return -EFAULT;
		if ((edata.val & STATS_QUEUE) && edata.addr != -1 &&
		    edata.addr >= pi->nqsets)
			return -EINVAL;
		if (edata.val & STATS_PORT) {
			spin_lock(&adapter->stats_lock);
			t3_mac_update_stats(&pi->mac);
			spin_unlock(&adapter->stats_lock);
			memset(&pi->mac.stats, 0, sizeof(pi->mac.stats));
			clear_sge_port_stats(adapter, pi);
		}
		if (edata.val & STATS_QUEUE) {
			if (edata.addr == -1)
				clear_port_qset_stats(adapter, pi);
			else
				clear_qset_stats(&adapter->sge.qs[edata.addr +
							      pi->first_qset]);
		}
		break;
	}

	case CHELSIO_DEVUP:
		if (!is_offload(adapter))
			return -EOPNOTSUPP;
		if (!capable(CAP_NET_ADMIN))
			return -EPERM;
		ret = offload_open(dev);
		if (ret)
			return ret;

		break;
#ifdef CONFIG_CHELSIO_T3_CORE
	case CHELSIO_SETMTUTAB: {
		struct ch_mtus m;
		int i;

		if (!is_offload(adapter))
			return -EOPNOTSUPP;
		if (!capable(CAP_NET_ADMIN))
			return -EPERM;
		if (offload_running(adapter))
			return -EBUSY;
		if (copy_from_user(&m, useraddr, sizeof(m)))
			return -EFAULT;
		if (m.nmtus != NMTUS)
			return -EINVAL;
		if (m.mtus[0] < 81)         /* accommodate SACK */
			return -EINVAL;

		// MTUs must be in ascending order
		for (i = 1; i < NMTUS; ++i)
			if (m.mtus[i] < m.mtus[i - 1])
				return -EINVAL;

		memcpy(adapter->params.mtus, m.mtus,
		       sizeof(adapter->params.mtus));
		break;
	}
	case CHELSIO_GETMTUTAB: {
		struct ch_mtus m;

		if (!is_offload(adapter))
			return -EOPNOTSUPP;

		memcpy(m.mtus, adapter->params.mtus, sizeof(m.mtus));
		m.nmtus = NMTUS;

		if (copy_to_user(useraddr, &m, sizeof(m)))
			return -EFAULT;
		break;
	}
#endif /* CONFIG_CHELSIO_T3_CORE */

	case CHELSIO_GET_PM: {
		struct tp_params *p = &adapter->params.tp;
		struct ch_pm m = { .cmd = CHELSIO_GET_PM };

		if (!is_offload(adapter))
			return -EOPNOTSUPP;
		m.tx_pg_sz  = p->tx_pg_size;
		m.tx_num_pg = p->tx_num_pgs;
		m.rx_pg_sz  = p->rx_pg_size;
		m.rx_num_pg = p->rx_num_pgs;
		m.pm_total  = p->pmtx_size + p->chan_rx_size * p->nchan;
		if (copy_to_user(useraddr, &m, sizeof(m)))
			return -EFAULT;
		break;
	}
	case CHELSIO_SET_PM: {
		struct ch_pm m;
		struct tp_params *p = &adapter->params.tp;

		if (!is_offload(adapter))
			return -EOPNOTSUPP;
		if (!capable(CAP_NET_ADMIN))
			return -EPERM;
		if (adapter->flags & FULL_INIT_DONE)
			return -EBUSY;
		if (copy_from_user(&m, useraddr, sizeof(m)))
			return -EFAULT;
		if (!m.rx_pg_sz || (m.rx_pg_sz & (m.rx_pg_sz - 1)) ||
		    !m.tx_pg_sz || (m.tx_pg_sz & (m.tx_pg_sz - 1)))
			return -EINVAL;      /* not power of 2 */
		if (!(m.rx_pg_sz & 0x14000))
			return -EINVAL;      /* not 16KB or 64KB */
		if (!(m.tx_pg_sz & 0x1554000))
			return -EINVAL;
		if (m.tx_num_pg == -1)
			m.tx_num_pg = p->tx_num_pgs;
		if (m.rx_num_pg == -1)
			m.rx_num_pg = p->rx_num_pgs;
		if (m.tx_num_pg % 24 || m.rx_num_pg % 24)
			return -EINVAL;
		if (m.rx_num_pg * m.rx_pg_sz > p->chan_rx_size ||
		    m.tx_num_pg * m.tx_pg_sz > p->chan_tx_size)
			return -EINVAL;
		p->rx_pg_size = m.rx_pg_sz;
		p->tx_pg_size = m.tx_pg_sz;
		p->rx_num_pgs = m.rx_num_pg;
		p->tx_num_pgs = m.tx_num_pg;
		break;
	}
	case CHELSIO_READ_TCAM_WORD: {
		struct ch_tcam_word t;

		if (!is_offload(adapter))
			return -EOPNOTSUPP;
		if (!(adapter->flags & FULL_INIT_DONE))
			return -EIO;         /* need MC5 */
		if (copy_from_user(&t, useraddr, sizeof(t)))
			return -EFAULT;
		ret = t3_read_mc5_range(&adapter->mc5, t.addr, 1, t.buf);
		if (ret)
			return ret;
		if (copy_to_user(useraddr, &t, sizeof(t)))
			return -EFAULT;
		break;
	}
	case CHELSIO_GET_MEM: {
		struct ch_mem_range t;
		struct mc7 *mem;
		u64 buf[32];

		if (!is_offload(adapter))
			return -EOPNOTSUPP;
		if (!(adapter->flags & FULL_INIT_DONE))
			return -EIO;         /* need the memory controllers */
		if (copy_from_user(&t, useraddr, sizeof(t)))
			return -EFAULT;
		if ((t.addr & 7) || (t.len & 7))
			return -EINVAL;
		if (t.mem_id == MEM_CM)
			mem = &adapter->cm;
		else if (t.mem_id == MEM_PMRX)
			mem = &adapter->pmrx;
		else if (t.mem_id == MEM_PMTX)
			mem = &adapter->pmtx;
		else
			return -EINVAL;

		/*
		 * Version scheme:
		 * bits 0..9: chip version
		 * bits 10..15: chip revision
		 */
		t.version = 3 | (adapter->params.rev << 10);
		if (copy_to_user(useraddr, &t, sizeof(t)))
			return -EFAULT;

		/*
		 * Read 256 bytes at a time as len can be large and we don't
		 * want to use huge intermediate buffers.
		 */
		useraddr += sizeof(t);   /* advance to start of buffer */
		while (t.len) {
			unsigned int chunk = min_t(unsigned int, t.len,
						   sizeof(buf));

			ret = t3_mc7_bd_read(mem, t.addr / 8, chunk / 8, buf);
			if (ret)
				return ret;
			if (copy_to_user(useraddr, buf, chunk))
				return -EFAULT;
			useraddr += chunk;
			t.addr += chunk;
			t.len -= chunk;
		}
		break;
	}
#ifdef CONFIG_CHELSIO_T3_CORE
	case CHELSIO_SET_TRACE_FILTER: {
		struct ch_trace t;
		const struct trace_params *tp;

		if (!capable(CAP_NET_ADMIN))
			return -EPERM;
		if (!offload_running(adapter))
			return -EAGAIN;
		if (copy_from_user(&t, useraddr, sizeof(t)))
			return -EFAULT;

		tp = (const struct trace_params *)&t.sip;
		if (t.config_tx)
			t3_config_trace_filter(adapter, tp, 0, t.invert_match,
					       t.trace_tx);
		if (t.config_rx)
			t3_config_trace_filter(adapter, tp, 1, t.invert_match,
					       t.trace_rx);
		break;
	}
	case CHELSIO_GET_TRACE_FILTER: {
		struct ch_trace t;
		struct ch_trace t1;
		struct trace_params *tp;
		int    inverted=0, enabled=0;

		if (!capable(CAP_NET_ADMIN))
			return -EPERM;
		if (!offload_running(adapter))
			return -EAGAIN;
		if (copy_from_user(&t, useraddr, sizeof(t)))
			return -EFAULT;

		/*
		 * read the filters into t.
		 */
		tp = (struct trace_params *)&t.sip;
		if (t.config_tx) {
			t3_query_trace_filter(adapter, tp, 0, &inverted, &enabled);
			if (inverted)
				t.invert_match = 1;
			if (enabled)
				t.trace_tx = 1;
		}
		if (t.config_rx) {
			if (enabled)
				tp = (struct trace_params *)&t1.sip;
			t3_query_trace_filter(adapter, tp, 1, &inverted, &enabled);
			if (inverted)
				t.invert_match = 1;
			if (enabled)
				t.trace_rx = 1;
		}
		if (copy_to_user(useraddr, &t, sizeof(t)))
			return -EFAULT;
		break;
	}
#endif
	case CHELSIO_SET_PKTSCHED: {
		struct ch_pktsched_params p;
		int port;

		if (!capable(CAP_NET_ADMIN))
			return -EPERM;
		if (!adapter->open_device_map)
			return -EAGAIN;        /* uP and SGE must be running */
		if (copy_from_user(&p, useraddr, sizeof(p)))
			return -EFAULT;
		if (p.sched == PKTSCHED_TUNNELQ && !in_range(p.idx, 0,
							     SGE_QSETS-1))
			return -EINVAL;
		if (p.sched == PKTSCHED_PORT && !in_range(p.idx, 0,
					      adapter->params.nports -1))
			return -EINVAL;

		if (p.sched == PKTSCHED_PORT) {
			struct port_info *pi;
			pi = netdev_priv(adapter->port[p.idx]);
			ret = send_pktsched_cmd(adapter, p.sched,
						p.idx, p.min, p.max,
						pi->tx_chan);
			if (ret)
				return -EINVAL;
			pi->sched_min = p.min;
			pi->sched_max = p.max;

			return 0;
		}

		/*
		 * Find the port corresponding to the queue set so we can
		 * determine the right transmit channel to use for the
		 * schedule binding.
		 */
		for_each_port(adapter, port) {
			struct port_info *pi;
			pi = netdev_priv(adapter->port[port]);
			if (p.idx >= pi->first_qset &&
			    p.idx < pi->first_qset + pi->nqsets)
				break;
		}

		ret = send_pktsched_cmd(adapter, p.sched,
					p.idx, p.min, p.max,
					pi->tx_chan);

		if (ret)
			return -EINVAL;

		(adapter->sge.qs[p.idx].txq)->sched_max = p.max;

		return 0;
	}

	case CHELSIO_GET_PKTSCHED: {
		struct ch_pktsched_params p;
		struct port_info *pi;

		if (!capable(CAP_NET_ADMIN))
			return -EPERM;
		if (!adapter->open_device_map)
			return -EAGAIN;        /* uP and SGE must be running */
		if (copy_from_user(&p, useraddr, sizeof(p)))
			return -EFAULT;
		if (p.sched == PKTSCHED_TUNNELQ && !in_range(p.idx, 0,
							     SGE_QSETS-1))
			return -EINVAL;
		if (p.sched == PKTSCHED_PORT && !in_range(p.idx, 0,
					      adapter->params.nports -1))
			return -EINVAL;


		if (p.sched == PKTSCHED_PORT) {
			pi = netdev_priv(adapter->port[p.idx]);
			p.min = pi->sched_min;
			p.max = pi->sched_max;
		} else if (p.sched == PKTSCHED_TUNNELQ)
			p.max = (adapter->sge.qs[p.idx].txq)->sched_max;
				
		if (copy_to_user(useraddr, &p, sizeof(p)))
			return -EFAULT;

		return 0;
	}

#ifdef CONFIG_CHELSIO_T3_CORE
	case CHELSIO_SET_HW_SCHED: {
		struct ch_hw_sched t;
		unsigned int ticks_per_usec = core_ticks_per_usec(adapter);

		if (!capable(CAP_NET_ADMIN))
			return -EPERM;
		if (!(adapter->flags & FULL_INIT_DONE))
			return -EAGAIN;       /* need TP to be initialized */
		if (copy_from_user(&t, useraddr, sizeof(t)))
			return -EFAULT;
		if (t.sched >= NTX_SCHED || !in_range(t.mode, 0, 1) ||
		    !in_range(t.channel, 0, 1) ||
		    !in_range(t.kbps, 0, 10000000) ||
		    !in_range(t.class_ipg, 0, 10000 * 65535 / ticks_per_usec) ||
		    !in_range(t.flow_ipg, 0,
			      dack_ticks_to_usec(adapter, 0x7ff)))
			return -EINVAL;

		if ((t.mode == 0 && t.flow_ipg >= 0) ||
		    (t.mode == 1 && t.kbps >= 0))
			return -EOPNOTSUPP;

		if (t.kbps >= 0) {
			ret = t3_config_sched(adapter, t.kbps, t.sched);
			if (ret < 0)
				return ret;
		}
		if (t.class_ipg >= 0)
			t3_set_sched_ipg(adapter, t.sched, t.class_ipg);
		if (t.flow_ipg >= 0) {
			t.flow_ipg *= 1000;     /* us -> ns */
			t3_set_pace_tbl(adapter, &t.flow_ipg, t.sched, 1);
		}
		if (t.mode >= 0) {
			int bit = 1 << (S_TX_MOD_TIMER_MODE + t.sched);

			t3_set_reg_field(adapter, A_TP_TX_MOD_QUEUE_REQ_MAP,
					 bit, t.mode ? bit : 0);
		}
		if (t.channel >= 0)
			t3_set_reg_field(adapter, A_TP_TX_MOD_QUEUE_REQ_MAP,
					 1 << t.sched, t.channel << t.sched);
		break;
	}
#endif /* CONFIG_CHELSIO_T3_CORE */
	case CHELSIO_GET_UP_LA: {
		struct ch_up_la t;
		int bufsize = LA_ENTRIES * 4;
		void *labuf;

		if (!capable(CAP_NET_ADMIN))
			return -EPERM;
		if (copy_from_user(&t, useraddr, sizeof(t)))
			return -EFAULT;

		labuf = kmalloc(bufsize, GFP_USER);
		if (!labuf)
			return -ENOMEM;

		ret = t3_get_up_la(adapter, &t.stopped, &t.idx,
				   &t.bufsize, labuf);
		if (ret)
			goto out_la;

		ret = -EFAULT;
		if (copy_to_user(useraddr, &t, sizeof(t)))
			goto out_la;
		useraddr += offsetof(struct ch_up_la, data);
		if (copy_to_user(useraddr, labuf, bufsize))
			goto out_la;
		ret = 0;
out_la:
		kfree(labuf);
		if (ret)
			return ret;

		break;
	}
	case CHELSIO_GET_UP_IOQS: {
		struct ch_up_ioqs t;
		int bufsize = IOQ_ENTRIES * sizeof(struct t3_ioq_entry);
		void *ioqbuf;
		u32 *v;

		if (!capable(CAP_NET_ADMIN))
			return -EPERM;
		if (copy_from_user(&t, useraddr, sizeof(t)))
			return -EFAULT;

		bufsize += 4 * 4; /* add room for rx/tx enable/status */
		ioqbuf = kmalloc(bufsize, GFP_USER);
		if (!ioqbuf)
			return -ENOMEM;

		ret = t3_get_up_ioqs(adapter, &t.bufsize, ioqbuf);
		if (ret)
			goto out_ioq;

		v = ioqbuf;
		t.ioq_rx_enable = *v++;
		t.ioq_tx_enable = *v++;
		t.ioq_rx_status = *v++;
		t.ioq_tx_status = *v++;

		ret = -EFAULT;
		if (copy_to_user(useraddr, &t, sizeof(t)))
			goto out_ioq;
		useraddr += offsetof(struct ch_up_ioqs, data);
		bufsize -= 4 * 4;
		if (copy_to_user(useraddr, v, bufsize))
			goto out_ioq;
		ret = 0;
out_ioq:
		kfree(ioqbuf);
		if (ret)
			return ret;

		break;
	}
	case CHELSIO_SET_OFLD_POLICY: {
#ifdef LINUX_2_4
		return -EOPNOTSUPP;
#else
		struct ch_mem_range t;
		struct ofld_policy_file *opf;

		if (!test_bit(OFFLOAD_DEVMAP_BIT,
			      &adapter->registered_device_map))
			return -EOPNOTSUPP;
		if (!capable(CAP_NET_ADMIN))
			return -EPERM;
		if (copy_from_user(&t, useraddr, sizeof(t)))
			return -EFAULT;

		/* len == 0 removes any existing policy */
		if (t.len == 0) {
			req_set_offload_policy(dev, NULL, 0);
			break;
		}

		opf = kmalloc(t.len, GFP_KERNEL);
		if (!opf)
			return -ENOMEM;

		if (copy_from_user(opf, useraddr + sizeof(t), t.len)) {
			kfree(opf);
			return -EFAULT;
		}

		ret = validate_offload_policy(dev, opf, t.len);
		if (!ret) {
			ret = validate_policy_settings(dev, adapter, opf);
			if (!ret)
				ret = req_set_offload_policy(dev, opf, t.len);
		}
		kfree(opf);
		return ret;
#endif
	}
	default:
		return -EOPNOTSUPP;
	}
	return 0;
}

static int cxgb_ioctl(struct net_device *dev, struct ifreq *req, int cmd)
{
	struct mii_ioctl_data *data = if_mii(req);
	struct port_info *pi = netdev_priv(dev);
	struct adapter *adapter = pi->adapter;
	int ret, mmd;

	switch (cmd) {
	case SIOCGMIIPHY:
		data->phy_id = pi->phy.addr;
		/* FALLTHRU */
	case SIOCGMIIREG: {
		u32 val;
		struct cphy *phy = &pi->phy;

		if (!phy->mdio_read)
			return -EOPNOTSUPP;
		if (is_10G(adapter)) {
			mmd = data->phy_id >> 8;
			if (!mmd)
				mmd = MDIO_DEV_PCS;
			else if (mmd > MDIO_DEV_VEND2)
				return -EINVAL;

			ret = phy->mdio_read(adapter, data->phy_id & 0x1f, mmd,
					     data->reg_num, &val);
		} else
			ret = phy->mdio_read(adapter, data->phy_id & 0x1f, 0,
					     data->reg_num & 0x1f, &val);
		if (!ret)
			data->val_out = val;
		break;
	}
	case SIOCSMIIREG: {
		struct cphy *phy = &pi->phy;

		if (!capable(CAP_NET_ADMIN))
			return -EPERM;
		if (!phy->mdio_write)
			return -EOPNOTSUPP;
		if (is_10G(adapter)) {
			mmd = data->phy_id >> 8;
			if (!mmd)
				mmd = MDIO_DEV_PCS;
			else if (mmd > MDIO_DEV_VEND2)
				return -EINVAL;

			ret = phy->mdio_write(adapter, data->phy_id & 0x1f,
					      mmd, data->reg_num, data->val_in);
		} else
			ret = phy->mdio_write(adapter, data->phy_id & 0x1f, 0,
					      data->reg_num & 0x1f,
					      data->val_in);
		break;
	}
	case SIOCCHIOCTL:
		return cxgb_extension_ioctl(dev, (void *)req->ifr_data);
	default:
		return -EOPNOTSUPP;
	}
	return ret;
}

static int cxgb_change_mtu(struct net_device *dev, int new_mtu)
{
 	struct port_info *pi = netdev_priv(dev);
	struct adapter *adapter = pi->adapter;
	int ret;

	if (new_mtu < 81)         /* accommodate SACK */
		return -EINVAL;
	if ((ret = t3_mac_set_mtu(&pi->mac, new_mtu)))
		return ret;

	dev->mtu = new_mtu;
	init_port_mtus(adapter);
	if (adapter->params.rev == 0 && offload_running(adapter))
		t3_load_mtus(adapter, adapter->params.mtus,
			     adapter->params.a_wnd, adapter->params.b_wnd,
			     adapter->port[0]->mtu);

	return 0;
}

static int cxgb_set_mac_addr(struct net_device *dev, void *p)
{
	struct port_info *pi = netdev_priv(dev);
	struct adapter *adapter = pi->adapter;
	struct sockaddr *addr = p;

	if (!is_valid_ether_addr(addr->sa_data))
		return -EINVAL;

	memcpy(dev->dev_addr, addr->sa_data, dev->addr_len);
	t3_mac_set_address(&pi->mac, 0, dev->dev_addr);
	if (offload_running(adapter))
		write_smt_entry(adapter, pi->port_id);

	return 0;
}

/**
 * t3_synchronize_rx - wait for current Rx processing on a port to complete
 * @adap: the adapter
 * @p: the port
 *
 * Ensures that current Rx processing on any of the queues associated with
 * the given port completes before returning.  We do this by acquiring and
 * releasing the locks of the response queues associated with the port.
 */
static void t3_synchronize_rx(struct adapter *adap, const struct port_info *p)
{
	int i;

	for (i = p->first_qset; i < p->first_qset + p->nqsets; i++) {
		struct sge_rspq *q = &adap->sge.qs[i].rspq;
		unsigned long flags;

		spin_lock_irqsave(&q->lock, flags);
		spin_unlock_irqrestore(&q->lock, flags);
	}
}

static void vlan_rx_register(struct net_device *dev, struct vlan_group *grp)
{
	struct port_info *pi = netdev_priv(dev);
	struct adapter *adapter = pi->adapter;

	pi->vlan_grp = grp;

	if (adapter->params.rev > 0)
		t3_set_vlan_accel(adapter, 1 << pi->tx_chan, grp != NULL);
	else {
		/* single control for all ports */
		unsigned int i, have_vlans = 0;
		for_each_port(adapter, i)
		    have_vlans |= adap2pinfo(adapter, i)->vlan_grp != NULL;

		t3_set_vlan_accel(adapter, 1, have_vlans);
	}
	t3_synchronize_rx(adapter, pi);
}

#if !defined(HAVE_NET_DEVICE_OPS)
static void vlan_rx_kill_vid(struct net_device *dev, unsigned short vid)
{
	/* nothing */
}
#endif

#ifdef CONFIG_NET_POLL_CONTROLLER
static void cxgb_netpoll(struct net_device *dev)
{
	struct port_info *pi = netdev_priv(dev);
	struct adapter *adapter = pi->adapter;
	unsigned long flags;
	int qidx;

	local_irq_save(flags);
	for (qidx = pi->first_qset; qidx < pi->first_qset + pi->nqsets; qidx++)
		t3_poll_handler(adapter, &adapter->sge.qs[qidx]);
	local_irq_restore(flags);
}
#endif

/*
 * Periodic accumulation of MAC statistics.
 */

static void mac_stats_update(struct adapter *adapter)
{
	int i;

	for_each_port(adapter, i) {
		struct net_device *dev = adapter->port[i];
		struct port_info *p = netdev_priv(dev);

		if (netif_running(dev)) {
			spin_lock(&adapter->stats_lock);
			t3_mac_update_stats(&p->mac);
			spin_unlock(&adapter->stats_lock);
		}
	}
}

static void check_link_status(struct adapter *adapter)
{
	int i;

	for_each_port(adapter, i) {
		struct net_device *dev = adapter->port[i];
		struct port_info *p = netdev_priv(dev);
		int link_fault;

		spin_lock_irq(&adapter->work_lock);
		link_fault = p->link_fault;
		spin_unlock_irq(&adapter->work_lock);

		if ((link_fault || !(p->phy.caps & SUPPORTED_LINK_IRQ)) &&
		    netif_running(dev)) {
			/*
			 * Disable interrupt so p->link_fault can't change out
			 * from under us ...
			 */
			t3_xgm_intr_disable(adapter, i);
			t3_read_reg(adapter, A_XGM_INT_STATUS + p->mac.offset);

			t3_link_changed(adapter, i);
			t3_xgm_intr_enable(adapter, i);

		}
	}
}

static void check_t3b2_mac(struct adapter *adapter)
{
	int i;

	if (!rtnl_trylock())       /* synchronize with ifdown */
		return;

	for_each_port(adapter, i) {
		struct net_device *dev = adapter->port[i];
		struct port_info *p = netdev_priv(dev);
		int status;

		if (!netif_running(dev))
			continue;

		status = 0;
		if (netif_running(dev) && netif_carrier_ok(dev))
			status = t3b2_mac_watchdog_task(&p->mac);
		if (status == 1)
			p->mac.stats.num_toggled++;
		else if (status == 2) {
			struct cmac *mac = &p->mac;

			t3_mac_set_mtu(mac, dev->mtu);
			t3_mac_set_address(mac, 0, dev->dev_addr);
			cxgb_set_rxmode(dev);
			t3_link_start(&p->phy, mac, &p->link_config);
			t3_mac_enable(mac, MAC_DIRECTION_RX | MAC_DIRECTION_TX);
			t3_port_intr_enable(adapter, p->port_id);
			p->mac.stats.num_resets++;
		}
	}
	rtnl_unlock();
}

extern void check_rspq_fl_status(adapter_t *adapter);

DECLARE_TASK_FUNC(t3_adap_check_task, task_param)
{
	struct adapter *adapter = DELWORK2ADAP(task_param, adap_check_task);
	const struct adapter_params *p = &adapter->params;
	int port;
	unsigned int reset;

	adapter->check_task_cnt++;

	check_link_status(adapter);

	/* Accumulate MAC stats if needed */
	if (!p->linkpoll_period ||
	    (adapter->check_task_cnt * p->linkpoll_period) / 10 >=
	     p->stats_update_period) {
		mac_stats_update(adapter);
		adapter->check_task_cnt = 0;
	}

	if (p->rev == T3_REV_B2 && p->nports < 4)
		check_t3b2_mac(adapter);

	/*
	 * Scan the XGMAC's to check for various conditions which we want to
	 * monitor in a periodic polling manner rather than via an interrupt
	 * condition.  This is used for condions which would otherwise flood
	 * the system with interrupts and we only really need to know that the
	 * conditions are "happening" ...  For each condition we count the
	 * detection of the condition and reset it for the next polling loop.
	 */
	for_each_port(adapter, port) {
		struct cmac *mac =  &adap2pinfo(adapter, port)->mac;
		u32 cause;

		if (mac->multiport)
			continue;

		cause = t3_read_reg(adapter, A_XGM_INT_CAUSE + mac->offset);
		reset = 0;
		if (cause & F_RXFIFO_OVERFLOW) {
			mac->stats.rx_fifo_ovfl++;
			reset |= F_RXFIFO_OVERFLOW;
		}

		t3_write_reg(adapter, A_XGM_INT_CAUSE + mac->offset, reset);
	}

	check_rspq_fl_status(adapter);

	/* Schedule the next check update if any port is active. */
	spin_lock_irq(&adapter->work_lock);
	if (adapter->open_device_map & PORT_MASK)
		schedule_chk_task(adapter);
	spin_unlock_irq(&adapter->work_lock);
}

DECLARE_TASK_FUNC(db_full_task, task_param)
{
	struct adapter *adapter = WORK2ADAP(task_param, db_full_task);

	cxgb3_err_notify(&adapter->tdev, OFFLOAD_DB_FULL, 0);
}

DECLARE_TASK_FUNC(db_empty_task, task_param)
{
	struct adapter *adapter = WORK2ADAP(task_param, db_empty_task);

	cxgb3_err_notify(&adapter->tdev, OFFLOAD_DB_EMPTY, 0);
}

DECLARE_TASK_FUNC(db_drop_task, task_param)
{
	struct adapter *adapter = WORK2ADAP(task_param, db_drop_task);
	unsigned long delay = 1000;
	unsigned short r;

	cxgb3_err_notify(&adapter->tdev, OFFLOAD_DB_DROP, 0);

	/*
	 * Sleep a while before ringing the driver qset dbs.
	 * The delay is between 1000-2023 usecs.
	 */
	get_random_bytes(&r, 2);
	delay += r & 1023;
	set_current_state(TASK_UNINTERRUPTIBLE);
	schedule_timeout(usecs_to_jiffies(delay));
	ring_dbs(adapter);
}

/*
 * Processes external (PHY) interrupts in process context.
 */
DECLARE_TASK_FUNC(ext_intr_task, task_param)
{
	struct adapter *adapter = WORK2ADAP(task_param, ext_intr_handler_task);
	unsigned long flags;
	int i;
	
	/* Disable link fault interrupts */
	if (adapter->params.nports < 4) {
		for_each_port(adapter, i) {
			struct net_device *dev = adapter->port[i];
			struct port_info *p = netdev_priv(dev);

			t3_xgm_intr_disable(adapter, i);
			t3_read_reg(adapter, A_XGM_INT_STATUS + p->mac.offset);
		}
	}
	t3_phy_intr_handler(adapter);

	/* Re-enable link fault interrupts */
	if (adapter->params.nports < 4) {
		for_each_port(adapter, i)
			t3_xgm_intr_enable(adapter, i);
	}

	/* Now reenable external interrupts */
	spin_lock_irqsave(&adapter->work_lock, flags);
	if (adapter->slow_intr_mask) {
		adapter->slow_intr_mask |= F_T3DBG;
		t3_write_reg(adapter, A_PL_INT_CAUSE0, F_T3DBG);
		t3_write_reg(adapter, A_PL_INT_ENABLE0,
			     adapter->slow_intr_mask);
	}
	spin_unlock_irqrestore(&adapter->work_lock, flags);
}

/*
 * Interrupt-context handler for external (PHY) interrupts.
 */
void t3_os_ext_intr_handler(struct adapter *adapter)
{
	/*
	 * Schedule a task to handle external interrupts as they may be slow
	 * and we use a mutex to protect MDIO registers.  We disable PHY
	 * interrupts in the meantime and let the task reenable them when
	 * it's done.
	 */
	spin_lock(&adapter->work_lock);
	if (adapter->slow_intr_mask) {
		adapter->slow_intr_mask &= ~F_T3DBG;
		t3_write_reg(adapter, A_PL_INT_ENABLE0,
			     adapter->slow_intr_mask);
		queue_work(cxgb3_wq, &adapter->ext_intr_handler_task);
	}
	spin_unlock(&adapter->work_lock);
}

void t3_os_link_fault_handler(struct adapter *adapter, int port_id)
{
	struct net_device *netdev = adapter->port[port_id];
	struct port_info *pi = netdev_priv(netdev);

	spin_lock(&adapter->work_lock);
	pi->link_fault = LF_MAYBE;
	spin_unlock(&adapter->work_lock);
}

static int t3_adapter_error(struct adapter *adapter, int reset, int on_wq)
{
	int i, ret = 0;

	if (is_offload(adapter) &&
	    test_bit(OFFLOAD_DEVMAP_BIT, &adapter->open_device_map)) {
		cxgb3_err_notify(&adapter->tdev, OFFLOAD_STATUS_DOWN, 0);
		offload_close(&adapter->tdev);
	}

	/* Stop all ports */
	for_each_port(adapter, i) {
		struct net_device *netdev = adapter->port[i];

		if (netif_running(netdev))
			__cxgb_close(netdev, on_wq);
	}

	/* Stop SGE timers */
	t3_stop_sge_timers(adapter);

	adapter->flags &= ~FULL_INIT_DONE;

	if (reset)
		ret = t3_reset_adapter(adapter);

	pci_disable_device(adapter->pdev);

	return ret;
}

static int t3_reenable_adapter(struct adapter *adapter)
{
	if (pci_enable_device(adapter->pdev)) {
		dev_err(&adapter->pdev->dev,
			"Cannot re-enable PCI device after reset.\n");
		goto err;
	}
	pci_set_master(adapter->pdev);
	t3_os_pci_restore_state(adapter);

	/* Free sge resources */
	t3_free_sge_resources(adapter);

	if (t3_reinit_adapter(adapter))
		goto err;

	return 0;
err:
	return -1;
}

static void t3_resume_ports(struct adapter *adapter)
{
	int i;

	/* Restart the ports */
	for_each_port(adapter, i) {
		struct net_device *netdev = adapter->port[i];

		if (netif_running(netdev)) {
			if (cxgb_open(netdev)) {
				dev_err(&adapter->pdev->dev,
					"can't bring device back up"
					" after reset\n");
				continue;
			}
		}
	}

	if (is_offload(adapter) && !ofld_disable)
		cxgb3_err_notify(&adapter->tdev, OFFLOAD_STATUS_UP, 0);
}

DECLARE_TASK_FUNC(fatal_error_task, task_param)
{
        struct adapter *adapter = WORK2ADAP(task_param, fatal_error_handler_task);
	int err = 0;

	rtnl_lock();
	if (t3_adapter_error(adapter, 1, 1))
		err = 1;
	else if (t3_reenable_adapter(adapter))
		err = 1;
	else t3_resume_ports(adapter);

	CH_ALERT(adapter, "adapter reset %s\n", err ? "failed" : "succeeded");
	rtnl_unlock();

}

void t3_fatal_err(struct adapter *adapter)
{
	unsigned int fw_status[4];
	static int retries = 0;

	if (adapter->flags & FULL_INIT_DONE) {
		t3_sge_stop(adapter);
		t3_write_reg(adapter, A_XGM_TX_CTRL, 0);
		t3_write_reg(adapter, A_XGM_RX_CTRL, 0);
		t3_write_reg(adapter, XGM_REG(A_XGM_TX_CTRL, 1), 0);
		t3_write_reg(adapter, XGM_REG(A_XGM_RX_CTRL, 1), 0);

		spin_lock(&adapter->work_lock);
		t3_intr_disable(adapter);

		if (++retries < 5)
			queue_work(cxgb3_wq, &adapter->fatal_error_handler_task);

		spin_unlock(&adapter->work_lock);
	}
	CH_ALERT(adapter, "encountered fatal error #%d, operation suspended\n", retries);
	if (!t3_cim_ctl_blk_read(adapter, 0xa0, 4, fw_status))
		CH_ALERT(adapter, "FW status: 0x%x, 0x%x, 0x%x, 0x%x\n",
			 fw_status[0], fw_status[1],
			 fw_status[2], fw_status[3]);
}

#if defined(HAS_EEH)
/**
 * t3_io_error_detected - called when PCI error is detected
 * @pdev: Pointer to PCI device
 * @state: The current pci connection state
 *
 * This function is called after a PCI bus error affecting
 * this device has been detected.
 */
static pci_ers_result_t t3_io_error_detected(struct pci_dev *pdev,
					     pci_channel_state_t state)
{
	struct adapter *adapter = pci_get_drvdata(pdev);
	int ret;

	ret = t3_adapter_error(adapter, 0, 0);

	/* Request a slot reset. */
	return PCI_ERS_RESULT_NEED_RESET;
}

/**
 * t3_io_slot_reset - called after the pci bus has been reset.
 * @pdev: Pointer to PCI device
 *
 * Restart the card from scratch, as if from a cold-boot.
 */
static pci_ers_result_t t3_io_slot_reset(struct pci_dev *pdev)
{
	struct adapter *adapter = pci_get_drvdata(pdev);

	if (!t3_reenable_adapter(adapter))
		return PCI_ERS_RESULT_RECOVERED;

	return PCI_ERS_RESULT_DISCONNECT;
}

/**
 * t3_io_resume - called when traffic can start flowing again.
 * @pdev: Pointer to PCI device
 *
 * This callback is called when the error recovery driver tells us that
 * its OK to resume normal operation.
 */
static void t3_io_resume(struct pci_dev *pdev)
{
	struct adapter *adapter = pci_get_drvdata(pdev);

	t3_resume_ports(adapter);
}

static struct pci_error_handlers t3_err_handler = {
	.error_detected = t3_io_error_detected,
	.slot_reset = t3_io_slot_reset,
	.resume = t3_io_resume,
};
#endif

/* Set the number of qsets based on the number of CPUs and the number of ports,
 * not to exceed the number of available qsets, assuming there are enough qsets
 * per port in HW.
 */
static inline void set_nqsets(struct adapter *adap)
{
	int i, j = 0;
	int num_cpus = num_online_cpus();
	int hwports = adap->params.nports;
	int nqsets = adap->msix_nvectors - 1;

	if (!(adap->flags & USING_MSIX)) {
		/* for now, only support 1 queue set/port in non-MSIX mode */
		nqsets = 1;
	} else if (adap->params.rev > 0 && !singleq && hwports <= 2) {
		if (hwports == 2 &&
		    (hwports * nqsets > SGE_QSETS ||
		     num_cpus >= nqsets/hwports))
			nqsets /= hwports;
		if (nqsets > num_cpus)
			nqsets = num_cpus;
		if (nqsets < 1)
			nqsets = 1;
	} else
		nqsets = 1;

	for_each_port(adap, i) {
		struct port_info *pi = adap2pinfo(adap, i);

		pi->first_qset = j;
		pi->nqsets = nqsets;
		j += nqsets;

		dev_info(&adap->pdev->dev,
			 "Port %d using %d queue sets.\n", i, nqsets);
	}

	adap->sge.nqsets = j;
}

static void __devinit check_msi(struct adapter *adap)
{
	int vec, mi1;

	if (!(t3_read_reg(adap, A_PL_INT_CAUSE0) & F_MI1))
		return;

	vec = (adap->flags & USING_MSI) ? adap->pdev->irq :
					  adap->msix_info[0].vec;

	if (request_irq(vec, check_intr_handler, 0, adap->name, adap))
		return;

	t3_set_reg_field(adap, A_PL_INT_ENABLE0, 0, F_MI1);
	msleep(10);
	mi1 = t3_read_reg(adap, A_PL_INT_ENABLE0) & F_MI1;
	if (mi1)
		t3_set_reg_field(adap, A_PL_INT_ENABLE0, F_MI1, 0);
	free_irq(vec, adap);

	if (mi1) {
		cxgb_disable_msi(adap);
		dev_info(&adap->pdev->dev,
			 "the kernel believes that MSI is available on this "
			 "platform\nbut the driver's MSI test has failed.  "
			 "Proceeding with INTx interrupts.\n");
	}
}

static int __devinit cxgb_enable_msix(struct adapter *adap)
{
	struct msix_entry entries[SGE_QSETS + 1];
	int vectors;
	int i, err;

	vectors = ARRAY_SIZE(entries);
	for (i = 0; i < vectors; ++i)
		entries[i].entry = i;

	while ((err = pci_enable_msix(adap->pdev, entries, vectors)) > 0)
		vectors = err;

	if (err < 0)
		pci_disable_msix(adap->pdev);

	if (!err && vectors < (adap->params.nports + 1)) {
		pci_disable_msix(adap->pdev);
		err = -1;
	}

	if (!err) {
		for (i = 0; i < vectors; ++i)
			adap->msix_info[i].vec = entries[i].vector;
		adap->msix_nvectors = vectors;
	}

	return err;
}

#ifdef T3_TRACE
static void __devinit alloc_trace_bufs(adapter_t *adap)
{
	int i;
	char s[32];

	for (i = 0; i < SGE_QSETS; ++i) {
		sprintf(s, "sge_q%d", i);
		adap->tb[i] = t3_trace_alloc(adap->debugfs_root, s, 512);
	}
}

static void free_trace_bufs(adapter_t *adap)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(adap->tb); ++i)
		t3_trace_free(adap->tb[i]);
}
#else
# define alloc_trace_bufs(adapter)
# define free_trace_bufs(adapter)
#endif

static void __devinit print_port_info(adapter_t *adap,
				      const struct adapter_info *ai)
{
	static const char *pci_variant[] = {
		"PCI", "PCI-X", "PCI-X ECC", "PCI-X 266", "PCI Express"
	};

	int i;
	char buf[80];

	if (is_pcie(adap))
		snprintf(buf, sizeof(buf), "%s x%d",
			 pci_variant[adap->params.pci.variant],
			 adap->params.pci.width);
	else
		snprintf(buf, sizeof(buf), "%s %dMHz/%d-bit",
			 pci_variant[adap->params.pci.variant],
			 adap->params.pci.speed, adap->params.pci.width);

	for_each_port(adap, i) {
		struct net_device *dev = adap->port[i];
		const struct port_info *pi = netdev_priv(dev);

		if (!test_bit(i, &adap->registered_device_map))
		       continue;
		printk(KERN_INFO "%s: %s %s %sNIC (rev %d) %s%s\n",
		       dev->name, ai->desc, pi->phy.desc,
		       is_offload(adap) ? "R" : "", adap->params.rev, buf,
		       (adap->flags & USING_MSIX) ? " MSI-X" :
		       (adap->flags & USING_MSI) ? " MSI" : "");
		if (adap->name == dev->name && adap->params.vpd.mclk) {
			printk(KERN_INFO
			       "%s: %uMB CM, %uMB PMTX, %uMB PMRX\n",
			       adap->name, t3_mc7_size(&adap->cm) >> 20,
			       t3_mc7_size(&adap->pmtx) >> 20,
			       t3_mc7_size(&adap->pmrx) >> 20);
			printk(KERN_INFO
			       "%s: S/N: %s E/C: %s\n",
			       adap->name, adap->params.vpd.sn,
			       adap->params.vpd.ec);
			}
	}
}

static void touch_bars(struct pci_dev *pdev)
{
#if BITS_PER_LONG < 64
	u32 v;

	pci_read_config_dword(pdev, PCI_BASE_ADDRESS_1, &v);
	pci_write_config_dword(pdev, PCI_BASE_ADDRESS_1, v);
	pci_read_config_dword(pdev, PCI_BASE_ADDRESS_3, &v);
	pci_write_config_dword(pdev, PCI_BASE_ADDRESS_3, v);
	pci_read_config_dword(pdev, PCI_BASE_ADDRESS_5, &v);
	pci_write_config_dword(pdev, PCI_BASE_ADDRESS_5, v);
#endif
}

#define VLAN_FEAT (NETIF_F_SG | NETIF_F_IP_CSUM | NETIF_F_TSO | NETIF_F_TSO6 |\
		   NETIF_F_IPV6_CSUM | NETIF_F_HIGHDMA)

#if defined(HAVE_NET_DEVICE_OPS)
static const struct net_device_ops cxgb_netdev_ops = {
        .ndo_open               = cxgb_open,
        .ndo_stop               = cxgb_close,
        .ndo_start_xmit         = t3_eth_xmit,
        .ndo_get_stats          = cxgb_get_stats,
        .ndo_validate_addr      = eth_validate_addr,
        .ndo_set_multicast_list = cxgb_set_rxmode,
        .ndo_do_ioctl           = cxgb_ioctl,
        .ndo_change_mtu         = cxgb_change_mtu,
        .ndo_set_mac_address    = cxgb_set_mac_addr,
        .ndo_vlan_rx_register   = vlan_rx_register,
#ifdef CONFIG_NET_POLL_CONTROLLER
        .ndo_poll_controller    = cxgb_netpoll,
#endif
};
#endif /* HAVE_NET_DEVICE_OPS */

static struct proc_dir_entry *cxgb3_proc_root;

static void cxgb_proc_remove(void)
{
	remove_proc_entry("devices", cxgb3_proc_root);
	remove_proc_entry("cxgb3", INET_PROC_DIR);
	cxgb3_proc_root = NULL;
}

static int cxgb_proc_init(void)
{
	struct proc_dir_entry *d;

	cxgb3_proc_root = proc_mkdir("cxgb3", INET_PROC_DIR);
	if (!cxgb3_proc_root)
		return -ENOMEM;
	SET_PROC_NODE_OWNER(cxgb3_proc_root, THIS_MODULE);

	d = create_proc_read_entry("devices", 0, cxgb3_proc_root,
				   offload_devices_read_proc, NULL);

	if (!d)
		goto cleanup;
	SET_PROC_NODE_OWNER(d, THIS_MODULE);
	return 0;

cleanup:
	cxgb_proc_remove();
	return -ENOMEM;
}

static int oflddev_idx = 0, nicdev_idx = 0;

static void __devinit cxgb_proc_dev_init(struct adapter *adapter)
{
	struct t3cdev *tdev = &adapter->tdev;

	if (!cxgb3_proc_root) {
		printk("%s: root proc dir is null\n", __func__);
		return;
	}

	if (is_offload(adapter))
		snprintf(tdev->name, sizeof(tdev->name), "ofld_dev%d", 
			 oflddev_idx++);
	else
		snprintf(tdev->name, sizeof(tdev->name), "nic_dev%d",
			 nicdev_idx++);

	tdev->proc_dir = proc_mkdir(tdev->name, cxgb3_proc_root);
	if (!tdev->proc_dir) {
		printk(KERN_WARNING "Unable to create /proc/net/cxgb3/%s dir\n",
		       tdev->name);
		return;
	}
	SET_PROC_NODE_OWNER(tdev->proc_dir, THIS_MODULE);
}

static void __devexit cxgb_proc_dev_exit(struct t3cdev *tdev)
{
	remove_proc_entry(tdev->name, cxgb3_proc_root);
	tdev->proc_dir = NULL;
}

static int __devinit init_one(struct pci_dev *pdev,
			      const struct pci_device_id *ent)
{
	static int version_printed;

	int i, err, pci_using_dac = 0;
	unsigned long mmio_start, mmio_len;
	const struct adapter_info *ai;
	struct adapter *adapter = NULL;

	if (!version_printed) {
		printk(KERN_INFO "%s - version %s\n", DRIVER_DESC, DRIVER_VERSION);
		++version_printed;
	}

	if (!cxgb3_wq) {
		cxgb3_wq = create_singlethread_workqueue(DRIVER_NAME);
		if (!cxgb3_wq) {
			printk(KERN_ERR DRIVER_NAME
			       ": cannot initialize work queue\n");
			return -ENOMEM;
		}
	}

	err = pci_enable_device(pdev);
	if (err) {
		dev_err(&pdev->dev, "cannot enable PCI device\n");
		return err;
	}

	/*
	 * Can't use pci_request_regions() here because some kernels want to
	 * request the MSI-X BAR in pci_enable_msix.  Also no need to request
	 * the doorbell BAR if we are not doing user-space RDMA.
	 * So only request BAR0.
	 */
	err = pci_request_region(pdev, 0, DRIVER_NAME);
	if (err) {
		/*
		 * Some other driver may have already claimed the device.
		 * Report the event but do not disable the device.
		 */
		printk(KERN_INFO "%s: cannot obtain PCI resources\n",
		       pci_name(pdev));
		return err;
	}

	if (!pci_set_dma_mask(pdev, DMA_BIT_MASK(64))) {
		pci_using_dac = 1;
		err = pci_set_consistent_dma_mask(pdev, DMA_BIT_MASK(64));
		if (err) {
			dev_err(&pdev->dev, "unable to obtain 64-bit DMA for "
			       "coherent allocations\n");
			goto out_release_regions;
		}
	} else if ((err = pci_set_dma_mask(pdev, DMA_BIT_MASK(32))) != 0) {
		dev_err(&pdev->dev, "no usable DMA configuration\n");
		goto out_release_regions;
	}

	touch_bars(pdev);
	pci_set_master(pdev);

	mmio_start = pci_resource_start(pdev, 0);
	mmio_len = pci_resource_len(pdev, 0);
	ai = t3_get_adapter_info(ent->driver_data);

	adapter = kzalloc(sizeof(*adapter), GFP_KERNEL);
	if (!adapter) {
		err = -ENOMEM;
		goto out_release_regions;
	}

	adapter->pdev = pdev;
	t3_os_pci_save_state(adapter);

	adapter->regs = ioremap_nocache(mmio_start, mmio_len);
	if (!adapter->regs) {
		dev_err(&pdev->dev,
			"cannot map device registers\n");
		err = -ENOMEM;
		goto out_free_adapter;
	}

	adapter->name = pci_name(pdev);
	adapter->msg_enable = dflt_msg_enable;
	adapter->mmio_len = mmio_len;
	atomic_set(&adapter->filter_toe_mode, CXGB3_FTM_NONE);
	memset(adapter->rrss_map, 0xff, sizeof(adapter->rrss_map));
	INIT_LIST_HEAD(&adapter->adapter_list);
	spin_lock_init(&adapter->mdio_lock);
	spin_lock_init(&adapter->elmer_lock);
	spin_lock_init(&adapter->work_lock);
	spin_lock_init(&adapter->stats_lock);

	T3_INIT_WORK(&adapter->ext_intr_handler_task,
			ext_intr_task, adapter);
        T3_INIT_WORK(&adapter->fatal_error_handler_task,
                        fatal_error_task, adapter);

	T3_INIT_WORK(&adapter->db_full_task, db_full_task, adapter);
	T3_INIT_WORK(&adapter->db_empty_task, db_empty_task, adapter);
	T3_INIT_WORK(&adapter->db_drop_task, db_drop_task, adapter);

	T3_INIT_DELAYED_WORK(&adapter->adap_check_task,
				t3_adap_check_task,
				adapter);
	init_timer(&adapter->watchdog_timer);

	for (i = 0; i < ai->nports0 + ai->nports1; ++i) {
		struct net_device *netdev;
		struct port_info *pi;

		netdev = alloc_etherdev_mq(sizeof(struct port_info),
					   SGE_QSETS);
		if (!netdev) {
			err = -ENOMEM;
			goto out_free_dev;
		}

		SET_MODULE_OWNER(netdev);
		SET_NETDEV_DEV(netdev, &pdev->dev);

		adapter->port[i] = netdev;
		pi = netdev_priv(netdev);
		pi->adapter = adapter;
		pi->rx_csum_offload = 1;
		pi->port_id = i;
		pi->tx_chan = i >= ai->nports0;
		pi->txpkt_intf = pi->tx_chan ? 2 * (i - ai->nports0) + 1 :
					       2 * i;
		pi->iscsi_ipv4addr = 0;
		pi->sched_min = 50;
		pi->sched_max = 100;
		adapter->rxpkt_map[pi->txpkt_intf] = i;
		netif_carrier_off(netdev);
		netdev->irq = pdev->irq;
		netdev->mem_start = mmio_start;
		netdev->mem_end = mmio_start + mmio_len - 1;
		netdev->features |= NETIF_F_SG | NETIF_F_IP_CSUM;
		netdev->features |= NETIF_F_LLTX;
		if (pci_using_dac)
			netdev->features |= NETIF_F_HIGHDMA;

		if (ai->nports0 + ai->nports1 <= 2)	// disable TSO on T304
			netdev->features |= NETIF_F_TSO;

		netdev->features |= NETIF_F_HW_VLAN_TX | NETIF_F_HW_VLAN_RX;
#if defined(HAVE_NET_DEVICE_OPS)
		netdev->netdev_ops = &cxgb_netdev_ops;
#else
		netdev->vlan_rx_register = vlan_rx_register;
		netdev->vlan_rx_kill_vid = vlan_rx_kill_vid;

		netdev->open = cxgb_open;
		netdev->stop = cxgb_close;
		netdev->hard_start_xmit = t3_eth_xmit;
		netdev->tx_queue_len = 10000;
		netdev->get_stats = cxgb_get_stats;
		netdev->set_multicast_list = cxgb_set_rxmode;
		netdev->do_ioctl = cxgb_ioctl;
		netdev->change_mtu = cxgb_change_mtu;
		netdev->set_mac_address = cxgb_set_mac_addr;
#ifdef CONFIG_NET_POLL_CONTROLLER
		netdev->poll_controller = cxgb_netpoll;
#endif
#endif /* HAVE_NET_DEVICE_OPS */

#if !defined(NAPI_UPDATE)
		netdev->weight = 64;
#endif
		SET_ETHTOOL_OPS(netdev, &cxgb_ethtool_ops);

#ifdef GSO_MAX_SIZE
		netdev->vlan_features = netdev->features & VLAN_FEAT;
		if (adapter->params.nports > 2)
			netif_set_gso_max_size(netdev, 32768);
#endif
	}
	adapter->sge.nqsets = i;

	pci_set_drvdata(pdev, adapter);
	if (t3_prep_adapter(adapter, ai, 1) < 0) {
		err = -ENODEV;
		goto out_free_dev;
	}

	/* See what interrupts we'll be using */
	if (msi > 1 && cxgb_enable_msix(adapter) == 0)
		adapter->flags |= USING_MSIX;
	else if (msi > 0 && pci_enable_msi(pdev) == 0)
		adapter->flags |= USING_MSI;
	if (adapter->flags & (USING_MSIX | USING_MSI))
		check_msi(adapter);

	/*
	 * We need to determine how many queues we're planning on using (by
	 * default) before we register the network devices.  These can be
	 * changed later via our CHELSIO_SET_QSET_NUM ioctl() ...
	 */
	set_nqsets(adapter);

	/*
	 * The card is now ready to go.  If any errors occur during device
	 * registration we do not fail the whole card but rather proceed only
	 * with the ports we manage to register successfully.  However we must
	 * register at least one net device.
	 */
	for_each_port(adapter, i) {
		struct net_device *netdev = adapter->port[i];
		struct port_info *pi = netdev_priv(netdev);

		t3_compat_set_num_tx_queues(netdev, pi->nqsets);

		err = register_netdev(adapter->port[i]);
		if (err)
			dev_warn(&pdev->dev,
				 "cannot register net device %s, skipping\n",
				 adapter->port[i]->name);
		else {
			/*
			 * Change the name we use for messages to the name of
			 * the first successfully registered interface.
			 */
			if (!adapter->registered_device_map)
				adapter->name = adapter->port[i]->name;

			__set_bit(i, &adapter->registered_device_map);
		}
	}
	if (!adapter->registered_device_map) {
		dev_err(&pdev->dev, "could not register any net devices\n");
		goto out_free_dev;
	}

	/* Driver's ready. Reflect it on LEDs */
	t3_led_ready(adapter);

#ifndef	LINUX_2_4
	if (cxgb3_debugfs_root) {
		adapter->debugfs_root = debugfs_create_dir(adapter->name,
							   cxgb3_debugfs_root);
		if (adapter->debugfs_root)
			alloc_trace_bufs(adapter);
	}
#endif	/* LINUX_2_4 */
	cxgb_proc_dev_init(adapter);
	cxgb_proc_setup(adapter, adapter->tdev.proc_dir);

	if (is_offload(adapter)) {
		__set_bit(OFFLOAD_DEVMAP_BIT, &adapter->registered_device_map);
		cxgb3_adapter_ofld(adapter);
	}

#ifndef	LINUX_2_4
	if (sysfs_create_group(net2kobj(adapter->port[0]), &cxgb3_attr_group))
		printk(KERN_INFO
		       "%s: cannot create sysfs cxgb3_attr_group", __func__);
#endif	/* LINUX_2_4 */

	print_port_info(adapter, ai);
	add_adapter(adapter);
	return 0;

out_free_dev:
	iounmap(adapter->regs);
	for (i = ai->nports0 + ai->nports1 - 1; i >= 0; --i)
		if (adapter->port[i])
			free_netdev(adapter->port[i]);

out_free_adapter:
	kfree(adapter);

 out_release_regions:
	pci_release_region(pdev, 0);
	pci_disable_device(pdev);
	pci_set_drvdata(pdev, NULL);
	return err;
}

static void __devexit remove_one(struct pci_dev *pdev)
{
	struct adapter *adapter = pci_get_drvdata(pdev);

	if (adapter) {
		int i;

		t3_sge_stop(adapter);
#ifndef	LINUX_2_4
		sysfs_remove_group(net2kobj(adapter->port[0]),
				   &cxgb3_attr_group);
#endif	/* LINUX_2_4 */
		cxgb_proc_cleanup(adapter->tdev.proc_dir);

		if (is_offload(adapter)) {
			if (test_bit(OFFLOAD_DEVMAP_BIT,
				     &adapter->open_device_map))
				offload_close(&adapter->tdev);
			cxgb3_adapter_unofld(adapter);
		}

		cxgb_proc_dev_exit(&adapter->tdev);

		for_each_port(adapter, i) {
			if (test_bit(i, &adapter->registered_device_map)) {
				unregister_netdev(adapter->port[i]);
			}
		}

		t3_stop_sge_timers(adapter);
		t3_free_sge_resources(adapter);
		if (adapter->filters)
			free_mem(adapter->filters);
		cxgb_disable_msi(adapter);

		if (adapter->debugfs_root) {
			free_trace_bufs(adapter);
#ifndef	LINUX_2_4
			debugfs_remove(adapter->debugfs_root);
#endif	/* LINUX_2_4 */
		}

#if !defined(NAPI_UPDATE)
		for (i = 0; i < ARRAY_SIZE(adapter->dummy_netdev); i++)
			if (adapter->dummy_netdev[i]) {
				free_netdev(adapter->dummy_netdev[i]);
				adapter->dummy_netdev[i] = NULL;
			}
#endif
		for_each_port(adapter, i)
			if (adapter->port[i])
				free_netdev(adapter->port[i]);

		iounmap(adapter->regs);
		remove_adapter(adapter);
		del_timer(&adapter->watchdog_timer);
		kfree(adapter);
		pci_release_region(pdev, 0);
		pci_disable_device(pdev);
		pci_set_drvdata(pdev, NULL);
	}
}

/*
 * cxgb3_die_notifier_cb - Bring down the link in case of a kernel panic.
 * @nb pointer to notifier block registered by the driver.
 * @event event that caused the callback to be invoked.
 * @p pointer to event related data.
 *
 * We need to bring down the link on each port in case of a kernel panic as 
 * the chip sends out pause frames at 8MB/sec which causes some switches to
 * stop working. This was observed at a customer site (bug 6661).
 *
 * NOTE: This function has to be atomic as we are registering an atomic
 * notifier callback.
 */
static int
cxgb3_die_notifier_cb(struct notifier_block *nb, unsigned long event,
		                void *p)
{
	struct adapter *adapter;
	int i;

	if ((event == DIE_OOPS) || (event == DIE_PANIC)) {
		list_for_each_entry(adapter, &adapter_list, adapter_list) {
			for_each_port(adapter, i) {
				struct net_device *netdev = adapter->port[i];
				struct port_info *pi = netdev_priv(netdev);
				/* Disable pause frames for all T3 ports */
				t3_set_reg_field(adapter,
						A_XGM_TX_CFG + pi->mac.offset,
						F_TXPAUSEEN, 0);
			}
			t3_write_reg(adapter, A_T3DBG_GPIO_EN, 0);
		}
	}
	return NOTIFY_OK;
}

/*
 * Notifier block to notify cxgb3 driver of a kernel panic so that
 * the it can take appropriate action.
 */
static struct notifier_block die_notifier = {
	.notifier_call = cxgb3_die_notifier_cb,
	.priority = 0
};


static struct pci_driver driver = {
	.name     = DRIVER_NAME,
	.id_table = cxgb3_pci_tbl,
	.probe    = init_one,
	.remove   = __devexit_p(remove_one),
#if defined(HAS_EEH)
	.err_handler = &t3_err_handler,
#endif

};

static int __init cxgb3_init_module(void)
{
	int ret;

#ifndef	LINUX_2_4
	/* Debugfs support is optional, just warn if this fails */
	cxgb3_debugfs_root = debugfs_create_dir(DRIVER_NAME, NULL);
	if (!cxgb3_debugfs_root)
		printk(KERN_WARNING DRIVER_NAME
		       ": could not create debugfs entry, continuing\n");
#endif	/* LINUX_2_4 */

	cxgb3_offload_init();
	cxgb_proc_init();

	register_die_notifier(&die_notifier);
	ret = pci_register_driver(&driver);

#ifndef	LINUX_2_4
	if (ret < 0)
		debugfs_remove(cxgb3_debugfs_root);
#else
	if (ret > 0)
		ret = 0;
#endif	/* LINUX_2_4 */
	return ret;
}

static void __exit cxgb3_cleanup_module(void)
{
	unregister_die_notifier(&die_notifier);
	pci_unregister_driver(&driver);
	if (cxgb3_wq) {
		destroy_workqueue(cxgb3_wq);
		cxgb3_wq = NULL;
	}
#ifndef	LINUX_2_4
	debugfs_remove(cxgb3_debugfs_root);  /* NULL ok */
#endif	/* LINUX_2_4 */
	cxgb3_offload_exit();
	cxgb_proc_remove();
}

module_init(cxgb3_init_module);
module_exit(cxgb3_cleanup_module);
