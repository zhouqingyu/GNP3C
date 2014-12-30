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

/* This file should not be included directly.  Include common.h instead. */

#ifndef __T3_ADAPTER_H__
#define __T3_ADAPTER_H__

#include <linux/pci.h>
#include <linux/spinlock.h>
#include <linux/interrupt.h>
#include <linux/timer.h>
#include <linux/cache.h>
#include "t3cdev.h"
#include <asm/bitops.h>
#include <asm/io.h>

#ifdef T3_TRACE
# include "trace.h"
#endif

struct vlan_group;

enum {
	LF_NO = 0,
	LF_MAYBE,
	LF_YES
};

enum {
	LOOPBACK_NONE		= 0,
	LOOPBACK_PHY_PMA_PMD	= 1,
	LOOPBACK_PHY_WIS	= 2,
	LOOPBACK_PHY_PCS	= 3,
	LOOPBACK_PHY_XS		= 4,
	LOOPBACK_XGMAC		= 5,
};

struct port_info {
	struct adapter *adapter;
	struct vlan_group *vlan_grp;
	struct sge_qset *qs;
	u8 port_id;
	u8 tx_chan;
	u8 txpkt_intf;
	u8 rx_csum_offload;
	u8 nqsets;
	u8 first_qset;
	struct cphy phy;
	struct cmac mac;
	struct link_config link_config;
	struct net_device_stats netstats;
	int activity;
	__be32 iscsi_ipv4addr;
	int max_ofld_bw;
	int link_fault;
	u8 sched_max;
	u8 sched_min;
	int loopback;
};

struct work_struct;
struct dentry;

enum {                                 /* adapter flags */
	FULL_INIT_DONE     = (1 << 0),
	USING_MSI          = (1 << 1),
	USING_MSIX         = (1 << 2),
	QUEUES_BOUND       = (1 << 3),
	TP_PARITY_INIT     = (1 << 4),
	NAPI_INIT	   = (1 << 5),
};

enum {					/* rspq flags */
	USING_POLLING      = (1 << 0),
	RSPQ_STARVING	   = (1 << 1),
};

struct fl_pg_chunk {
	struct page *page;
	void *va;
	unsigned int offset;
	unsigned long *p_cnt;
	dma_addr_t mapping;
};

struct rx_desc;
struct rx_sw_desc;

struct sge_fl {                     /* SGE per free-buffer list state */
	unsigned int buf_size;      /* size of each Rx buffer */
	unsigned int credits;       /* # of available Rx buffers */
	unsigned int pend_cred;     /* new buffers since last FL DB ring */
	unsigned int size;          /* capacity of free list */
	unsigned int cidx;          /* consumer index */
	unsigned int pidx;          /* producer index */
	unsigned int gen;           /* free list generation */
	struct fl_pg_chunk pg_chunk;/* page chunk cache */
	unsigned int use_pages;     /* whether FL uses pages or sk_buffs */
	unsigned int order;         /* order of page allocations */
	unsigned int alloc_size;    /* size of allocated buffer */
	struct rx_desc *desc;       /* address of HW Rx descriptor ring */
	struct rx_sw_desc *sdesc;   /* address of SW Rx descriptor ring */
	dma_addr_t   phys_addr;     /* physical address of HW ring start */
	unsigned int cntxt_id;      /* SGE context id for the free list */
	unsigned long empty;        /* # of times queue ran out of buffers */
	unsigned long alloc_failed; /* # of times buffer allocation failed */
};

/* max concurrent LRO sessions per queue set */
#define MAX_LRO_SES 8

struct lro_session {
	struct sk_buff *head;
	struct sk_buff *tail;
	u32 seq;
	u16 iplen;
	u16 mss;
	__be16 vlan;
	u8  npkts;
};

struct lro_state {
	unsigned short enabled;
	unsigned short active_idx;  /* index of most recently added session */
	unsigned int nactive;       /* # of active sessions */
	struct lro_session sess[MAX_LRO_SES];
};

/*
 * Bundle size for grouping offload RX packets for delivery to the stack.
 * Don't make this too big as we do prefetch on each packet in a bundle.
 */
# define RX_BUNDLE_SIZE 8

struct rsp_desc;

struct sge_rspq {                   /* state for an SGE response queue */
	unsigned int credits;       /* # of pending response credits */
	unsigned int size;          /* capacity of response queue */
	unsigned int cidx;          /* consumer index */
	unsigned int gen;           /* current generation bit */
	unsigned long flags;       /* is the queue serviced through NAPI? */
	unsigned int holdoff_tmr;   /* interrupt holdoff timer in 100ns */
	unsigned int next_holdoff;  /* holdoff time for next interrupt */
	unsigned int rx_recycle_buf; /* whether recycling occurred within current sop-eop */
	struct rsp_desc *desc;      /* address of HW response ring */
	dma_addr_t   phys_addr;     /* physical address of the ring */
	unsigned int cntxt_id;      /* SGE context id for the response q */
	spinlock_t   lock;          /* guards response processing */
	struct sk_buff *rx_head;    /* offload packet receive queue head */
	struct sk_buff *rx_tail;    /* offload packet receive queue tail */
	struct sk_buff *pg_skb;     /* skb for building frag list in napi response handler */
	unsigned long offload_pkts;
	unsigned long offload_bundles;
	unsigned long eth_pkts;     /* # of ethernet packets */
	unsigned long pure_rsps;    /* # of pure (non-data) responses */
	unsigned long imm_data;     /* responses with immediate data */
	unsigned long rx_drops;     /* # of packets dropped due to no mem */
	unsigned long async_notif;  /* # of asynchronous notification events */
	unsigned long empty;        /* # of times queue ran out of credits */
	unsigned long nomem;        /* # of responses deferred due to no mem */
	unsigned long unhandled_irqs; /* # of spurious intrs */
	unsigned long starved;
	unsigned long restarted;
};

struct tx_desc;
struct tx_sw_desc;
struct eth_coalesce_sw_desc;

struct sge_txq {                    /* state for an SGE Tx queue */
	unsigned long flags;        /* HW DMA fetch status */
	unsigned int  in_use;       /* # of in-use Tx descriptors */
	unsigned int  size;         /* # of descriptors */
	unsigned int  processed;    /* total # of descs HW has processed */
	unsigned int  cleaned;      /* total # of descs SW has reclaimed */
	unsigned int  stop_thres;   /* SW TX queue suspend threshold */
	unsigned int  cidx;         /* consumer index */
	unsigned int  pidx;         /* producer index */
	unsigned int  gen;          /* current value of generation bit */
	unsigned int  unacked;      /* Tx descriptors used since last COMPL */
	struct tx_desc *desc;       /* address of HW Tx descriptor ring */
	struct tx_sw_desc *sdesc;   /* address of SW Tx descriptor ring */
	unsigned int eth_coalesce_idx;  /* idx of the next coalesce pkt */
	unsigned int eth_coalesce_bytes; /* total lentgh of coalesced pkts */
	struct eth_coalesce_sw_desc *eth_coalesce_sdesc;
	spinlock_t    lock;         /* guards enqueueing of new packets */
	unsigned int  token;        /* WR token */
	dma_addr_t    phys_addr;    /* physical address of the ring */
	struct sk_buff_head sendq;  /* List of backpressured offload packets */
	struct tasklet_struct qresume_tsk; /* restarts the queue */
	unsigned int  cntxt_id;     /* SGE context id for the Tx q */
	unsigned long stops;        /* # of times q has been stopped */
	unsigned long restarts;     /* # of queue restarts */
	unsigned long tx_pkts;      /* # of transmitted pkts */
	unsigned int sched_max;
};

enum {                              /* per port SGE statistics */
	SGE_PSTAT_TSO,              /* # of TSO requests */
	SGE_PSTAT_RX_CSUM_GOOD,     /* # of successful RX csum offloads */
	SGE_PSTAT_TX_CSUM,          /* # of TX checksum offloads */
	SGE_PSTAT_VLANEX,           /* # of VLAN tag extractions */
	SGE_PSTAT_VLANINS,          /* # of VLAN tag insertions */
	SGE_PSTAT_TX_COALESCE_WR,   /* # of TX Coalesce Work Requests */
	SGE_PSTAT_TX_COALESCE_PKT,  /* # of TX Coalesced packets */
	SGE_PSTAT_LRO,              /* # of completed LRO packets */
	SGE_PSTAT_LRO_SKB,          /* # of sk_buffs added to LRO sessions */
	SGE_PSTAT_LRO_PG,           /* # of page chunks added to LRO sessions */
	SGE_PSTAT_LRO_ACK,          /* # of pure ACKs fully merged by LRO */
	SGE_PSTAT_LRO_OVFLOW,       /* # of LRO session overflows */
	SGE_PSTAT_LRO_COLSN,        /* # of LRO hash collisions */

	SGE_PSTAT_MAX               /* must be last */
};

struct sge_qset {                   /* an SGE queue set */
	struct adapter *adap;
#if defined(NAPI_UPDATE)
	struct napi_struct napi;
#endif
	struct sge_rspq rspq;
	struct sge_fl   fl[SGE_RXQ_PER_SET];
	struct lro_state lro;
	struct sge_txq  txq[SGE_TXQ_PER_SET];
	struct net_device *netdev;            /* associated net device */
	struct netdev_queue *tx_q;            /* associated netdev TX queue */
	unsigned long txq_stopped;            /* which Tx queues are stopped */
	struct timer_list tx_reclaim_timer;   /* reclaims TX buffers */
	struct timer_list rx_reclaim_timer;
	unsigned long port_stats[SGE_PSTAT_MAX];
} ____cacheline_aligned;

struct sge {
	struct sge_qset qs[SGE_QSETS];
	unsigned int nqsets; /* # of active queue sets */
	spinlock_t reg_lock; /* guards non-atomic SGE registers (eg context) */
};

struct filter_info;

struct adapter {
	struct t3cdev tdev;
	struct list_head adapter_list;
	void __iomem *regs;
	struct pci_dev *pdev;
	unsigned long registered_device_map;
	unsigned long open_device_map;
	unsigned long flags;

	const char *name;
	int msg_enable;
	unsigned int mmio_len;

	struct timer_list watchdog_timer;
	struct adapter_params params;
	unsigned int slow_intr_mask;
	unsigned long irq_stats[IRQ_NUM_STATS];

	int msix_nvectors;
	struct {
		unsigned short vec;
		char desc[22];
	} msix_info[SGE_QSETS + 1];

#ifdef T3_TRACE
	struct trace_buf *tb[SGE_QSETS];
#endif

	/* T3 modules */
	struct sge sge;
	struct mc7 pmrx;
	struct mc7 pmtx;
	struct mc7 cm;
	struct mc5 mc5;

	struct net_device *port[MAX_NPORTS];
	u8 rxpkt_map[8];        /* maps RX_PKT interface values to port ids */
	u8 rrss_map[SGE_QSETS]; /* reverse RSS map table */

	atomic_t filter_toe_mode;	/* filter / TOE exclusion switch */
	struct filter_info *filters;	/* software copy of hardware filters */

	unsigned int check_task_cnt;
	struct delayed_work adap_check_task;
	struct work_struct ext_intr_handler_task;
	struct work_struct fatal_error_handler_task;
	struct work_struct link_fault_handler_task;

	struct work_struct db_full_task;
	struct work_struct db_empty_task;
	struct work_struct db_drop_task;

#if !defined(NAPI_UPDATE)
	/*
	 * Dummy netdevices are needed when using multiple receive queues with
	 * NAPI as each netdevice can service only one queue.
	 */
	struct net_device *dummy_netdev[SGE_QSETS - 1];
#endif
	u32 t3_config_space[16]; /* For old kernels only */

	struct dentry *debugfs_root;

	spinlock_t mdio_lock;
	spinlock_t elmer_lock;
	spinlock_t stats_lock;
	spinlock_t work_lock;
};

/* values for filter_toe_mode interlock */
enum {
	CXGB3_FTM_NONE		= 0,	/* no filters or TOE activated */
	CXGB3_FTM_FILTER	= 1,	/* filters used */
	CXGB3_FTM_TOE		= 2,	/* TOE activated */
};

int cxgb3_filter_toe_mode(struct adapter *, int);

#include "cxgb3_compat.h"

#define MDIO_LOCK(adapter) spin_lock(&(adapter)->mdio_lock)
#define MDIO_UNLOCK(adapter) spin_unlock(&(adapter)->mdio_lock)

#define ELMR_LOCK(adapter) spin_lock(&(adapter)->elmer_lock)
#define ELMR_UNLOCK(adapter) spin_unlock(&(adapter)->elmer_lock)

/**
 * t3_read_reg - read a HW register
 * @adapter: the adapter
 * @reg_addr: the register address
 *
 * Returns the 32-bit value of the given HW register.
 */
static inline u32 t3_read_reg(adapter_t *adapter, u32 reg_addr)
{
	u32 val = readl(adapter->regs + reg_addr);

	CH_DBG(adapter, MMIO, "read register 0x%x value 0x%x\n", reg_addr,
	       val);
	return val;
}

/**
 * t3_write_reg - write a HW register
 * @adapter: the adapter
 * @reg_addr: the register address
 * @val: the value to write
 *
 * Write a 32-bit value into the given HW register.
 */
static inline void t3_write_reg(adapter_t *adapter, u32 reg_addr, u32 val)
{
	CH_DBG(adapter, MMIO, "setting register 0x%x to 0x%x\n", reg_addr,
	       val);
	writel(val, adapter->regs + reg_addr);
}

/**
 * t3_os_pci_write_config_4 - 32-bit write to PCI config space
 * @adapter: the adapter
 * @reg: the register address
 * @val: the value to write
 *
 * Write a 32-bit value into the given register in PCI config space.
 */
static inline void t3_os_pci_write_config_4(adapter_t *adapter, int reg,
					    u32 val)
{
	pci_write_config_dword(adapter->pdev, reg, val);
}

/**
 * t3_os_pci_read_config_4 - read a 32-bit value from PCI config space
 * @adapter: the adapter
 * @reg: the register address
 * @val: where to store the value read
 *
 * Read a 32-bit value from the given register in PCI config space.
 */
static inline void t3_os_pci_read_config_4(adapter_t *adapter, int reg,
					   u32 *val)
{
	pci_read_config_dword(adapter->pdev, reg, val);
}

/**
 * t3_os_pci_write_config_2 - 16-bit write to PCI config space
 * @adapter: the adapter
 * @reg: the register address
 * @val: the value to write
 *
 * Write a 16-bit value into the given register in PCI config space.
 */
static inline void t3_os_pci_write_config_2(adapter_t *adapter, int reg,
					    u16 val)
{
	pci_write_config_word(adapter->pdev, reg, val);
}

/**
 * t3_os_pci_read_config_2 - read a 16-bit value from PCI config space
 * @adapter: the adapter
 * @reg: the register address
 * @val: where to store the value read
 *
 * Read a 16-bit value from the given register in PCI config space.
 */
static inline void t3_os_pci_read_config_2(adapter_t *adapter, int reg,
					   u16 *val)
{
	pci_read_config_word(adapter->pdev, reg, val);
}

/**
 * t3_os_find_pci_capability - lookup a capability in the PCI capability list
 * @adapter: the adapter
 * @cap: the capability
 *
 * Return the address of the given capability within the PCI capability list.
 */
static inline int t3_os_find_pci_capability(adapter_t *adapter, int cap)
{
	return pci_find_capability(adapter->pdev, cap);
}

/**
 * port_name - return the string name of a port
 * @adapter: the adapter
 * @port_idx: the port index
 *
 * Return the string name of the selected port.
 */
static inline const char *port_name(adapter_t *adapter, unsigned int port_idx)
{
	return adapter->port[port_idx]->name;
}

/**
 * t3_os_set_hw_addr - store a port's MAC address in SW
 * @adapter: the adapter
 * @port_idx: the port index
 * @hw_addr: the Ethernet address
 *
 * Store the Ethernet address of the given port in SW.  Called by the common
 * code when it retrieves a port's Ethernet address from EEPROM.
 */
static inline void t3_os_set_hw_addr(adapter_t *adapter, int port_idx,
				     u8 hw_addr[])
{
	memcpy(adapter->port[port_idx]->dev_addr, hw_addr, ETH_ALEN);
#ifdef ETHTOOL_GPERMADDR
	memcpy(adapter->port[port_idx]->perm_addr, hw_addr, ETH_ALEN);
#endif
}

/**
 * adap2pinfo - return the port_info of a port
 * @adap: the adapter
 * @idx: the port index
 *
 * Return the port_info structure for the port of the given index.
 */
static inline struct port_info *adap2pinfo(struct adapter *adap, int idx)
{
	return netdev_priv(adap->port[idx]);
}

#define OFFLOAD_DEVMAP_BIT 15

#define tdev2adap(d) container_of(d, struct adapter, tdev)

static inline int offload_running(adapter_t *adapter)
{
	return test_bit(OFFLOAD_DEVMAP_BIT, &adapter->open_device_map);
}

int t3_offload_tx(struct t3cdev *tdev, struct sk_buff *skb);

void t3_os_ext_intr_handler(adapter_t *adapter);
void t3_os_link_changed(adapter_t *adapter, int port_id, int link_status,
			int speed, int duplex, int fc, int mac_was_reset);
void t3_os_phymod_changed(struct adapter *adap, int port_id);
void t3_os_link_fault_handler(adapter_t *adapter, int port_id);

void t3_sge_start(adapter_t *adap);
void t3_sge_stop(adapter_t *adap);
void t3_start_sge_timers(struct adapter *adap);
void t3_stop_sge_timers(struct adapter *adap);
void t3_free_sge_resources(adapter_t *adap);
void t3_sge_err_intr_handler(adapter_t *adapter);
int t3_eth_xmit(struct sk_buff *skb, struct net_device *dev);
int t3_mgmt_tx(adapter_t *adap, struct sk_buff *skb);
void t3_update_qset_coalesce(struct sge_qset *qs, const struct qset_params *p);
int t3_sge_alloc_qset(adapter_t *adapter, unsigned int id, int nports,
	       	      int irq_vec_idx, const struct qset_params *p,
		      int ntxq, struct net_device *netdev,
		      struct netdev_queue *netdevq);
int t3_get_desc(const struct sge_qset *qs, unsigned int qnum, unsigned int idx,
		unsigned char *data);
int t3_get_edc_fw(struct cphy *phy, int edc_idx);
extern struct workqueue_struct *cxgb3_wq;

#endif /* __T3_ADAPTER_H__ */
