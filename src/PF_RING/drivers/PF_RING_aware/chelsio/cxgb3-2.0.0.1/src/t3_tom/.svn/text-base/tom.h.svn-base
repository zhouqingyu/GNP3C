/*
 * Copyright (C) 2003-2009 Chelsio Communications.  All rights reserved.
 *
 * Written by Dimitris Michailidis (dm@chelsio.com)
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

#ifndef _CHELSIO_TOM_T3_H
#define _CHELSIO_TOM_T3_H

#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/cache.h>
#include <linux/workqueue.h>
#include <linux/skbuff.h>
#include <linux/toedev.h>
#include <asm/atomic.h>

struct sock;

enum {
	FW_VERSION_T3 = 1,
	FW_VERSION_MAJOR = 7,
	FW_VERSION_MINOR = 12,
	FW_VERSION_MICRO = 0
};

#define S_TP_VERSION_MAJOR              16
#define M_TP_VERSION_MAJOR              0xFF
#define V_TP_VERSION_MAJOR(x)           ((x) << S_TP_VERSION_MAJOR)
#define G_TP_VERSION_MAJOR(x)           \
            (((x) >> S_TP_VERSION_MAJOR) & M_TP_VERSION_MAJOR)

#define S_TP_VERSION_MINOR              8
#define M_TP_VERSION_MINOR              0xFF
#define V_TP_VERSION_MINOR(x)           ((x) << S_TP_VERSION_MINOR)
#define G_TP_VERSION_MINOR(x)           \
            (((x) >> S_TP_VERSION_MINOR) & M_TP_VERSION_MINOR)

#define S_TP_VERSION_MICRO              0
#define M_TP_VERSION_MICRO              0xFF
#define V_TP_VERSION_MICRO(x)           ((x) << S_TP_VERSION_MICRO)
#define G_TP_VERSION_MICRO(x)           \
            (((x) >> S_TP_VERSION_MICRO) & M_TP_VERSION_MICRO)

enum {
	TP_VERSION_MAJOR = 1,
	TP_VERSION_MINOR = 1,
	TP_VERSION_MICRO = 0
};

enum {
	TP_VERSION_MAJOR_T3B = 1,
	TP_VERSION_MINOR_T3B = 1,
	TP_VERSION_MICRO_T3B = 0
};

struct listen_info {
	struct listen_info *next;  /* Link to next entry */
	struct sock *sk;           /* The listening socket */
	unsigned int stid;         /* The server TID */
};

/*
 * TOM tunable parameters.  They can be manipulated through sysctl(2) or /proc.
 */
struct tom_tunables {
	int max_host_sndbuf;	// max host RAM consumed by a sndbuf
	int tx_hold_thres;	// push/pull threshold for non-full TX sk_buffs
	int max_wrs;            // max # of outstanding WRs per connection
	int rx_credit_thres;	// min # of RX credits needed for RX_DATA_ACK
	int mss;		// max TX_DATA WR payload size
	int delack;		// delayed ACK control
	int max_conn;		// maximum number of offloaded connections
	int soft_backlog_limit;	// whether the listen backlog limit is soft
	int kseg_ddp;
	int ddp;		// whether to put new connections in DDP mode
	int ddp_thres;          // min recvmsg size before activating DDP
	int ddp_copy_limit;     // capacity of kernel DDP buffer
	int ddp_push_wait;      // whether blocking DDP waits for PSH flag
	int ddp_rcvcoalesce;    // whether receive coalescing is enabled
#if defined(CONFIG_T3_ZCOPY_SENDMSG) || defined(CONFIG_T3_ZCOPY_SENDMSG_MODULE)
	int zcopy_sendmsg_partial_thres; // < is never zcopied
	int zcopy_sendmsg_partial_copy; // bytes copied in partial zcopy
	int zcopy_sendmsg_thres;// >= are mostly zcopied
	int zcopy_sendmsg_copy; // bytes coped in zcopied
	int zcopy_sendmsg_ret_pending_dma;// pot. return while pending DMA
#endif
	int activated;		// TOE engine activation state
	int cop_managed_offloading;// offloading decisions managed by a COP
};

#define FAILOVER_MAX_ATTEMPTS 5

struct tom_sysctl_table;
struct pci_dev;

#define LISTEN_INFO_HASH_SIZE 32

struct tom_data {
	struct list_head list_node;
	struct t3cdev *cdev;
	struct pci_dev *pdev;
	struct toedev tdev;

	struct cxgb3_client *client;

	struct tom_tunables conf;
	struct tom_sysctl_table *sysctl;

	/*
	 * The next three locks listen_lock, deferq.lock, and tid_release_lock
	 * are used rarely so we let them potentially share a cacheline.
	 */

	struct listen_info *listen_hash_tab[LISTEN_INFO_HASH_SIZE];
	spinlock_t listen_lock;

	struct sk_buff_head deferq;
	struct work_struct deferq_task;

	struct sock **tid_release_list;
	spinlock_t tid_release_lock;
	struct work_struct tid_release_task;

#ifdef T3_TRACE_TOM
#define T3_TRACE_TOM_BUFFERS 8
	struct dentry *debugfs_root;
	struct trace_buf *tb[T3_TRACE_TOM_BUFFERS];
#endif

#if defined(CONFIG_T3_ZCOPY_SENDMSG) || defined(CONFIG_T3_ZCOPY_SENDMSG_MODULE)
	atomic_t tx_dma_pending;
#endif

	unsigned int ddp_llimit;
	unsigned int ddp_ulimit;

	unsigned int rx_page_size;

	u8 *ppod_map;
	unsigned int nppods;
	spinlock_t ppod_map_lock;

	struct adap_ports *ports;

	/*
	 * Synchronizes access to the various SYN queues.  We assume that SYN
	 * queue accesses do not cause much contention so that one lock for all
	 * the queues suffices.  This is because the primary user of this lock
	 * is the TOE softirq, which runs on one CPU and so most accesses
	 * should be naturally contention-free.  The only contention can come
	 * from listening sockets processing backlogged messages, and that
	 * should not be high volume.
	 */
	spinlock_t synq_lock ____cacheline_aligned_in_smp;
};

struct listen_ctx {
	struct sock *lsk;
	struct tom_data *tom_data;
};

/*
 * toedev -> tom_data accessor
 */
#define TOM_DATA(dev) (*(struct tom_data **)&(dev)->l4opt)
#define T3C_DEV(sk) ((TOM_DATA(CPL_IO_STATE(sk)->toedev))->cdev)

#ifdef T3_TRACE_TOM
#include "cpl_io_state.h"
static inline struct trace_buf *TIDTB(struct sock *sk)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	struct toedev *tdev = cplios->toedev;

	if (tdev == NULL)
		return NULL;
	return TOM_DATA(tdev)->tb[cplios->tid%T3_TRACE_TOM_BUFFERS];
}
#endif

/*
 * Access a configurable parameter of a TOE device's TOM.
 */
#define TOM_TUNABLE(dev, param) (TOM_DATA(dev)->conf.param)

void t3_init_tunables(struct tom_data *t);
void t3_sysctl_unregister(struct tom_sysctl_table *t);
struct tom_sysctl_table *t3_sysctl_register(struct toedev *dev,
					    const struct tom_tunables *p);
#endif
