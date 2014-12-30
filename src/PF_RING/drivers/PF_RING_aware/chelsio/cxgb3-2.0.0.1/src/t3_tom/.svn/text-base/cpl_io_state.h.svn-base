/*
 * This file contains declarations for the Chelsio CPL5 message processing.
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

#ifndef _CHELSIO_CPL_IO_STATE_H
#define _CHELSIO_CPL_IO_STATE_H

#include "t3_ddp_state.h"
#include "l2t.h"

/*
 * A map of the world.
 * -------------------
 */

/*
 *    ---           +----------------+
 *     |            |      sock      |
 *     |     Linux  | -------------- |
 *     |            |    tcp_sock    |
 *     |            +----------------+
 *     |                    | sk_protinfo
 * Connection               V
 *     |            +----------------+
 *     |            |                |
 *     |    t3_tom  |  cpl_io_state  |
 *     |            |                |
 *    ---           +----------------+
 *                          | toedev
 *                          V
 *    ---           +----------------+    lldev     +----------------+
 *     |            |                |------------->|                |
 *     |   toecore  |     toedev     |    ec_ptr    |   net_device   |  Linux
 *     |            |                |<-------------|                |
 *     |            |                |<---,         | -------------- |
 *     |            +----------------+    |         | priv:port_info |  cxgb3
 *   Device                 | l4opt       |         +----------------+
 *     |                    V             | tdev
 *     |            +----------------+    |
 *     |            |                |    |
 *     |    t3_tom  |    tom_data    |----'
 *     |            |                |
 *    ---           +----------------+
 *                          | cdev
 *                          V
 *    ---           +----------------+              +----------------+
 *     |            |     t3cdev     |    l4opt     |                |
 *  Adapter  cxgb3  | -------------- |------------->|    t3c_data    |  cxgb3
 *     |            |    adapter     |              |                |
 *    ---           +----------------+              +----------------+
 *
 * The net_device private area contains the "port_info" data structure which
 * contains a pointer to the t3cdev/adapter data structure (t3cdev starts at
 * the beginning of the adapter structure) and the adapter structure contains
 * pointers to its net_device's in "port[i]".  These linkages have been
 * ommitted in the above diagram in the interest of not creating a completely
 * messy picture ...
 */


/*
 * Per-connection state.
 * ---------------------
 */

/*
 * This structure records all "non-standard" per-connection state for
 * offloaded TCP connections.  For "standard" state like packet/byte count
 * statistics and other data elements which are tracked by the Linux kernel
 * for software socket/TCP connections, we use the existing Linux data
 * structure fields.  This allows standard tools like netstat, etc. to work
 * well with offloaded connections and report reasonable results.
 */
struct cpl_io_state {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
	unsigned long sk_flags;		/* Linux 2.4 didn't have sk_flags */
#endif
	unsigned long flags;		/* offload connection flags */

	unsigned int wr_max;		/* max number of WRs */
	unsigned int wr_avail;		/* number of available WRs credits */
	unsigned int wr_unacked;	/* number of unacked WRs */

	unsigned int delack_mode;	/* current delack mode */
	unsigned int delack_seq;	/* RX sequence of most recent delack */
					/*   mode change */
	unsigned int hw_rcv_nxt;	/* rcv_nxt from a GET_TCB_RPL */

	unsigned int mtu_idx;		/* MTU table index */
	unsigned int qset_idx;		/* HW queue-set associated with the */
					/*   connection */
	unsigned int rss_cpu_idx;	/* TOE RSS CPU index */
	unsigned int tid;		/* TCP Control Block ID */
	unsigned int sched_cls;		/* scheduling class */
	unsigned int ulp_mode;		/* ULP mode */

	struct toedev *toedev;		/* TOE device */
	struct l2t_entry *l2t_entry;	/* pointer to the L2T entry */

	/*
	 * Singly-linked list of skb write requests (WRs) hung off a
	 * connection.  Skbs are linked via (struct wr_skb_cb *)->wr_next.
	 */
	struct sk_buff *wr_skb_head;	/* head of WR queue */
	struct sk_buff *wr_skb_tail;	/* tail of WR queue */

	struct sk_buff *skb_cache;	/* cached sk_buff for small control */
					/*   messages */
	struct sk_buff *skb_ulp_lhdr;	/* ulp iscsi with msg coalescing */
					/*   off: last cpl_iscsi_hdr (pdu */
					/*   header) rcv'ed */

	struct toedev *migration_toedev;/* pointer to toedev for connection */
					/*   migration */
	unsigned int migration_tid;	/* TID of a migrating socket */
	unsigned int migration_held_fin;/* held_fin in the migrating */
					/*   connection was set in the TCB */

	struct ddp_state ddp_state;	/* DDP state data */
};

#define CPL_IO_STATE(sk)	(*(struct cpl_io_state **)&((sk)->sk_protinfo))
#define DDP_STATE(sk)		(&(CPL_IO_STATE(sk)->ddp_state))

/*
 * Offloaded connection state flags.
 */
enum cplios_flags {
	CPLIOS_CALLBACKS_CHKD,		/* socket callbacks have been sanitized */
	CPLIOS_ABORT_RPL_RCVD,		/* received one ABORT_RPL_RSS message */
	CPLIOS_ABORT_REQ_RCVD,		/* received one ABORT_REQ_RSS message */
	CPLIOS_TX_MORE_DATA,		/* still sending ULP data; don't set the SHOVE bit */
	CPLIOS_TX_WAIT_IDLE,		/* suspend Tx until in-flight data is ACKed */
	CPLIOS_ABORT_SHUTDOWN,		/* shouldn't send more abort requests */
	CPLIOS_ABORT_RPL_PENDING,	/* expecting an abort reply */
	CPLIOS_ABORT_RPL_SENT,		/* we've sent an abort reply */
	CPLIOS_CLOSE_CON_REQUESTED,	/* we've sent a close_conn_req */
	CPLIOS_TX_DATA_SENT,		/* already sent a TX_DATA WR on this connection */
	CPLIOS_TX_FAILOVER,		/* Tx traffic failing over */
	CPLIOS_UPDATE_RCV_WND		/* Need to update rcv window */
};

static inline void cplios_set_flag(struct sock *sk, enum cplios_flags flag)
{
	__set_bit(flag, &CPL_IO_STATE(sk)->flags);
}

static inline void cplios_reset_flag(struct sock *sk, enum cplios_flags flag)
{
	__clear_bit(flag, &CPL_IO_STATE(sk)->flags);
}

static inline int cplios_flag(struct sock *sk, enum cplios_flags flag)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);

	if (cplios == NULL)
		return 0;
	return test_bit(flag, &CPL_IO_STATE(sk)->flags);
}


/*
 * List of write requests hung off of connection.
 * ----------------------------------------------
 */

/*
 * This lives in skb->cb and is used to chain WRs in a linked list.
 */
struct wr_skb_cb {
	struct l2t_skb_cb l2t;		/* reserve space for l2t CB */
	struct sk_buff *next_wr;	/* next write request */
};

#define WR_SKB_CB(skb) ((struct wr_skb_cb *)(skb)->cb)

static inline void reset_wr_list(struct sock *sk)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	cplios->wr_skb_head = cplios->wr_skb_tail = NULL;
}

/*
 * Add a WR to a socket's list of pending WRs.
 */
static inline void enqueue_wr(struct sock *sk, struct sk_buff *skb)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);

	/*
 	 * We want to take an extra reference since both us and the driver
 	 * need to free the packet before it's really freed.  We know there's
 	 * just one user currently so we use atomic_set rather than skb_get
 	 * to avoid the atomic op.
 	 */
	atomic_set(&skb->users, 2);

	WR_SKB_CB(skb)->next_wr = NULL;
	if (cplios->wr_skb_head == NULL)
		cplios->wr_skb_head = skb;
	else
		WR_SKB_CB(cplios->wr_skb_tail)->next_wr = skb;
	cplios->wr_skb_tail = skb;
}

/*
 * Return the first pending WR without removing it from the list.
 */
static inline struct sk_buff *peek_wr(const struct sock *sk)
{
	return CPL_IO_STATE(sk)->wr_skb_head;
}

/*
 * Dequeue and return the first unacknowledged's WR on a socket's pending list.
 */
static inline struct sk_buff *dequeue_wr(struct sock *sk)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	struct sk_buff *skb = cplios->wr_skb_head;

	if (likely(skb)) {
		/* Don't bother clearing the tail */
		cplios->wr_skb_head = WR_SKB_CB(skb)->next_wr;
		WR_SKB_CB(skb)->next_wr = NULL;
	}
	return skb;
}

#define wr_queue_walk(sk, skb) \
        for (skb = peek_wr(sk); skb; skb = WR_SKB_CB(skb)->next_wr)


/*
 * Upper Layer Protocol skb handling.
 * ----------------------------------
 */

/*
 * Similar to tcp_skb_cb but with ULP elements added to support DDP, iSCSI,
 * etc.
 */
struct ulp_skb_cb {
	struct wr_skb_cb wr;		/* reserve space for write request */
	u8 flags;			/* TCP-like flags */
	u8 ulp_mode;			/* ULP mode/submode of sk_buff */
	u32 seq;			/* TCP sequence number */
	union { /* ULP-specific fields */
		struct {
			u32 ddigest;	/* ULP rx_data_ddp selected field */
			u32 pdulen;	/* ULP rx_data_ddp selected field */
		} iscsi;
		struct {
			u32 offset;	/* ULP DDP offset notification */
			u8 flags;	/* ULP DDP flags ... */
		} ddp;
	} ulp;
	u8 ulp_data[16];		/* scratch area for ULP */
};

#define ULP_SKB_CB(skb) ((struct ulp_skb_cb *)&((skb)->cb[0]))

/*
 * Flags for ulp_skb_cb.flags.
 */
enum {
	ULPCB_FLAG_NEED_HDR  = 1 << 0,	/* packet needs a TX_DATA_WR header */
	ULPCB_FLAG_NO_APPEND = 1 << 1,	/* don't grow this skb */
	ULPCB_FLAG_BARRIER   = 1 << 2,	/* set TX_WAIT_IDLE after sending */
	ULPCB_FLAG_HOLD      = 1 << 3,	/* skb not ready for Tx yet */
	ULPCB_FLAG_COMPL     = 1 << 4,	/* request WR completion */
	ULPCB_FLAG_URG       = 1 << 5,	/* urgent data */
#if defined(CONFIG_T3_ZCOPY_SENDMSG) || defined(CONFIG_T3_ZCOPY_SENDMSG_MODULE)
	ULPCB_FLAG_ZCOPY     = 1 << 6,	/* direct reference to user pages */
	ULPCB_FLAG_ZCOPY_COW = 1 << 7,	/* copy on write for deferred writes */
#endif
};

/* The ULP mode/submode of an skbuff */
#define skb_ulp_mode(skb)  (ULP_SKB_CB(skb)->ulp_mode)

/* ULP: iSCSI rx_data_ddp selected field */
#define skb_ulp_iscsi_ddigest(skb)	(ULP_SKB_CB(skb)->ulp.iscsi.ddigest)
#define skb_ulp_iscsi_pdulen(skb)	(ULP_SKB_CB(skb)->ulp.iscsi.pdulen)

/* XXX temporary compatibility for old code-base chisci */
#define skb_ulp_lhdr(sk)		(CPL_IO_STATE(sk)->skb_ulp_lhdr)
#define skb_ulp_ddigest(skb)		skb_ulp_iscsi_ddigest(skb)
#define skb_ulp_pdulen(skb)		skb_ulp_iscsi_pdulen(skb)

/* ULP: DDP */
#define skb_ulp_ddp_offset(skb)		(ULP_SKB_CB(skb)->ulp.ddp.offset)
#define skb_ulp_ddp_flags(skb)		(ULP_SKB_CB(skb)->ulp.ddp.flags)

/*
 * Set the ULP mode and submode for a Tx packet.
 */
static inline void skb_set_ulp_mode(struct sk_buff *skb, int mode, int submode)
{
	skb_ulp_mode(skb) = (mode << 4) | submode;
}

/*
 * Return the length of any HW additions that will be made to a Tx packet.
 * Such additions can happen for some types of ULP packets.
 */
static inline unsigned int ulp_extra_len(const struct sk_buff *skb)
{
	extern const unsigned int t3_ulp_extra_len[];
	return t3_ulp_extra_len[skb_ulp_mode(skb) & 3];
}


/*
 * Deferred skb processing.
 * ------------------------
 */

typedef void (*defer_handler_t)(struct toedev *dev, struct sk_buff *skb);

/*
 * Stores information used to send deferred CPL replies from process context.
 */
struct deferred_skb_cb {
	defer_handler_t handler;
	struct toedev *dev;
};

#define DEFERRED_SKB_CB(skb) ((struct deferred_skb_cb *)(skb)->cb)

void t3_defer_reply(struct sk_buff *skb, struct toedev *dev,
		    defer_handler_t handler);


/*
 * Backlog skb handling.
 * ---------------------
 */

/*
 * The definition of the backlog skb control buffer is provided by the
 * general TOE infrastructure.
 */
#include <net/offload.h>

/*
 * Top-level CPL message processing used by most CPL messages that
 * pertain to connections.
 */
static inline void process_cpl_msg(void (*fn)(struct sock *, struct sk_buff *),
				   struct sock *sk, struct sk_buff *skb)
{
	bh_lock_sock(sk);
	if (unlikely(sock_owned_by_user(sk))) {
		BLOG_SKB_CB(skb)->backlog_rcv = fn;
		__sk_add_backlog(sk, skb);
	} else
		fn(sk, skb);
	bh_unlock_sock(sk);
}

#endif /* _CHELSIO_CPL_IO_STATE_H */
