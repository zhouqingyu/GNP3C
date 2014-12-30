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

#ifndef _CHELSIO_TOM_DEFS_H
#define _CHELSIO_TOM_DEFS_H

#include <linux/skbuff.h>
#include <net/tcp.h>
#include <net/offload.h>

/* CPL message correctness validation switches */
#define VALIDATE_TID 1
#define VALIDATE_LEN 1
#define VALIDATE_SEQ 1

#define SCHED_CLS_NONE 0xff

struct proc_dir_entry;
struct toedev;
struct tom_data;

#include "tom_compat.h"

/*
 * Opaque version of structure the SGE stores at skb->head of TX_DATA packets
 * and for which we must reserve space.
 */
struct sge_opaque_hdr {
	void *dev;
	dma_addr_t addr[MAX_SKB_FRAGS + 1];
};

/*
 * Allocate an sk_buff when allocation failure is not an option.
 */
static inline struct sk_buff *alloc_skb_nofail(unsigned int len)
{
	return alloc_skb(len, GFP_KERNEL | __GFP_NOFAIL);
}

/*
 * Returns true if the socket is in one of the supplied states.
 */
static inline unsigned int sk_in_state(const struct sock *sk,
				       unsigned int states)
{
	return states & (1 << sk->sk_state);
}

/*
 * Release a socket's local TCP port if the socket is bound.  This is normally
 * done by tcp_done() but because we need to wait for HW to release TIDs we
 * usually call tcp_done at a later time than the SW stack would have.  This
 * can be used to release the port earlier so the SW stack can reuse it before
 * we are done with the connection.
 */
static inline void release_tcp_port(struct sock *sk)
{
#ifdef	LINUX_2_4
	if (sk->prev)
#else
	if (inet_csk(sk)->icsk_bind_hash)
#endif	/* LINUX_2_4 */
		t3_inet_put_port(&tcp_hashinfo, sk);
}


/*
 * Max receive window supported by HW in bytes.  Only a small part of it can
 * be set through option0, the rest needs to be set through RX_DATA_ACK.
 */
#define MAX_RCV_WND ((1U << 27) - 1)

#include "cxgb3_offload.h"

/* for TX: a skb must have a headroom of at least TX_HEADER_LEN bytes */
#define TX_HEADER_LEN \
		(sizeof(struct tx_data_wr) + sizeof(struct sge_opaque_hdr))

/*
 * Determine the value of a packet's ->priority field.  Bit 0 determines
 * whether the packet should use a control Tx queue, bits 1..3 determine
 * the queue set to use.
 */
static inline unsigned int mkprio(unsigned int cntrl, const struct sock *sk)
{
	return cntrl;
}

void t3tom_register_cpl_handler(unsigned int opcode, cxgb3_cpl_handler_func h);
void t3_listen_start(struct toedev *dev, struct sock *sk,
		     const struct offload_req *r);
void t3_listen_stop(struct toedev *dev, struct sock *sk, struct t3cdev *cdev);
int t3_push_frames(struct sock *sk, int);
int t3_sendskb(struct sock *sk, struct sk_buff *skb, int flags);
void t3_purge_write_queue(struct sock *sk);
void t3_set_tcb_field(struct sock *sk, u16 word, u64 mask, u64 val);
void t3_set_nagle(struct sock *sk);
void t3_set_tos(struct sock *sk);
void t3_set_keepalive(struct sock *sk, int on_off);
void t3_enable_ddp(struct sock *sk, int on);
void t3_set_ddp_tag(struct sock *sk, int buf_idx, unsigned int tag);
void t3_set_ddp_buf(struct sock *sk, int buf_idx, unsigned int offset,
		    unsigned int len);
void t3_write_space(struct sock *sk);
void t3_cleanup_rbuf(struct sock *sk, int copied, int request);
int t3_get_tcb(struct sock *sk);
int t3_send_reset(struct sock *sk, int mode, struct sk_buff *skb);
int t3_connect(struct toedev *dev, struct sock *sk, struct net_device *edev);
void t3_disconnect_acceptq(struct sock *sk);
void t3_reset_synq(struct sock *sk);
u32 t3_send_rx_credits(struct sock *sk, u32 credits, u32 dack, int nofail);
void t3_send_rx_modulate(struct sock *sk);
int t3_set_cong_control(struct sock *sk, const char *name);
int t3_listen_proc_setup(struct proc_dir_entry *dir, struct tom_data *d);
void t3_listen_proc_free(struct proc_dir_entry *dir);
void t3_set_rcv_coalesce_enable(struct sock *sk, int on);
void t3_set_dack(struct sock *sk, int on);
void t3_set_dack_mss(struct sock *sk, int on);
void failover_check(void *data);
unsigned int t3_select_delack(struct sock *sk);
void t3_select_window(struct sock *sk, int request);

#if defined(CONFIG_T3_ZCOPY_SENDMSG) || defined(CONFIG_T3_ZCOPY_SENDMSG_MODULE)
void t3_zcopy_cleanup_skb(struct sk_buff *);
#endif

#if defined(BOND_SUPPORT)
int t3_failover(struct toedev *tdev, struct net_device *bond_dev,
		 struct net_device *slave_dev, int event, struct net_device *last);
void t3_update_master_devs(struct toedev *tdev);
#else
static inline int t3_failover(struct toedev *tdev, struct net_device *bond_dev,
			       struct net_device *slave_dev, int event, struct net_device *last)
{ return 0; }

static inline void t3_update_master_devs(struct toedev *tdev) {}
#endif

// initialization
void t3_init_offload_ops(void);
void t3_init_listen_cpl_handlers(void);
void t3_init_wr_tab(unsigned int wr_len);
int t3_init_cpl_io(void);
#endif
