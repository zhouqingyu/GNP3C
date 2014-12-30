/*
 * This file implements the Chelsio CPL5 message processing.
 *
 * Copyright (C) 2003-2010 Chelsio Communications.  All rights reserved.
 *
 * Written by Dimitris Michailidis (dm@chelsio.com)
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

#include "defs.h"
#include <linux/module.h>
#include <linux/vmalloc.h>
#include <linux/ip.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/toedev.h>
#include <linux/if_vlan.h>
#include <net/tcp.h>
#include <net/offload.h>
#include <net/route.h>
#include <asm/atomic.h>
#include "tom.h"
#include "cpl_io_state.h"
#include "t3_ddp.h"
#include "t3cdev.h"
#include "l2t.h"
#include "tcb.h"
#include "cxgb3_defs.h"
#include "cxgb3_ctl_defs.h"
#include "firmware_exports.h"
#include "trace.h"
#include "tom_compat.h"

#define DEBUG_WR 0

extern struct sk_ofld_proto t3_tcp_prot;
extern struct request_sock_ops t3_rsk_ops;

/*
 * For ULP connections HW may add headers, e.g., for digests, that aren't part
 * of the messages sent by the host but that are part of the TCP payload and
 * therefore consume TCP sequence space.  Tx connection parameters that
 * operate in TCP sequence space are affected by the HW additions and need to
 * compensate for them to accurately track TCP sequence numbers. This array
 * contains the compensating extra lengths for ULP packets.  It is indexed by
 * a packet's ULP submode.
 */
const unsigned int t3_ulp_extra_len[] = {0, 4, 4, 8};

/*
 * TOS values for HW scheduling classes.  If an offload policy assigns a
 * connection to a class we use a value from this table as its TOS.  These
 * are special values and we do not otherwise use them as TOS.
 */
static const u8 sched_class_tos[] = {
	0x30, 0x32, 0x34, 0x36, 0x31, 0x33, 0x35, 0x37
};

/*
 * This sk_buff holds a fake header-only TCP segment that we use whenever we
 * need to exploit SW TCP functionality that expects TCP headers, such as
 * tcp_create_openreq_child().  It's a RO buffer that may be used by multiple
 * CPUs without locking.
 */
static struct sk_buff *tcphdr_skb __read_mostly;

/*
 * Size of WRs in bytes.  Note that we assume all devices we are handling have
 * the same WR size.
 */
static unsigned int wrlen __read_mostly;

/*
 * The number of WRs needed for an skb depends on the number of page fragments
 * in the skb and whether it has any payload in its main body.  This maps the
 * length of the gather list represented by an skb into the # of necessary WRs.
 */
static unsigned int skb_wrs[MAX_SKB_FRAGS + 2] __read_mostly;

/*
 * Socket filter that drops everything by specifying a 0-length filter program.
 */
static struct sk_filter drop_all = { .refcnt = ATOMIC_INIT(1) };

/*
 * TOE information returned through inet_diag for offloaded connections.
 */
struct t3_inet_diag_info {
	u32 toe_id;    /* determines how to interpret the rest of the fields */
	u32 tid;
	u8  wrs;
	u8  queue;
	u8  ulp_mode:4;
	u8  sched_class:4;
	u8  ddp_enabled;
	char dev_name[TOENAMSIZ];
};

/*
 * Similar to process_cpl_msg() but takes an extra socket reference around the
 * call to the handler.  Should be used if the handler may drop a socket
 * reference.
 */
static inline void process_cpl_msg_ref(void (*fn)(struct sock *,
						  struct sk_buff *),
				       struct sock *sk, struct sk_buff *skb)
{
	sock_hold(sk);
	process_cpl_msg(fn, sk, skb);
	sock_put(sk);
}

static inline int is_t3a(const struct toedev *dev)
{
	return dev->ttid == TOE_ID_CHELSIO_T3;
}

/*
 * Returns an sk_buff for a reply CPL message of size len.  If the input
 * sk_buff has no other users it is trimmed and reused, otherwise a new buffer
 * is allocated.  The input skb must be of size at least len.  Note that this
 * operation does not destroy the original skb data even if it decides to reuse
 * the buffer.
 */
static struct sk_buff *get_cpl_reply_skb(struct sk_buff *skb, size_t len,
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

/*
 * Like get_cpl_reply_skb() but the returned buffer starts out empty.
 */
static struct sk_buff *__get_cpl_reply_skb(struct sk_buff *skb, size_t len,
					   int gfp)
{
	if (likely(!skb_cloned(skb) && !skb->data_len)) {
		__skb_trim(skb, 0);
		skb_get(skb);
	} else
		skb = alloc_skb(len, gfp);
	return skb;
}

/*
 * Determine whether to send a CPL message now or defer it.  A message is
 * deferred if the connection is in SYN_SENT since we don't know the TID yet.
 * For connections in other states the message is sent immediately.
 * If through_l2t is set the message is subject to ARP processing, otherwise
 * it is sent directly.
 */
static inline void send_or_defer(struct sock *sk, struct tcp_sock *tp,
				 struct sk_buff *skb, int through_l2t)
{
	struct t3cdev *cdev = T3C_DEV(sk);
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);

	if (unlikely(sk->sk_state == TCP_SYN_SENT))
		__skb_queue_tail(&tp->out_of_order_queue, skb);  // defer
	else if (through_l2t)
		l2t_send(cdev, skb, cplios->l2t_entry);  // send through L2T
	else
		cxgb3_ofld_send(cdev, skb);          // send directly
}

/*
 * Populate a TID_RELEASE WR.  The skb must be already propely sized.
 */
static inline void mk_tid_release(struct sk_buff *skb, const struct sock *sk,
				  unsigned int tid)
{
	struct cpl_tid_release *req;

	skb->priority = mkprio(CPL_PRIORITY_SETUP, sk);
	req = (struct cpl_tid_release *)__skb_put(skb, sizeof(*req));
	req->wr.wr_hi = htonl(V_WR_OP(FW_WROPCODE_FORWARD));
	OPCODE_TID(req) = htonl(MK_OPCODE_TID(CPL_TID_RELEASE, tid));
}

/*
 * Insert a socket to the TID table and take an extra reference.
 */
static inline void sk_insert_tid(struct tom_data *d, struct sock *sk,
				 unsigned int tid)
{
	sock_hold(sk);
	cxgb3_insert_tid(d->cdev, d->client, sk, tid);
}

/**
 *	find_best_mtu - find the entry in the MTU table closest to an MTU
 *	@d: TOM state
 *	@mtu: the target MTU
 *
 *	Returns the index of the value in the MTU table that is closest to but
 *	does not exceed the target MTU.
 */
static unsigned int find_best_mtu(const struct t3c_data *d, unsigned short mtu)
{
	int i = 0;

	while (i < d->nmtus - 1 && d->mtus[i + 1] <= mtu)
		++i;
	return i;
}

static unsigned int select_mss(struct sock *sk, unsigned int pmtu)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	unsigned int idx;
	struct tcp_sock *tp = tcp_sk(sk);
	struct dst_entry *dst = __sk_dst_get(sk);
	struct tom_data *d = TOM_DATA(cplios->toedev);
	const struct t3c_data *td = T3C_DATA(d->cdev);

	tp->advmss = dst_metric(dst, RTAX_ADVMSS);
	if (USER_MSS(tp) && tp->advmss > USER_MSS(tp))
		tp->advmss = USER_MSS(tp);
	if (tp->advmss > pmtu - 40)
		tp->advmss = pmtu - 40;
	if (tp->advmss < td->mtus[0] - 40)
		tp->advmss = td->mtus[0] - 40;
	idx = find_best_mtu(td, tp->advmss + 40);
	tp->advmss = td->mtus[idx] - 40;
	inet_csk(sk)->icsk_pmtu_cookie = pmtu;
	return idx;
}

void t3_select_window(struct sock *sk, int request)
{
        struct toedev *dev = CPL_IO_STATE(sk)->toedev;
        struct tom_data *d = TOM_DATA(dev);
	struct tcp_sock *tp = tcp_sk(sk);
	unsigned int wnd = tp->rcv_wnd;
	unsigned int max_rcv_wnd;

	if ((tp->copied_seq - tp->rcv_wup)  > (tp->rcv_wnd >> 1))
		wnd = tp->advmss*(tp->rcv_wnd/tp->advmss) << 1;

	wnd = max_t(unsigned int, wnd, tcp_full_space(sk));
	wnd = max_t(unsigned int, request, wnd);

        /* PR 5138 */
        max_rcv_wnd = (dev->ttid < TOE_ID_CHELSIO_T3C ?
                                    (u32)d->rx_page_size * 23 :
                                    MAX_RCV_WND);

        if (wnd > max_rcv_wnd)
                wnd = max_rcv_wnd;
/*
 * Check if we need to grow the receive window in response to an increase in
 * the socket's receive buffer size.  Some applications increase the buffer
 * size dynamically and rely on the window to grow accordingly.
 */

        if (wnd > tp->rcv_wnd) {
                tp->rcv_wup -= wnd - tp->rcv_wnd;
                tp->rcv_wnd = wnd;
		/* Mark the recieve window as updated*/
		cplios_reset_flag(sk, CPLIOS_UPDATE_RCV_WND);
        }

}

unsigned int t3_select_delack(struct sock *sk)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	struct toedev *dev = cplios->toedev;
	unsigned int dack_mode;
	
	dack_mode = TOM_TUNABLE(dev, delack);
	if (!dack_mode)
		return 0;

	if ((dack_mode == 2) && (MSS_CLAMP(tp) > 1680))
		dack_mode = 3;

	if ((dack_mode == 3) && (tp->rcv_wnd < 2 * 26880))
		dack_mode = 1;

	if ((dack_mode == 2) && (tp->rcv_wnd < 2 * 16 * MSS_CLAMP(tp)))
		dack_mode = 1;
		
	if ((dev->ttid >= TOE_ID_CHELSIO_T3C) && (cplios->delack_mode == 0) &&
		(tp->rcv_wnd > 2 * 2 * MSS_CLAMP(tp)))
		dack_mode = 1;
                                
	return dack_mode;
}

#if VALIDATE_TID
/*
 * Returns true if a connection TID is in range and currently unused.
 */
static int valid_new_tid(const struct tid_info *t, unsigned int tid)
{
	return tid < t->ntids && !t->tid_tab[tid].ctx;
}

#define VALIDATE_SOCK(sk) \
	do { \
		if (unlikely(!(sk))) \
			return CPL_RET_UNKNOWN_TID | CPL_RET_BUF_DONE; \
	} while (0)
#else
#define VALIDATE_SOCK(sk) do {} while (0)
#endif

/*
 * Called when we receive the last message from HW for a connection.  A
 * connection cannot transition to TCP_CLOSE prior to this event.
 * Resources related to the offload state of a connection (e.g., L2T entries)
 * must have been relinquished prior to calling this.
 */
static void connection_done(struct sock *sk)
{
#if 0
	printk("connection_done: TID: %u, state: %d, dead %d, refs %d\n",
	       CPL_IO_STATE(sk)->tid, sk->sk_state, sock_flag(sk, SOCK_DEAD),
	       atomic_read(&sk->sk_refcnt));
//	dump_stack();
#endif

#ifdef T3_TRACE
	T3_TRACE1(TIDTB(sk),
		  "connection_done: GTS rpl pending %d, if pending wake",
		  cplios_flag(sk, CPLIOS_ABORT_RPL_PENDING));
#endif

	sk_wakeup_sleepers(sk, 0);
	tcp_done(sk);
}

/*
 * Min receive window.  We want it to be large enough to accommodate receive
 * coalescing, handle jumbo frames, and not trigger sender SWS avoidance.
 */
#define MIN_RCV_WND (24 * 1024U)

/*
 * Determine the receive window scaling factor given a target max
 * receive window.
 */
static inline int select_rcv_wscale(int space, int wscale_ok, int window_clamp)
{
	int wscale = 0;

	if (space > MAX_RCV_WND)
		space = MAX_RCV_WND;
	if (window_clamp && window_clamp < space)
		space = window_clamp;

	if (wscale_ok)
		for (; space > 65535 && wscale < 14; space >>= 1, ++wscale) ;
	return wscale;
}

/* Returns bits 2:7 of a socket's TOS field */
#define SK_TOS(sk) ((inet_sk(sk)->tos >> 2) & M_TOS)

/*
 * The next two functions calculate the option 0 value for a socket.
 */
static inline unsigned int calc_opt0h(struct sock *sk)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	struct tcp_sock *tp = tcp_sk(sk);

	return V_NAGLE((tp->nonagle & TCP_NAGLE_OFF) == 0) |
	    V_KEEP_ALIVE(sock_flag(sk, SOCK_KEEPOPEN) != 0) | F_TCAM_BYPASS |
	    V_WND_SCALE(RCV_WSCALE(tp)) | V_MSS_IDX(cplios->mtu_idx);
}

static inline unsigned int calc_opt0l(struct sock *sk)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	unsigned int tos;

	if (cplios->sched_cls < ARRAY_SIZE(sched_class_tos))
		tos = sched_class_tos[cplios->sched_cls];
	else {
		tos = SK_TOS(sk);
		if ((tos & 0x38) == 0x30) /* suppress values in special range */
			tos = 0;
	}

	return V_TOS(tos) | V_ULP_MODE(cplios->ulp_mode) |
	       V_RCV_BUFSIZ(min(tp->rcv_wnd >> 10, (u32)M_RCV_BUFSIZ));
}

static unsigned int calc_opt2(const struct sock *sk,
			      const struct offload_settings *s)
{
	u32 opt2 = (F_CPU_INDEX_VALID |
		    V_CPU_INDEX(CPL_IO_STATE(sk)->rss_cpu_idx));

	if (unlikely(!s))
		return opt2;

	if (s->rx_coalesce >= 0)
		opt2 |= F_RX_COALESCE_VALID |
		       	V_RX_COALESCE(s->rx_coalesce ? 3 : 0);
	if (s->cong_algo >= 0)
		opt2 |= F_FLAVORS_VALID | V_CONG_CONTROL_FLAVOR(s->cong_algo) |
			V_PACING_FLAVOR(1);
	return opt2;
}

#ifdef CTRL_SKB_CACHE
/*
 * This function is intended for allocations of small control messages.
 * Such messages go as immediate data and usually the pakets are freed
 * immediately.  We maintain a cache of one small sk_buff and use it whenever
 * it is available (has a user count of 1).  Otherwise we get a fresh buffer.
 */
static struct sk_buff *alloc_ctrl_skb(const struct tcp_sock *tp, int len)
{
	struct sk_buff *skb = cplios->ctrl_skb_cache;

	if (likely(skb && !skb_shared(skb) && !skb_cloned(skb))) {
		__skb_trim(skb, 0);
		atomic_set(&skb->users, 2);
	} else if (likely(!in_atomic()))
		skb = alloc_skb_nofail(len);
	else
		skb = alloc_skb(len, GFP_ATOMIC);
	return skb;
}
#else
# define alloc_ctrl_skb(tp, len) alloc_skb_nofail(len)
#endif

static inline void free_wr_skb(struct sk_buff *skb)
{
#if defined(CONFIG_T3_ZCOPY_SENDMSG) || defined(CONFIG_T3_ZCOPY_SENDMSG_MODULE)
	if (skb->data[0] == FW_WROPCODE_OFLD_TX_DATA)
		t3_zcopy_cleanup_skb(skb);
#endif
	kfree_skb(skb);
}

static void purge_wr_queue(struct sock *sk)
{
	struct sk_buff *skb;
	while ((skb = dequeue_wr(sk)) != NULL)
		free_wr_skb(skb);
}

/*
 * Returns true if an sk_buff carries urgent data.
 */
static inline int skb_urgent(struct sk_buff *skb)
{
	return (ULP_SKB_CB(skb)->flags & ULPCB_FLAG_URG) != 0;
}

/*
 * Generic ARP failure handler that discards the buffer.
 */
static void arp_failure_discard(struct t3cdev *cdev, struct sk_buff *skb)
{
	kfree_skb(skb);
}

static inline void make_tx_data_wr(struct sock *sk, struct sk_buff *skb,
				   int len)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	struct tx_data_wr *req;
	struct tcp_sock *tp = tcp_sk(sk);

	skb_reset_transport_header(skb);
	req = (struct tx_data_wr *)__skb_push(skb, sizeof(*req));
	req->wr_hi = htonl(V_WR_OP(FW_WROPCODE_OFLD_TX_DATA));
	req->wr_lo = htonl(V_WR_TID(cplios->tid));
	req->sndseq = htonl(tp->snd_nxt);
	/* len includes the length of any HW ULP additions */
	req->len = htonl(len);
	req->param = htonl(V_TX_PORT(cplios->l2t_entry->chan_idx));
	/* V_TX_ULP_SUBMODE sets both the mode and submode */
	req->flags = htonl(V_TX_ULP_SUBMODE(skb_ulp_mode(skb)) |
			   V_TX_URG(skb_urgent(skb)) |
			   V_TX_SHOVE((!cplios_flag(sk, CPLIOS_TX_MORE_DATA)) &&
				      (skb_peek(&sk->sk_write_queue) ? 0 : 1)));

	if (!cplios_flag(sk, CPLIOS_TX_DATA_SENT)) {
		req->flags |= htonl(V_TX_ACK_PAGES(2) | F_TX_INIT | 
				    V_TX_CPU_IDX(cplios->rss_cpu_idx));
 
		/* Sendbuffer is in units of 32KB.
		 */
		req->param |= htonl(V_TX_SNDBUF(sk->sk_sndbuf >> 15));
		cplios_set_flag(sk, CPLIOS_TX_DATA_SENT);
	}
}

/*
 * Prepends TX_DATA_WR or CPL_CLOSE_CON_REQ headers to buffers waiting in a
 * socket's send queue and sends them on to the TOE.  Must be called with the
 * socket lock held.  Returns the amount of send buffer space that was freed
 * as a result of sending queued data to the TOE.
 */
int t3_push_frames(struct sock *sk, int req_completion)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	int total_size = 0;
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *skb;
	struct t3cdev *cdev;
	struct tom_data *d;

	if (unlikely(sk_in_state(sk, TCPF_SYN_SENT | TCPF_CLOSE)))
		return 0;

	/*
	 * We shouldn't really be called at all after an abort but check just
	 * in case.
	 */
	if (unlikely(cplios_flag(sk, CPLIOS_ABORT_SHUTDOWN)))
		return 0;

	d = TOM_DATA(cplios->toedev);
	cdev = d->cdev;

	while (cplios->wr_avail && (skb = skb_peek(&sk->sk_write_queue)) != NULL &&
	       !cplios_flag(sk, CPLIOS_TX_WAIT_IDLE) &&
	       (!(ULP_SKB_CB(skb)->flags & ULPCB_FLAG_HOLD) ||
		skb_queue_len(&sk->sk_write_queue) > 1)) {

		int len = skb->len;	/* length before skb_push */
		int frags = skb_shinfo(skb)->nr_frags + (len != skb->data_len);
		int wrs_needed = skb_wrs[frags];

		if (wrs_needed > 1 && len + sizeof(struct tx_data_wr) <= wrlen)
			wrs_needed = 1;

		WARN_ON(frags >= ARRAY_SIZE(skb_wrs) || wrs_needed < 1);
		if (cplios->wr_avail < wrs_needed)
			break;

		__skb_unlink(skb, &sk->sk_write_queue);
		skb->priority = mkprio(CPL_PRIORITY_DATA, sk);
		skb->csum = wrs_needed;    /* remember this until the WR_ACK */
		cplios->wr_avail -= wrs_needed;
		cplios->wr_unacked += wrs_needed;
		enqueue_wr(sk, skb);

		if (likely(ULP_SKB_CB(skb)->flags & ULPCB_FLAG_NEED_HDR)) {
			len += ulp_extra_len(skb);
			make_tx_data_wr(sk, skb, len);
			tp->snd_nxt += len;
			tp->lsndtime = tcp_time_stamp;
#if defined(CONFIG_T3_ZCOPY_SENDMSG) || defined(CONFIG_T3_ZCOPY_SENDMSG_MODULE)
			atomic_add(skb->len - sizeof (struct tx_data_wr),
				   &d->tx_dma_pending);
			skb->sk = sk;
#endif
			if ((req_completion && cplios->wr_unacked == wrs_needed) ||
			    (ULP_SKB_CB(skb)->flags & ULPCB_FLAG_COMPL) ||
			    cplios->wr_unacked >= cplios->wr_max / 2) {
				struct work_request_hdr *wr = cplhdr(skb);

				wr->wr_hi |= htonl(F_WR_COMPL);
				cplios->wr_unacked = 0;
			}
			ULP_SKB_CB(skb)->flags &= ~ULPCB_FLAG_NEED_HDR;
		} else if (skb->data[0] == FW_WROPCODE_OFLD_CLOSE_CON)
			cplios_set_flag(sk, CPLIOS_CLOSE_CON_REQUESTED);

		total_size += skb->truesize;
		if (ULP_SKB_CB(skb)->flags & ULPCB_FLAG_BARRIER)
			cplios_set_flag(sk, CPLIOS_TX_WAIT_IDLE);
		set_arp_failure_handler(skb, arp_failure_discard);

		l2t_send(cdev, skb, cplios->l2t_entry);
	}
	sk->sk_wmem_queued -= total_size;
	return total_size;
}
EXPORT_SYMBOL(t3_push_frames);

#ifndef TCP_CONGESTION_CONTROL
struct tcp_congestion_ops tcp_init_congestion_ops  = {
	.name		= "",
	.owner		= THIS_MODULE,
};
#endif

static inline void free_atid(struct t3cdev *cdev, unsigned int tid)
{
	struct sock *sk = cxgb3_free_atid(cdev, tid);
	if (sk)
		sock_put(sk);
}
/*
 * Release resources held by an offload connection (TID, L2T entry, etc.)
 */
void t3_release_offload_resources(struct sock *sk)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	struct toedev *tdev = cplios->toedev;
	struct t3cdev *cdev;
	unsigned int tid = cplios->tid;

	if (!tdev)
		return;

	cdev = T3C_DEV(sk);
	if (!cdev)
		return;

	cplios->rss_cpu_idx = 0;
	t3_release_ddp_resources(sk);

#ifdef CTRL_SKB_CACHE
	kfree_skb(cplios->ctrl_skb_cache);
	cplios->ctrl_skb_cache = NULL;
#endif

	if (cplios->wr_avail != cplios->wr_max) {
		purge_wr_queue(sk);
		reset_wr_list(sk);
	}

	if (cplios->l2t_entry) {
		l2t_release(L2DATA(cdev), cplios->l2t_entry);
		cplios->l2t_entry = NULL;
	}

	if (sk->sk_state == TCP_SYN_SENT) {               // we have ATID
		free_atid(cdev, tid);
		__skb_queue_purge(&tp->out_of_order_queue);
	} else {                                          // we have TID
		cxgb3_remove_tid(cdev, (void *)sk, tid);
		sock_put(sk);
	}

	t3_set_ca_ops(sk, &tcp_init_congestion_ops);
	cplios->toedev = NULL;
#if 0
	printk(KERN_INFO "closing TID %u, state %u\n", tid, sk->sk_state);
#endif
}

/*
 * Returns whether a CPL message is not expected in the socket backlog of a
 * closed connection.  Most messages are illegal at that point except
 * ABORT_RPL_RSS and GET_TCB_RPL sent by DDP.
 */
static int bad_backlog_msg(unsigned int opcode)
{
	return opcode != CPL_ABORT_RPL_RSS && opcode != CPL_GET_TCB_RPL;
}

/*
 * Called for each sk_buff in a socket's receive backlog during
 * backlog processing.
 */
static int t3_backlog_rcv(struct sock *sk, struct sk_buff *skb)
{
#if VALIDATE_TID
	unsigned int opcode = ntohl(skb->csum) >> 24;

	if (unlikely(sk->sk_state == TCP_CLOSE && bad_backlog_msg(opcode))) {
		printk(KERN_ERR "unexpected CPL message with opcode %x for "
		       "closed TID %u\n", opcode, CPL_IO_STATE(sk)->tid);
		kfree_skb(skb);
		return 0;
	}
#endif

	BLOG_SKB_CB(skb)->backlog_rcv(sk, skb);
	return 0;
}

#ifdef CONFIG_TCP_OFFLOAD_MODULE
static void dummy_tcp_keepalive_timer(unsigned long data)
{
}
#endif

/*
 * Switch a socket to the offload protocol operations.  Note that the offload
 * operations do not contain the offload backlog handler, we install that
 * directly to the socket.
 */
static void install_offload_ops(struct sock *sk)
{
	sk->sk_prot = &t3_tcp_prot.proto;
	sk->sk_backlog_rcv = t3_backlog_rcv;
	if (sk->sk_write_space == sk_stream_write_space)
		sk->sk_write_space = t3_write_space;

#ifdef	LINUX_2_4
	if (sk->filter)
		sk_filter_release(sk, sk->filter);
	sk->filter = &drop_all;
	sk_filter_charge(sk, sk->filter);
#else
	if (sk->sk_filter)
		sk_filter_uncharge(sk, sk->sk_filter);
	sk->sk_filter = &drop_all;
	sk_filter_charge(sk, sk->sk_filter);
#endif	/* LINUX_2_4 */

#ifdef CONFIG_TCP_OFFLOAD_MODULE
	sk->sk_timer.function = dummy_tcp_keepalive_timer;
#endif
	sock_set_flag(sk, SOCK_OFFLOADED);
}

#if DEBUG_WR
static void dump_wrs(struct sock *sk)
{
	u64 *d;
	struct sk_buff *p;

	printk("TID %u info:\n", CPL_IO_STATE(sk)->tid);
	skb_queue_walk(&sk->sk_write_queue, p) {
		d = cplhdr(p);
		printk("   len %u, frags %u, flags %x, data %llx\n",
		       p->len, skb_shinfo(p)->nr_frags, ULP_SKB_CB(p)->flags,
		       (unsigned long long)be64_to_cpu(*d));
	}
	printk("outstanding:\n");
	wr_queue_walk(sk, p) {
		d = cplhdr(p);
		printk("   len %u, frags %u, flags %x, data %llx,%llx,%llx\n",
		       p->len, skb_shinfo(p)->nr_frags, ULP_SKB_CB(p)->flags,
		       (unsigned long long)be64_to_cpu(*d),
		       (unsigned long long)be64_to_cpu(d[1]),
		       (unsigned long long)be64_to_cpu(d[2]));
	}
}

static int count_pending_wrs(const struct sock *sk)
{
	int n = 0;
	const struct sk_buff *p;

	wr_queue_walk(sk, p)
		n += p->csum;
	return n;
}

static void check_wr_invariants(const struct sock *sk)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	int pending = count_pending_wrs(sk);

	if (unlikely(cplios->wr_avail + pending != cplios->wr_max))
		printk(KERN_ERR "TID %u: credit imbalance: avail %u, "
		       "pending %u, total should be %u\n", cplios->tid,
		       cplios->wr_avail, pending, cplios->wr_max);
}
#endif

static void t3_idiag_get_info(struct sock *sk, u32 ext, struct sk_buff *skb)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
#if DEBUG_WR
	if (ext & (1 << (INET_DIAG_MEMINFO - 1))) {
		bh_lock_sock(sk);
		if (!sock_owned_by_user(sk))
			dump_wrs(sk);
		bh_unlock_sock(sk);
	}
#endif
	if (ext & (1 << INET_DIAG_MAX)) {
		struct rtattr *rta;
		struct t3_inet_diag_info *info;

		rta = __RTA_PUT(skb, INET_DIAG_MAX + 1, sizeof(*info));
		info = RTA_DATA(rta);
		info->toe_id = TOE_ID_CHELSIO_T3;
		info->tid    = cplios->tid;
		info->wrs    = cplios->wr_max - cplios->wr_avail;
		info->queue  = cplios->qset_idx;
		info->ulp_mode = cplios->ulp_mode;
		info->sched_class = cplios->sched_cls != SCHED_CLS_NONE ?
				    cplios->sched_cls : 0;
		info->ddp_enabled = DDP_STATE(sk)->ddp_setup;
		strcpy(info->dev_name, cplios->toedev->name);
rtattr_failure: ;
	}
}

#define T3_CONG_OPS(s) \
	{ .name = s, .owner = THIS_MODULE, .get_info = t3_idiag_get_info }

static struct tcp_congestion_ops t3_cong_ops[] = {
	T3_CONG_OPS("reno"),        T3_CONG_OPS("tahoe"),
	T3_CONG_OPS("newreno"),     T3_CONG_OPS("highspeed")
};

static void mk_act_open_req(struct sock *sk, struct sk_buff *skb,
			    unsigned int atid, const struct l2t_entry *e,
			    const struct offload_settings *s)
{
	struct cpl_act_open_req *req;

	skb->priority = mkprio(CPL_PRIORITY_SETUP, sk);
	req = (struct cpl_act_open_req *)__skb_put(skb, sizeof(*req));
	req->wr.wr_hi = htonl(V_WR_OP(FW_WROPCODE_FORWARD));
	OPCODE_TID(req) = htonl(MK_OPCODE_TID(CPL_ACT_OPEN_REQ, atid));
#ifdef	LINUX_2_4
	req->local_port = sk->inet_sport;
	req->peer_port = sk->inet_dport;
	req->local_ip = sk->inet_saddr;
	req->peer_ip = sk->inet_daddr;
#else
	req->local_port = inet_sk(sk)->inet_sport;
	req->peer_port = inet_sk(sk)->inet_dport;
	req->local_ip = inet_sk(sk)->inet_saddr;
	req->peer_ip = inet_sk(sk)->inet_daddr;
#endif	/* LINUX_2_4 */
	req->opt0h = htonl(calc_opt0h(sk) | V_L2T_IDX(e->idx) |
			   V_TX_CHANNEL(e->chan_idx));
	req->opt0l = htonl(calc_opt0l(sk));
	req->params = 0;

	/*
	 * Because we may need to retransmit an ACT_OPEN_REQ and we don't want
	 * to keep the offload settings around we use the following hack:
	 *
	 * - if we are given offload settings we use them and store the
	 *   resulting opt2 in rcv_tstamp
	 * - otherwise we use the previously saved opt2
	 */
	if (likely(s))
		tcp_sk(sk)->rcv_tstamp = calc_opt2(sk, s);
	req->opt2 = htonl(tcp_sk(sk)->rcv_tstamp);
}

/*
 * Convert an ACT_OPEN_RPL status to a Linux errno.
 */
static int act_open_rpl_status_to_errno(int status)
{
	switch (status) {
	case CPL_ERR_CONN_RESET:
		return ECONNREFUSED;
	case CPL_ERR_ARP_MISS:
		return EHOSTUNREACH;
	case CPL_ERR_CONN_TIMEDOUT:
		return ETIMEDOUT;
	case CPL_ERR_TCAM_FULL:
		return ENOMEM;
	case CPL_ERR_CONN_EXIST:
		printk(KERN_ERR "ACTIVE_OPEN_RPL: 4-tuple in use\n");
		return EADDRINUSE;
	default:
		return EIO;
	}
}

static void act_open_req_arp_failure(struct t3cdev *dev, struct sk_buff *skb);

static void fail_act_open(struct sock *sk, int errno)
{
	sk->sk_err = errno;
	sk->sk_error_report(sk);
	t3_release_offload_resources(sk);
	connection_done(sk);
	T3_TCP_INC_STATS_BH(sock_net(sk), TCP_MIB_ATTEMPTFAILS);
}

static void act_open_retry_timer(unsigned long data)
{
	struct sk_buff *skb;
	struct sock *sk = (struct sock *)data;
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	struct inet_connection_sock *icsk = inet_csk(sk);

	bh_lock_sock(sk);
	if (sock_owned_by_user(sk))         /* try in a bit */
		sk_reset_timer(sk, &icsk->icsk_retransmit_timer,
			       jiffies + HZ / 20);
	else {
		skb = alloc_skb(sizeof(struct cpl_act_open_req), GFP_ATOMIC);
		if (!skb)
			fail_act_open(sk, ENOMEM);
		else {
			skb->sk = sk;
			set_arp_failure_handler(skb, act_open_req_arp_failure);
			mk_act_open_req(sk, skb, cplios->tid,
					cplios->l2t_entry, NULL);
			l2t_send(T3C_DEV(sk), skb, cplios->l2t_entry);
		}
	}
	bh_unlock_sock(sk);
	sock_put(sk);
}

/*
 * Handle active open failures.
 */
static void active_open_failed(struct sock *sk, struct sk_buff *skb)
{
	struct cpl_act_open_rpl *rpl = cplhdr(skb);
	struct inet_connection_sock *icsk = inet_csk(sk);

	if (rpl->status == CPL_ERR_CONN_EXIST &&
	    icsk->icsk_retransmit_timer.function != act_open_retry_timer) {
		icsk->icsk_retransmit_timer.function = act_open_retry_timer;
		sk_reset_timer(sk, &icsk->icsk_retransmit_timer,
			       jiffies + HZ / 2);
	} else
		fail_act_open(sk, act_open_rpl_status_to_errno(rpl->status));
	__kfree_skb(skb);
}

/*
 * Return whether a failed active open has allocated a TID
 */
static inline int act_open_has_tid(int status)
{
	return status != CPL_ERR_TCAM_FULL && status != CPL_ERR_CONN_EXIST &&
	       status != CPL_ERR_ARP_MISS;
}

/*
 * Process an ACT_OPEN_RPL CPL message.
 */
static int do_act_open_rpl(struct t3cdev *cdev, struct sk_buff *skb, void *ctx)
{
	struct sock *sk = (struct sock *)ctx;
	struct cpl_act_open_rpl *rpl = cplhdr(skb);

	VALIDATE_SOCK(sk);

	if (cdev->type != T3A && act_open_has_tid(rpl->status))
		cxgb3_queue_tid_release(cdev, GET_TID(rpl));

	process_cpl_msg_ref(active_open_failed, sk, skb);
	return 0;
}

/*
 * Handle an ARP failure for an active open.   XXX purge ofo queue
 *
 * XXX badly broken for crossed SYNs as the ATID is no longer valid.
 * XXX crossed SYN errors should be generated by PASS_ACCEPT_RPL which should
 * check SOCK_DEAD or sk->sk_sock.  Or maybe generate the error here but don't
 * free the atid.  Hmm.
 */
static void act_open_req_arp_failure(struct t3cdev *dev, struct sk_buff *skb)
{
	struct sock *sk = skb->sk;

	sock_hold(sk);
	bh_lock_sock(sk);
	if (sk->sk_state == TCP_SYN_SENT || sk->sk_state == TCP_SYN_RECV) {
		if (!sock_owned_by_user(sk)) {
			fail_act_open(sk, EHOSTUNREACH);
			__kfree_skb(skb);
		} else {
			/*
			 * Smart solution: Synthesize an ACTIVE_OPEN_RPL in the
			 * existing sk_buff and queue it to the backlog.  We
			 * are certain the sk_buff is not shared.  We also
			 * don't bother trimming the buffer.
			 */
			struct cpl_act_open_rpl *rpl = cplhdr(skb);

			rpl->ot.opcode = CPL_ACT_OPEN_RPL;
			rpl->status = CPL_ERR_ARP_MISS;
			BLOG_SKB_CB(skb)->backlog_rcv = active_open_failed;
			__sk_add_backlog(sk, skb);

			/*
			 * XXX Make sure a PASS_ACCEPT_RPL behind us doesn't
			 * destroy the socket.  Unfortunately we can't go into
			 * SYN_SENT because we don't have an atid.
			 * Needs more thought.
			 */
		}
	}
	bh_unlock_sock(sk);
	sock_put(sk);
}

/*
 * Determine the receive window size for a socket.
 */
static unsigned int select_rcv_wnd(struct sock *sk)
{
	struct toedev *dev = CPL_IO_STATE(sk)->toedev;
	struct tom_data *d = TOM_DATA(dev);
	unsigned int wnd = tcp_full_space(sk);
	unsigned int max_rcv_wnd;
	
	/*
	 * For receive coalescing to work effectively we need a receive window
	 * that can accomodate a coalesced segment.
	 */	
	if (wnd < MIN_RCV_WND)
		wnd = MIN_RCV_WND; 
	
	/* PR 5138 */
	max_rcv_wnd = (dev->ttid < TOE_ID_CHELSIO_T3C ?
				    (u32)d->rx_page_size * 23 :
				    MAX_RCV_WND);

	cplios_set_flag(sk, CPLIOS_UPDATE_RCV_WND);
	
	return min(wnd, max_rcv_wnd);
}

#if defined(TCP_CONGESTION_CONTROL)
static void pivot_ca_ops(struct sock *sk, int cong)
{
	struct inet_connection_sock *icsk = inet_csk(sk);

	if (icsk->icsk_ca_ops->release)
		icsk->icsk_ca_ops->release(sk);
	module_put(icsk->icsk_ca_ops->owner);
	icsk->icsk_ca_ops = &t3_cong_ops[cong < 0 ? 2 : cong];
}
#endif

#define CTRL_SKB_LEN 120

/*
 * Assign offload parameters to some socket fields.  This code is used by
 * both active and passive opens.
 */
static void init_offload_sk(struct sock *sk, struct toedev *dev,
			    unsigned int tid, struct l2t_entry *e,
			    struct dst_entry *dst,
			    struct net_device *egress_dev,
			    const struct offload_settings *s)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	struct tcp_sock *tp = tcp_sk(sk);

	cplios->toedev = dev;
	cplios->tid = tid;
	cplios->l2t_entry = e;
	cplios->wr_max = cplios->wr_avail = TOM_TUNABLE(dev, max_wrs);
	cplios->wr_unacked = 0;
	cplios->delack_mode = 0;
	cplios->mtu_idx = select_mss(sk, dst_mtu(dst));
	tp->rcv_wnd = select_rcv_wnd(sk);
	cplios->ulp_mode = (TOM_TUNABLE(dev, ddp) &&
			    !sock_flag(sk, SOCK_NO_DDP) &&
			    tp->rcv_wnd >= MIN_DDP_RCV_WIN
			    ? ULP_MODE_TCPDDP
			    : ULP_MODE_NONE);

	cplios->sched_cls = (s->sched_class >= 0
			     ? s->sched_class
			     : SCHED_CLS_NONE); 
	cplios->qset_idx = 0;
	cplios->rss_cpu_idx = 0;
	if (s->rssq >= 0) {
		unsigned int id = s->rssq;

		if (dev->ctl(dev, GET_CPUIDX_OF_QSET, &id) == 0) {
			cplios->qset_idx = s->rssq;
			cplios->rss_cpu_idx = id;
		}
	}

#ifdef CTRL_SKB_CACHE
	cplios->ctrl_skb_cache = alloc_skb(CTRL_SKB_LEN, gfp_any());
#endif
	reset_wr_list(sk);

	if (!tp->window_clamp)
		tp->window_clamp = dst_metric(dst, RTAX_WINDOW);

	/*
	 * Set sk_sndbuf so that t3_write_space and sk_stream_write_space
	 * calculate available socket space the same way.  This allows us to
	 * keep the original ->sk_write_space callback in cases of kernel
	 * sockets that provide their own version and expect
	 * sk_stream_write_space's method to be working.
	 *
	 * The only case we don't handle are sockets that have their own
	 * ->sk_write_space callback and set SOCK_SNDBUF_LOCK.
	 */
	if (!(sk->sk_userlocks & SOCK_SNDBUF_LOCK))
		sk->sk_sndbuf = TOM_TUNABLE(dev, max_host_sndbuf);

#if defined(TCP_CONGESTION_CONTROL)
	pivot_ca_ops(sk, s->cong_algo);
#endif
}

static inline void check_sk_callbacks(struct sock *sk)
{
	if (unlikely(sk->sk_user_data &&
		     !cplios_flag(sk, CPLIOS_CALLBACKS_CHKD))) {
		if (install_special_data_ready(sk) > 0)
			sock_set_flag(sk, SOCK_NO_DDP);
		cplios_set_flag(sk, CPLIOS_CALLBACKS_CHKD);
	}
}

/*
 * Send an active open request.
 */
int t3_connect(struct toedev *tdev, struct sock *sk,
	       struct net_device *egress_dev)
{
	int atid;
	struct sk_buff *skb;
	struct l2t_entry *e;
	struct tom_data *d = TOM_DATA(tdev);
	struct tcp_sock *tp = tcp_sk(sk);
	struct dst_entry *dst = __sk_dst_get(sk);
	struct cpl_io_state *cplios;
	struct offload_req orq;
	struct offload_settings settings;

	offload_req_from_sk(&orq, sk, OPEN_TYPE_ACTIVE);
	settings = *lookup_ofld_policy(tdev, &orq, d->conf.cop_managed_offloading);
#ifndef LINUX_2_4
	rcu_read_unlock();
#else
	read_unlock(&tdev->policy_lock);
#endif
	if (!settings.offload)
		goto out_err;

	atid = cxgb3_alloc_atid(d->cdev, d->client, sk);
	if (atid < 0)
		goto out_err;

	cplios = kzalloc(sizeof *cplios, GFP_KERNEL);
	if (cplios == NULL)
		goto out_err;

	e = t3_l2t_get(d->cdev, dst->neighbour, egress_dev);
	if (!e)
		goto free_tid;

	skb = alloc_skb_nofail(sizeof(struct cpl_act_open_req));
	skb->sk = sk;
	set_arp_failure_handler(skb, act_open_req_arp_failure);

	sock_hold(sk);

	CPL_IO_STATE(sk) = cplios;
	install_offload_ops(sk);
	check_sk_callbacks(sk);

	init_offload_sk(sk, tdev, atid, e, dst, egress_dev, &settings);
	RCV_WSCALE(tp) = select_rcv_wscale(tcp_full_space(sk),
					   sysctl_tcp_window_scaling,
					   tp->window_clamp);
	sk->sk_err = 0;
	sock_reset_flag(sk, SOCK_DONE);
	T3_TCP_INC_STATS(sock_net(sk), TCP_MIB_ACTIVEOPENS);

	mk_act_open_req(sk, skb, atid, e, &settings);
	l2t_send(d->cdev, skb, e);
	if (cplios->ulp_mode == ULP_MODE_TCPDDP)
		t3_enable_ddp(sk, 0);
	return 0;

free_tid:
	free_atid(d->cdev, atid);
out_err:
	return -1;
}

/*
 * Handle an ARP failure for a CPL_ABORT_REQ.  Change it into a no RST variant
 * and send it along.
 */
static void abort_arp_failure(struct t3cdev *cdev, struct sk_buff *skb)
{
	struct cpl_abort_req *req = cplhdr(skb);

	req->cmd = CPL_ABORT_NO_RST;
	cxgb3_ofld_send(cdev, skb);
}

/*
 * Send an ABORT_REQ message.  Cannot fail.  This routine makes sure we do
 * not send multiple ABORT_REQs for the same connection and also that we do
 * not try to send a message after the connection has closed.  Returns 1 if
 * an ABORT_REQ wasn't generated after all, 0 otherwise.
 */
int t3_send_reset(struct sock *sk, int mode, struct sk_buff *skb)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	struct cpl_abort_req *req;
	struct tcp_sock *tp = tcp_sk(sk);
	unsigned int tid = cplios->tid;

	if (unlikely(cplios_flag(sk, CPLIOS_ABORT_SHUTDOWN) ||
		     !cplios->toedev)) {
		if (skb)
			__kfree_skb(skb);
		return 1;
	}

	cplios_set_flag(sk, CPLIOS_ABORT_RPL_PENDING);
	cplios_set_flag(sk, CPLIOS_ABORT_SHUTDOWN);

	/* Purge the send queue so we don't send anything after an abort. */
	t3_purge_write_queue(sk);

	if (cplios_flag(sk, CPLIOS_CLOSE_CON_REQUESTED) && is_t3a(cplios->toedev))
		mode |= CPL_ABORT_POST_CLOSE_REQ;

	if (!skb)
		skb = alloc_skb_nofail(sizeof(*req));
	skb->priority = mkprio(CPL_PRIORITY_DATA, sk);
	set_arp_failure_handler(skb, abort_arp_failure);

	req = (struct cpl_abort_req *)skb_put(skb, sizeof(*req));
	req->wr.wr_hi = htonl(V_WR_OP(FW_WROPCODE_OFLD_HOST_ABORT_CON_REQ));
	req->wr.wr_lo = htonl(V_WR_TID(tid));
	OPCODE_TID(req) = htonl(MK_OPCODE_TID(CPL_ABORT_REQ, tid));
	req->rsvd0 = htonl(tp->snd_nxt);
	req->rsvd1 = !cplios_flag(sk, CPLIOS_TX_DATA_SENT);
	req->cmd = mode;
	if (sk->sk_state == TCP_SYN_SENT)
		__skb_queue_tail(&tp->out_of_order_queue, skb);	// defer
	else
		l2t_send(T3C_DEV(sk), skb, cplios->l2t_entry);
	return 0;
}
EXPORT_SYMBOL(t3_send_reset);

/*
 * Reset a connection that is on a listener's SYN queue or accept queue,
 * i.e., one that has not had a struct socket associated with it.
 * Must be called from process context.
 *
 * Modeled after code in inet_csk_listen_stop().
 */
static void reset_listen_child(struct sock *child)
{
	struct sk_buff *skb = alloc_skb_nofail(sizeof(struct cpl_abort_req));

	sock_hold(child);      // need to survive past inet_csk_destroy_sock()
	local_bh_disable();
	bh_lock_sock(child);

	t3_send_reset(child, CPL_ABORT_SEND_RST, skb);
	sock_orphan(child);
	INC_ORPHAN_COUNT(child);
	if (child->sk_state == TCP_CLOSE)
		inet_csk_destroy_sock(child);

	bh_unlock_sock(child);
	local_bh_enable();
	sock_put(child);
}

/*
 * The reap list is the list of passive open sockets that were orphaned when
 * their listening parent went away and wasn't able to nuke them for whatever
 * reason.  These sockets are terminated through a work request from process
 * context.
 */
static struct sock *reap_list;
static spinlock_t reap_list_lock = SPIN_LOCK_UNLOCKED;

/*
 * Process the reap list.
 */
DECLARE_TASK_FUNC(process_reap_list, task_param)
{
	spin_lock_bh(&reap_list_lock);
	while (reap_list) {
		struct sock *sk = reap_list;

		reap_list = sk->sk_user_data;
		sk->sk_user_data = NULL;
		spin_unlock_bh(&reap_list_lock);
		reset_listen_child(sk);
		spin_lock_bh(&reap_list_lock);
	}
	spin_unlock_bh(&reap_list_lock);
}

static T3_DECLARE_WORK(reap_task, process_reap_list, NULL);

/*
 * Add a socket to the reap list and schedule a work request to process it.
 * We thread sockets through their sk_user_data pointers.  May be called
 * from softirq context and any associated open request must have already
 * been freed.
 */
static void add_to_reap_list(struct sock *sk)
{
	BUG_ON(sk->sk_user_data);

	release_tcp_port(sk); // release the port immediately, it may be reused

	spin_lock_bh(&reap_list_lock);
	sk->sk_user_data = reap_list;
	reap_list = sk;
	if (!sk->sk_user_data)
		schedule_work(&reap_task);
	spin_unlock_bh(&reap_list_lock);
}

static void __set_tcb_field(struct sock *sk, struct sk_buff *skb, u16 word,
			    u64 mask, u64 val, int no_reply)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	struct cpl_set_tcb_field *req;

	req = (struct cpl_set_tcb_field *)__skb_put(skb, sizeof(*req));
	req->wr.wr_hi = htonl(V_WR_OP(FW_WROPCODE_FORWARD));
	OPCODE_TID(req) = htonl(MK_OPCODE_TID(CPL_SET_TCB_FIELD, cplios->tid));
	req->reply = V_NO_REPLY(no_reply);
	req->cpu_idx = cplios->rss_cpu_idx;
	req->word = htons(word);
	req->mask = cpu_to_be64(mask);
	req->val = cpu_to_be64(val);

	skb->priority = mkprio(CPL_PRIORITY_CONTROL, sk);
}

void t3_set_tcb_field(struct sock *sk, u16 word, u64 mask, u64 val)
{
	struct sk_buff *skb;

	if (sk->sk_state == TCP_CLOSE || cplios_flag(sk, CPLIOS_ABORT_SHUTDOWN))
		return;

	skb = alloc_ctrl_skb(tcp_sk(sk), sizeof(struct cpl_set_tcb_field));
	__set_tcb_field(sk, skb, word, mask, val, 1);
	send_or_defer(sk, tcp_sk(sk), skb, 0);
}

/*
 * Set one of the t_flags bits in the TCB.
 */
static void set_tcb_tflag(struct sock *sk, unsigned int bit_pos, int val)
{
	t3_set_tcb_field(sk, W_TCB_T_FLAGS1, 1ULL << bit_pos, val << bit_pos);
}

/*
 * Send a SET_TCB_FIELD CPL message to change a connection's Nagle setting.
 */
void t3_set_nagle(struct sock *sk)
{
	set_tcb_tflag(sk, S_TF_NAGLE, !(tcp_sk(sk)->nonagle & TCP_NAGLE_OFF));
}

/*
 * Send a SET_TCB_FIELD CPL message to change a connection's keepalive setting.
 */
void t3_set_keepalive(struct sock *sk, int on_off)
{
	set_tcb_tflag(sk, S_TF_KEEPALIVE, on_off);
}

void t3_set_rcv_coalesce_enable(struct sock *sk, int on_off)
{
	set_tcb_tflag(sk, S_TF_RCV_COALESCE_ENABLE, on_off);
}

void t3_set_dack(struct sock *sk, int on_off)
{
        set_tcb_tflag(sk, S_TF_DACK, on_off);
}

void t3_set_dack_mss(struct sock *sk, int on_off)
{
	set_tcb_tflag(sk, S_TF_DACK_MSS, on_off);
}

void t3_set_migrating(struct sock *sk, int on_off)
{
        set_tcb_tflag(sk, S_TF_MIGRATING, on_off);
}

void t3_set_non_offload(struct sock *sk, int on_off)
{
        set_tcb_tflag(sk, S_TF_NON_OFFLOAD, on_off);
}

/*
 * Send a SET_TCB_FIELD CPL message to change a connection's TOS setting.
 */
void t3_set_tos(struct sock *sk)
{
	t3_set_tcb_field(sk, W_TCB_TOS, V_TCB_TOS(M_TCB_TOS),
			 V_TCB_TOS(SK_TOS(sk)));
}

/*
 * In DDP mode, TP fails to schedule a timer to push RX data to the host when
 * DDP is disabled (data is delivered to freelist). [Note that, the peer should
 * set the PSH bit in the last segment, which would trigger delivery.]
 * We work around the issue by setting a DDP buffer in a partial placed state,
 * which guarantees that TP will schedule a timer.
 */
#define TP_DDP_TIMER_WORKAROUND_MASK\
    (V_TF_DDP_BUF0_VALID(1) | V_TF_DDP_ACTIVE_BUF(1) |\
     ((V_TCB_RX_DDP_BUF0_OFFSET(M_TCB_RX_DDP_BUF0_OFFSET) |\
       V_TCB_RX_DDP_BUF0_LEN(3)) << 32))
#define TP_DDP_TIMER_WORKAROUND_VAL\
    (V_TF_DDP_BUF0_VALID(1) | V_TF_DDP_ACTIVE_BUF(0) |\
     ((V_TCB_RX_DDP_BUF0_OFFSET((u64)1) | V_TCB_RX_DDP_BUF0_LEN((u64)2)) <<\
      32))

void t3_enable_ddp(struct sock *sk, int on)
{
	if (on)
		t3_set_tcb_field(sk, W_TCB_RX_DDP_FLAGS, V_TF_DDP_OFF(1),
				 V_TF_DDP_OFF(0));
	else
		t3_set_tcb_field(sk, W_TCB_RX_DDP_FLAGS,
				 V_TF_DDP_OFF(1) |
				 TP_DDP_TIMER_WORKAROUND_MASK,
				 V_TF_DDP_OFF(1) |
				 TP_DDP_TIMER_WORKAROUND_VAL);
}

void t3_set_ddp_tag(struct sock *sk, int buf_idx, unsigned int tag_color)
{
	t3_set_tcb_field(sk, W_TCB_RX_DDP_BUF0_TAG + buf_idx,
			 V_TCB_RX_DDP_BUF0_TAG(M_TCB_RX_DDP_BUF0_TAG),
			 tag_color);
}

void t3_set_ddp_buf(struct sock *sk, int buf_idx, unsigned int offset,
		    unsigned int len)
{
	if (buf_idx == 0)
		t3_set_tcb_field(sk, W_TCB_RX_DDP_BUF0_OFFSET,
			 V_TCB_RX_DDP_BUF0_OFFSET(M_TCB_RX_DDP_BUF0_OFFSET) |
			 V_TCB_RX_DDP_BUF0_LEN(M_TCB_RX_DDP_BUF0_LEN),
			 V_TCB_RX_DDP_BUF0_OFFSET((u64)offset) |
			 V_TCB_RX_DDP_BUF0_LEN((u64)len));
	else
		t3_set_tcb_field(sk, W_TCB_RX_DDP_BUF1_OFFSET,
			 V_TCB_RX_DDP_BUF1_OFFSET(M_TCB_RX_DDP_BUF1_OFFSET) |
			 V_TCB_RX_DDP_BUF1_LEN(M_TCB_RX_DDP_BUF1_LEN << 32),
			 V_TCB_RX_DDP_BUF1_OFFSET((u64)offset) |
			 V_TCB_RX_DDP_BUF1_LEN(((u64)len) << 32));
}

int t3_set_cong_control(struct sock *sk, const char *name)
{
	int cong_algo;

	for (cong_algo = 0; cong_algo < ARRAY_SIZE(t3_cong_ops); cong_algo++)
		if (!strcmp(name, t3_cong_ops[cong_algo].name))
			break;

	if (cong_algo >= ARRAY_SIZE(t3_cong_ops))
		return -EINVAL;
	return 0;
}

int t3_get_tcb(struct sock *sk)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	struct cpl_get_tcb *req;
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *skb = alloc_skb(sizeof(*req), gfp_any());

	if (!skb)
		return -ENOMEM;

	skb->priority = mkprio(CPL_PRIORITY_CONTROL, sk);
	req = (struct cpl_get_tcb *)__skb_put(skb, sizeof(*req));
	req->wr.wr_hi = htonl(V_WR_OP(FW_WROPCODE_FORWARD));
	OPCODE_TID(req) = htonl(MK_OPCODE_TID(CPL_GET_TCB, cplios->tid));
	req->cpuno = htons(cplios->rss_cpu_idx);
	if (sk->sk_state == TCP_SYN_SENT)
		__skb_queue_tail(&tp->out_of_order_queue, skb);	// defer
	else
		cxgb3_ofld_send(T3C_DEV(sk), skb);
	return 0;
}


/*
 * Send RX credits through an RX_DATA_ACK CPL message.  If nofail is 0 we are
 * permitted to return without sending the message in case we cannot allocate
 * an sk_buff.  Returns the number of credits sent.
 */
u32 t3_send_rx_credits(struct sock *sk, u32 credits, u32 dack, int nofail)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	struct sk_buff *skb;
	struct cpl_rx_data_ack *req;

	skb = nofail ? alloc_ctrl_skb(tp, sizeof(*req)) :
		       alloc_skb(sizeof(*req), GFP_ATOMIC);
	if (!skb)
		return 0;

	req = (struct cpl_rx_data_ack *)__skb_put(skb, sizeof(*req));
	req->wr.wr_hi = htonl(V_WR_OP(FW_WROPCODE_FORWARD));
	OPCODE_TID(req) = htonl(MK_OPCODE_TID(CPL_RX_DATA_ACK, cplios->tid));
	req->credit_dack = htonl(dack | V_RX_CREDITS(credits));
	skb->priority = mkprio(CPL_PRIORITY_ACK, sk);
	cxgb3_ofld_send(T3C_DEV(sk), skb);
	return credits;
}

/*
 * Send RX_DATA_ACK CPL message to request a modulation timer to be scheduled.
 * This is only used in DDP mode, so we take the opportunity to also set the
 * DACK mode and flush any Rx credits.
 */
void t3_send_rx_modulate(struct sock *sk)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	struct sk_buff *skb;
	struct cpl_rx_data_ack *req;
	struct tcp_sock *tp = tcp_sk(sk);
	u32 dack;

	dack = t3_select_delack(sk);

	skb = alloc_ctrl_skb(tp, sizeof(*req));

	req = (struct cpl_rx_data_ack *)__skb_put(skb, sizeof(*req));
	req->wr.wr_hi = htonl(V_WR_OP(FW_WROPCODE_FORWARD));
	OPCODE_TID(req) = htonl(MK_OPCODE_TID(CPL_RX_DATA_ACK, cplios->tid));
	req->credit_dack = htonl(F_RX_MODULATE | F_RX_DACK_CHANGE |
				 V_RX_DACK_MODE(dack) |
				 V_RX_CREDITS(tp->copied_seq - tp->rcv_wup));
	skb->priority = mkprio(CPL_PRIORITY_CONTROL, sk);
	cxgb3_ofld_send(T3C_DEV(sk), skb);
	tp->rcv_wup = tp->copied_seq;
}

/*
 * Handle receipt of an urgent pointer.
 */
static void handle_urg_ptr(struct sock *sk, u32 urg_seq)
{
	struct tcp_sock *tp = tcp_sk(sk);

	urg_seq--;   /* initially points past the urgent data, per BSD */

	if (tp->urg_data && !after(urg_seq, tp->urg_seq))
		return;                                 /* duplicate pointer */

	sk_send_sigurg(sk);
	if (tp->urg_seq == tp->copied_seq && tp->urg_data &&
	    !sock_flag(sk, SOCK_URGINLINE) && tp->copied_seq != tp->rcv_nxt) {
		struct sk_buff *skb = skb_peek(&sk->sk_receive_queue);

		tp->copied_seq++;
		if (skb && tp->copied_seq - ULP_SKB_CB(skb)->seq >= skb->len)
			tom_eat_skb(sk, skb, 0);
	}
	tp->urg_data = TCP_URG_NOTYET;
	tp->urg_seq = urg_seq;
}

/*
 * Returns true if a socket cannot accept new Rx data.
 */
static inline int sk_no_receive(const struct sock *sk)
{
	return (sk->sk_shutdown & RCV_SHUTDOWN);
}

/*
 * Process an urgent data notification.
 */
static void rx_urg_notify(struct sock *sk, struct sk_buff *skb)
{
	struct cpl_rx_urg_notify *hdr = cplhdr(skb);

	if (!sk_no_receive(sk))
		handle_urg_ptr(sk, ntohl(hdr->seq));

	__kfree_skb(skb);
}

/*
 * Handler for RX_URG_NOTIFY CPL messages.
 */
static int do_rx_urg_notify(struct t3cdev *cdev, struct sk_buff *skb, void *ctx)
{
	struct sock *sk = (struct sock *)ctx;

	VALIDATE_SOCK(sk);

	process_cpl_msg(rx_urg_notify, sk, skb);
	return 0;
}

/*
 * A helper function that aborts a connection and increments the given MIB
 * counter.  The supplied skb is used to generate the ABORT_REQ message if
 * possible.  Must be called with softirqs disabled.
 */
static inline void abort_conn(struct sock *sk, struct sk_buff *skb, int mib)
{
	struct sk_buff *abort_skb;

	abort_skb = __get_cpl_reply_skb(skb, sizeof(struct cpl_abort_req),
					GFP_ATOMIC);
	if (abort_skb) {
		T3_NET_INC_STATS_BH(sock_net(sk), mib);
		t3_send_reset(sk, CPL_ABORT_SEND_RST, abort_skb);
	}
}

/*
 * Returns true if we need to explicitly request RST when we receive new data
 * on an RX-closed connection.
 */
static inline int need_rst_on_excess_rx(const struct sock *sk)
{
	return 1;
}

/*
 * Handles Rx data that arrives in a state where the socket isn't accepting
 * new data.
 */
static void handle_excess_rx(struct sock *sk, struct sk_buff *skb)
{
	if (need_rst_on_excess_rx(sk) && !cplios_flag(sk, CPLIOS_ABORT_SHUTDOWN))
		abort_conn(sk, skb, LINUX_MIB_TCPABORTONDATA);

	kfree_skb(skb);  /* can't use __kfree_skb here */
}

/*
 * Process a get_tcb_rpl as a DDP completion (similar to RX_DDP_COMPLETE)
 * by getting the DDP offset from the TCB.
 */
static void tcb_rpl_as_ddp_complete(struct sock *sk, struct sk_buff *skb)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	struct ddp_state *q = DDP_STATE(sk);
	struct ddp_buf_state *bsp;
	struct cpl_get_tcb_rpl *hdr;
	unsigned int ddp_offset, dack, dack_mss;
	u64 t;
	__be64 *tcb;

	if (unlikely(!(tp = tcp_sk(sk)))) {
		kfree_skb(skb);
		return;
	}

	/* Note that we only accout for CPL_GET_TCB issued by the DDP code. We
	 * really need a cookie in order to dispatch the RPLs.
	 */
	q->get_tcb_count--;

	/* It is a possible that a previous CPL already invalidated UBUF DDP
	 * and moved the cur_buf idx and hence no further processing of this
	 * skb is required. However, the app might be sleeping on
	 * !q->get_tcb_count and we need to wake it up.
	 */
	if (q->cancel_ubuf && !t3_ddp_ubuf_pending(sk)) {
		kfree_skb(skb);

		if (!sock_flag(sk, SOCK_DEAD))
			sk->sk_data_ready(sk, 0);

		return;
	}

	bsp = &q->buf_state[q->cur_buf];
	hdr = cplhdr(skb);
	tcb = (__be64 *)(hdr + 1);
	if (q->cur_buf == 0) {
		t = be64_to_cpu(tcb[(31 - W_TCB_RX_DDP_BUF0_OFFSET) / 2]);
		ddp_offset = t >> (32 + S_TCB_RX_DDP_BUF0_OFFSET);
	} else {
		t = be64_to_cpu(tcb[(31 - W_TCB_RX_DDP_BUF1_OFFSET) / 2]);
		ddp_offset = t >> S_TCB_RX_DDP_BUF1_OFFSET;
	}
	ddp_offset &= M_TCB_RX_DDP_BUF0_OFFSET;
	t = be64_to_cpu(tcb[(31 - W_TCB_T_FLAGS1) /2]);
	dack = (t >> (32 + S_TF_DACK)) & 0x1;
	t = be64_to_cpu(tcb[(31 - W_TCB_T_FLAGS2) /2]);
	dack_mss = (t >> (S_TF_DACK_MSS - 32)) & 0x1;
	dack |= dack_mss << 1;
	if (unlikely(dack != cplios->delack_mode)) {
		cplios->delack_mode = dack;
		cplios->delack_seq = tp->rcv_nxt;
	}

#ifdef T3_TRACE
	T3_TRACE4(TIDTB(sk),
		  "tcb_rpl_as_ddp_complete: seq 0x%x hwbuf %u ddp_offset %u delack_mode %u",
		  tp->rcv_nxt, q->cur_buf, ddp_offset, cplios->delack_mode);
#endif

#if 0
{
	unsigned int ddp_flags, rcv_nxt, rx_hdr_offset, buf_idx;

	t = be64_to_cpu(tcb[(31 - W_TCB_RX_DDP_FLAGS) / 2]);
	ddp_flags = (t >> S_TCB_RX_DDP_FLAGS) & M_TCB_RX_DDP_FLAGS;

        t = be64_to_cpu(tcb[(31 - W_TCB_RCV_NXT) / 2]);
        rcv_nxt = t >> S_TCB_RCV_NXT;
        rcv_nxt &= M_TCB_RCV_NXT;

        t = be64_to_cpu(tcb[(31 - W_TCB_RX_HDR_OFFSET) / 2]);
        rx_hdr_offset = t >> (32 + S_TCB_RX_HDR_OFFSET);
        rx_hdr_offset &= M_TCB_RX_HDR_OFFSET;

	T3_TRACE2(TIDTB(sk),
		  "tcb_rpl_as_ddp_complete: DDP FLAGS 0x%x dma up to 0x%x",
		  ddp_flags, rcv_nxt - rx_hdr_offset);
	T3_TRACE4(TB(q),
		  "tcb_rpl_as_ddp_complete: rcvnxt 0x%x hwbuf %u cur_offset %u cancel %u",
		  tp->rcv_nxt, q->cur_buf, bsp->cur_offset, q->cancel_ubuf);
	T3_TRACE3(TB(q),
		  "tcb_rpl_as_ddp_complete: TCB rcvnxt 0x%x hwbuf 0x%x ddp_offset %u",
		  rcv_nxt - rx_hdr_offset, ddp_flags, ddp_offset);
	T3_TRACE2(TB(q),
		  "tcb_rpl_as_ddp_complete: flags0 0x%x flags1 0x%x",
		 q->buf_state[0].flags, q->buf_state[1].flags);

}
#endif

	skb_ulp_ddp_offset(skb) = bsp->cur_offset;
	bsp->cur_offset = ddp_offset;
	skb->len = ddp_offset - skb_ulp_ddp_offset(skb);

	if (unlikely(sk_no_receive(sk) && skb->len)) {
		handle_excess_rx(sk, skb);
		return;
	}

#ifdef T3_TRACE
	if ((int)skb->len < 0) {
		T3_TRACE0(TIDTB(sk), "tcb_rpl_as_ddp_complete: neg len");
	}
#endif
	if (bsp->flags & DDP_BF_NOCOPY) {
#ifdef T3_TRACE
		T3_TRACE0(TIDTB(sk),
			  "tcb_rpl_as_ddp_complete: CANCEL UBUF");

		if (!q->cancel_ubuf && !(sk->sk_shutdown & RCV_SHUTDOWN)) {
			printk("!cancel_ubuf");
		}
#endif
		skb_ulp_ddp_flags(skb) = DDP_BF_PSH | DDP_BF_NOCOPY | 1;
		bsp->flags &= ~(DDP_BF_NOCOPY|DDP_BF_NODATA);
		q->cur_buf ^= 1;
	} else if (bsp->flags & DDP_BF_NOFLIP) {

		skb_ulp_ddp_flags(skb) = 1;    /* always a kernel buffer */

		/* now HW buffer carries a user buffer */
		bsp->flags &= ~DDP_BF_NOFLIP;
		bsp->flags |= DDP_BF_NOCOPY;

		/* It is possible that the CPL_GET_TCB_RPL doesn't indicate
		 * any new data in which case we're done. If in addition the
		 * offset is 0, then there wasn't a completion for the kbuf
		 * and we need to decrement the posted count.
		 */
		if (!skb->len) {
			if (!ddp_offset) {
				q->kbuf_posted--;
				bsp->flags |= DDP_BF_NODATA;
			}
			BUG_ON(skb->len);
			kfree_skb(skb);
			return;
		}
	} else {
		/* This reply is for a CPL_GET_TCB_RPL to cancel the UBUF DDP,
		 * but it got here way late and nobody cares anymore.
		 */
		kfree_skb(skb);
		return;
	}

	skb_gl_set(skb, bsp->gl);
	ULP_SKB_CB(skb)->seq = tp->rcv_nxt;
	tp->rcv_nxt += skb->len;

	skb_reset_transport_header(skb);
	tcp_hdr(skb)->fin = 0;          /* changes original TCB */

	inet_csk(sk)->icsk_ack.lrcvtime = tcp_time_stamp;

#ifdef T3_TRACE
	T3_TRACE3(TIDTB(sk),
		  "tcb_rpl_as_ddp_complete: seq 0x%x hwbuf %u lskb->len %u",
		  ULP_SKB_CB(skb)->seq, q->cur_buf, skb->len);
#endif

	__skb_queue_tail(&sk->sk_receive_queue, skb);

	if (!sock_flag(sk, SOCK_DEAD))
		sk->sk_data_ready(sk, 0);
}

/*
 * Process a CPL_GET_TCB_RPL.  These can also be generated by the DDP code,
 * in that case they are similar to DDP completions.
 */
static int do_get_tcb_rpl(struct t3cdev *cdev, struct sk_buff *skb, void *ctx)
{
	struct sock *sk = (struct sock *)ctx;

	/* OK if socket doesn't exist */
	if (!sk)
		return CPL_RET_BUF_DONE;

	process_cpl_msg(tcb_rpl_as_ddp_complete, sk, skb);
	return 0;
}

static void handle_ddp_data(struct sock *sk, struct sk_buff *origskb)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	struct ddp_state *q;
	struct ddp_buf_state *bsp;
	struct cpl_rx_data *hdr = cplhdr(origskb);
	unsigned int rcv_nxt = ntohl(hdr->seq);
	struct sk_buff *skb;

	/* If the sequence number received is less than expected then the assumptions
	   that follow do not apply.
	*/

	if (tp->rcv_nxt >= rcv_nxt)
		return;

	q = DDP_STATE(sk);
	if (!q->ddp_setup)
		return;

	skb = skb_clone(origskb, GFP_ATOMIC);
	if (!skb)
		return;

	bsp = &q->buf_state[q->cur_buf];

	/* Here we assume that data placed into host memory by DDP corresponds
	   to the difference between the sequence number received in the RX_DATA header
	   and the expected sequence number. And since we tested the sequence above
	   so the computed skb->len is positive we won't panic later on...
	*/

	skb->len = rcv_nxt - tp->rcv_nxt;

#ifdef T3_TRACE
	if ((int)skb->len < 0) {
		T3_TRACE0(TIDTB(sk), "handle_ddp_data: neg len");
	}
#endif

	skb_gl_set(skb, bsp->gl);

	skb_ulp_ddp_offset(skb) = bsp->cur_offset;
	skb_ulp_ddp_flags(skb) =
	    DDP_BF_PSH | (bsp->flags & DDP_BF_NOCOPY) | 1;
	if (bsp->flags & DDP_BF_NOCOPY)
		bsp->flags &= ~DDP_BF_NOCOPY;

	if (unlikely(hdr->dack_mode != cplios->delack_mode)) {
		cplios->delack_mode = hdr->dack_mode;
		cplios->delack_seq = tp->rcv_nxt;
	}
	
	ULP_SKB_CB(skb)->seq = tp->rcv_nxt;
	tp->rcv_nxt = rcv_nxt;
	bsp->cur_offset += skb->len;
	if (!(bsp->flags & DDP_BF_NOFLIP))
		q->cur_buf ^= 1;
	inet_csk(sk)->icsk_ack.lrcvtime = tcp_time_stamp;
	__skb_queue_tail(&sk->sk_receive_queue, skb);

	/* For now, don't re-enable DDP after a connection fell out of  DDP
	 * mode.
	 */
	q->ubuf_ddp_ready = 0;
}
/*
 * Process new data received for a connection.
 */
static void new_rx_data(struct sock *sk, struct sk_buff *skb)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	struct cpl_rx_data *hdr = cplhdr(skb);
	struct tcp_sock *tp = tcp_sk(sk);

	if (unlikely(sk_no_receive(sk))) {
		handle_excess_rx(sk, skb);
		return;
	}

	if (cplios->ulp_mode == ULP_MODE_TCPDDP)
		handle_ddp_data(sk, skb);

	ULP_SKB_CB(skb)->seq = ntohl(hdr->seq);
	ULP_SKB_CB(skb)->flags = 0;
	skb_ulp_mode(skb) = ULP_MODE_NONE;	/* for iSCSI */
	skb_ulp_ddp_flags(skb) = 0;		/* for DDP */

#if VALIDATE_SEQ
	if (unlikely(ULP_SKB_CB(skb)->seq != tp->rcv_nxt)) {
		printk(KERN_ERR
		       "%s: TID %u: Bad sequence number %u, expected %u\n",
		       cplios->toedev->name, cplios->tid, ULP_SKB_CB(skb)->seq,
		       tp->rcv_nxt);
		__kfree_skb(skb);
		return;
	}
#endif
	skb_reset_transport_header(skb);
	__skb_pull(skb, sizeof(*hdr));
	if (!skb->data_len)
		__skb_trim(skb, ntohs(hdr->len));

	if (unlikely(hdr->urg))
		handle_urg_ptr(sk, tp->rcv_nxt + ntohs(hdr->urg));
	if (unlikely(tp->urg_data == TCP_URG_NOTYET &&
		     tp->urg_seq - tp->rcv_nxt < skb->len))
		tp->urg_data = TCP_URG_VALID | skb->data[tp->urg_seq -
							 tp->rcv_nxt];

	if (unlikely(hdr->dack_mode != cplios->delack_mode)) {
		cplios->delack_mode = hdr->dack_mode;
		cplios->delack_seq = tp->rcv_nxt;
	}

	tcp_hdr(skb)->fin = 0;          /* modifies original hdr->urg */
	tp->rcv_nxt += skb->len;

#ifdef T3_TRACE
	T3_TRACE2(TIDTB(sk),
		  "new_rx_data: seq 0x%x len %u",
		  ULP_SKB_CB(skb)->seq, skb->len);
#endif

	inet_csk(sk)->icsk_ack.lrcvtime = tcp_time_stamp;
	__skb_queue_tail(&sk->sk_receive_queue, skb);

	if (!sock_flag(sk, SOCK_DEAD)) {
		check_sk_callbacks(sk);
		sk->sk_data_ready(sk, 0);
	}
}

/*
 * Handler for RX_DATA CPL messages.
 */
static int do_rx_data(struct t3cdev *cdev, struct sk_buff *skb, void *ctx)
{
	struct sock *sk = (struct sock *)ctx;

	VALIDATE_SOCK(sk);

	skb_gl_set(skb, NULL);		/* indicates packet is RX_DATA */

	process_cpl_msg(new_rx_data, sk, skb);
	return 0;
}

static void new_rx_data_ddp(struct sock *sk, struct sk_buff *skb)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	struct tcp_sock *tp;
	struct ddp_state *q;
	struct ddp_buf_state *bsp;
	struct cpl_rx_data_ddp *hdr;
	unsigned int ddp_len, rcv_nxt, ddp_report, end_offset, buf_idx;
	unsigned int nomoredata=0;
	unsigned int delack_mode;
	
	if (unlikely(sk_no_receive(sk))) {
		handle_excess_rx(sk, skb);
		return;
	}

	tp = tcp_sk(sk);
	q = DDP_STATE(sk);
	hdr = cplhdr(skb);
	ddp_report = ntohl(hdr->ddp_report);
	buf_idx = (ddp_report >> S_DDP_BUF_IDX) & 1;
	bsp = &q->buf_state[buf_idx];

#ifdef T3_TRACE
	T3_TRACE5(TIDTB(sk),
		  "new_rx_data_ddp: tp->rcv_nxt 0x%x cur_offset %u "
		  "hdr seq 0x%x len %u offset %u",
		  tp->rcv_nxt, bsp->cur_offset, ntohl(hdr->seq),
		  ntohs(hdr->len), G_DDP_OFFSET(ddp_report));
	T3_TRACE1(TIDTB(sk),
		  "new_rx_data_ddp: ddp_report 0x%x",
		  ddp_report);
#endif

	ddp_len = ntohs(hdr->len);
	rcv_nxt = ntohl(hdr->seq) + ddp_len;

	delack_mode = G_DDP_DACK_MODE(ddp_report);
	if (unlikely(G_DDP_DACK_MODE(ddp_report) != cplios->delack_mode)) {
		cplios->delack_mode = delack_mode;
		cplios->delack_seq = tp->rcv_nxt;
	}

	ULP_SKB_CB(skb)->seq = tp->rcv_nxt;
	tp->rcv_nxt = rcv_nxt;

	/*
	 * Store the length in skb->len.  We are changing the meaning of
	 * skb->len here, we need to be very careful that nothing from now on
	 * interprets ->len of this packet the usual way.
	 */
	skb->len = tp->rcv_nxt - ULP_SKB_CB(skb)->seq;

	/*
	 * Figure out where the new data was placed in the buffer and store it
	 * in when.  Assumes the buffer offset starts at 0, consumer needs to
	 * account for page pod's pg_offset.
	 */
	end_offset = G_DDP_OFFSET(ddp_report) + ddp_len;
	skb_ulp_ddp_offset(skb) = end_offset - skb->len;

	/*
	 * We store in mac.raw the address of the gather list where the
	 * placement happened.
	 */
	skb_gl_set(skb, bsp->gl);
	bsp->cur_offset = end_offset;

	/*
	 * Bit 0 of DDP flags stores whether the DDP buffer is completed.
	 * Note that other parts of the code depend on this being in bit 0.
	 */
	if ((bsp->flags & DDP_BF_NOINVAL) && end_offset != bsp->gl->length) {
		skb_ulp_ddp_flags(skb) = 0;  /* potential spurious completion */
		BUG_ON(1);
	} else {
		skb_ulp_ddp_flags(skb) = !!(ddp_report & F_DDP_BUF_COMPLETE);
		if (skb_ulp_ddp_flags(skb) && !(bsp->flags & DDP_BF_NOFLIP)) {
			q->cur_buf ^= 1;                     /* flip buffers */
			if (end_offset < q->kbuf[0]->length)
				nomoredata=1;
		}
	}

	if (bsp->flags & DDP_BF_NOCOPY) {
		skb_ulp_ddp_flags(skb) |= (bsp->flags & DDP_BF_NOCOPY);
		bsp->flags &= ~DDP_BF_NOCOPY;
	}

	if (ddp_report & F_DDP_PSH)
		skb_ulp_ddp_flags(skb) |= DDP_BF_PSH;

	if (nomoredata)
		skb_ulp_ddp_flags(skb) |= DDP_BF_NODATA;

	skb_reset_transport_header(skb);
	tcp_hdr(skb)->fin = 0;          /* changes original hdr->ddp_report */

	inet_csk(sk)->icsk_ack.lrcvtime = tcp_time_stamp;
	__skb_queue_tail(&sk->sk_receive_queue, skb);
	if (!sock_flag(sk, SOCK_DEAD))
		sk->sk_data_ready(sk, 0);
}

#define DDP_ERR (F_DDP_PPOD_MISMATCH | F_DDP_LLIMIT_ERR | F_DDP_ULIMIT_ERR |\
		 F_DDP_PPOD_PARITY_ERR | F_DDP_PADDING_ERR | F_DDP_OFFSET_ERR |\
		 F_DDP_INVALID_TAG | F_DDP_COLOR_ERR | F_DDP_TID_MISMATCH |\
		 F_DDP_INVALID_PPOD)

/*
 * Handler for RX_DATA_DDP CPL messages.
 */
static int do_rx_data_ddp(struct t3cdev *cdev, struct sk_buff *skb, void *ctx)
{
	struct sock *sk = ctx;
	const struct cpl_rx_data_ddp *hdr = cplhdr(skb);

	VALIDATE_SOCK(sk);

	if (unlikely(ntohl(hdr->ddpvld_status) & DDP_ERR)) {
		printk(KERN_ERR "RX_DATA_DDP for TID %u reported error 0x%x\n",
		       GET_TID(hdr), G_DDP_VALID(ntohl(hdr->ddpvld_status)));
		return CPL_RET_BUF_DONE;
	}

	process_cpl_msg(new_rx_data_ddp, sk, skb);
	return 0;
}

static void process_ddp_complete(struct sock *sk, struct sk_buff *skb)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	struct ddp_state *q;
	struct ddp_buf_state *bsp;
	struct cpl_rx_ddp_complete *hdr;
	unsigned int ddp_report, buf_idx;
	unsigned int nomoredata=0;
	unsigned int delack_mode;

	if (unlikely(sk_no_receive(sk))) {
		handle_excess_rx(sk, skb);
		return;
	}

	tp = tcp_sk(sk);
	q = DDP_STATE(sk);
	hdr = cplhdr(skb);
	ddp_report = ntohl(hdr->ddp_report);
	buf_idx = (ddp_report >> S_DDP_BUF_IDX) & 1;
	bsp = &q->buf_state[buf_idx];

	skb_ulp_ddp_offset(skb) = bsp->cur_offset;
	skb->len = G_DDP_OFFSET(ddp_report) - skb_ulp_ddp_offset(skb);

#ifdef T3_TRACE
	T3_TRACE5(TIDTB(sk),
		  "process_ddp_complete: tp->rcv_nxt 0x%x cur_offset %u "
		  "ddp_report 0x%x offset %u, len %u",
		  tp->rcv_nxt, bsp->cur_offset, ddp_report,
		   G_DDP_OFFSET(ddp_report), skb->len);
#endif

	bsp->cur_offset += skb->len;

	if (!(bsp->flags & DDP_BF_NOFLIP)) {
		q->cur_buf ^= 1;                     /* flip buffers */
		if (G_DDP_OFFSET(ddp_report) < q->kbuf[0]->length)
			nomoredata=1;
	}


#ifdef T3_TRACE
	T3_TRACE4(TIDTB(sk),
		  "process_ddp_complete: tp->rcv_nxt 0x%x cur_offset %u "
		  "ddp_report %u offset %u",
		  tp->rcv_nxt, bsp->cur_offset, ddp_report,
		   G_DDP_OFFSET(ddp_report));
#endif
	skb_gl_set(skb, bsp->gl);
	skb_ulp_ddp_flags(skb) = (bsp->flags & DDP_BF_NOCOPY) | 1;

	if (bsp->flags & DDP_BF_NOCOPY)
		bsp->flags &= ~DDP_BF_NOCOPY;
	if (nomoredata)
		skb_ulp_ddp_flags(skb) |= DDP_BF_NODATA;

	delack_mode = G_DDP_DACK_MODE(ddp_report);
	if (unlikely(G_DDP_DACK_MODE(ddp_report) != cplios->delack_mode)) {
		cplios->delack_mode = delack_mode;
		cplios->delack_seq = tp->rcv_nxt;
	}

	ULP_SKB_CB(skb)->seq = tp->rcv_nxt;
	tp->rcv_nxt += skb->len;

	skb_reset_transport_header(skb);
	tcp_hdr(skb)->fin = 0;          /* changes valid memory past CPL */

	inet_csk(sk)->icsk_ack.lrcvtime = tcp_time_stamp;
	__skb_queue_tail(&sk->sk_receive_queue, skb);
	if (!sock_flag(sk, SOCK_DEAD))
		sk->sk_data_ready(sk, 0);
}

/*
 * Handler for RX_DDP_COMPLETE CPL messages.
 */
static int do_rx_ddp_complete(struct t3cdev *cdev, struct sk_buff *skb,
			      void *ctx)
{
	struct sock *sk = ctx;

	VALIDATE_SOCK(sk);

	process_cpl_msg(process_ddp_complete, sk, skb);
	return 0;
}

/*
 * Move a socket to TIME_WAIT state.  We need to make some adjustments to the
 * socket state before calling tcp_time_wait to comply with its expectations.
 */
static void enter_timewait(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

	/*
	 * Bump rcv_nxt for the peer FIN.  We don't do this at the time we
	 * process peer_close because we don't want to carry the peer FIN in
	 * the socket's receive queue and if we increment rcv_nxt without
	 * having the FIN in the receive queue we'll confuse facilities such
	 * as SIOCINQ.
	 */
	tp->rcv_nxt++;

	TS_RECENT_STAMP(tp) = 0;	     /* defeat recycling */
	tp->srtt = 0;                        /* defeat tcp_update_metrics */
	tcp_time_wait(sk, TCP_TIME_WAIT, 0); /* calls tcp_done */
}

/*
 * For TCP DDP a PEER_CLOSE may also be an implicit RX_DDP_COMPLETE.  This
 * function deals with the data that may be reported along with the FIN.
 * Returns -1 if no further processing of the PEER_CLOSE is needed, >= 0 to
 * perform normal FIN-related processing.  In the latter case 1 indicates that
 * there was an implicit RX_DDP_COMPLETE and the skb should not be freed, 0 the
 * skb can be freed.
 */
static int handle_peer_close_data(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct ddp_state *q;
	struct ddp_buf_state *bsp;
	struct cpl_peer_close *req = cplhdr(skb);
	unsigned int rcv_nxt = ntohl(req->rcv_nxt) - 1; /* exclude FIN */

	if (tp->rcv_nxt == rcv_nxt)			/* no data */
		return 0;

	if (unlikely(sk_no_receive(sk))) {
		handle_excess_rx(sk, skb);

		/*
		 * Although we discard the data we want to process the FIN so
		 * that PEER_CLOSE + data behaves the same as RX_DATA_DDP +
		 * PEER_CLOSE without data.  In particular this PEER_CLOSE
		 * may be what will close the connection.  We return 1 because
		 * handle_excess_rx() already freed the packet.
		 */
		return 1;
	}

	q = DDP_STATE(sk);
	bsp = &q->buf_state[q->cur_buf];
	skb->len = rcv_nxt - tp->rcv_nxt;
	skb_gl_set(skb, bsp->gl);
	skb_ulp_ddp_offset(skb) = bsp->cur_offset;
	skb_ulp_ddp_flags(skb) =
	    DDP_BF_PSH | (bsp->flags & DDP_BF_NOCOPY) | 1;
	ULP_SKB_CB(skb)->seq = tp->rcv_nxt;
	tp->rcv_nxt = rcv_nxt;
	bsp->cur_offset += skb->len;
	if (!(bsp->flags & DDP_BF_NOFLIP))
		q->cur_buf ^= 1;

	skb_reset_transport_header(skb);
	tcp_hdr(skb)->fin = 0;          /* changes valid memory past CPL */

	inet_csk(sk)->icsk_ack.lrcvtime = tcp_time_stamp;
	__skb_queue_tail(&sk->sk_receive_queue, skb);
	if (!sock_flag(sk, SOCK_DEAD))
		sk->sk_data_ready(sk, 0);
	return 1;
}

/*
 * Handle a peer FIN.
 */
static void do_peer_fin(struct sock *sk, struct sk_buff *skb)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	int keep = 0, dead = sock_flag(sk, SOCK_DEAD);

#ifdef T3_TRACE
	T3_TRACE0(TIDTB(sk),"do_peer_fin:");
#endif

	if (!is_t3a(cplios->toedev) &&
	    cplios_flag(sk, CPLIOS_ABORT_RPL_PENDING))
		goto out;

	if (cplios->ulp_mode == ULP_MODE_TCPDDP) {
		keep = handle_peer_close_data(sk, skb);
		if (keep < 0)
			return;
	}

	sk->sk_shutdown |= RCV_SHUTDOWN;
	sock_set_flag(sk, SOCK_DONE);
	switch (sk->sk_state) {
	case TCP_SYN_RECV:
	case TCP_ESTABLISHED:
		tcp_set_state(sk, TCP_CLOSE_WAIT);
		break;
	case TCP_FIN_WAIT1:
		tcp_set_state(sk, TCP_CLOSING);
		break;
	case TCP_FIN_WAIT2:
		/*
		 * If we've sent an abort_req we must have sent it too late,
		 * HW will send us a reply telling us so, and this peer_close
		 * is really the last message for this connection and needs to
		 * be treated as an abort_rpl, i.e., transition the connection
		 * to TCP_CLOSE (note that the host stack does this at the
		 * time of generating the RST but we must wait for HW).
		 * Otherwise we enter TIME_WAIT.
		 */
		t3_release_offload_resources(sk);
		if (cplios_flag(sk, CPLIOS_ABORT_RPL_PENDING))
			connection_done(sk);
		else
			enter_timewait(sk);
		break;
	default:
		printk(KERN_ERR
		       "%s: TID %u received PEER_CLOSE in bad state %d\n",
		       cplios->toedev->name, cplios->tid, sk->sk_state);
	}

	if (!dead) {
		sk->sk_state_change(sk);

		/* Do not send POLL_HUP for half duplex close. */
		if ((sk->sk_shutdown & SEND_SHUTDOWN) ||
		    sk->sk_state == TCP_CLOSE)
			sk_wake_async(sk, 1, POLL_HUP);
		else
			sk_wake_async(sk, 1, POLL_IN);
	}
out:	if (!keep)
		__kfree_skb(skb);
}

/*
 * Handler for PEER_CLOSE CPL messages.
 */
static int do_peer_close(struct t3cdev *cdev, struct sk_buff *skb, void *ctx)
{
	struct sock *sk = (struct sock *)ctx;

	VALIDATE_SOCK(sk);

	process_cpl_msg_ref(do_peer_fin, sk, skb);
	return 0;
}

/*
 * Process a peer ACK to our FIN.
 */
static void process_close_con_rpl(struct sock *sk, struct sk_buff *skb)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	struct cpl_close_con_rpl *rpl = cplhdr(skb);

	tp->snd_una = ntohl(rpl->snd_nxt) - 1;  /* exclude FIN */

	if (!is_t3a(cplios->toedev) && cplios_flag(sk, CPLIOS_ABORT_RPL_PENDING))
		goto out;

	switch (sk->sk_state) {
	case TCP_CLOSING:              /* see FIN_WAIT2 case in do_peer_fin */
		t3_release_offload_resources(sk);
		if (cplios_flag(sk, CPLIOS_ABORT_RPL_PENDING))
			connection_done(sk);
		else
			enter_timewait(sk);
		break;
	case TCP_LAST_ACK:
		/*
		 * In this state we don't care about pending abort_rpl.
		 * If we've sent abort_req it was post-close and was sent too
		 * late, this close_con_rpl is the actual last message.
		 */
		t3_release_offload_resources(sk);
		connection_done(sk);
		break;
	case TCP_FIN_WAIT1:
		tcp_set_state(sk, TCP_FIN_WAIT2);
		sk->sk_shutdown |= SEND_SHUTDOWN;
		dst_confirm(sk->sk_dst_cache);

		if (!sock_flag(sk, SOCK_DEAD))
			sk->sk_state_change(sk); // Wake up lingering close()
		else if (tcp_sk(sk)->linger2 < 0 &&
			 !cplios_flag(sk, CPLIOS_ABORT_SHUTDOWN))
			abort_conn(sk, skb, LINUX_MIB_TCPABORTONLINGER);
		break;
	default:
		printk(KERN_ERR
		       "%s: TID %u received CLOSE_CON_RPL in bad state %d\n",
		       cplios->toedev->name, cplios->tid, sk->sk_state);
	}
out:	kfree_skb(skb);  /* can't use __kfree_skb here */
}

/*
 * Handler for CLOSE_CON_RPL CPL messages.
 */
static int do_close_con_rpl(struct t3cdev *cdev, struct sk_buff *skb,
			    void *ctx)
{
	struct sock *sk = (struct sock *)ctx;

	VALIDATE_SOCK(sk);

	process_cpl_msg_ref(process_close_con_rpl, sk, skb);
	return 0;
}

/*
 * Process abort replies.  We only process these messages if we anticipate
 * them as the coordination between SW and HW in this area is somewhat lacking
 * and sometimes we get ABORT_RPLs after we are done with the connection that
 * originated the ABORT_REQ.
 */
static void process_abort_rpl(struct sock *sk, struct sk_buff *skb)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
#ifdef T3_TRACE
	T3_TRACE1(TIDTB(sk),
		  "process_abort_rpl: GTS rpl pending %d",
		  cplios_flag(sk, CPLIOS_ABORT_RPL_PENDING));
#endif

	if (cplios_flag(sk, CPLIOS_ABORT_RPL_PENDING)) {
		if (!cplios_flag(sk, CPLIOS_ABORT_RPL_RCVD) &&
		    !is_t3a(cplios->toedev))
			cplios_set_flag(sk, CPLIOS_ABORT_RPL_RCVD);
		else {
			cplios_reset_flag(sk, CPLIOS_ABORT_RPL_RCVD);
			cplios_reset_flag(sk, CPLIOS_ABORT_RPL_PENDING);
			if (!cplios_flag(sk, CPLIOS_ABORT_REQ_RCVD) ||
			    !is_t3a(cplios->toedev)) {
				BUG_ON(cplios_flag(sk, CPLIOS_ABORT_REQ_RCVD));
				t3_release_offload_resources(sk);
				connection_done(sk);
			}
		}
	}
	__kfree_skb(skb);
}

/*
 * Handle an ABORT_RPL_RSS CPL message.
 */
static int do_abort_rpl(struct t3cdev *cdev, struct sk_buff *skb, void *ctx)
{
	struct sock *sk;
	struct cpl_abort_rpl_rss *rpl = cplhdr(skb);

	/*
	 * Ignore replies to post-close aborts indicating that the abort was
	 * requested too late.  These connections are terminated when we get
	 * PEER_CLOSE or CLOSE_CON_RPL and by the time the abort_rpl_rss
	 * arrives the TID is either no longer used or it has been recycled.
	 */
	if (rpl->status == CPL_ERR_ABORT_FAILED) {
discard:
		__kfree_skb(skb);
		return 0;
	}

	sk = (struct sock *)ctx;

	/*
	 * Sometimes we've already closed the socket, e.g., a post-close
	 * abort races with ABORT_REQ_RSS, the latter frees the socket
	 * expecting the ABORT_REQ will fail with CPL_ERR_ABORT_FAILED,
	 * but FW turns the ABORT_REQ into a regular one and so we get
	 * ABORT_RPL_RSS with status 0 and no socket.  Only on T3A.
	 */
	if (!sk)
		goto discard;

	process_cpl_msg_ref(process_abort_rpl, sk, skb);
	return 0;
}

/*
 * Convert the status code of an ABORT_REQ into a Linux error code.  Also
 * indicate whether RST should be sent in response.
 */
static int abort_status_to_errno(struct sock *sk, int abort_reason,
				 int *need_rst)
{
	switch (abort_reason) {
	case CPL_ERR_BAD_SYN:
		// fall through
		T3_NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_TCPABORTONSYN);
	case CPL_ERR_CONN_RESET:
		// XXX need to handle SYN_RECV due to crossed SYNs
		return sk->sk_state == TCP_CLOSE_WAIT ? EPIPE : ECONNRESET;
	case CPL_ERR_XMIT_TIMEDOUT:
	case CPL_ERR_PERSIST_TIMEDOUT:
	case CPL_ERR_FINWAIT2_TIMEDOUT:
	case CPL_ERR_KEEPALIVE_TIMEDOUT:
		T3_NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_TCPABORTONTIMEOUT);
		return ETIMEDOUT;
	default:
		return EIO;
	}
}

static inline void set_abort_rpl_wr(struct sk_buff *skb, unsigned int tid,
				    int cmd)
{
	struct cpl_abort_rpl *rpl = cplhdr(skb);

	rpl->wr.wr_hi = htonl(V_WR_OP(FW_WROPCODE_OFLD_HOST_ABORT_CON_RPL));
	rpl->wr.wr_lo = htonl(V_WR_TID(tid));
	OPCODE_TID(rpl) = htonl(MK_OPCODE_TID(CPL_ABORT_RPL, tid));
	rpl->cmd = cmd;
}

static void send_deferred_abort_rpl(struct toedev *tdev, struct sk_buff *skb)
{
	struct sk_buff *reply_skb;
	struct cpl_abort_req_rss *req = cplhdr(skb);

	reply_skb = alloc_skb_nofail(sizeof(struct cpl_abort_rpl));
	reply_skb->priority = CPL_PRIORITY_DATA;
	__skb_put(reply_skb, sizeof(struct cpl_abort_rpl));
	set_abort_rpl_wr(reply_skb, GET_TID(req), req->status);
	cxgb3_ofld_send(TOM_DATA(tdev)->cdev, reply_skb);
	kfree_skb(skb);
}

/*
 * Returns whether an ABORT_REQ_RSS message is a negative advice.
 */
static inline int is_neg_adv_abort(unsigned int status)
{
	return status == CPL_ERR_RTX_NEG_ADVICE ||
	       status == CPL_ERR_PERSIST_NEG_ADVICE;
}

static void send_abort_rpl(struct sk_buff *skb, struct toedev *tdev,
			   int rst_status)
{
	struct sk_buff *reply_skb;
	struct cpl_abort_req_rss *req = cplhdr(skb);

	reply_skb = get_cpl_reply_skb(skb, sizeof(struct cpl_abort_rpl),
				      gfp_any());
	if (!reply_skb) {
		/* Defer the reply.  Stick rst_status into req->cmd. */
		req->status = rst_status;
		t3_defer_reply(skb, tdev, send_deferred_abort_rpl);
		return;
	}

	reply_skb->priority = CPL_PRIORITY_DATA;
	set_abort_rpl_wr(reply_skb, GET_TID(req), rst_status);
	kfree_skb(skb);	       /* can't use __kfree_skb here */
	/*
	 * XXX need to sync with ARP as for SYN_RECV connections we can send
	 * these messages while ARP is pending.  For other connection states
	 * it's not a problem.
	 */
	cxgb3_ofld_send(TOM_DATA(tdev)->cdev, reply_skb);
}

static void cleanup_syn_rcv_conn(struct sock *child, struct sock *parent)
{
	struct request_sock *req = child->sk_user_data;

	inet_csk_reqsk_queue_removed(parent, req);
	synq_remove(child);
	__reqsk_free(req);
	child->sk_user_data = NULL;
}

/*
 * Performs the actual work to abort a SYN_RECV connection.
 */
static void do_abort_syn_rcv(struct sock *child, struct sock *parent)
{
	/*
	 * If the server is still open we clean up the child connection,
	 * otherwise the server already did the clean up as it was purging
	 * its SYN queue and the skb was just sitting in its backlog.
	 */
	if (likely(parent->sk_state == TCP_LISTEN)) {
		cleanup_syn_rcv_conn(child, parent);
		t3_release_offload_resources(child);
		connection_done(child);
	}
}

/*
 * This is run from a listener's backlog to abort a child connection in
 * SYN_RCV state (i.e., one on the listener's SYN queue).
 */
static void bl_abort_syn_rcv(struct sock *lsk, struct sk_buff *skb)
{
	struct sock *child = skb->sk;

	skb->sk = NULL;
	do_abort_syn_rcv(child, lsk);
	send_abort_rpl(skb, BLOG_SKB_CB(skb)->dev, CPL_ABORT_NO_RST);
}

/*
 * Handle abort requests for a SYN_RECV connection.  These need extra work
 * because the socket is on its parent's SYN queue.
 */
static int abort_syn_rcv(struct sock *sk, struct sk_buff *skb)
{
	struct sock *parent;
	struct toedev *tdev = CPL_IO_STATE(sk)->toedev;
	struct t3cdev *cdev = TOM_DATA(tdev)->cdev;
	const struct request_sock *oreq = sk->sk_user_data;
	struct t3c_tid_entry *t3c_stid;
	struct tid_info *t;

	if (!oreq)
		return -1;        /* somehow we are not on the SYN queue */

	t = &(T3C_DATA(cdev))->tid_maps;
	t3c_stid = lookup_stid(t, oreq->ts_recent);
	parent = ((struct listen_ctx *)t3c_stid->ctx)->lsk;

	bh_lock_sock(parent);
	if (!sock_owned_by_user(parent)) {
		do_abort_syn_rcv(sk, parent);
		send_abort_rpl(skb, tdev, CPL_ABORT_NO_RST);
	} else {
		skb->sk = sk;
		BLOG_SKB_CB(skb)->backlog_rcv = bl_abort_syn_rcv;
		__sk_add_backlog(parent, skb);
	}
	bh_unlock_sock(parent);
	return 0;
}

/*
 * Process abort requests.  If we are waiting for an ABORT_RPL we ignore this
 * request except that we need to reply to it.
 */
static void process_abort_req(struct sock *sk, struct sk_buff *skb)
{
	int rst_status = CPL_ABORT_NO_RST;
	const struct cpl_abort_req_rss *req = cplhdr(skb);

	if (!cplios_flag(sk, CPLIOS_ABORT_REQ_RCVD)) {
		cplios_set_flag(sk, CPLIOS_ABORT_REQ_RCVD);
		cplios_set_flag(sk, CPLIOS_ABORT_SHUTDOWN);
		__kfree_skb(skb);
		return;
	}
	cplios_reset_flag(sk, CPLIOS_ABORT_REQ_RCVD);

	/*
	 * Three cases to consider:
	 * a) We haven't sent an abort_req; close the connection.
	 * b) We have sent a post-close abort_req that will get to TP too late
	 *    and will generate a CPL_ERR_ABORT_FAILED reply.  The reply will
	 *    be ignored and the connection should be closed now.
	 * c) We have sent a regular abort_req that will get to TP too late.
	 *    That will generate an abort_rpl with status 0, wait for it.
	 */
	if (!cplios_flag(sk, CPLIOS_ABORT_RPL_PENDING) ||
	    (is_t3a(CPL_IO_STATE(sk)->toedev) &&
	     cplios_flag(sk, CPLIOS_CLOSE_CON_REQUESTED))) {
		sk->sk_err = abort_status_to_errno(sk, req->status,
						   &rst_status);
		if (!sock_flag(sk, SOCK_DEAD))
			sk->sk_error_report(sk);
		/*
		 * SYN_RECV needs special processing.  If abort_syn_rcv()
		 * returns 0 is has taken care of the abort.
		 */
		if (sk->sk_state == TCP_SYN_RECV && !abort_syn_rcv(sk, skb))
			return;

		t3_release_offload_resources(sk);
		connection_done(sk);
	}

	send_abort_rpl(skb, BLOG_SKB_CB(skb)->dev, rst_status);
}

/*
 * Handle an ABORT_REQ_RSS CPL message.
 */
static int do_abort_req(struct t3cdev *cdev, struct sk_buff *skb, void *ctx)
{
	const struct cpl_abort_req_rss *req = cplhdr(skb);
	struct sock *sk = (struct sock *)ctx;

	if (is_neg_adv_abort(req->status)) {
		__kfree_skb(skb);
		return 0;
	}

	VALIDATE_SOCK(sk);

	/*
	 * Save the offload device in the skb, we may process this message
	 * after the socket has closed.
	 */
	BLOG_SKB_CB(skb)->dev = CPL_IO_STATE(sk)->toedev;

	process_cpl_msg_ref(process_abort_req, sk, skb);
	return 0;
}

static void pass_open_abort(struct sock *child, struct sock *parent,
			    struct sk_buff *skb)
{
	struct toedev *tdev = BLOG_SKB_CB(skb)->dev;

	do_abort_syn_rcv(child, parent);
	if (tdev->ttid == TOE_ID_CHELSIO_T3) {
		struct cpl_pass_accept_rpl *rpl = cplhdr(skb);

		rpl->opt0h = htonl(F_TCAM_BYPASS);
		rpl->opt0l_status = htonl(CPL_PASS_OPEN_REJECT);
		cxgb3_ofld_send(TOM_DATA(tdev)->cdev, skb);
	} else
		kfree_skb(skb);
}

/*
 * Runs from a listener's backlog to abort a child connection that had an
 * ARP failure.
 */
static void bl_pass_open_abort(struct sock *lsk, struct sk_buff *skb)
{
	pass_open_abort(skb->sk, lsk, skb);
}

static void handle_pass_open_arp_failure(struct sock *sk, struct sk_buff *skb)
{
	struct t3cdev *cdev;
	struct sock *parent;
	const struct request_sock *oreq;
	struct t3c_tid_entry *t3c_stid;
	struct tid_info *t;
	/*
	 * If the connection is being aborted due to the parent listening
	 * socket going away there's nothing to do, the ABORT_REQ will close
	 * the connection.
	 */
	if (cplios_flag(sk, CPLIOS_ABORT_RPL_PENDING)) {
		kfree_skb(skb);
		return;
	}

	oreq = sk->sk_user_data;
	cdev = T3C_DEV(sk);
	t = &(T3C_DATA(cdev))->tid_maps;
	t3c_stid = lookup_stid(t, oreq->ts_recent);
	parent = ((struct listen_ctx *)t3c_stid->ctx)->lsk;

	bh_lock_sock(parent);
	if (!sock_owned_by_user(parent))
		pass_open_abort(sk, parent, skb);
	else {
		BLOG_SKB_CB(skb)->backlog_rcv = bl_pass_open_abort;
		__sk_add_backlog(parent, skb);
	}
	bh_unlock_sock(parent);
}

/*
 * Handle an ARP failure for a CPL_PASS_ACCEPT_RPL.  This is treated similarly
 * to an ABORT_REQ_RSS in SYN_RECV as both events need to tear down a SYN_RECV
 * connection.
 */
static void pass_accept_rpl_arp_failure(struct t3cdev *cdev, struct sk_buff *skb)
{
	T3_TCP_INC_STATS_BH(sock_net(skb->sk), TCP_MIB_ATTEMPTFAILS);
	BLOG_SKB_CB(skb)->dev = CPL_IO_STATE(skb->sk)->toedev;
	process_cpl_msg_ref(handle_pass_open_arp_failure, skb->sk, skb);
}

#if defined(ROUTE_REQ)
static struct dst_entry *route_req(struct sock *sk, struct open_request *req)
{
	struct rtable *rt;
	struct flowi fl = { .oif = sk->sk_bound_dev_if,
			    .nl_u = { .ip4_u =
				      { .daddr = req->af.v4_req.rmt_addr,
					.saddr = req->af.v4_req.loc_addr,
					.tos = RT_CONN_FLAGS(sk)}},
			    .proto = IPPROTO_TCP,
			    .uli_u = { .ports =
#ifdef	LINUX_2_4
				       { .sport = sk->sport,
#else
				       { .sport = inet_sk(sk)->inet_sport,
#endif	/* LINUX_2_4 */
					 .dport = req->rmt_port}}
	};

	if (ip_route_output_flow(&rt, &fl, sk, 0)) {
		IP_INC_STATS_BH(IPSTATS_MIB_OUTNOROUTES);
		return NULL;
	}
	return &rt->u.dst;
}
#endif

/*
 * Create a new socket as a child of the listening socket 'lsk' and initialize
 * with the information in the supplied PASS_ACCEPT_REQ message.
 *
 * 'retry' indicates to the caller whether a failure is device-related and the
 * connection should be passed to the host stack, or connection-related and
 * the connection request should be rejected.
 */
static struct sock *mk_pass_sock(struct sock *lsk, struct toedev *dev, int tid,
				 const struct cpl_pass_accept_req *req,
				 int *retry,
				 const struct offload_settings *s)
{
	struct sock *newsk;
	struct cpl_io_state *newcplios;
	struct l2t_entry *e;
	struct dst_entry *dst;
	struct tcp_sock *newtp;
	struct net_device *egress;
	struct request_sock *oreq = reqsk_alloc(&t3_rsk_ops);

	*retry = 0;
	if (!oreq)
		goto out_err;

	tcp_rsk(oreq)->rcv_isn = ntohl(req->rcv_isn);
	inet_rsk(oreq)->rmt_port = req->peer_port;
	t3_set_req_addr(oreq, req->local_ip, req->peer_ip);
	t3_set_req_opt(oreq, NULL);
	if (sysctl_tcp_window_scaling) {
		inet_rsk(oreq)->wscale_ok = 1;
		inet_rsk(oreq)->snd_wscale = req->tcp_options.wsf;
	}

#ifdef CONFIG_SECURITY_NETWORK
	if (security_inet_conn_request(lsk, tcphdr_skb, oreq))
		goto free_or;
#endif

	dst = route_req(lsk, oreq);
	if (!dst)
		goto free_or;

	egress = offload_get_phys_egress(dst->neighbour->dev, NULL, TOE_OPEN);
	if (!egress || TOEDEV(egress) != dev) {
		*retry = 1;                       /* asymmetric route */
		goto free_dst;
	}

	e = t3_l2t_get(TOM_DATA(dev)->cdev, dst->neighbour, egress);
	if (!e) {
		*retry = 1;                       /* out of HW resources */
		goto free_dst;
	}

	newcplios = kzalloc(sizeof *newcplios, GFP_ATOMIC);
	if (!newcplios)
		goto free_l2t;
	newsk = tcp_create_openreq_child(lsk, oreq, tcphdr_skb);
	if (!newsk) {
		kfree(newcplios);
		goto free_l2t;
	}
	CPL_IO_STATE(newsk) = newcplios;

	if (sock_flag(newsk, SOCK_KEEPOPEN))
		inet_csk_delete_keepalive_timer(newsk);
	oreq->ts_recent = G_PASS_OPEN_TID(ntohl(req->tos_tid));
	newsk->sk_user_data = oreq;
	sk_setup_caps(newsk, dst);

	newtp = tcp_sk(newsk);
	init_offload_sk(newsk, dev, tid, e, dst, egress, s);
	newcplios->delack_seq = newtp->rcv_nxt;
	RCV_WSCALE(newtp) = select_rcv_wscale(tcp_full_space(newsk),
					      WSCALE_OK(newtp),
					      newtp->window_clamp);

#ifdef	LINUX_2_4
	newsk->daddr = req->peer_ip;
	newsk->rcv_saddr = req->local_ip;
	newsk->saddr = req->local_ip;
#else
	inet_sk(newsk)->inet_daddr = req->peer_ip;
	inet_sk(newsk)->inet_rcv_saddr = req->local_ip;
	inet_sk(newsk)->inet_saddr = req->local_ip;
#endif	/* LINUX_2_4 */

	lsk->sk_prot->hash(newsk);
	t3_inet_inherit_port(&tcp_hashinfo, lsk, newsk);
	install_offload_ops(newsk);
	bh_unlock_sock(newsk);     // counters tcp_create_openreq_child()
	return newsk;

free_l2t:
	l2t_release(L2DATA(dev), e);	
free_dst:
	dst_release(dst);
free_or:
	__reqsk_free(oreq);
out_err:
	return NULL;
}

/*
 * Populate a reject/tunnel CPL_PASS_ACCEPT_RPL WR.
 */
static void mk_pass_accept_rpl(struct sk_buff *reply_skb,
			       struct sk_buff *req_skb, int cmd)
{
	struct cpl_pass_accept_req *req = cplhdr(req_skb);
	struct cpl_pass_accept_rpl *rpl = cplhdr(reply_skb);
	unsigned int tid = GET_TID(req);

	reply_skb->priority = CPL_PRIORITY_SETUP;
	rpl->wr.wr_hi = htonl(V_WR_OP(FW_WROPCODE_FORWARD));
	OPCODE_TID(rpl) = htonl(MK_OPCODE_TID(CPL_PASS_ACCEPT_RPL, tid));
	rpl->peer_ip = req->peer_ip;   // req->peer_ip not overwritten yet
	rpl->opt0h = htonl(F_TCAM_BYPASS);
	rpl->opt0l_status = htonl(cmd);
	rpl->opt2 = 0;
	rpl->rsvd = rpl->opt2;   /* workaround for HW bug */
}

/*
 * Send a deferred reject to an accept request.
 */
static void reject_pass_request(struct toedev *tdev, struct sk_buff *skb)
{
	struct sk_buff *reply_skb;

	reply_skb = alloc_skb_nofail(sizeof(struct cpl_pass_accept_rpl));
	__skb_put(reply_skb, sizeof(struct cpl_pass_accept_rpl));
	mk_pass_accept_rpl(reply_skb, skb, CPL_PASS_OPEN_REJECT);
	cxgb3_ofld_send(TOM_DATA(tdev)->cdev, reply_skb);
	kfree_skb(skb);
}

static void offload_req_from_pass_accept_req(struct offload_req *oreq,
				      const struct cpl_pass_accept_req *req,
				      const struct sock *listen_sk)
{
	oreq->sip[0] = req->peer_ip;
	oreq->sip[1] = oreq->sip[2] = oreq->sip[3] = 0;
	oreq->dip[0] = req->local_ip;
	oreq->dip[1] = oreq->dip[2] = oreq->dip[3] = 0;
	oreq->sport  = req->peer_port;
	oreq->dport  = req->local_port;
	oreq->ipvers_opentype = (OPEN_TYPE_PASSIVE << 4) | 4;
	oreq->tos = G_PASS_OPEN_TOS(ntohl(req->tos_tid));
	oreq->vlan = req->vlan_tag ? req->vlan_tag & htons(VLAN_VID_MASK) :
				     htons(0xfff);
#ifdef SO_MARK
	oreq->mark = listen_sk->sk_mark;
#else
	oreq->mark = 0;
#endif
}

/*
 * Process a CPL_PASS_ACCEPT_REQ message.  Does the part that needs the socket
 * lock held.  Note that the sock here is a listening socket that is not owned
 * by the TOE.
 */
static void process_pass_accept_req(struct sock *sk, struct sk_buff *skb)
{
	int rt_flags;
	int pass2host;
	struct sock *newsk;
	struct l2t_entry *e;
	struct iff_mac tim;
	struct offload_req orq;
	struct offload_settings settings;
	struct sk_buff *reply_skb, *ddp_skb = NULL;
	struct cpl_pass_accept_rpl *rpl;
	struct cpl_pass_accept_req *req = cplhdr(skb);
	unsigned int tid = GET_TID(req);
	struct toedev *tdev = BLOG_SKB_CB(skb)->dev;
	struct tom_data *d = TOM_DATA(tdev);
	struct t3cdev *cdev = d->cdev;

	reply_skb = get_cpl_reply_skb(skb, sizeof(*rpl), GFP_ATOMIC);
	if (unlikely(!reply_skb)) {
		if (tdev->ttid == TOE_ID_CHELSIO_T3)
			t3_defer_reply(skb, tdev, reject_pass_request);
		else {
			cxgb3_queue_tid_release(cdev, tid);
			kfree_skb(skb);
		}
		goto out;
	}

	if (sk->sk_state != TCP_LISTEN)
		goto reject;
	if (inet_csk_reqsk_queue_is_full(sk))
		goto reject;
	if (sk_acceptq_is_full(sk) && d->conf.soft_backlog_limit)
		goto reject;

	tim.mac_addr = req->dst_mac;
	tim.vlan_tag = ntohs(req->vlan_tag);
	if (cdev->ctl(cdev, GET_IFF_FROM_MAC, &tim) < 0 || !tim.dev)
		goto reject;

	if (ip_route_input(skb, req->local_ip, req->peer_ip,
			   G_PASS_OPEN_TOS(ntohl(req->tos_tid)), tim.dev))
		goto reject;
	rt_flags = ((struct rtable *)skb_dst(skb))->rt_flags &
		(RTCF_BROADCAST | RTCF_MULTICAST | RTCF_LOCAL);
	dst_release(skb_dst(skb));	// done with the input route, release it
	skb_dst_set(skb, NULL);
	if (rt_flags != RTCF_LOCAL)
		goto reject;

	offload_req_from_pass_accept_req(&orq, req, sk);
	settings = *lookup_ofld_policy(tdev, &orq, d->conf.cop_managed_offloading);
#ifndef LINUX_2_4
	rcu_read_unlock();
#else
	read_unlock(&tdev->policy_lock);
#endif

	newsk = mk_pass_sock(sk, tdev, tid, req, &pass2host, &settings);
	if (!newsk)
		goto reject;

	/*
	 * Our use of sk_user_data for sockets on the SYNQ can confuse the
	 * sanitization of socket callbacks in the RX_DATA handler.  Since
	 * there aren't any kernel apps that need to sanitize the callbacks
	 * of passively opened sockets we solve the problem by skipping
	 * the sanitization on such sockets.
	 */
	cplios_set_flag(newsk, CPLIOS_CALLBACKS_CHKD);

	inet_csk_reqsk_queue_added(sk, TCP_TIMEOUT_INIT);
	synq_add(sk, newsk);

	/* Don't get a reference, newsk starts out with ref count 2 */
	cxgb3_insert_tid(cdev, d->client, newsk, tid);

	if (CPL_IO_STATE(newsk)->ulp_mode == ULP_MODE_TCPDDP) {
		ddp_skb = alloc_skb(sizeof(struct cpl_set_tcb_field),
				    GFP_ATOMIC);
		if (!ddp_skb)
			CPL_IO_STATE(newsk)->ulp_mode = ULP_MODE_NONE;
	}

	reply_skb->sk = newsk;
	set_arp_failure_handler(reply_skb, pass_accept_rpl_arp_failure);

	e = CPL_IO_STATE(newsk)->l2t_entry;

	rpl = cplhdr(reply_skb);
	rpl->wr.wr_hi = htonl(V_WR_OP(FW_WROPCODE_FORWARD));
	OPCODE_TID(rpl) = htonl(MK_OPCODE_TID(CPL_PASS_ACCEPT_RPL, tid));
	rpl->peer_ip = req->peer_ip;	// req->peer_ip is not overwritten
	rpl->opt0h = htonl(calc_opt0h(newsk) | V_L2T_IDX(e->idx) |
			   V_TX_CHANNEL(e->chan_idx));
	rpl->opt0l_status = htonl(calc_opt0l(newsk) |
				  CPL_PASS_OPEN_ACCEPT);
	rpl->opt2 = htonl(calc_opt2(newsk, &settings));

	rpl->rsvd = rpl->opt2;                /* workaround for HW bug */
	reply_skb->priority = mkprio(CPL_PRIORITY_SETUP, newsk);
	l2t_send(cdev, reply_skb, e);
	kfree_skb(skb);

	if (ddp_skb) {
		set_arp_failure_handler(ddp_skb, arp_failure_discard);
		__set_tcb_field(newsk, ddp_skb, W_TCB_RX_DDP_FLAGS,
				V_TF_DDP_OFF(1) |
				TP_DDP_TIMER_WORKAROUND_MASK,
				V_TF_DDP_OFF(1) |
				TP_DDP_TIMER_WORKAROUND_VAL, 1);
		l2t_send(cdev, ddp_skb, e);
	}
	return;

reject:
	if (tdev->ttid == TOE_ID_CHELSIO_T3)
		mk_pass_accept_rpl(reply_skb, skb, CPL_PASS_OPEN_REJECT);
	else {
		__skb_trim(reply_skb, 0);
		mk_tid_release(reply_skb, NULL, tid);
	}
	cxgb3_ofld_send(cdev, reply_skb);
	kfree_skb(skb);
out:
	T3_TCP_INC_STATS_BH(sock_net(sk), TCP_MIB_ATTEMPTFAILS);
}

/*
 * Handle a CPL_PASS_ACCEPT_REQ message.
 */
static int do_pass_accept_req(struct t3cdev *cdev, struct sk_buff *skb,
			      void *ctx)
{
	struct cpl_pass_accept_req *req = cplhdr(skb);
	struct listen_ctx *listen_ctx = (struct listen_ctx *)ctx;
	struct sock *lsk = listen_ctx->lsk;
	struct tom_data *d = listen_ctx->tom_data;

#if VALIDATE_TID
	unsigned int tid = GET_TID(req);
	struct tid_info *t = &(T3C_DATA(cdev))->tid_maps;

	if (unlikely(!lsk)) {
		printk(KERN_ERR "%s: PASS_ACCEPT_REQ had unknown STID %lu\n",
		       cdev->name,
		       (unsigned long)((union listen_entry *)ctx -
					t->stid_tab));
		return CPL_RET_BUF_DONE;
	}
	if (unlikely(tid >= t->ntids)) {
		printk(KERN_ERR "%s: passive open TID %u too large\n",
		       cdev->name, tid);
		return CPL_RET_BUF_DONE;
	}
	/*
	 * For T3A the current user of the TID may have closed but its last
	 * message(s) may have been backlogged so the TID appears to be still
	 * in use.  Just take the TID away, the connection can close at its
	 * own leisure.  For T3B this situation is a bug.
	 */
	if (!valid_new_tid(t, tid) &&
	    cdev->type != T3A) {
		printk(KERN_ERR "%s: passive open uses existing TID %u\n",
		       cdev->name, tid);
		return CPL_RET_BUF_DONE;
	}
#endif

	BLOG_SKB_CB(skb)->dev = &d->tdev;
	process_cpl_msg(process_pass_accept_req, lsk, skb);
	return 0;
}

/*
 * Add a passively open socket to its parent's accept queue.  Note that the
 * child may be in any state by now, including TCP_CLOSE.  We can guarantee
 * though that it has not been orphaned yet.
 */
static void add_pass_open_to_parent(struct sock *child, struct sock *lsk,
				    struct toedev *dev)
{
	struct request_sock *oreq;

	/*
	 * If the server is closed it has already killed its embryonic
	 * children.  There is nothing further to do about child.
	 */
	if (lsk->sk_state != TCP_LISTEN)
		return;

	oreq = child->sk_user_data;
	child->sk_user_data = NULL;

	inet_csk_reqsk_queue_removed(lsk, oreq);
	synq_remove(child);

	if (sk_acceptq_is_full(lsk) && !TOM_TUNABLE(dev, soft_backlog_limit)) {
		T3_NET_INC_STATS_BH(sock_net(lsk), LINUX_MIB_LISTENOVERFLOWS);
		T3_NET_INC_STATS_BH(sock_net(lsk), LINUX_MIB_LISTENDROPS);
		__reqsk_free(oreq);
		add_to_reap_list(child);
	} else {
		inet_csk_reqsk_queue_add(lsk, oreq, child);
		lsk->sk_data_ready(lsk, 0);
	}
}

/*
 * This is run from a listener's backlog to add a child socket to its accept
 * queue.  Note that at this point the child is not locked and we intentionally
 * do not bother locking it as the only fields we may be using are
 * sk_user_data, and the open request and there aren't any concurrent users
 * for them.
 */
static void bl_add_pass_open_to_parent(struct sock *lsk, struct sk_buff *skb)
{
	struct sock *child = skb->sk;

	skb->sk = NULL;
	add_pass_open_to_parent(child, lsk, BLOG_SKB_CB(skb)->dev);
	__kfree_skb(skb);
}

/*
 * Called when a connection is established to translate the TCP options
 * reported by HW to Linux's native format.
 */
static void assign_rxopt(struct sock *sk, unsigned int opt)
{
	const struct t3c_data *td = T3C_DATA(T3C_DEV(sk));
	struct tcp_sock *tp = tcp_sk(sk);

	MSS_CLAMP(tp)	      = td->mtus[G_TCPOPT_MSS(opt)] - 40;
	tp->mss_cache         = MSS_CLAMP(tp);
	tp->tcp_header_len    = sizeof(struct tcphdr);
	TSTAMP_OK(tp)         = G_TCPOPT_TSTAMP(opt);
	SACK_OK(tp)           = G_TCPOPT_SACK(opt);
	WSCALE_OK(tp)         = G_TCPOPT_WSCALE_OK(opt);
	SND_WSCALE(tp)        = G_TCPOPT_SND_WSCALE(opt);
	if (!WSCALE_OK(tp))
		RCV_WSCALE(tp) = 0;
	if (TSTAMP_OK(tp)) {
		tp->tcp_header_len += TCPOLEN_TSTAMP_ALIGNED;
		tp->mss_cache -= TCPOLEN_TSTAMP_ALIGNED;
	}
}

/*
 * Completes some final bits of initialization for just established connections
 * and changes their state to TCP_ESTABLISHED.
 *
 * snd_isn here is the ISN after the SYN, i.e., the true ISN + 1.
 */
static void make_established(struct sock *sk, u32 snd_isn, unsigned int opt)
{
	struct tcp_sock *tp = tcp_sk(sk);

	tp->pushed_seq = tp->write_seq = tp->snd_nxt = tp->snd_una = snd_isn;
	inet_sk(sk)->inet_id = tp->write_seq ^ jiffies;
	assign_rxopt(sk, opt);

	/*
	 * Causes the first RX_DATA_ACK to supply any Rx credits we couldn't
	 * pass through opt0.
	 */
	if (tp->rcv_wnd > (M_RCV_BUFSIZ << 10))
		tp->rcv_wup -= tp->rcv_wnd - (M_RCV_BUFSIZ << 10);

	dst_confirm(sk->sk_dst_cache);

	/*
	 * tcp_poll() does not lock socket, make sure initial values are
	 * committed before changing to ESTABLISHED.
	 */
	mb();
	tcp_set_state(sk, TCP_ESTABLISHED);
}

/*
 * Process a CPL_PASS_ESTABLISH message.  XXX a lot of the locking doesn't work
 * if we are in TCP_SYN_RECV due to crossed SYNs
 */
static int do_pass_establish(struct t3cdev *cdev, struct sk_buff *skb,
			     void *ctx)
{
	struct cpl_pass_establish *req = cplhdr(skb);
	struct sock *lsk, *sk = (struct sock *)ctx;
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	struct toedev *tdev = cplios->toedev;

	VALIDATE_SOCK(sk);

	bh_lock_sock(sk);
	if (unlikely(sock_owned_by_user(sk))) {
		// This can only happen in simultaneous opens.  XXX TBD
		__kfree_skb(skb);
	} else {
		// Complete socket initialization now that we have the SND_ISN
		struct t3c_tid_entry *t3c_stid;
		struct tid_info *t;
		unsigned int stid;

		cplios->wr_max = cplios->wr_avail = TOM_TUNABLE(tdev, max_wrs);
		cplios->wr_unacked = 0;
		cplios->rss_cpu_idx = G_QNUM(ntohl(skb->csum));
		make_established(sk, ntohl(req->snd_isn), ntohs(req->tcp_opt));

		if (unlikely(sk->sk_socket)) {   // simultaneous opens only
			sk->sk_state_change(sk);
			sk_wake_async(sk, 0, POLL_OUT);
		}

		/*
		 * The state for the new connection is now up to date.
		 * Next check if we should add the connection to the parent's
		 * accept queue.  When the parent closes it resets connections
		 * on its SYN queue, so check if we are being reset.  If so we
		 * don't need to do anything more, the coming ABORT_RPL will
		 * destroy this socket.  Otherwise move the connection to the
		 * accept queue.
		 *
		 * Note that we reset the synq before closing the server so if
		 * we are not being reset the stid is still open.
		 */
		if (unlikely(synq_empty(sk))) {
			/* removed from synq */
			__kfree_skb(skb);
			goto unlock;
		}

		stid = G_PASS_OPEN_TID(ntohl(req->tos_tid));
		t = &(T3C_DATA(cdev))->tid_maps;
		t3c_stid = lookup_stid(t, stid);
		lsk = ((struct listen_ctx *)t3c_stid->ctx)->lsk;

		bh_lock_sock(lsk);
		if (likely(!sock_owned_by_user(lsk))) {
			__kfree_skb(skb);
			add_pass_open_to_parent(sk, lsk, tdev);
		} else {
			skb->sk = sk;
			BLOG_SKB_CB(skb)->dev = tdev;
			BLOG_SKB_CB(skb)->backlog_rcv = bl_add_pass_open_to_parent;
			__sk_add_backlog(lsk, skb);
		}
		bh_unlock_sock(lsk);
	}
unlock:
	bh_unlock_sock(sk);
	return 0;
}

/*
 * Fill in the right TID for CPL messages waiting in the out-of-order queue
 * and send them to the TOE.
 */
static void fixup_and_send_ofo(struct sock *sk)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	struct sk_buff *skb;
	struct toedev *tdev = cplios->toedev;
	struct tcp_sock *tp = tcp_sk(sk);
	unsigned int tid = cplios->tid;

	while ((skb = __skb_dequeue(&tp->out_of_order_queue)) != NULL) {
		/*
		 * A variety of messages can be waiting but the fields we'll
		 * be touching are common to all so any message type will do.
		 */
		struct cpl_close_con_req *p = cplhdr(skb);

		p->wr.wr_lo = htonl(V_WR_TID(tid));
		OPCODE_TID(p) = htonl(MK_OPCODE_TID(p->ot.opcode, tid));
		cxgb3_ofld_send(TOM_DATA(tdev)->cdev, skb);
	}
}

/*
 * Adjust buffers already in write queue after a SYN_SENT->ESTABLISHED
 * transition.  For TX_DATA we need to adjust the start sequence numbers, and
 * for other packets we need to adjust the TID.  TX_DATA packets don't have
 * headers yet and so not TIDs.
 */
static void fixup_pending_writeq_buffers(struct sock *sk)
{
	struct sk_buff *skb;
	struct tcp_sock *tp = tcp_sk(sk);
	unsigned int tid = CPL_IO_STATE(sk)->tid;

	skb_queue_walk(&sk->sk_write_queue, skb) {
		if (ULP_SKB_CB(skb)->flags & ULPCB_FLAG_NEED_HDR) {
			ULP_SKB_CB(skb)->seq = tp->write_seq;
			tp->write_seq += skb->len + ulp_extra_len(skb);
		} else {
			struct cpl_close_con_req *p = cplhdr(skb);

			p->wr.wr_lo = htonl(V_WR_TID(tid));
			OPCODE_TID(p) = htonl(MK_OPCODE_TID(p->ot.opcode, tid));
		}
	}
}

/*
 * Updates socket state from an active establish CPL message.  Runs with the
 * socket lock held.
 */
static void sock_act_establish(struct sock *sk, struct sk_buff *skb)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	struct cpl_act_establish *req = cplhdr(skb);
	u32 rcv_isn = ntohl(req->rcv_isn);	/* real RCV_ISN + 1 */
	struct tcp_sock *tp = tcp_sk(sk);

	if (unlikely(sk->sk_state != TCP_SYN_SENT))
		printk(KERN_ERR "TID %u expected SYN_SENT, found %d\n",
		       cplios->tid, sk->sk_state);

	tp->rcv_tstamp = tcp_time_stamp;
	cplios->delack_seq = tp->copied_seq = tp->rcv_wup = tp->rcv_nxt = rcv_isn;
	make_established(sk, ntohl(req->snd_isn), ntohs(req->tcp_opt));

#if defined(CONFIG_SECURITY_NETWORK) && defined(SEC_INET_CONN_ESTABLISHED)
	security_inet_conn_estab(sk, tcphdr_skb);
#endif

	/*
	 * Now that we finally have a TID send any CPL messages that we had to
	 * defer for lack of a TID.
	 */
	if (skb_queue_len(&tp->out_of_order_queue))
		fixup_and_send_ofo(sk);

	if (likely(!sock_flag(sk, SOCK_DEAD))) {
		sk->sk_state_change(sk);
		sk_wake_async(sk, 0, POLL_OUT);
	}

	__kfree_skb(skb);

	/*
	 * Currently the send queue must be empty at this point because the
	 * socket layer does not send anything before a connection is
	 * established.  To be future proof though we handle the possibility
	 * that there are pending buffers to send (either TX_DATA or
	 * CLOSE_CON_REQ).  First we need to adjust the sequence number of the
	 * buffers according to the just learned write_seq, and then we send
	 * them on their way.
	 */
	fixup_pending_writeq_buffers(sk);
	if (t3_push_frames(sk, 1))
		sk->sk_write_space(sk);
}

/*
 * Process a CPL_ACT_ESTABLISH message.
 */
static int do_act_establish(struct t3cdev *cdev, struct sk_buff *skb, void *ctx)
{
	struct cpl_act_establish *req = cplhdr(skb);
	unsigned int tid = GET_TID(req);
	unsigned int atid = G_PASS_OPEN_TID(ntohl(req->tos_tid));
	struct sock *sk = (struct sock *)ctx;
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	struct toedev *tdev = cplios->toedev;
	struct tom_data *d = TOM_DATA(tdev);

	/*
	 * It's OK if the TID is currently in use, the owning socket may have
	 * backlogged its last CPL message(s).  Just take it away.
	 */
	CPL_IO_STATE(sk)->tid = tid;
	sk_insert_tid(d, sk, tid);
	free_atid(cdev, atid);

	cplios->rss_cpu_idx = G_QNUM(ntohl(skb->csum));

	process_cpl_msg(sock_act_establish, sk, skb);
	return 0;
}

/*
 * Process an acknowledgment of WR completion.  Advance snd_una and send the
 * next batch of work requests from the write queue.
 */
static void wr_ack(struct sock *sk, struct sk_buff *skb)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	struct cpl_wr_ack *hdr = cplhdr(skb);
	unsigned int credits = ntohs(hdr->credits);
	u32 snd_una = ntohl(hdr->snd_una);

	cplios->wr_avail += credits;

	/*
	 * If the last write request in the queue with a request completion
	 * flag has been consumed, reset our bookeepping.
	 */
	if (cplios->wr_unacked > cplios->wr_max - cplios->wr_avail)
		cplios->wr_unacked = cplios->wr_max - cplios->wr_avail;

	while (credits) {
		struct sk_buff *p = peek_wr(sk);

		if (unlikely(!p)) {
			printk(KERN_ERR "%u WR_ACK credits for TID %u with "
			       "nothing pending, state %u\n",
			       credits, cplios->tid, sk->sk_state);
			break;
		}
		if (unlikely(credits < p->csum)) {
#if DEBUG_WR > 1
			struct tx_data_wr *w = cplhdr(p);

			printk(KERN_ERR
			       "TID %u got %u WR credits, need %u, len %u, "
			       "main body %u, frags %u, seq # %u, ACK una %u,"
			       " ACK nxt %u, WR_AVAIL %u, WRs pending %u\n",
			       cplios->tid, credits, p->csum, p->len,
			       p->len - p->data_len, skb_shinfo(p)->nr_frags,
			       ntohl(w->sndseq), snd_una, ntohl(hdr->snd_nxt),
			       cplios->wr_avail, count_pending_wrs(sk) - credits);
#endif
			p->csum -= credits;
			break;
		} else {
			dequeue_wr(sk);
			credits -= p->csum;
			free_wr_skb(p);
		}
	}

#if DEBUG_WR
	check_wr_invariants(sk);
#endif

	if (unlikely(before(snd_una, tp->snd_una))) {
#if VALIDATE_SEQ
		struct tom_data *d = TOM_DATA(cplios->toedev);

		printk(KERN_ERR "%s: unexpected sequence # %u in WR_ACK "
		       "for TID %u, snd_una %u\n", (&d->tdev)->name, snd_una,
		       cplios->tid, tp->snd_una);
#endif
		goto out_free;
	}

	if (tp->snd_una != snd_una) {
		tp->snd_una = snd_una;
		dst_confirm(sk->sk_dst_cache);
		tp->rcv_tstamp = tcp_time_stamp;
		if (tp->snd_una == tp->snd_nxt)
			cplios_reset_flag(sk, CPLIOS_TX_WAIT_IDLE);
	}

	/*
	 * If there's more data queued up, see if we can get it into the write
	 * queue ...  If we're able to push any data into the write queue,
	 * free up socket send buffer space.
	 */
	if (skb_queue_len(&sk->sk_write_queue) && t3_push_frames(sk, 0))
		sk->sk_write_space(sk);
out_free:
	__kfree_skb(skb);
}

/*
 * Handler for TX_DATA_ACK CPL messages.
 */
static int do_wr_ack(struct t3cdev *dev, struct sk_buff *skb, void *ctx)
{
	struct sock *sk = (struct sock *)ctx;

	VALIDATE_SOCK(sk);

	process_cpl_msg(wr_ack, sk, skb);
	return 0;
}

/*
 * Handler for TRACE_PKT CPL messages.  Just sink these packets.
 */
static int do_trace_pkt(struct t3cdev *dev, struct sk_buff *skb, void *ctx)
{
	__kfree_skb(skb);
	return 0;
}

/*
 * Disconnect offloaded established but not yet accepted connections sitting
 * on a server's accept_queue.  We just send an ABORT_REQ at this point and
 * finish off the disconnect later as we may need to wait for the ABORT_RPL.
 */
void t3_disconnect_acceptq(struct sock *listen_sk)
{
	struct request_sock **pprev;

	pprev = ACCEPT_QUEUE(listen_sk);
	while (*pprev) {
		struct request_sock *req = *pprev;

		if (req->rsk_ops == RSK_OPS(&t3_rsk_ops)) {       // one of ours
			struct sock *child = req->sk;

			*pprev = req->dl_next;
			sk_acceptq_removed(listen_sk);
			__reqsk_free(req);
			release_tcp_port(child);
			reset_listen_child(child);
		} else
			pprev = &req->dl_next;
	}
}

/*
 * Reset offloaded connections sitting on a server's syn queue.  As above
 * we send ABORT_REQ and finish off when we get ABORT_RPL.
 */
void t3_reset_synq(struct sock *listen_sk)
{
	struct sock **nextsk = &synq_next(listen_sk);

	/*
	 * Note: the while predicate below is a little tricky because the
	 * fields used to implement the doubly linked list have been hijacked
	 * out of the (struct tcp_sock) portion of the socket.  If the fields
	 * were solely ours to use, then the test of "*nextsk != listen_sk"
	 * would be enough.  But when we empty the SYN queue, the state of
	 * those hijacked fields are reset to the values expected by Linux
	 * and "*nextsk" will no longer have any legitimate meaning for us.
	 * Thus the double predicate of testing for both the SYN queue being
	 * empty (which is implemented in a Linux version-dependent fashion)
	 * and making sure the next socket to process isn't our listen
	 * socket ...
	 */
	while (!synq_empty(listen_sk) && *nextsk != listen_sk) {
		struct sock *child = *nextsk;

		if (child->sk_prot == &t3_tcp_prot.proto) {
			/* one of ours */
			cleanup_syn_rcv_conn(child, listen_sk);
			release_tcp_port(child);
			reset_listen_child(child);
		} else {
			/* some other offloaded socket ... */
			nextsk = &synq_next(*nextsk);
		}
	}
}

int t3_setup_ppods(struct sock *sk, const struct ddp_gather_list *gl,
		   unsigned int nppods, unsigned int tag, unsigned int maxoff,
		   unsigned int pg_off, unsigned int color)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	unsigned int i, j, pidx;
	struct pagepod *p;
	struct sk_buff *skb;
	struct ulp_mem_io *req;
	struct tcp_sock *tp = tcp_sk(sk);
	unsigned int tid = cplios->tid;
	const struct tom_data *td = TOM_DATA(cplios->toedev);
	unsigned int ppod_addr = tag * PPOD_SIZE + td->ddp_llimit;

	for (i = 0; i < nppods; ++i) {
		skb = alloc_ctrl_skb(tp, sizeof(*req) + PPOD_SIZE);
		skb->priority = mkprio(CPL_PRIORITY_CONTROL, sk);
		req = (struct ulp_mem_io *)__skb_put(skb,
						     sizeof(*req) + PPOD_SIZE);
		req->wr.wr_hi = htonl(V_WR_OP(FW_WROPCODE_BYPASS));
		req->cmd_lock_addr = htonl(V_ULP_MEMIO_ADDR(ppod_addr >> 5) |
					   V_ULPTX_CMD(ULP_MEM_WRITE));
		req->len = htonl(V_ULP_MEMIO_DATA_LEN(PPOD_SIZE / 32) |
				 V_ULPTX_NFLITS(PPOD_SIZE / 8 + 1));

		p = (struct pagepod *)(req + 1);
		if (likely(i < nppods - NUM_SENTINEL_PPODS)) {
			p->vld_tid = htonl(F_PPOD_VALID | V_PPOD_TID(tid));
			p->pgsz_tag_color = htonl(V_PPOD_TAG(tag) |
						  V_PPOD_COLOR(color));
			p->max_offset = htonl(maxoff);
			p->page_offset = htonl(pg_off);
			p->rsvd = 0;
			for (pidx = 4 * i, j = 0; j < 5; ++j, ++pidx)
				p->addr[j] = pidx < gl->nelem ?
				     cpu_to_be64(gl->phys_addr[pidx]) : 0;
		} else
			p->vld_tid = 0;   /* mark sentinel page pods invalid */
		send_or_defer(sk, tp, skb, 0);
		ppod_addr += PPOD_SIZE;
	}
	return 0;
}

/*
 * Build a CPL_BARRIER message as payload of a ULP_TX_PKT command.
 */
static inline void mk_cpl_barrier_ulp(struct cpl_barrier *b)
{
	struct ulp_txpkt *txpkt = (struct ulp_txpkt *)b;

	txpkt->cmd_dest = htonl(V_ULPTX_CMD(ULP_TXPKT));
	txpkt->len = htonl(V_ULPTX_NFLITS(sizeof(*b) / 8));
	b->opcode = CPL_BARRIER;
}

/*
 * Build a CPL_GET_TCB message as payload of a ULP_TX_PKT command.
 */
static inline void mk_get_tcb_ulp(struct cpl_get_tcb *req, unsigned int tid,
				  unsigned int cpuno)
{
	struct ulp_txpkt *txpkt = (struct ulp_txpkt *)req;

	txpkt = (struct ulp_txpkt *)req;
	txpkt->cmd_dest = htonl(V_ULPTX_CMD(ULP_TXPKT));
	txpkt->len = htonl(V_ULPTX_NFLITS(sizeof(*req) / 8));
	OPCODE_TID(req) = htonl(MK_OPCODE_TID(CPL_GET_TCB, tid));
	req->cpuno = htons(cpuno);
}

/*
 * Build a CPL_SET_TCB_FIELD message as payload of a ULP_TX_PKT command.
 */
static inline void mk_set_tcb_field_ulp(struct cpl_set_tcb_field *req,
				unsigned int tid, unsigned int word,
				u64 mask, u64 val)
{
	struct ulp_txpkt *txpkt = (struct ulp_txpkt *)req;

	txpkt->cmd_dest = htonl(V_ULPTX_CMD(ULP_TXPKT));
	txpkt->len = htonl(V_ULPTX_NFLITS(sizeof(*req) / 8));
	OPCODE_TID(req) = htonl(MK_OPCODE_TID(CPL_SET_TCB_FIELD, tid));
	req->reply = V_NO_REPLY(1);
	req->cpu_idx = 0;
	req->word = htons(word);
	req->mask = cpu_to_be64(mask);
	req->val = cpu_to_be64(val);
}

/*
 * Build a CPL_RX_DATA_ACK message as payload of a ULP_TX_PKT command.
 */
static void mk_rx_data_ack_ulp(struct sock *sk, struct cpl_rx_data_ack *ack,
			       unsigned int tid,
			       unsigned int credits)
{
	struct ulp_txpkt *txpkt = (struct ulp_txpkt *)ack;
	u32 dack;

	dack = t3_select_delack(sk);

	txpkt->cmd_dest = htonl(V_ULPTX_CMD(ULP_TXPKT));
	txpkt->len = htonl(V_ULPTX_NFLITS(sizeof(*ack) / 8));
	OPCODE_TID(ack) = htonl(MK_OPCODE_TID(CPL_RX_DATA_ACK, tid));
	ack->credit_dack = htonl(F_RX_MODULATE | F_RX_DACK_CHANGE |
				 V_RX_DACK_MODE(dack) |
				 V_RX_CREDITS(credits));
}

void t3_cancel_ddpbuf(struct sock *sk, unsigned int bufidx)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	unsigned int wrlen;
	struct sk_buff *skb;
	struct work_request_hdr *wr;
	struct cpl_barrier *lock;
	struct cpl_set_tcb_field *req;
	struct cpl_get_tcb *getreq;
	struct ddp_state *p = DDP_STATE(sk);

	wrlen = sizeof(*wr) + sizeof(*req) + 2 * sizeof(*lock) +
		sizeof(*getreq);
	skb = alloc_ctrl_skb(tp, wrlen);
	skb->priority = mkprio(CPL_PRIORITY_CONTROL, sk);

	wr = (struct work_request_hdr *)__skb_put(skb, wrlen);
	wr->wr_hi = htonl(V_WR_OP(FW_WROPCODE_BYPASS));

	lock = (struct cpl_barrier *)(wr + 1);
	mk_cpl_barrier_ulp(lock);

	req = (struct cpl_set_tcb_field *)(lock + 1);

	/* Hmmm, not sure if this actually a good thing: reactivating
	 * the other buffer might be an issue if it has been completed
	 * already. However, that is unlikely, since the fact that the UBUF
	 * is not completed indicates that there is no oustanding data.
	 */
	if (bufidx == 0)
		mk_set_tcb_field_ulp(req, cplios->tid, W_TCB_RX_DDP_FLAGS,
				     V_TF_DDP_ACTIVE_BUF(1) |
				     V_TF_DDP_BUF0_VALID(1),
				     V_TF_DDP_ACTIVE_BUF(1));
	else
		mk_set_tcb_field_ulp(req, cplios->tid, W_TCB_RX_DDP_FLAGS,
				     V_TF_DDP_ACTIVE_BUF(1) |
				     V_TF_DDP_BUF1_VALID(1), 0);

	getreq = (struct cpl_get_tcb *)(req + 1);
	mk_get_tcb_ulp(getreq, cplios->tid, cplios->rss_cpu_idx);

	mk_cpl_barrier_ulp((struct cpl_barrier *)(getreq + 1));

	/* Keep track of the number of oustanding CPL_GET_TCB requests
	 */
	p->get_tcb_count++;

#ifdef T3_TRACE
	T3_TRACE1(TIDTB(sk),
		  "t3_cancel_ddpbuf: bufidx %u", bufidx);
#endif
	cxgb3_ofld_send(T3C_DEV(sk), skb);
}

/**
 * t3_overlay_ddpbuf - overlay an existing DDP buffer with a new one
 * @sk: the socket associated with the buffers
 * @bufidx: index of HW DDP buffer (0 or 1)
 * @tag0: new tag for HW buffer 0
 * @tag1: new tag for HW buffer 1
 * @len: new length for HW buf @bufidx
 *
 * Sends a compound WR to overlay a new DDP buffer on top of an existing
 * buffer by changing the buffer tag and length and setting the valid and
 * active flag accordingly.  The caller must ensure the new buffer is at
 * least as big as the existing one.  Since we typically reprogram both HW
 * buffers this function sets both tags for convenience. Read the TCB to
 * determine how made data was written into the buffer before the overlay
 * took place.
 */
void t3_overlay_ddpbuf(struct sock *sk, unsigned int bufidx, unsigned int tag0,
	 	       unsigned int tag1, unsigned int len)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	unsigned int wrlen;
	struct sk_buff *skb;
	struct work_request_hdr *wr;
	struct cpl_get_tcb *getreq;
	struct cpl_set_tcb_field *req;
	struct ddp_state *p = DDP_STATE(sk);

	wrlen = sizeof(*wr) + 3 * sizeof(*req) + sizeof(*getreq);
	skb = alloc_ctrl_skb(tp, wrlen);
	skb->priority = mkprio(CPL_PRIORITY_CONTROL, sk);

	wr = (struct work_request_hdr *)__skb_put(skb, wrlen);

	/* Set the ATOMIC flag to make sure that TP processes the following
	 * CPLs in an atomic manner and no wire segments can be interleaved.
	 */
	wr->wr_hi = htonl(V_WR_OP(FW_WROPCODE_BYPASS) | F_WR_ATOMIC);

	req = (struct cpl_set_tcb_field *)(wr + 1);
	mk_set_tcb_field_ulp(req, cplios->tid, W_TCB_RX_DDP_BUF0_TAG,
			     V_TCB_RX_DDP_BUF0_TAG(M_TCB_RX_DDP_BUF0_TAG) |
			     V_TCB_RX_DDP_BUF1_TAG(M_TCB_RX_DDP_BUF1_TAG) << 32,
			     V_TCB_RX_DDP_BUF0_TAG(tag0) |
			     V_TCB_RX_DDP_BUF1_TAG((u64)tag1) << 32);
	req++;
	if (bufidx == 0) {
		mk_set_tcb_field_ulp(req, cplios->tid, W_TCB_RX_DDP_BUF0_LEN,
			    V_TCB_RX_DDP_BUF0_LEN(M_TCB_RX_DDP_BUF0_LEN),
			    V_TCB_RX_DDP_BUF0_LEN((u64)len));
		req++;
		mk_set_tcb_field_ulp(req, cplios->tid, W_TCB_RX_DDP_FLAGS,
			    V_TF_DDP_PUSH_DISABLE_0(1) |
			    V_TF_DDP_BUF0_VALID(1) | V_TF_DDP_ACTIVE_BUF(1),
			    V_TF_DDP_PUSH_DISABLE_0(0) |
			    V_TF_DDP_BUF0_VALID(1));
	} else {
		mk_set_tcb_field_ulp(req, cplios->tid, W_TCB_RX_DDP_BUF1_LEN,
			    V_TCB_RX_DDP_BUF1_LEN(M_TCB_RX_DDP_BUF1_LEN),
			    V_TCB_RX_DDP_BUF1_LEN((u64)len));
		req++;
		mk_set_tcb_field_ulp(req, cplios->tid, W_TCB_RX_DDP_FLAGS,
			    V_TF_DDP_PUSH_DISABLE_1(1) |
			    V_TF_DDP_BUF1_VALID(1) | V_TF_DDP_ACTIVE_BUF(1),
			    V_TF_DDP_PUSH_DISABLE_1(0) |
			    V_TF_DDP_BUF1_VALID(1) | V_TF_DDP_ACTIVE_BUF(1));
	}

	getreq = (struct cpl_get_tcb *)(req + 1);
	mk_get_tcb_ulp(getreq, cplios->tid, cplios->rss_cpu_idx);

	/* Keep track of the number of oustanding CPL_GET_TCB requests
	 */
	p->get_tcb_count++;

#ifdef T3_TRACE
	T3_TRACE4(TIDTB(sk),
		  "t3_overlay_ddpbuf: bufidx %u tag0 %u tag1 %u "
		  "len %d",
		  bufidx, tag0, tag1, len);
#endif
	cxgb3_ofld_send(T3C_DEV(sk), skb);
}

/*
 * Sends a compound WR containing all the CPL messages needed to program the
 * two HW DDP buffers, namely optionally setting up the length and offset of
 * each buffer, programming the DDP flags, and optionally sending RX_DATA_ACK.
 */
void t3_setup_ddpbufs(struct sock *sk, unsigned int len0, unsigned int offset0,
		      unsigned int len1, unsigned int offset1,
		      u64 ddp_flags, u64 flag_mask, int modulate)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	unsigned int wrlen;
	struct sk_buff *skb;
	struct work_request_hdr *wr;
	struct cpl_set_tcb_field *req;
	struct tcp_sock *tp = tcp_sk(sk);

	wrlen = sizeof(*wr) + sizeof(*req) + (len0 ? sizeof(*req) : 0) +
		(len1 ? sizeof(*req) : 0) +
		(modulate ? sizeof(struct cpl_rx_data_ack) : 0);
	skb = alloc_ctrl_skb(tp, wrlen);
	skb->priority = mkprio(CPL_PRIORITY_CONTROL, sk);

	wr = (struct work_request_hdr *)__skb_put(skb, wrlen);
	wr->wr_hi = htonl(V_WR_OP(FW_WROPCODE_BYPASS));

	req = (struct cpl_set_tcb_field *)(wr + 1);
	if (len0) {                  /* program buffer 0 offset and length */
		mk_set_tcb_field_ulp(req, cplios->tid, W_TCB_RX_DDP_BUF0_OFFSET,
			V_TCB_RX_DDP_BUF0_OFFSET(M_TCB_RX_DDP_BUF0_OFFSET) |
			V_TCB_RX_DDP_BUF0_LEN(M_TCB_RX_DDP_BUF0_LEN),
			V_TCB_RX_DDP_BUF0_OFFSET((u64)offset0) |
			V_TCB_RX_DDP_BUF0_LEN((u64)len0));
		req++;
	}
	if (len1) {                  /* program buffer 1 offset and length */
		mk_set_tcb_field_ulp(req, cplios->tid, W_TCB_RX_DDP_BUF1_OFFSET,
			V_TCB_RX_DDP_BUF1_OFFSET(M_TCB_RX_DDP_BUF1_OFFSET) |
			V_TCB_RX_DDP_BUF1_LEN(M_TCB_RX_DDP_BUF1_LEN) << 32,
			V_TCB_RX_DDP_BUF1_OFFSET((u64)offset1) |
			V_TCB_RX_DDP_BUF1_LEN((u64)len1) << 32);
		req++;
	}

	mk_set_tcb_field_ulp(req, cplios->tid, W_TCB_RX_DDP_FLAGS, flag_mask,
			     ddp_flags);

	if (modulate) {
		mk_rx_data_ack_ulp(sk, (struct cpl_rx_data_ack *)(req + 1),
				   cplios->tid,
				   tp->copied_seq - tp->rcv_wup);
		tp->rcv_wup = tp->copied_seq;
	}

#ifdef T3_TRACE
	T3_TRACE5(TIDTB(sk),
		  "t3_setup_ddpbufs: len0 %u len1 %u ddp_flags 0x%08x%08x "
		  "modulate %d",
		  len0, len1, ddp_flags >> 32, ddp_flags & 0xffffffff,
		  modulate);
#endif

	cxgb3_ofld_send(T3C_DEV(sk), skb);
}

void t3_init_wr_tab(unsigned int wr_len)
{
	int i;

	if (skb_wrs[1])     /* already initialized */
		return;

	for (i = 1; i < ARRAY_SIZE(skb_wrs); i++) {
		int sgl_len = (3 * i) / 2 + (i & 1);

		sgl_len += 3;
		skb_wrs[i] = sgl_len <= wr_len ?
		       	1 : 1 + (sgl_len - 2) / (wr_len - 1);
	}

	wrlen = wr_len * 8;
}

int __init t3_init_cpl_io(void)
{
	tcphdr_skb = alloc_skb(sizeof(struct tcphdr), GFP_KERNEL);
	if (!tcphdr_skb) {
		printk(KERN_ERR
		       "Chelsio TCP offload: can't allocate sk_buff\n");
		return -1;
	}
	skb_put(tcphdr_skb, sizeof(struct tcphdr));
	skb_reset_transport_header(tcphdr_skb);
	memset(tcphdr_skb->data, 0, tcphdr_skb->len);
	/* CIPSO_V4_OPTEXIST is false for tcphdr_skb without anything extra */

	t3tom_register_cpl_handler(CPL_PASS_ESTABLISH, do_pass_establish);
	t3tom_register_cpl_handler(CPL_ACT_ESTABLISH, do_act_establish);
	t3tom_register_cpl_handler(CPL_ACT_OPEN_RPL, do_act_open_rpl);
	t3tom_register_cpl_handler(CPL_PASS_ACCEPT_REQ, do_pass_accept_req);
	t3tom_register_cpl_handler(CPL_RX_URG_NOTIFY, do_rx_urg_notify);
	t3tom_register_cpl_handler(CPL_RX_DATA, do_rx_data);
	t3tom_register_cpl_handler(CPL_RX_DATA_DDP, do_rx_data_ddp);
	t3tom_register_cpl_handler(CPL_RX_DDP_COMPLETE, do_rx_ddp_complete);
	t3tom_register_cpl_handler(CPL_TX_DMA_ACK, do_wr_ack);
	t3tom_register_cpl_handler(CPL_PEER_CLOSE, do_peer_close);
	t3tom_register_cpl_handler(CPL_ABORT_REQ_RSS, do_abort_req);
	t3tom_register_cpl_handler(CPL_ABORT_RPL_RSS, do_abort_rpl);
	t3tom_register_cpl_handler(CPL_CLOSE_CON_RPL, do_close_con_rpl);
	t3tom_register_cpl_handler(CPL_TRACE_PKT, do_trace_pkt);
	t3tom_register_cpl_handler(CPL_GET_TCB_RPL, do_get_tcb_rpl);
	return 0;
}
