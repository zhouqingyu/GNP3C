/*
 * This file contains pieces of the Linux TCP/IP stack needed for modular
 * TOE support.
 *
 * Copyright (C) 2006-2009 Chelsio Communications.  All rights reserved.
 * See the corresponding files in the Linux tree for copyrights of the
 * original Linux code a lot of this file is based on.
 *
 * Written by Dimitris Michailidis (dm@chelsio.com)
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

/* The following tags are used by the out-of-kernel Makefile to identify
 * supported kernel versions if a module_support-<kver> file is not found.
 * Do not remove these tags.
 * $SUPPORTED KERNEL 2.6.9$
 */

#include <linux/kallsyms.h>
#include <net/tcp.h>
#include <linux/pkt_sched.h>
#include "defs.h"

int sysctl_tcp_window_scaling = 1;
int sysctl_tcp_adv_win_scale  = 2;
int tcp_tw_count = 0;
int sysctl_tcp_max_tw_buckets = 1;

atomic_t tcp_orphan_count_offload = ATOMIC_INIT(0);


#define ECN_OR_COST(class)	TC_PRIO_##class

__u8 ip_tos2prio[16] = {
	TC_PRIO_BESTEFFORT,
	ECN_OR_COST(FILLER),
	TC_PRIO_BESTEFFORT,
	ECN_OR_COST(BESTEFFORT),
	TC_PRIO_BULK,
	ECN_OR_COST(BULK),
	TC_PRIO_BULK,
	ECN_OR_COST(BULK),
	TC_PRIO_INTERACTIVE,
	ECN_OR_COST(INTERACTIVE),
	TC_PRIO_INTERACTIVE,
	ECN_OR_COST(INTERACTIVE),
	TC_PRIO_INTERACTIVE_BULK,
	ECN_OR_COST(INTERACTIVE_BULK),
	TC_PRIO_INTERACTIVE_BULK,
	ECN_OR_COST(INTERACTIVE_BULK)
};

static void (*flush_tlb_page_p)(struct vm_area_struct *vma, unsigned long addr);

void flush_tlb_page_offload(struct vm_area_struct *vma, unsigned long addr)
{
        if (flush_tlb_page_p)
                flush_tlb_page_p(vma, addr);
}

static int (*ip_route_output_flow_p)(struct rtable **rp, struct flowi *flp,
				     struct sock *sk, int flags);

int ip_route_output_flow_offload(struct rtable **rp,
				 struct flowi *flp,
				 struct sock *sk, int flags)
{
	if (ip_route_output_flow_p)
		return ip_route_output_flow_p(rp, flp, sk, flags);
	else
		return -1;
}

static void (*tcp_tw_schedule_p)(struct tcp_tw_bucket *tw, int timeo);
static inline void tcp_tw_schedule_offload(struct tcp_tw_bucket *tw, int timeo)
{
	if (tcp_tw_schedule_p)
	 	tcp_tw_schedule_p(tw, timeo);
}

static void (*tcp_update_metrics_p)(struct sock *sk);
static inline void tcp_update_metrics_offload(struct sock *sk)
{
	if (tcp_update_metrics_p)
	 	tcp_update_metrics_p(sk);
}	

/*
 * Adapted from tcp_minisocks.c
 */
/* Enter the time wait state.  This is called with locally disabled BH.
 * Essentially we whip up a timewait bucket, copy the
 * relevant info into it from the SK, and mess with hash chains
 * and list linkage.
 */
static void __tcp_tw_hashdance(struct sock *sk, struct tcp_tw_bucket *tw)
{
	struct tcp_ehash_bucket *ehead = &tcp_ehash[sk->sk_hashent];
	struct tcp_bind_hashbucket *bhead;

	/* Step 1: Put TW into bind hash. Original socket stays there too.
	   Note, that any socket with inet_sk(sk)->num != 0 MUST be bound in
	   binding cache, even if it is closed.
	 */
	bhead = &tcp_bhash[tcp_bhashfn(inet_sk(sk)->num)];
	spin_lock(&bhead->lock);
	tw->tw_tb = tcp_sk(sk)->bind_hash;
	BUG_TRAP(tcp_sk(sk)->bind_hash);
	tw_add_bind_node(tw, &tw->tw_tb->owners);
	spin_unlock(&bhead->lock);

	write_lock(&ehead->lock);

	/* Step 2: Remove SK from established hash. */
	if (__sk_del_node_init(sk))
		sock_prot_dec_use(sk->sk_prot);

	/* Step 3: Hash TW into TIMEWAIT half of established hash table. */
	tw_add_node(tw, &(ehead + tcp_ehash_size)->chain);
	atomic_inc(&tw->tw_refcnt);

	write_unlock(&ehead->lock);
}

void tcp_time_wait(struct sock *sk, int state, int timeo)
{
	struct tcp_tw_bucket *tw = NULL;
	struct tcp_opt *tp = tcp_sk(sk);
	int recycle_ok = 0;

	if (sysctl_tcp_tw_recycle && tp->ts_recent_stamp)
		recycle_ok = tp->af_specific->remember_stamp(sk);

	if (tcp_tw_count < sysctl_tcp_max_tw_buckets)
		tw = kmem_cache_alloc(tcp_timewait_cachep, SLAB_ATOMIC);

	if(tw != NULL) {
		struct inet_opt *inet = inet_sk(sk);
		int rto = (tp->rto<<2) - (tp->rto>>1);

		/* Give us an identity. */
		tw->tw_daddr		= inet->daddr;
		tw->tw_rcv_saddr	= inet->rcv_saddr;
		tw->tw_bound_dev_if	= sk->sk_bound_dev_if;
		tw->tw_num		= inet->num;
		tw->tw_state		= TCP_TIME_WAIT;
		tw->tw_substate		= state;
		tw->tw_sport		= inet->sport;
		tw->tw_dport		= inet->dport;
		tw->tw_family		= sk->sk_family;
		tw->tw_reuse		= sk->sk_reuse;
		tw->tw_rcv_wscale	= tp->rcv_wscale;
		atomic_set(&tw->tw_refcnt, 1);

		tw->tw_hashent		= sk->sk_hashent;
		tw->tw_rcv_nxt		= tp->rcv_nxt;
		tw->tw_snd_nxt		= tp->snd_nxt;
		tw->tw_rcv_wnd		= tcp_receive_window(tp);
		tw->tw_ts_recent	= tp->ts_recent;
		tw->tw_ts_recent_stamp	= tp->ts_recent_stamp;
		tw_dead_node_init(tw);

		/* Linkage updates. */
		__tcp_tw_hashdance(sk, tw);

		/* Get the TIME_WAIT timeout firing. */
		if (timeo < rto)
			timeo = rto;

		if (recycle_ok) {
			tw->tw_timeout = rto;
		} else {
			tw->tw_timeout = TCP_TIMEWAIT_LEN;
			if (state == TCP_TIME_WAIT)
				timeo = TCP_TIMEWAIT_LEN;
		}

		tcp_tw_schedule_offload(tw, timeo);
		tcp_tw_put(tw);
	} else {
		/* Sorry, if we're out of memory, just CLOSE this
		 * socket up.  We've got bigger problems than
		 * non-graceful socket closings.
		 */
		if (net_ratelimit())
			printk(KERN_INFO "TCP: time wait bucket table overflow\n");
	}

	tcp_update_metrics_p(sk);
	tcp_done(sk);
}

int prepare_tom_for_offload(void)
{
#if defined(CONFIG_SMP)
        flush_tlb_page_p = (void *)kallsyms_lookup_name("flush_tlb_page");
        if (!flush_tlb_page_p) {
                printk(KERN_ERR "Could not locate flush_tlb_page");
                return -1;
        }
#endif

	ip_route_output_flow_p = (void *)kallsyms_lookup_name("ip_route_output_flow");
	if (!ip_route_output_flow_p) {
		printk(KERN_ERR "Could not locate ip_route_output_flow");
		return -1;
	}

	tcp_tw_schedule_p = (void *)kallsyms_lookup_name("tcp_tw_schedule");
	if (!tcp_tw_schedule_p) {
		printk(KERN_ERR "Could not locate tcp_tw_schedule");
		return -1;
	}

	tcp_update_metrics_p = (void *)kallsyms_lookup_name("tcp_update_metrics");
	if (!tcp_update_metrics_p) {
		printk(KERN_ERR "Could not locate tcp_update_metrics");
		return -1;
	}
	return 0;
}
