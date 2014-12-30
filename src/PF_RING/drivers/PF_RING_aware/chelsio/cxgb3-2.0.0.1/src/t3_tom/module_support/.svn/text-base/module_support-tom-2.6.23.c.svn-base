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
 * $SUPPORTED KERNEL 2.6.23$
 * $SUPPORTED KERNEL 2.6.24$
 * $SUPPORTED KERNEL 2.6.25$
 * $SUPPORTED KERNEL 2.6.26$
 * $SUPPORTED KERNEL 2.6.27$
 * $SUPPORTED KERNEL 2.6.28$
 * $SUPPORTED KERNEL 2.6.29$
 * $SUPPORTED KERNEL 2.6.30$
 * $SUPPORTED KERNEL 2.6.31$
 * $SUPPORTED KERNEL 2.6.32$
 * $SUPPORTED KERNEL 2.6.33$
 * $SUPPORTED KERNEL 2.6.34$
 * $SUPPORTED KERNEL 2.6.35$
 * $SUPPORTED KERNEL 2.6.36$
 * $SUPPORTED KERNEL 2.6.37$
 */

#include <net/tcp.h>
#include <linux/pkt_sched.h>
#include <linux/kprobes.h>
#include "defs.h"
#include <asm/tlbflush.h>

#if defined(CONFIG_SMP) && !defined(PPC64_TLB_BATCH_NR)
static unsigned long (*kallsyms_lookup_name_p)(const char *name);
static void (*flush_tlb_mm_p)(struct mm_struct *mm);
static void (*flush_tlb_page_p)(struct vm_area_struct *vma,
				unsigned long va);

void flush_tlb_mm_offload(struct mm_struct *mm);
#endif

void flush_tlb_page_offload(struct vm_area_struct *vma, unsigned long addr)
{
#if defined(CONFIG_SMP) && !defined(PPC64_TLB_BATCH_NR)
	flush_tlb_page_p(vma, addr);
#endif
}

int sysctl_tcp_window_scaling = 1;
int sysctl_tcp_adv_win_scale  = 2;

#define ECN_OR_COST(class)	TC_PRIO_##class

const __u8 ip_tos2prio[16] = {
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

/*
 * Adapted from tcp_minisocks.c
 */
void tcp_time_wait(struct sock *sk, int state, int timeo)
{
	struct inet_timewait_sock *tw = NULL;
	const struct inet_connection_sock *icsk = inet_csk(sk);
	const struct tcp_sock *tp = tcp_sk(sk);
	int recycle_ok = 0;

	if (tcp_death_row.tw_count < tcp_death_row.sysctl_max_tw_buckets)
		tw = inet_twsk_alloc(sk, state);

	if (tw != NULL) {
		struct tcp_timewait_sock *tcptw = tcp_twsk((struct sock *)tw);
		const int rto = (icsk->icsk_rto << 2) - (icsk->icsk_rto >> 1);

		tw->tw_rcv_wscale	= tp->rx_opt.rcv_wscale;
		tcptw->tw_rcv_nxt	= tp->rcv_nxt;
		tcptw->tw_snd_nxt	= tp->snd_nxt;
		tcptw->tw_rcv_wnd	= tcp_receive_window(tp);
		tcptw->tw_ts_recent	= tp->rx_opt.ts_recent;
		tcptw->tw_ts_recent_stamp = tp->rx_opt.ts_recent_stamp;

		/* Linkage updates. */
		__inet_twsk_hashdance(tw, sk, &tcp_hashinfo);

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

		inet_twsk_schedule(tw, &tcp_death_row, timeo,
				   TCP_TIMEWAIT_LEN);
		inet_twsk_put(tw);
	} else {
		/* Sorry, if we're out of memory, just CLOSE this
		 * socket up.  We've got bigger problems than
		 * non-graceful socket closings.
		 */
		if (net_ratelimit())
			printk(KERN_INFO
			       "TCP: time wait bucket table overflow\n");
	}

	tcp_done(sk);
}

void flush_tlb_mm_offload(struct mm_struct *mm)
{
#if defined(CONFIG_SMP) && !defined(PPC64_TLB_BATCH_NR)
	if (flush_tlb_mm_p)
		flush_tlb_mm_p(mm);
#endif
}

#if defined(CONFIG_SMP) && !defined(PPC64_TLB_BATCH_NR)
static int find_kallsyms_lookup_name(void)
{
	int err = 0;

#if defined(KPROBES_KALLSYMS)
	struct kprobe kp;

	memset(&kp, 0, sizeof kp);
	kp.symbol_name = "kallsyms_lookup_name";
	err = register_kprobe(&kp);
	if (!err) {
		kallsyms_lookup_name_p = (void *)kp.addr;
		unregister_kprobe(&kp);
	}
#else
	kallsyms_lookup_name_p = (void *)KALLSYMS_LOOKUP;
#endif

	if (!err)
		err = kallsyms_lookup_name_p == NULL;

	return err;
}
#endif

int prepare_tom_for_offload(void)
{
#if defined(CONFIG_SMP) && !defined(PPC64_TLB_BATCH_NR)
	if (!kallsyms_lookup_name_p) {
		int err = find_kallsyms_lookup_name();
		if (err)
			return err;
	}

	flush_tlb_mm_p = (void *)kallsyms_lookup_name_p("flush_tlb_mm");
        if (!flush_tlb_mm_p) {
                printk(KERN_ERR "Could not locate flush_tlb_mm");
                return -1;
        }

	flush_tlb_page_p = (void *)kallsyms_lookup_name_p("flush_tlb_page");
        if (!flush_tlb_page_p) {
                printk(KERN_ERR "Could not locate flush_tlb_page");
                return -1;
        }
#endif
	return 0;
}
