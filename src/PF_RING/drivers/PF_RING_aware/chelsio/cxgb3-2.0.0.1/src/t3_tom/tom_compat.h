/*
 * Copyright (C) 2003-2009 Chelsio Communications.  All rights reserved.
 *
 * Written by Dimitris Michailidis (dm@chelsio.com),
 *	      Divy Le Ray (divy@chelsio.com)
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

#ifndef __TOM_COMPAT_H
#define __TOM_COMPAT_H

#include <linux/version.h>

/*
 * Pull in either Linux 2.6 or earlier compatibility definitions.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
#include "tom_compat_2_6.h"
#else
#include "tom_compat_2_4.h"
#endif

#ifdef CONFIG_DEBUG_FS
#include <linux/debugfs.h>
#endif

#if !defined(NEW_SKB_OFFSET)
static inline void skb_reset_transport_header(struct sk_buff *skb)
{
	skb->h.raw = skb->data;
}

#if !defined(T3_TCP_HDR)
static inline struct tcphdr *tcp_hdr(const struct sk_buff *skb)
{
	return skb->h.th;
}
#endif
#endif

#if !defined(SEC_INET_CONN_REQUEST)
static inline int security_inet_conn_request(struct sock *sk,
					     struct sk_buff *skb,
					     struct request_sock *req)
{
	return 0;
}
#endif

#if defined(OLD_OFFLOAD_H)
/*
 * Extended 'struct proto' with additional members used by offloaded
 * connections.
 */
struct sk_ofld_proto {
        struct proto proto;    /* keep this first */
        int (*read_sock)(struct sock *sk, read_descriptor_t *desc,
                         sk_read_actor_t recv_actor);
};

#if defined(CONFIG_TCP_OFFLOAD_MODULE)
extern int  install_special_data_ready(struct sock *sk);
extern void restore_special_data_ready(struct sock *sk);
#else
static inline int install_special_data_ready(struct sock *sk) { return 0; }
static inline void restore_special_data_ready(struct sock *sk) {}
#endif

#if defined(CONFIG_DEBUG_RODATA) && defined(CONFIG_TCP_OFFLOAD_MODULE)
extern void offload_socket_ops(struct sock *sk);
extern void restore_socket_ops(struct sock *sk);
#else
static inline void offload_socket_ops(struct sock *sk) {}
static inline void restore_socket_ops(struct sock *sk) {}
#endif

#endif

#if defined(DEACTIVATE_OFFLOAD)
struct toedev;
static inline int deactivate_offload(struct toedev *dev)
{
        return -1;
}
#endif

#if defined(CONFIG_KPROBES) && defined(KPROBES_SYMBOL_NAME)
#define KPROBES_KALLSYMS
#endif

#if !defined(SK_FILTER_UNCHARGE)
#define sk_filter_uncharge sk_filter_release
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
#define TUNABLE_INT_CTL_NAME(name) (TOE_CONF_ ## name)
#define TUNABLE_INT_RANGE_CTL_NAME(name) (TOE_CONF_ ## name)
#define TOM_INSTANCE_DIR_CTL_NAME 1
#define ROOT_DIR_CTL_NAME CTL_TOE
#else
#define TUNABLE_INT_CTL_NAME(name) CTL_UNNUMBERED
#define TUNABLE_INT_RANGE_CTL_NAME(name) CTL_UNNUMBERED
#define TOM_INSTANCE_DIR_CTL_NAME CTL_UNNUMBERED
#define ROOT_DIR_CTL_NAME CTL_UNNUMBERED
#endif

#if defined(PPC64_TLB_BATCH_NR)
static inline void flush_tlb_mm_p(struct mm_struct *mm)
{
}

static inline void flush_tlb_page_p(struct vm_area_struct *vma,
				  unsigned long vmaddr)
{
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,30)
#define SET_PROC_NODE_OWNER(_p, _owner) \
	do { (_p)->owner = (_owner); } while (0)
#else
#define SET_PROC_NODE_OWNER(_p, _owner) \
	do { } while (0)
#endif

#if !defined(INET_PREFIX)
#define inet_daddr daddr
#define inet_rcv_saddr rcv_saddr
#define inet_dport dport
#define inet_saddr saddr
#define inet_sport sport
#define inet_num num
#define inet_id id
#endif

#if defined(CXGB3_BOOL)
#define bool int
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35)

static inline wait_queue_head_t *sk_sleep(struct sock *sk)
{
	return sk->sk_sleep;
}

static inline bool sk_has_sleepers(struct sock *sk)
{
	smp_mb();
	return sk->sk_sleep && waitqueue_active(sk->sk_sleep);
}

#else

static inline bool sk_has_sleepers(struct sock *sk)
{
	/* wq_has_sleeper() has smp_mb() in it ... */
	return wq_has_sleeper(sk->sk_wq);
}

#endif

static inline void sk_wakeup_sleepers(struct sock *sk, bool interruptable)
{
	if (sk_has_sleepers(sk)) {
		if (interruptable)
			wake_up_interruptible(sk_sleep(sk));
		else
			wake_up_all(sk_sleep(sk));
	}
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,31)
typedef int socklen_t;
#else
typedef unsigned int socklen_t;
#endif

#if defined(CXGB3___SK_ADD_BACKLOG)
static inline void __sk_add_backlog(struct sock *sk, struct sk_buff *skb)
{
	sk_add_backlog(sk, skb);
}
#endif

#if !defined(CXGB3_NIPQUAD)
#define NIPQUAD(addr) \
	((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[3]
#define NIPQUAD_FMT "%u.%u.%u.%u"
#endif

#if defined(T3_LINUX_MUTEX_H)
#include <linux/mutex.h>
#else
#define DEFINE_MUTEX(x) DECLARE_MUTEX(x)
#define mutex_lock(x) down(x)
#define mutex_unlock(x) up(x)
#endif

#endif /* __TOM_COMPAT_H */
