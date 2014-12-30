/*
 * Copyright (c) 2007-2009 Chelsio, Inc. All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */
#ifndef __TOM_COMPAT_2_4_H
#define __TOM_COMPAT_2_4_H

#include <linux/version.h>
#include <linux/hugetlb.h>

/* XXX Only built against 2.4.21 */
#if LINUX_VERSION_CODE != KERNEL_VERSION(2,4,21)
#endif

/*
 * Definitions here are mostly borrowed from cxgb3/linux_2_4_compat.h
 * and from earliest kernel version in tom_compat_2_6.h.
 */

/******************************************************************************
 * directives
 ******************************************************************************/
#define	__read_mostly
#define	__user
#define	__iomem
/* To avoid compiler warnings use 2.6 definitions */
#undef likely
#undef unlikely
#define likely(x)	__builtin_expect(!!(x), 1)
#define unlikely(x)	__builtin_expect(!!(x), 0)

/******************************************************************************
 * types
 ******************************************************************************/
typedef unsigned int gfp_t;

#define	__be64	u64
#define	__be32	u32
#define	__be16	u16

/******************************************************************************
 * debug compat
 ******************************************************************************/
#define WARN_ON(condition) do { \
        if (unlikely((condition)!=0)) { \
                printk("BUG: warning at %s:%d/%s()\n", __FILE__, __LINE__, __FUNCTION__); \
                dump_stack(); \
        } \
} while (0)

#define dev_printk(level, dev, format, arg...)  \
         printk(level  format , ## arg)

#define dev_err(dev, format, arg...)            \
        dev_printk(KERN_ERR , dev , format , ## arg)

#define dev_info(dev, format, arg...)            \
        dev_printk(KERN_INFO , dev , format , ## arg)

#define dev_warn(dev, format, arg...)            \
        dev_printk(KERN_WARNING , dev , format , ## arg)


/******************************************************************************
 * lock compatibility
 ******************************************************************************/
#define	DEFINE_MUTEX(l)			DECLARE_MUTEX((l))
#define mutex_lock(l)			down((l))
#define mutex_unlock(l)			up((l))
#define mutex_init(l)			sema_init((l), 1)
#define	DEFINE_RWLOCK(l)		rwlock_t (l) = RW_LOCK_UNLOCKED

#define spin_trylock_irq(lock) \
({ \
        local_irq_disable(); \
        spin_trylock(lock) ? \
        1 : ({ local_irq_enable(); 0;  }); \
})

/******************************************************************************
 * module compatibility
 ******************************************************************************/
#define	MODULE_VERSION(x)

#ifdef CONFIG_CHELSIO_T3_OFFLOAD_MODULE
/*
 * For module, just do regular module init.
 */
#define late_initcall(x)	module_init(x)
#else
/*
 * Since 2.4 does not provide ordered init calls,
 * must add explicit call at appropriate place during boot
 * (e.g. call t3_tom_init() from do_basic_setup() after TCP init)
 * -OR- ensure .o's are in appropriate link order but this is messy
 * since DRIVERS come before NETWORK.
 */
#define late_initcall(x)
#endif

/*
 * this macro only works for integer type parameters. If other types of
 * module parameters are added then this will need to be updated.
 */
#define module_param(param, type, perm)		MODULE_PARM(param, "i");

typedef void irqreturn_t;

#define SEQ_START_TOKEN ((void *)1)
/******************************************************************************
 * TCP compatibility
 ******************************************************************************/

#define TCP_NAGLE_OFF           1
#define TCP_NAGLE_CORK          2
#define TCP_CONGESTION  	13      /* Congestion control algorithm */
#define TCP_CA_NAME_MAX 	16

/* TCP congestion stuff. Added for compilation only */
#define TCP_CA_NAME_MAX 16
struct tcp_congestion_ops {
        void (*get_info)(struct sock *sk, u32 ext, struct sk_buff *skb);

        char            name[TCP_CA_NAME_MAX];
        struct module   *owner;
};

static inline void tcp_v4_setup_caps(struct sock *sk, struct dst_entry *dst)
{
	sk->route_caps = dst->dev->features;
}

static inline void t3_set_ca_ops(struct sock *sk,
                                 struct tcp_congestion_ops *t_ops)
{}

#define t3_inet_inherit_port(p_hashinfo, lsk, newsk) tcp_inherit_port(lsk, newsk)
#define t3_inet_put_port(a, sk) tcp_put_port(sk)

/******************************************************************************
 * socket compatibility
 ******************************************************************************/
enum sock_flags {
        SOCK_DEAD,
        SOCK_DONE,
        SOCK_URGINLINE,
        SOCK_KEEPOPEN,
        SOCK_LINGER,
        SOCK_DESTROY,
        SOCK_BROADCAST,
        SOCK_TIMESTAMP,
        SOCK_ZAPPED,
        SOCK_USE_WRITE_QUEUE, /* whether to call sk->sk_write_space in sock_wfree */
        SOCK_DBG, /* %SO_DEBUG setting */
        SOCK_RCVTSTAMP, /* %SO_TIMESTAMP setting */
        SOCK_LOCALROUTE, /* route locally only, %SO_DONTROUTE setting */
        SOCK_QUEUE_SHRUNK, /* write queue has been shrunk recently */
};

/*
 * map 2.6 field names to 2.4 names
 */
#define sk_state		state
#define sk_sleep		sleep
#define sk_write_queue		write_queue
#define sk_userlocks		userlocks
#define sk_sndbuf		sndbuf
#define sk_prot			prot
#define sk_backlog_rcv		backlog_rcv
#define sk_write_space		write_space
#define sk_timer		timer
#define sk_dst_cache		dst_cache
#define sk_data_ready		data_ready
#define sk_user_data		user_data
#define sk_state_change		state_change
#define sk_err			err
#define sk_wmem_queued		wmem_queued
#define sk_error_report		error_report
#define sk_shutdown		shutdown
#define sk_receive_queue	receive_queue
#define sk_data_ready		data_ready
#define sk_bound_dev_if		bound_dev_if
#define sk_socket		socket
#define sk_sndmsg_page		sndmsg_page
#define sk_sndmsg_off		sndmsg_off
#define sk_allocation		allocation
#define sk_backlog		backlog
#define sk_lingertime		lingertime
#define sk_priority		priority
#define sk_callback_lock	callback_lock
#define sk_protinfo		pair
#define sk_family		family

/* Also a struct and function with same name so handle this one in C code!
#define sk_filter		filter
*/
#define sk_write_pending	tp_pinfo.af_tcp.write_pending
#define	sk_omem_alloc		omem_alloc

#define TCP_PAGE(sk)    (inet_sk(sk)->sndmsg_page)
#define TCP_OFF(sk)     (inet_sk(sk)->sndmsg_off)

/*
 * map 2.6 function calls to 2.4 ones defined in include/net/tcp.h
 */
#define sk_acceptq_removed	tcp_acceptq_removed
#define sk_acceptq_is_full	tcp_acceptq_is_full
#define sk_stream_min_wspace	tcp_min_write_space

#ifndef ATOMIC_ADD_RETURN
#if defined(CONFIG_X86_64)
static __inline__ int atomic_add_return(int i, atomic_t *v)
{
	int __i = i;
	__asm__ __volatile__(
		LOCK "xaddl %0, %1;"
		:"=r"(i)
		:"m"(v->counter), "0"(i));
	return i + __i;
} 

#elif defined(CONFIG_X86)
static __inline__ int atomic_add_return(int i, atomic_t *v)
{
	int __i;
#ifdef CONFIG_M386
	if(unlikely(boot_cpu_data.x86==3))
		goto no_xadd;
#endif
	/* Modern 486+ processor */
	__i = i;
	__asm__ __volatile__(
		LOCK "xaddl %0, %1;"
		:"=r"(i)
		:"m"(v->counter), "0"(i));
	return i + __i;

#ifdef CONFIG_M386
no_xadd: /* Legacy 386 processor */
	local_irq_disable();
	__i = atomic_read(v);
	atomic_set(v, i + __i);
	local_irq_enable();
	return i + __i;
#endif
} 

#elif defined(CONFIG_IA64)
#define atomic_add_return(i,v)						\
({									\
	int __ia64_aar_i = (i);						\
	(__builtin_constant_p(i)					\
	 && (   (__ia64_aar_i ==  1) || (__ia64_aar_i ==   4)		\
	     || (__ia64_aar_i ==  8) || (__ia64_aar_i ==  16)		\
	     || (__ia64_aar_i == -1) || (__ia64_aar_i ==  -4)		\
	     || (__ia64_aar_i == -8) || (__ia64_aar_i == -16)))		\
		? ia64_fetch_and_add(__ia64_aar_i, &(v)->counter)	\
		: ia64_atomic_add(__ia64_aar_i, v);			\
})
#endif
#endif /* ATOMIC_ADD_RETURN */

#define sock_owned_by_user(sk)  ((sk)->lock.users != 0)

#include "cpl_io_state.h"

static inline void sock_set_flag_val(struct sock *sk, enum sock_flags flag, int val)
{
	switch (flag) {
        	case SOCK_DEAD:
			sk->dead = val;
			break;
        	case SOCK_DONE:
			sk->done = val;
			break;
        	case SOCK_URGINLINE:
			sk->urginline = val;
			break;
        	case SOCK_KEEPOPEN:
			sk->keepopen = val;
			break;
        	case SOCK_LINGER:
			sk->linger = val;
			break;
        	case SOCK_DESTROY:
			sk->destroy = val;
			break;
        	case SOCK_BROADCAST:
			sk->broadcast = val;
			break;
        	case SOCK_USE_WRITE_QUEUE:
			sk->use_write_queue = val;
			break;
        	case SOCK_DBG:
			sk->debug = val;
			break;
        	case SOCK_RCVTSTAMP:
			sk->rcvtstamp = val;
			break;
        	case SOCK_ZAPPED:
			sk->zapped = val;
			break;
        	case SOCK_LOCALROUTE:
			sk->localroute = val;
			break;
        	case SOCK_TIMESTAMP:
			sk->rcvtstamp = val;
			break;
        	case SOCK_QUEUE_SHRUNK:
			sk->tp_pinfo.af_tcp.queue_shrunk = 1;
			break;
		case SOCK_NO_DDP:
		case SOCK_OFFLOADED:
			if (val)
				set_bit(flag, &CPL_IO_STATE(sk)->sk_flags);
			else
				clear_bit(flag, &CPL_IO_STATE(sk)->sk_flags);
			break;
		default:
			/* XXX In case new flag used but not handled here */
			printk("t3_tom: sock_set_flag_val: unknown flag\n");
			break;
	}
}

static inline void sock_reset_flag(struct sock *sk, enum sock_flags flag)
{
	sock_set_flag_val(sk, flag, 0);
}

static inline int sock_flag(struct sock *sk, enum sock_flags flag)
{
	int val = 0;

	switch (flag) {
        	case SOCK_DEAD:
			val = sk->dead;
			break;
        	case SOCK_DONE:
			val = sk->done;
			break;
        	case SOCK_URGINLINE:
			val = sk->urginline;
			break;
        	case SOCK_KEEPOPEN:
			val = sk->keepopen;
			break;
        	case SOCK_LINGER:
			val = sk->linger;
			break;
        	case SOCK_DESTROY:
			val = sk->destroy;
			break;
        	case SOCK_BROADCAST:
			val = sk->broadcast;
			break;
        	case SOCK_USE_WRITE_QUEUE:
			val = sk->use_write_queue;
			break;
        	case SOCK_DBG:
			val = sk->debug;
			break;
        	case SOCK_RCVTSTAMP:
			val = sk->rcvtstamp;
			break;
        	case SOCK_ZAPPED:
			val = sk->zapped;
			break;
        	case SOCK_LOCALROUTE:
			val = sk->localroute;
			break;
        	case SOCK_TIMESTAMP:
			val = sk->rcvtstamp;
			break;
        	case SOCK_QUEUE_SHRUNK:
			val = sk->tp_pinfo.af_tcp.queue_shrunk;
			break;
		case SOCK_NO_DDP:
		case SOCK_OFFLOADED:
			val = test_bit(flag, &CPL_IO_STATE(sk)->sk_flags);
			break;
		default:
			/* XXX In case new flag used but not handled here */
			printk("t3_tom: sock_flag: unknown flag\n");
			break;
	}
        return val;
}

static inline void sock_set_flag(struct sock *sk, enum sock_flags flag)
{
	sock_set_flag_val(sk, flag, 1);
}

static inline void sk_reset_timer(struct sock *sk, struct timer_list* timer,
                    unsigned long expires)
{
        if (!mod_timer(timer, expires))
                sock_hold(sk);
}

/*
 * map 2.6 function calls to 2.4 ones defined in net/ipv4/tcp.c
 * and in-lined here
 */
static inline void sk_eat_skb(struct sock *sk, struct sk_buff * skb)
{
	__skb_unlink(skb, &sk->receive_queue);
	__kfree_skb(skb);
}

static inline int sk_stream_error(struct sock *sk, int flags, int err)
{
	if (err == -EPIPE)
		err = sock_error(sk) ? : -EPIPE;
	if (err == -EPIPE && !(flags&MSG_NOSIGNAL))
		send_sig(SIGPIPE, current, 0);
	return err;
}

/* from 2.4 net/ipv4/ip_output.c */
static inline int
skb_can_coalesce(struct sk_buff *skb, int i, struct page *page, int off)
{
	if (i) {
		skb_frag_t *frag = &skb_shinfo(skb)->frags[i-1];
		return page == frag->page &&
			off == frag->page_offset+frag->size;
	}
	return 0;
}

/*
 * map 2.6 function calls to 2.4 ones defined in net/ipv4/tcp.c
 * and newly exported for our use
 */
#define sk_stream_write_space	tcp_write_space
#define sk_stream_wait_connect(sk,timeo_p)  wait_for_tcp_connect(sk,0,timeo_p)
#define sk_wait_data(sk,timeo_p)	tcp_data_wait(sk,*(timeo_p))

/*
 * from 2.4 code inside tcp_close() in net/ipv4/tcp.c
 * (i.e. version of tcp_wait_close() if it ever existed)
 */
static inline int closing(struct sock * sk)
{
	return ((1 << sk->state) & (TCPF_FIN_WAIT1|TCPF_CLOSING|TCPF_LAST_ACK));
}

static inline void sk_stream_wait_close(struct sock *sk, long timeout)
{
	if (timeout) {
		struct task_struct *tsk = current;
		DECLARE_WAITQUEUE(wait, current);

		add_wait_queue(sk->sleep, &wait);

		do {
			set_current_state(TASK_INTERRUPTIBLE);
			if (!closing(sk))
				break;
			release_sock(sk);
			timeout = schedule_timeout(timeout);
			lock_sock(sk);
		} while (!signal_pending(tsk) && timeout);

		tsk->state = TASK_RUNNING;
		remove_wait_queue(sk->sleep, &wait);
	}
}

/*
 * from 2.6 include/net/sock.h
 */
#define sk_wait_event(__sk, __timeo, __condition)               \
({      int rc;                                                 \
        release_sock(__sk);                                     \
        rc = __condition;                                       \
        if (!rc) {                                              \
                *(__timeo) = schedule_timeout(*(__timeo));      \
        }                                                       \
        lock_sock(__sk);                                        \
        rc = __condition;                                       \
        rc;                                                     \
})

/*
 * From 2.4 net/ipv4/tcp_input.c routine tcp_check_urg().
 */
static inline void sk_send_sigurg(struct sock *sk)
{
	/* Tell the world about our new urgent pointer. */
	if (sk->proc != 0) {
		if (sk->proc > 0)
			kill_proc(sk->proc, SIGURG, 1);
		else
			kill_pg(-sk->proc, SIGURG, 1);
		sk_wake_async(sk, 3, POLL_PRI);
	}
}

#define sock_create_kern	sock_create

/******************************************************************************
 * routing compatibility
 ******************************************************************************/
#define ROUTE_REQ

static inline struct rtattr *
__rta_reserve(struct sk_buff *skb, int attrtype, int attrlen)
{
        struct rtattr *rta;
        int size = RTA_LENGTH(attrlen);

        rta = (struct rtattr*)skb_put(skb, RTA_ALIGN(size));
        rta->rta_type = attrtype;
        rta->rta_len = size;
        memset(RTA_DATA(rta) + attrlen, 0, RTA_ALIGN(size) - size);
        return rta;
}

#define __RTA_PUT(skb, attrtype, attrlen) \
({      if (unlikely(skb_tailroom(skb) < (int)RTA_SPACE(attrlen))) \
                goto rtattr_failure; \
        __rta_reserve(skb, attrtype, attrlen); })

#ifdef CONFIG_TCP_OFFLOAD_MODULE
extern atomic_t tcp_orphan_count_offload;
extern int ip_route_output_flow_offload(struct rtable **rp,
                                        struct flowi *flp,
                                        struct sock *sk, int flags);
#define ip_route_output_flow ip_route_output_flow_offload
#define INC_ORPHAN_COUNT(sk) (atomic_inc(&tcp_orphan_count_offload))
#else
#define INC_ORPHAN_COUNT(sk) (atomic_inc(&tcp_orphan_count))
#endif /* CONFIG_TCP_OFFLOAD_MODULE */

#define dst_mtu(dst) dst_metric(dst, RTAX_MTU)

/******************************************************************************
 * net data structure compatibility
 ******************************************************************************/
#define tcp_sock tcp_opt
#define inet_sock inet_opt
#define request_sock open_request

#define inet_csk(sk) tcp_sk(sk)
#define inet_csk_destroy_sock(sk) tcp_destroy_sock(sk)
#define inet_csk_route_req(lsk, oreq) tcp_v4_route_req(lsk, oreq)

#define inet_connection_sock tcp_opt
#define icsk_af_ops af_specific
#define icsk_ack ack
#define icsk_pmtu_cookie pmtu_cookie
#define icsk_retransmit_timer retransmit_timer
#define inet_csk_reqsk_queue_removed tcp_synq_removed
#define inet_csk_delete_keepalive_timer tcp_delete_keepalive_timer
#define inet_csk_reqsk_queue_is_full tcp_synq_is_full
#define inet_csk_reqsk_queue_add tcp_acceptq_queue
#define inet_csk_reqsk_queue_added(sk, timeo) tcp_synq_added(sk)

#define __reqsk_free tcp_openreq_fastfree
#define tcp_rsk
#define inet_rsk

#define inet_inherit_port(p_hashinfo, lsk, newsk) tcp_inherit_port(lsk, newsk)
#define t3_inet_put_port(a, sk) tcp_put_port(sk)

#define ACCEPT_QUEUE(sk) (&(tcp_sk(sk)->accept_queue))

#define MSS_CLAMP(tp) ((tp)->mss_clamp)
#define SND_WSCALE(tp) ((tp)->snd_wscale)
#define RCV_WSCALE(tp) ((tp)->rcv_wscale)
#define USER_MSS(tp) ((tp)->user_mss)
#define TS_RECENT_STAMP(tp) ((tp)->ts_recent_stamp)
#define WSCALE_OK(tp) ((tp)->wscale_ok)
#define TSTAMP_OK(tp) ((tp)->tstamp_ok)
#define SACK_OK(tp) ((tp)->sack_ok)

/******************************************************************************
 * netdev compatibility
 ******************************************************************************/
#define __netif_rx_schedule_prep(netdev)	(1)
#define __netif_rx_schedule(netdev)		netif_rx_schedule((netdev))
#define __netif_rx_complete(netdev)		netif_rx_complete((netdev))

#define NETDEV_TX_OK 0          /* driver took care of packet */
#define NETDEV_TX_BUSY 1        /* driver tx path was busy*/
#define NETDEV_TX_LOCKED -1     /* driver tx lock was already taken */

#ifndef SET_NETDEV_DEV
#define	SET_NETDEV_DEV(netdev, pdev)
#endif

#define NETIF_F_LLTX	0
#define NETIF_F_TSO	0

void *netdev_priv(struct net_device *dev);
#ifndef ALLOC_NETDEV
struct net_device *alloc_netdev(int sizeof_priv, const char *mask,
                                       void (*setup)(struct net_device *));
#endif

/******************************************************************************
 * stat compatibility
 ******************************************************************************/

#define LINUX_MIB_TCPABORTONDATA		1
#define LINUX_MIB_TCPABORTONLINGER		2
#define LINUX_MIB_TCPABORTONSYN			3
#define LINUX_MIB_TCPABORTONTIMEOUT		4
#define LINUX_MIB_LISTENOVERFLOWS		5
#define LINUX_MIB_LISTENDROPS			6
#define LINUX_MIB_TCPABORTONCLOSE		7
#define LINUX_MIB_TCPABORTONMEMORY		8

#define	IPSTATS_MIB_OUTNOROUTES 		IpOutNoRoutes

#define	TCP_MIB_ATTEMPTFAILS			TcpAttemptFails
#define	TCP_MIB_ACTIVEOPENS			TcpActiveOpens

static inline void net_inc_stats_bh(int stat)
{
	switch(stat) {
		case LINUX_MIB_TCPABORTONDATA:
			SNMP_INC_STATS_BH(net_statistics, TCPAbortOnData);
			break;
		case LINUX_MIB_TCPABORTONLINGER:
			SNMP_INC_STATS_BH(net_statistics, TCPAbortOnLinger);
			break;
		case LINUX_MIB_TCPABORTONSYN:
			SNMP_INC_STATS_BH(net_statistics, TCPAbortOnSyn);
			break;
		case LINUX_MIB_TCPABORTONTIMEOUT:
			SNMP_INC_STATS_BH(net_statistics, TCPAbortOnTimeout);
			break;
		case LINUX_MIB_LISTENOVERFLOWS:
			SNMP_INC_STATS_BH(net_statistics, ListenOverflows);
			break;
		case LINUX_MIB_LISTENDROPS:
			SNMP_INC_STATS_BH(net_statistics, ListenDrops);
			break;
		case LINUX_MIB_TCPABORTONCLOSE:
			SNMP_INC_STATS_BH(net_statistics, TCPAbortOnClose);
			break;
		case LINUX_MIB_TCPABORTONMEMORY:
			SNMP_INC_STATS_BH(net_statistics, TCPAbortOnMemory);
			break;
	}
}

static inline void net_inc_stats_user(int stat)
{
	switch(stat) {
		case LINUX_MIB_TCPABORTONDATA:
			SNMP_INC_STATS_USER(net_statistics, TCPAbortOnData);
			break;
		case LINUX_MIB_TCPABORTONCLOSE:
			SNMP_INC_STATS_USER(net_statistics, TCPAbortOnClose);
			break;
	}
}

#undef	NET_INC_STATS_USER
#undef	NET_INC_STATS_BH

#define	NET_INC_STATS_BH(stat)			net_inc_stats_bh((stat))
#define	NET_INC_STATS_USER(stat)		net_inc_stats_user((stat))

/******************************************************************************
 * inet_diag
 ******************************************************************************/

enum {
	INET_DIAG_NONE,
	INET_DIAG_MEMINFO,
	INET_DIAG_INFO,
	INET_DIAG_VEGASINFO,
	INET_DIAG_CONG,
};
#define INET_DIAG_MAX INET_DIAG_CONG

/******************************************************************************
 * request_sock
 ******************************************************************************/

struct request_sock_ops {
        int             family;
        int             obj_size;
};

#define rsk_ops class
#define RSK_OPS(rsk) (struct or_calltable *)(rsk)
static inline void t3_init_rsk_ops(struct proto *t3_tcp_prot,
                                   struct request_sock_ops *t3_tcp_ops,
                                   struct proto *tcp_prot)
{}

static inline struct open_request *reqsk_alloc(struct request_sock_ops *rsk)
{
        struct open_request *oreq = tcp_openreq_alloc();

        if (oreq)
                oreq->class = (struct or_calltable *)rsk;

        return oreq;
}

static inline void t3_set_req_addr(struct open_request *oreq,
                                   __u32 local_ip, __u32 peer_ip)
{
        oreq->af.v4_req.loc_addr = local_ip;
        oreq->af.v4_req.rmt_addr = peer_ip;
}

static inline void t3_set_req_opt(struct open_request *oreq,
                                  struct ip_options *ip_opt)
{
}

static inline void sk_setup_caps(struct sock *sk, struct dst_entry *dst)
{
        __sk_dst_set(sk, dst);
        tcp_v4_setup_caps(sk, dst);
}

static inline void setup_timer(struct timer_list * timer,
                                void (*function)(unsigned long),
                                unsigned long data)
{
        timer->function = function;
        timer->data = data;
        init_timer(timer);
}

extern int prepare_tom_for_offload(void);

/******************************************************************************
 * memory management compatibility
 ******************************************************************************/
#define	__GFP_NOFAIL	0

#ifndef KZALLOC
static inline void *kzalloc(size_t size, int flags)
{
	void *ret = kmalloc(size, flags);
	if (ret)
		memset(ret, 0, size);
	return ret;
}
#endif

/* from include/linux/libata-compat.h */
static inline void *kcalloc(size_t nmemb, size_t size, int flags)
{
	size_t total = nmemb * size;
	void *mem = kmalloc(total, flags);
	if (mem)
		memset(mem, 0, total);
	return mem;
}

#define set_page_dirty_lock	set_page_dirty

/******************************************************************************
 * timer compatibility
 ******************************************************************************/
unsigned int jiffies_to_msecs(const unsigned long j);
unsigned long msecs_to_jiffies(const unsigned int m);
signed long schedule_timeout_interruptible(signed long timeout);
signed long schedule_timeout_uninterruptible(signed long timeout);
void msleep(unsigned int msecs);
unsigned long msleep_interruptible(unsigned int msecs);

/******************************************************************************
 * work queue compatibility
 ******************************************************************************/
#include <linux/workqueue.h>
struct workqueue_struct * create_singlethread_workqueue(const char *name);
void destroy_workqueue(struct workqueue_struct *wq);
int queue_work(struct workqueue_struct *cwq, struct work_struct *work);
int queue_delayed_work(struct workqueue_struct *wq,
                        struct work_struct *work, unsigned long delay);
void cancel_rearming_delayed_workqueue(struct workqueue_struct *wq,
                                       struct work_struct *work);

/******************************************************************************
 * SMP compatibility
 ******************************************************************************/
static inline int num_online_cpus(void)
{
	return smp_num_cpus;
}

int generic_fls(int x);

#ifndef IF_MII
/******************************************************************************
 * MII compatibility
 ******************************************************************************/
static inline struct mii_ioctl_data *if_mii(struct ifreq *rq)
{
	return (struct mii_ioctl_data *) &rq->ifr_ifru;
} 
#endif

/******************************************************************************
 * atomic ops
 ******************************************************************************/

#if defined(CONFIG_T3_ZCOPY_SENDMSG) || defined(CONFIG_T3_ZCOPY_SENDMSG_MODULE)
# define t3_ptep_set_wrprotect(mm, address, ptep) ptep_set_wrprotect(ptep)
#endif

#if defined(NETDMA_IN_KERNEL) && !defined(IOAT_SOCK)
if defined(NETDMA_IN_KERNEL) && !defined(IOAT_SOCK)
static inline void tom_eat_skb(struct sock *sk, struct sk_buff *skb,
			      int copied_early)
{
	skb->dst = NULL;
	sk_eat_skb(sk, skb, copied_early);
}

#else
static inline void tom_eat_skb(struct sock *sk, struct sk_buff *skb,
			      int copied_early)
{
	skb->dst = NULL;
	sk_eat_skb(sk, skb);
}
#endif

#define DECLARE_TASK_FUNC(task, task_param) \
	static void task(void *task_param)

#define T3_INIT_WORK INIT_WORK

#define WORK2TOMDATA(task_param, task) task_param

#define T3_DECLARE_WORK(task, func, data) \
	DECLARE_WORK(task, func, data)

#if defined(CONFIG_T3_ZCOPY_SENDMSG) || defined(CONFIG_T3_ZCOPY_SENDMSG_MODULE)

/* Older kernels don't have a PUD; if that's the case, simply fold that level.
 */
#ifndef PUD_SIZE
# define pud_t			pgd_t
# define pud_offset(pgd, addr)	(pgd)
# define pud_none(pud)		0
# define pud_bad(pud)		0
# define pud_present(pud)	0
#endif

/* Unfortunately, flush_tlb_range() is not available on all platforms and 
 * configurations and we must fall back to an implementation based on
 * flush_tlb_page(). Good thing that tlb flushing is in the exception path
 * only.
 */ 
static inline void _t3_flush_tlb_range(struct vm_area_struct *vma,
				       unsigned long start, unsigned long end)
{
	for (; start < end; start += PAGE_SIZE)
		flush_tlb_page(vma, start);
}

#if defined(CONFIG_X86)
# if !defined(CONFIG_SMP)
#  define t3_flush_tlb_range flush_tlb_range
# else
#  define t3_flush_tlb_range _t3_flush_tlb_range
# endif
#elif defined(CONFIG_PPC)
# define t3_flush_tlb_range _t3_flush_tlb_range
#else
# define t3_flush_tlb_range flush_tlb_range
#endif

#if defined(CONFIG_T3_ZCOPY_HUGEPAGES)
static __inline__ int zcopy_vma(struct vm_area_struct *vma) {
	return !(vma->vm_flags & VM_SHARED);
}
#else
static __inline__ int zcopy_vma(struct vm_area_struct *vma) {
	return !((vma->vm_flags & VM_SHARED) || is_vm_hugetlb_page(vma));
}
#endif

#if defined(CONFIG_T3_ZCOPY_HUGEPAGES) && defined(CONFIG_HUGETLB_PAGE)
#if defined(CONFIG_IA64)
static __inline__ pte_t *
t3_huge_pte_offset (struct mm_struct *mm, unsigned long addr)
{
        unsigned long taddr = htlbpage_to_page(addr);
        pgd_t *pgd;
        pmd_t *pmd;
        pte_t *pte = NULL;

        pgd = pgd_offset(mm, taddr);
        if (pgd_present(*pgd)) {
                pmd = pmd_offset(pgd, taddr);
                if (pmd_present(*pmd))
                        pte = pte_offset(pmd, taddr);
        }

        return pte;
}
#else
static __inline__ pte_t *t3_huge_pte_offset(struct mm_struct *mm, unsigned long addr)
{
	return pte_offset(mm, addr);
}
#endif
#endif
#endif /* ZCOPY_SENDMSG */

#define T3_NET_INC_STATS_BH(net, field) NET_INC_STATS_BH(field)
#define T3_TCP_INC_STATS_BH(net, field) TCP_INC_STATS_BH(field)
#define T3_TCP_INC_STATS(net, field)    TCP_INC_STATS(field)
#define T3_NET_INC_STATS_USER(net, field) NET_INC_STATS_USER(field)
#define t3_type_compat int

/******************************************************************************
 * sysctl compatibility
 ******************************************************************************/
static inline void tom_sysctl_set_de(ctl_table *tbl)
{
	tbl->de = NULL;
}
#define tom_register_sysctl_table register_sysctl_table

/******************************************************************************
 * PCI compatibility
 ******************************************************************************/
static inline int t3_pci_dma_mapping_error(struct pci_dev *pdev,
					   dma_addr_t dma_addr)
{
	return dma_addr == 0;
}
#endif /* __TOM_COMPAT_2_4_H */
