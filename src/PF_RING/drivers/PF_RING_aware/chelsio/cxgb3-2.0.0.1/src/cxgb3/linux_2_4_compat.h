/*
 * Copyright (c) 2003-2009 Chelsio, Inc. All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

#ifndef __LINUX_2_4_COMPAT_H__
#define __LINUX_2_4_COMPAT_H__

#include <linux/pci.h>
#include <linux/spinlock.h>
#include <linux/interrupt.h>
#include <linux/timer.h>
#include <linux/netdevice.h>
#include <linux/rtnetlink.h>
#include <linux/filter.h>
#include <linux/cache.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <net/sock.h>
#include <net/snmp.h>
#include <net/ip.h>
#include <asm/atomic.h>
#include <asm/semaphore.h>
#include <asm/bitops.h>
#include <asm/io.h>

/******************************************************************************
 * directives
 ******************************************************************************/
#define	__read_mostly
#define	__user
#define	__iomem

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

#ifndef spin_trylock_irq
#define spin_trylock_irq(lock) \
({ \
	local_irq_disable(); \
	spin_trylock(lock) ? \
	1 : ({ local_irq_enable(); 0;  }); \
})
#endif

#ifndef spin_trylock_irqsave
#define _spin_trylock	spin_trylock
#define spin_trylock_irqsave(lock, flags) \
({ \
	local_irq_save(flags); \
	_spin_trylock(lock) ? \
	1 : ({ local_irq_restore(flags); 0; }); \
})
#endif

/******************************************************************************
 * module compatibility
 ******************************************************************************/
#define	MODULE_VERSION(x)

/*
 * this macro only works for integer type parameters. If other types of
 * module parameters are added then this will need to be updated.
 */
#define module_param(param, type, perm)		MODULE_PARM(param, "i");

typedef void irqreturn_t;

int atomic_add_return(int i, atomic_t *v);

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

void tcp_v4_setup_caps(struct sock *sk, struct dst_entry *dst);

static inline void t3_set_ca_ops(struct sock *sk,
                                 struct tcp_congestion_ops *t_ops)
{}

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
        	case SOCK_TIMESTAMP:
        	case SOCK_QUEUE_SHRUNK:
		default:
			/* XXX */
			printk("sock_set_flag_val: unknown flag\n");
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
        	case SOCK_TIMESTAMP:
        	case SOCK_QUEUE_SHRUNK:
		default:
			/* XXX */
			printk("sock_set_flag_val: unknown flag\n");
			break;
	}
        return val;
}

static inline void sock_set_flag(struct sock *sk, enum sock_flags flag)
{
	sock_set_flag_val(sk, flag, 1);
}

#define sock_owned_by_user(sk)  ((sk)->lock.users != 0)

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

#define INET_DIAG_MAX INET_DIAG_CONG

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
#define inet_csk_reqsk_queue_removed tcp_synq_removed
#define inet_csk_delete_keepalive_timer tcp_delete_keepalive_timer
#define inet_csk_reqsk_queue_is_full tcp_synq_is_full
#define inet_csk_reqsk_queue_add tcp_acceptq_queue
#define inet_csk_reqsk_queue_added(sk, timeo) tcp_synq_added(sk)

#define __reqsk_free tcp_openreq_fastfree
#define tcp_rsk
#define inet_rsk

#define inet_inherit_port(p_hashinfo, lsk, newsk) tcp_inherit_port(lsk, newsk)
#define inet_put_port(a, sk) tcp_put_port(sk)

#define ACCEPT_QUEUE(sk) (&(tcp_sk(sk)->accept_queue))
#define ACCEPT_QUEUE_TAIL(sk) (&(tcp_sk(sk)->accept_queue_tail))
#define LISTEN_OPT(sk) (&(tcp_sk(sk)->listen_opt))

#define PACKETS_OUT(tcp_sock) ((tcp_sock)->packets_out)
#define LEFT_OUT(tcp_sock) ((tcp_sock)->left_out)
#define RETRANS_OUT(tcp_sock) ((tcp_sock)->retrans_out)

#define MSS_CLAMP(tp) ((tp)->mss_clamp)
#define SND_WSCALE(tp) ((tp)->snd_wscale)
#define RCV_WSCALE(tp) ((tp)->rcv_wscale)
#define USER_MSS(tp) ((tp)->user_mss)
#define NUM_SACKS(tp) ((tp)->num_sacks)
#define TS_RECENT_STAMP(tp) ((tp)->ts_recent_stamp)
#define WSCALE_OK(tp) ((tp)->wscale_ok)
#define TSTAMP_OK(tp) ((tp)->tstamp_ok)
#define SACK_OK(tp) ((tp)->sack_ok)

#define forward_skb_hint ucopy.prequeue.next
#define fastpath_skb_hint ucopy.prequeue.prev


/******************************************************************************
 * netdev compatibility
 ******************************************************************************/
static inline int __netif_rx_schedule_prep(struct net_device *dev)
{
	return !test_and_set_bit(__LINK_STATE_RX_SCHED, &dev->state);
}

#define NETDEV_TX_OK 0          /* driver took care of packet */
#define NETDEV_TX_BUSY 1        /* driver tx path was busy*/
#define NETDEV_TX_LOCKED -1     /* driver tx lock was already taken */

#ifndef SET_NETDEV_DEV
#define	SET_NETDEV_DEV(netdev, pdev)
#endif

#ifndef NETIF_F_LLTX
#define NETIF_F_LLTX	0
#endif
#ifndef NETIF_F_TSO
#define NETIF_F_TSO	0
#define NETIF_F_TSO_FAKE
#endif

#define NETDEV_ALIGN            32
#define NETDEV_ALIGN_CONST      (NETDEV_ALIGN - 1)

static inline void *netdev_priv(struct net_device *dev)
{
        return (char *)dev + ((sizeof(struct net_device)
                                        + NETDEV_ALIGN_CONST)
                                & ~NETDEV_ALIGN_CONST);
}

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


static inline void net_inc_stats(int stat)
{
	switch(stat) {
		case LINUX_MIB_TCPABORTONDATA:
			SNMP_INC_STATS(net_statistics, TCPAbortOnData);
			break;
		case LINUX_MIB_TCPABORTONLINGER:
			SNMP_INC_STATS(net_statistics, TCPAbortOnLinger);
			break;
		case LINUX_MIB_TCPABORTONSYN:
			SNMP_INC_STATS(net_statistics, TCPAbortOnSyn);
			break;
		case LINUX_MIB_TCPABORTONTIMEOUT:
			SNMP_INC_STATS(net_statistics, TCPAbortOnTimeout);
			break;
		case LINUX_MIB_LISTENOVERFLOWS:
			SNMP_INC_STATS(net_statistics, ListenOverflows);
			break;
		case LINUX_MIB_LISTENDROPS:
			SNMP_INC_STATS(net_statistics, ListenDrops);
			break;
		case LINUX_MIB_TCPABORTONCLOSE:
			SNMP_INC_STATS(net_statistics, TCPAbortOnClose);
			break;
		case LINUX_MIB_TCPABORTONMEMORY:
			SNMP_INC_STATS(net_statistics, TCPAbortOnMemory);
			break;
	}
}

#if XXX
#undef	NET_INC_STATS_USER
#undef	NET_INC_STATS_BH

#define	NET_INC_STATS_BH(stat)			net_inc_stats((stat))
#define	NET_INC_STATS_USER(stat)		net_inc_stats((stat))
#endif

struct request_sock_ops {
        int             family;
        int             obj_size;
};

/* Inet diag stuff. Added for compilation only */
enum {
        INET_DIAG_NONE,
        INET_DIAG_MEMINFO,
        INET_DIAG_INFO,
        INET_DIAG_VEGASINFO,
        INET_DIAG_CONG,
};

static inline void t3_init_rsk_ops(struct proto *t3_tcp_prot,
                                   struct request_sock_ops *t3_tcp_ops,
                                   struct proto *tcp_prot)
{}

#ifdef XXX
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
#endif

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

static inline int synq_empty(struct sock *sk)
{
	return skb_queue_empty(&tcp_sk(sk)->ucopy.prequeue);
}

static inline void reset_synq(struct tcp_sock *tp)
{
	skb_queue_head_init(&tp->ucopy.prequeue);
}

static inline void reset_wr_list(struct tcp_sock *tp)
{
	skb_queue_head_init(&tp->ucopy.prequeue);
}

static inline int wr_list_empty(struct tcp_sock *tp)
{
	return (skb_queue_empty(&tp->ucopy.prequeue));
}

/*
 * Add a WR to a socket's list of pending WRs.  This is a singly-linked list
 */
static inline void enqueue_wr(struct tcp_sock *tp, struct sk_buff *skb)
{
        struct sk_buff *tail = (struct sk_buff *)tp->ucopy.iov;

        skb->dev = NULL;
        /*
         *  We want to take an extra reference since both us and the driver
         *  need to free the packet before it's really freed.  We know there's
         * just one user currently so we use atomic_set rather than skb_get
         * to avoid the atomic op.
         */
        atomic_set(&skb->users, 2);

        if (wr_list_empty(tp))
                tp->ucopy.prequeue.next = skb;
        else
                tail->dev = (void *)skb;
        tp->ucopy.iov = (void *)skb;

}


/*
 * Return the first pending WR without removing it from the list.
 */
static inline struct sk_buff *peek_wr(struct tcp_sock *tp)
{
        if (unlikely(wr_list_empty(tp)))
                return NULL;
        return (tp->ucopy.prequeue.next);
}

/*
 * Dequeue and return the first unacknowledged's WR on a socket's pending list.
 */
static inline struct sk_buff *dequeue_wr(struct tcp_sock *tp)
{
        struct sk_buff *skb = tp->ucopy.prequeue.next;

        if (unlikely(wr_list_empty(tp)))
                        return NULL;

        if (!skb->dev)
                tp->ucopy.prequeue.next = tp->ucopy.prequeue.prev;
        else
                tp->ucopy.prequeue.next = (void *)skb->dev;

        skb->dev = NULL;
        return skb;
}

extern int prepare_tom_for_offload(void);

/* these are defined to nothing since 2.4 interrupt handlers are voids */
#define	IRQ_NONE
#define	IRQ_HANDLED
#define	IRQ_RETVAL(x)

/******************************************************************************
 * DMA compatibility
 ******************************************************************************/
#define DMA_64BIT_MASK  0xffffffffffffffffULL
#define DMA_48BIT_MASK  0x0000ffffffffffffULL
#define DMA_40BIT_MASK  0x000000ffffffffffULL
#define DMA_39BIT_MASK  0x0000007fffffffffULL
#define DMA_32BIT_MASK  0x00000000ffffffffULL
#define DMA_31BIT_MASK  0x000000007fffffffULL
#define DMA_30BIT_MASK  0x000000003fffffffULL
#define DMA_29BIT_MASK  0x000000001fffffffULL
#define DMA_28BIT_MASK  0x000000000fffffffULL
#define DMA_24BIT_MASK  0x0000000000ffffffULL

/******************************************************************************
 * PHY compatibility
 ******************************************************************************/
#define BMCR_SPEED1000          0x0040  /* MSB of Speed (1000)         */

#define MII_CTRL1000        0x09        /* 1000BASE-T control          */

#define ADVERTISE_1000XFULL     0x0020  /* Try for 1000BASE-X full-duplex */
#define ADVERTISE_1000XHALF     0x0040  /* Try for 1000BASE-X half-duplex */
#define ADVERTISE_1000XPAUSE	0x0080	/* Try for 1000BASE-X pause    */
#define ADVERTISE_1000XPSE_ASYM	0x0100	/* Try for 1000BASE-X asym pause */
#define ADVERTISE_PAUSE_CAP     0x0400  /* Try for pause               */
#define ADVERTISE_PAUSE_ASYM    0x0800  /* Try for asymetric pause     */

/* 1000BASE-T Control register */
#define ADVERTISE_1000FULL      0x0200  /* Advertise 1000BASE-T full duplex */
#define ADVERTISE_1000HALF      0x0100  /* Advertise 1000BASE-T half duplex */

#define ADVERTISED_Pause                (1 << 13)
#define ADVERTISED_Asym_Pause           (1 << 14)

/******************************************************************************
 * PCI compatibility
 ******************************************************************************/
int pci_set_consistent_dma_mask(struct pci_dev *dev, u64 mask);
static inline int pci_dma_mapping_error(dma_addr_t addr)
{
	return (addr == 0);
}

#define PCI_VPD_ADDR            2       /* Address to access (15 bits!) */
#define  PCI_VPD_ADDR_MASK      0x7fff  /* Address mask */
#define  PCI_VPD_ADDR_F         0x8000  /* Write 0, 1 indicates completion */
#define PCI_VPD_DATA            4       /* 32-bits of data returned here */

/* PCI Express capability registers */
#define PCI_EXP_FLAGS           2       /* Capabilities register */
#define PCI_EXP_FLAGS_VERS      0x000f  /* Capability version */
#define PCI_EXP_FLAGS_TYPE      0x00f0  /* Device/Port type */
#define  PCI_EXP_TYPE_ENDPOINT  0x0     /* Express Endpoint */
#define  PCI_EXP_TYPE_LEG_END   0x1     /* Legacy Endpoint */
#define  PCI_EXP_TYPE_ROOT_PORT 0x4     /* Root Port */
#define  PCI_EXP_TYPE_UPSTREAM  0x5     /* Upstream Port */
#define  PCI_EXP_TYPE_DOWNSTREAM 0x6    /* Downstream Port */
#define  PCI_EXP_TYPE_PCI_BRIDGE 0x7    /* PCI/PCI-X Bridge */
#define PCI_EXP_FLAGS_SLOT      0x0100  /* Slot implemented */
#define PCI_EXP_FLAGS_IRQ       0x3e00  /* Interrupt message number */
#define PCI_EXP_DEVCAP          4       /* Device capabilities */
#define  PCI_EXP_DEVCAP_PAYLOAD 0x07    /* Max_Payload_Size */
#define  PCI_EXP_DEVCAP_PHANTOM 0x18    /* Phantom functions */
#define  PCI_EXP_DEVCAP_EXT_TAG 0x20    /* Extended tags */
#define  PCI_EXP_DEVCAP_L0S     0x1c0   /* L0s Acceptable Latency */
#define  PCI_EXP_DEVCAP_L1      0xe00   /* L1 Acceptable Latency */
#define  PCI_EXP_DEVCAP_ATN_BUT 0x1000  /* Attention Button Present */
#define  PCI_EXP_DEVCAP_ATN_IND 0x2000  /* Attention Indicator Present */
#define  PCI_EXP_DEVCAP_PWR_IND 0x4000  /* Power Indicator Present */
#define  PCI_EXP_DEVCAP_PWR_VAL 0x3fc0000 /* Slot Power Limit Value */
#define  PCI_EXP_DEVCAP_PWR_SCL 0xc000000 /* Slot Power Limit Scale */
#define PCI_EXP_DEVCTL          8       /* Device Control */
#define  PCI_EXP_DEVCTL_CERE    0x0001  /* Correctable Error Reporting En. */
#define  PCI_EXP_DEVCTL_NFERE   0x0002  /* Non-Fatal Error Reporting Enable */
#define  PCI_EXP_DEVCTL_FERE    0x0004  /* Fatal Error Reporting Enable */
#define  PCI_EXP_DEVCTL_URRE    0x0008  /* Unsupported Request Reporting En. */
#define  PCI_EXP_DEVCTL_RELAX_EN 0x0010 /* Enable relaxed ordering */
#define  PCI_EXP_DEVCTL_PAYLOAD 0x00e0  /* Max_Payload_Size */
#define  PCI_EXP_DEVCTL_EXT_TAG 0x0100  /* Extended Tag Field Enable */
#define  PCI_EXP_DEVCTL_PHANTOM 0x0200  /* Phantom Functions Enable */
#define  PCI_EXP_DEVCTL_AUX_PME 0x0400  /* Auxiliary Power PM Enable */
#define  PCI_EXP_DEVCTL_NOSNOOP_EN 0x0800  /* Enable No Snoop */
#define  PCI_EXP_DEVCTL_READRQ  0x7000  /* Max_Read_Request_Size */
#define PCI_EXP_DEVSTA          10      /* Device Status */
#define  PCI_EXP_DEVSTA_CED     0x01    /* Correctable Error Detected */
#define  PCI_EXP_DEVSTA_NFED    0x02    /* Non-Fatal Error Detected */
#define  PCI_EXP_DEVSTA_FED     0x04    /* Fatal Error Detected */
#define  PCI_EXP_DEVSTA_URD     0x08    /* Unsupported Request Detected */
#define  PCI_EXP_DEVSTA_AUXPD   0x10    /* AUX Power Detected */
#define  PCI_EXP_DEVSTA_TRPND   0x20    /* Transactions Pending */
#define PCI_EXP_LNKCAP          12      /* Link Capabilities */
#define PCI_EXP_LNKCTL          16      /* Link Control */
#define PCI_EXP_LNKSTA          18      /* Link Status */
#define PCI_EXP_SLTCAP          20      /* Slot Capabilities */
#define PCI_EXP_SLTCTL          24      /* Slot Control */
#define PCI_EXP_SLTSTA          26      /* Slot Status */
#define PCI_EXP_RTCTL           28      /* Root Control */
#define  PCI_EXP_RTCTL_SECEE    0x01    /* System Error on Correctable Error */
#define  PCI_EXP_RTCTL_SENFEE   0x02    /* System Error on Non-Fatal Error */
#define  PCI_EXP_RTCTL_SEFEE    0x04    /* System Error on Fatal Error */
#define  PCI_EXP_RTCTL_PMEIE    0x08    /* PME Interrupt Enable */
#define  PCI_EXP_RTCTL_CRSSVE   0x10    /* CRS Software Visibility Enable */
#define PCI_EXP_RTCAP           30      /* Root Capabilities */
#define PCI_EXP_RTSTA           32      /* Root Status */

#define  PCI_CAP_ID_EXP         0x10    /* PCI Express */

struct msix_entry {
        u16     vector; /* kernel uses to write allocated vector */
        u16     entry;  /* driver uses to specify entry, OS writes */
};

int pci_enable_msi(struct pci_dev* dev);
int pci_disable_msi(struct pci_dev* dev);
int pci_enable_msix(struct pci_dev* dev, struct msix_entry *entries, int nvec);
int pci_disable_msix(struct pci_dev* dev);

inline int t3_os_pci_save_state(adapter_t *adapter);
inline int t3_os_pci_restore_state(adapter_t *adapter);

#define	pci_dma_sync_single_for_cpu	pci_dma_sync_single
#define	pci_dma_sync_single_for_device	pci_dma_sync_single


/******************************************************************************
 * memory management compatibility
 ******************************************************************************/
#define	__GFP_NOFAIL	0
#define __GFP_COMP	0

void *kzalloc(size_t size, gfp_t flags);
void *kcalloc(size_t n, size_t size, gfp_t flags);

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

#endif 	/* __LINUX_2_4_COMPAT_H__ */
