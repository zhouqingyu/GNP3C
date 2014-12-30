/*
 * This file contains pieces of the Linux TCP/IP stack needed for modular
 * TOE support.
 *
 * Copyright (C) 2006-2009 Chelsio Communications.  All rights reserved.
 * See the corresponding files in the Linux tree for copyrights of the
 * original Linux code a lot of this file is based on.
 *
 * Additional code written by Dimitris Michailidis (dm@chelsio.com)
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

#ifndef AUTOCONF_INCLUDED
#include <linux/autoconf.h>
#endif
#include <net/tcp.h>
#include <linux/random.h>
#include <linux/kallsyms.h>
#include <linux/toedev.h>
#include <net/offload.h>
#include "toe_compat.h"
#include <linux/sunrpc/xprt.h>

int sysctl_tcp_tw_reuse = 0;

static struct proto orig_tcp_prot;
static struct proto_ops *inet_stream_ops;

/* The next few definitions track the data_ready callbacks for RPC and iSCSI */
static void (*iscsi_tcp_data_ready_p)(struct sock *sk, int bytes);
static sk_read_actor_t iscsi_tcp_recv_p;
static void (*xs_tcp_data_ready_p)(struct sock *sk, int bytes);
static sk_read_actor_t xs_tcp_data_recv_p;

/*
 * The next two definitions provide a replacement for route.h:rt_get_peer(),
 * which is not exported to modules.
 */
static void (*rt_bind_peer_p)(struct rtable *rt, int create);

static inline struct inet_peer *rt_get_peer_offload(struct rtable *rt)
{
	if (rt->peer)
		return rt->peer;

	if (rt_bind_peer_p)
		rt_bind_peer_p(rt, 0);
	return rt->peer;
}

static void find_rpc_iscsi_callbacks(void)
{
	/* All of these may fail since RPC/iSCSI may not be loaded */
	iscsi_tcp_data_ready_p =
		(void *)kallsyms_lookup_name("iscsi_tcp_data_ready");
	iscsi_tcp_recv_p = (void *)kallsyms_lookup_name("iscsi_tcp_recv");
	xs_tcp_data_ready_p =
		(void *)kallsyms_lookup_name("tcp_data_ready");
	xs_tcp_data_recv_p = (void *)kallsyms_lookup_name("tcp_data_recv");
}

void security_inet_conn_estab(struct sock *sk, struct sk_buff *skb)
{
	security_inet_conn_established(sk, skb);
}
EXPORT_SYMBOL(security_inet_conn_estab);

static int (*__ip_route_output_key_p)(struct rtable **rp, const struct flowi *flp);

static inline int __ip_route_output_key_offload(struct rtable **rp,
						const struct flowi *flp)
{
	if (__ip_route_output_key_p)
		return __ip_route_output_key_p(rp, flp);
	else
		return -1;
}

static int (*ip_route_output_flow_p)(struct rtable **rp, struct flowi *flp,
				     struct sock *sk, int flags);

static inline int ip_route_output_flow_offload(struct rtable **rp,
					       struct flowi *flp,
				  	       struct sock *sk, int flags)
{
	if (ip_route_output_flow_p)
		return ip_route_output_flow_p(rp, flp, sk, flags);
	else
		return -1;
}

static inline int ip_route_connect_offload(struct rtable **rp, u32 dst,
				   u32 src, u32 tos, int oif, u8 protocol,
				   u16 sport, u16 dport, struct sock *sk)
{
	struct flowi fl = { .oif = oif,
			    .nl_u = { .ip4_u = { .daddr = dst,
						 .saddr = src,
						 .tos   = tos } },
			    .proto = protocol,
			    .uli_u = { .ports =
				       { .sport = sport,
					 .dport = dport } } };

	int err;
	if (!dst || !src) {
		err = __ip_route_output_key_offload(rp, &fl);
		if (err)
			return err;
		fl.fl4_dst = (*rp)->rt_dst;
		fl.fl4_src = (*rp)->rt_src;
		ip_rt_put(*rp);
		*rp = NULL;
	}
	return ip_route_output_flow_offload(rp, &fl, sk, 0);
}

static inline int ip_route_newports_offload(struct rtable **rp,
					    u16 sport, u16 dport,
					    struct sock *sk)
{
	if (sport != (*rp)->fl.fl_ip_sport ||
	    dport != (*rp)->fl.fl_ip_dport) {
		struct flowi fl;

		memcpy(&fl, &(*rp)->fl, sizeof(fl));
		fl.fl_ip_sport = sport;
		fl.fl_ip_dport = dport;
		ip_rt_put(*rp);
		*rp = NULL;
		return ip_route_output_flow_offload(rp, &fl, sk, 0);
	}
	return 0;
}

/*
 * The functions below replace some of the original methods of tcp_prot to
 * support offloading.
 */

static void tcp_v4_hash_offload(struct sock *sk)
{
	orig_tcp_prot.hash(sk);
	if (sk->sk_state == TCP_LISTEN)
		start_listen_offload(sk);
}

static void tcp_unhash_offload(struct sock *sk)
{
	if (sk->sk_state == TCP_LISTEN)
		stop_listen_offload(sk);

	orig_tcp_prot.unhash(sk);
}

/*
 * The functions below are adapted from tcp_ipv4.c
 * to provide tcp_tcp_v4_hash_connect().
 */
static __inline__ int tcp_hashfn(__u32 laddr, __u16 lport,
				 __u32 faddr, __u16 fport)
{
	int h = (laddr ^ lport) ^ (faddr ^ fport);
	h ^= h >> 16;
	h ^= h >> 8;
	return h & (tcp_ehash_size - 1);
}

static __inline__ int tcp_sk_hashfn(struct sock *sk)
{
	struct inet_opt *inet = inet_sk(sk);
	__u32 laddr = inet->rcv_saddr;
	__u16 lport = inet->num;
	__u32 faddr = inet->daddr;
	__u16 fport = inet->dport;

	return tcp_hashfn(laddr, lport, faddr, fport);
}

/* called with local bh disabled */
static int __tcp_v4_check_established(struct sock *sk, __u16 lport,
				      struct tcp_tw_bucket **twp)
{
	struct inet_opt *inet = inet_sk(sk);
	u32 daddr = inet->rcv_saddr;
	u32 saddr = inet->daddr;
	int dif = sk->sk_bound_dev_if;
	TCP_V4_ADDR_COOKIE(acookie, saddr, daddr)
	__u32 ports = TCP_COMBINED_PORTS(inet->dport, lport);
	int hash = tcp_hashfn(daddr, lport, saddr, inet->dport);
	struct tcp_ehash_bucket *head = &tcp_ehash[hash];
	struct sock *sk2;
	struct hlist_node *node;
	struct tcp_tw_bucket *tw;

	write_lock(&head->lock);

	/* Check TIME-WAIT sockets first. */
	sk_for_each(sk2, node, &(head + tcp_ehash_size)->chain) {
		tw = (struct tcp_tw_bucket *)sk2;

		if (TCP_IPV4_TW_MATCH(sk2, acookie, saddr, daddr, ports, dif)) {
			struct tcp_opt *tp = tcp_sk(sk);

			/* With PAWS, it is safe from the viewpoint
			   of data integrity. Even without PAWS it
			   is safe provided sequence spaces do not
			   overlap i.e. at data rates <= 80Mbit/sec.

			   Actually, the idea is close to VJ's one,
			   only timestamp cache is held not per host,
			   but per port pair and TW bucket is used
			   as state holder.

			   If TW bucket has been already destroyed we
			   fall back to VJ's scheme and use initial
			   timestamp retrieved from peer table.
			 */
			if (tw->tw_ts_recent_stamp &&
			    (!twp || (sysctl_tcp_tw_reuse &&
				      xtime.tv_sec -
				      tw->tw_ts_recent_stamp > 1))) {
				if ((tp->write_seq =
						tw->tw_snd_nxt + 65535 + 2) == 0)
					tp->write_seq = 1;
				tp->ts_recent	    = tw->tw_ts_recent;
				tp->ts_recent_stamp = tw->tw_ts_recent_stamp;
				sock_hold(sk2);
				goto unique;
			} else
				goto not_unique;
		}
	}
	tw = NULL;

	/* And established part... */
	sk_for_each(sk2, node, &head->chain) {
		if (TCP_IPV4_MATCH(sk2, acookie, saddr, daddr, ports, dif))
			goto not_unique;
	}

unique:
	/* Must record num and sport now. Otherwise we will see
	 * in hash table socket with a funny identity. */
	inet->num = lport;
	inet->sport = htons(lport);
	sk->sk_hashent = hash;
	BUG_TRAP(sk_unhashed(sk));
	__sk_add_node(sk, &head->chain);
	sock_prot_inc_use(sk->sk_prot);
	write_unlock(&head->lock);

	if (twp) {
		*twp = tw;
		NET_INC_STATS_BH(LINUX_MIB_TIMEWAITRECYCLED);
	} else if (tw) {
		/* Silly. Should hash-dance instead... */
		tcp_tw_deschedule(tw);
		NET_INC_STATS_BH(LINUX_MIB_TIMEWAITRECYCLED);

		tcp_tw_put(tw);
	}

	return 0;

not_unique:
	write_unlock(&head->lock);
	return -EADDRNOTAVAIL;
}

static __inline__ void __tcp_v4_hash(struct sock *sk, const int listen_possible)
{
	struct hlist_head *list;
	rwlock_t *lock;

	BUG_TRAP(sk_unhashed(sk));
	if (listen_possible && sk->sk_state == TCP_LISTEN) {
		list = &tcp_listening_hash[tcp_sk_listen_hashfn(sk)];
		lock = &tcp_lhash_lock;
		tcp_listen_wlock();
	} else {
		list = &tcp_ehash[(sk->sk_hashent = tcp_sk_hashfn(sk))].chain;
		lock = &tcp_ehash[sk->sk_hashent].lock;
		write_lock(lock);
	}
	__sk_add_node(sk, list);
	sock_prot_inc_use(sk->sk_prot);
	write_unlock(lock);
	if (listen_possible && sk->sk_state == TCP_LISTEN)
		wake_up(&tcp_lhash_wait);
}

/*
 * Bind a port for a connect operation and hash it.
 */
static int tcp_v4_hash_connect(struct sock *sk)
{
	unsigned short snum = inet_sk(sk)->num;
 	struct tcp_bind_hashbucket *head;
 	struct tcp_bind_bucket *tb;
	int ret;

 	if (!snum) {
 		int rover;
 		int low = sysctl_local_port_range[0];
 		int high = sysctl_local_port_range[1];
 		int remaining = (high - low) + 1;
		struct hlist_node *node;
 		struct tcp_tw_bucket *tw = NULL;

 		local_bh_disable();

 		/* TODO. Actually it is not so bad idea to remove
 		 * tcp_portalloc_lock before next submission to Linus.
 		 * As soon as we touch this place at all it is time to think.
 		 *
 		 * Now it protects single _advisory_ variable tcp_port_rover,
 		 * hence it is mostly useless.
 		 * Code will work nicely if we just delete it, but
 		 * I am afraid in contented case it will work not better or
 		 * even worse: another cpu just will hit the same bucket
 		 * and spin there.
 		 * So some cpu salt could remove both contention and
 		 * memory pingpong. Any ideas how to do this in a nice way?
 		 */
 		spin_lock(&tcp_portalloc_lock);
 		rover = tcp_port_rover;

 		do {
 			rover++;
 			if ((rover < low) || (rover > high))
 				rover = low;
 			head = &tcp_bhash[tcp_bhashfn(rover)];
 			spin_lock(&head->lock);

 			/* Does not bother with rcv_saddr checks,
 			 * because the established check is already
 			 * unique enough.
 			 */
			tb_for_each(tb, node, &head->chain) {
 				if (tb->port == rover) {
 					BUG_TRAP(!hlist_empty(&tb->owners));
 					if (tb->fastreuse >= 0)
 						goto next_port;
 					if (!__tcp_v4_check_established(sk,
									rover,
									&tw))
 						goto ok;
 					goto next_port;
 				}
 			}

 			tb = tcp_bucket_create(head, rover);
 			if (!tb) {
 				spin_unlock(&head->lock);
 				break;
 			}
 			tb->fastreuse = -1;
 			goto ok;

 		next_port:
 			spin_unlock(&head->lock);
 		} while (--remaining > 0);
 		tcp_port_rover = rover;
 		spin_unlock(&tcp_portalloc_lock);

 		local_bh_enable();

 		return -EADDRNOTAVAIL;

ok:
 		/* All locks still held and bhs disabled */
 		tcp_port_rover = rover;
 		spin_unlock(&tcp_portalloc_lock);

 		tcp_bind_hash(sk, tb, rover);
		if (sk_unhashed(sk)) {
 			inet_sk(sk)->sport = htons(rover);
 			__tcp_v4_hash(sk, 0);
 		}
 		spin_unlock(&head->lock);

 		if (tw) {
 			tcp_tw_deschedule(tw);
 			tcp_tw_put(tw);
 		}

		ret = 0;
		goto out;
 	}

 	head  = &tcp_bhash[tcp_bhashfn(snum)];
 	tb  = tcp_sk(sk)->bind_hash;
	spin_lock_bh(&head->lock);
	if (sk_head(&tb->owners) == sk && !sk->sk_bind_node.next) {
		__tcp_v4_hash(sk, 0);
		spin_unlock_bh(&head->lock);
		return 0;
	} else {
		spin_unlock(&head->lock);
		/* No definite answer... Walk to established hash table */
		ret = __tcp_v4_check_established(sk, snum, NULL);
out:
		local_bh_enable();
		return ret;
	}
}

static int tcp_v4_connect_offload(struct sock *sk, struct sockaddr *uaddr,
				  int addr_len)
{
	struct inet_opt *inet = inet_sk(sk);
	struct tcp_opt *tp = tcp_sk(sk);
	struct sockaddr_in *usin = (struct sockaddr_in *)uaddr;
	struct rtable *rt;
	u32 daddr, nexthop;
	int tmp;
	int err;

	if (addr_len < sizeof(struct sockaddr_in))
		return -EINVAL;

	if (usin->sin_family != AF_INET)
		return -EAFNOSUPPORT;

	nexthop = daddr = usin->sin_addr.s_addr;
	if (inet->opt && inet->opt->srr) {
		if (!daddr)
			return -EINVAL;
		nexthop = inet->opt->faddr;
	}

	tmp = ip_route_connect_offload(&rt, nexthop, inet->saddr,
				       RT_CONN_FLAGS(sk), sk->sk_bound_dev_if,
				       IPPROTO_TCP,
				       inet->sport, usin->sin_port, sk);
	if (tmp < 0)
		return tmp;

	if (rt->rt_flags & (RTCF_MULTICAST | RTCF_BROADCAST)) {
		ip_rt_put(rt);
		return -ENETUNREACH;
	}

	if (!inet->opt || !inet->opt->srr)
		daddr = rt->rt_dst;

	if (!inet->saddr)
		inet->saddr = rt->rt_src;
	inet->rcv_saddr = inet->saddr;

	if (tp->ts_recent_stamp && inet->daddr != daddr) {
		/* Reset inherited state */
		tp->ts_recent	    = 0;
		tp->ts_recent_stamp = 0;
		tp->write_seq	    = 0;
	}

	if (sysctl_tcp_tw_recycle &&
	    !tp->ts_recent_stamp && rt->rt_dst == daddr) {
		struct inet_peer *peer = rt_get_peer_offload(rt);

		/* VJ's idea. We save last timestamp seen from
		 * the destination in peer table, when entering state TIME-WAIT
		 * and initialize ts_recent from it, when trying new connection.
		 */

		if (peer && peer->tcp_ts_stamp + TCP_PAWS_MSL >= xtime.tv_sec) {
			tp->ts_recent_stamp = peer->tcp_ts_stamp;
			tp->ts_recent = peer->tcp_ts;
		}
	}

	inet->dport = usin->sin_port;
	inet->daddr = daddr;

	tp->ext_header_len = 0;
	if (inet->opt)
		tp->ext_header_len = inet->opt->optlen;

	tp->mss_clamp = 536;

	/* Socket identity is still unknown (sport may be zero).
	 * However we set state to SYN-SENT and not releasing socket
	 * lock select source port, enter ourselves into the hash tables and
	 * complete initialization after this.
	 */
	tcp_set_state(sk, TCP_SYN_SENT);
	err = tcp_v4_hash_connect(sk);
	if (err)
		goto failure;

	err = ip_route_newports_offload(&rt, inet->sport, inet->dport, sk);
	if (err)
		goto failure;

	/* OK, now commit destination to socket.  */
	__sk_dst_set(sk, &rt->u.dst);
	tcp_v4_setup_caps(sk, &rt->u.dst);
	tp->ext2_header_len = rt->u.dst.header_len;

	if (tcp_connect_offload(sk))
		return 0;

	if (!tp->write_seq)
		tp->write_seq = secure_tcp_sequence_number(inet->saddr,
							   inet->daddr,
							   inet->sport,
							   usin->sin_port);

	inet->id = tp->write_seq ^ jiffies;

	err = tcp_connect(sk);
	rt = NULL;
	if (err)
		goto failure;

	return 0;

failure:
	/* This unhashes the socket and releases the local port, if necessary. */
	tcp_set_state(sk, TCP_CLOSE);
	ip_rt_put(rt);
	sk->sk_route_caps = 0;
	inet->dport = 0;
	return err;
}

ssize_t tcp_sendpage_offload(struct socket *sock, struct page *page,
				    int offset, size_t size, int flags)
{
	struct sock *sk = sock->sk;

	if (sk->sk_prot->sendpage)
		return sk->sk_prot->sendpage(sk, page, offset, size, flags);

	return tcp_sendpage(sock, page, offset, size, flags);
}
EXPORT_SYMBOL(tcp_sendpage_offload);

int prepare_tcp_for_offload(void)
{
	int err;
	struct socket *sock;

	if (inet_stream_ops)   /* already done */
		return 0;

	err = sock_create_kern(PF_INET, SOCK_STREAM, IPPROTO_TCP, &sock);
	if (err < 0) {
		printk(KERN_ERR "Could not create TCP socket, error %d\n", err);
		return err;
	}

	/*
	 * rt_bind_peer is not a critical function, it's ok if we are unable
	 * to locate it.
	 */
	rt_bind_peer_p = (void *)kallsyms_lookup_name("rt_bind_peer");
	
	inet_stream_ops = (struct proto_ops *)sock->ops;
	inet_stream_ops->sendpage = tcp_sendpage_offload;
	sock_release(sock);

	orig_tcp_prot = tcp_prot;
	tcp_prot.hash = tcp_v4_hash_offload;
	tcp_prot.unhash = tcp_unhash_offload;
	tcp_prot.connect = tcp_v4_connect_offload;

	__ip_route_output_key_p = (void *)kallsyms_lookup_name("__ip_route_output_key");
	if (!__ip_route_output_key_p) {
		printk(KERN_ERR "Could not locate __ip_route_output_key_p");
		return -1;
	}

	ip_route_output_flow_p = (void *)kallsyms_lookup_name("ip_route_output_flow");
	if (!ip_route_output_flow_p) {
		printk(KERN_ERR "Could not locate ip_route_output_flow");
		return -1;
	}

	return 0;
}

void restore_tcp_to_nonoffload(void)
{
	if (inet_stream_ops) {
		inet_stream_ops->sendpage = tcp_sendpage;
		tcp_prot.hash = orig_tcp_prot.hash;
		tcp_prot.unhash = orig_tcp_prot.unhash;
		tcp_prot.connect = orig_tcp_prot.connect;
	}
}

static inline int ofld_read_sock(struct sock *sk, read_descriptor_t *desc,
				 sk_read_actor_t recv_actor)
{
	if (sock_flag(sk, SOCK_OFFLOADED)) {
		const struct sk_ofld_proto *p = (void *)sk->sk_prot;

		return p->read_sock(sk, desc, recv_actor);
	}
	return tcp_read_sock(sk, desc, recv_actor);
}

/* Replacement for RPC's ->data_ready callback */
static void xs_ofld_tcp_data_ready(struct sock *sk, int bytes)
{
	struct rpc_xprt *xprt;
	read_descriptor_t rd_desc;

	read_lock(&sk->sk_callback_lock);
	if (!(xprt = sk->sk_user_data))
		goto out;
	if (xprt->shutdown)
		goto out;

	/* We use rd_desc to pass struct xprt to xs_tcp_data_recv */
	rd_desc.arg.data = xprt;
	rd_desc.count = 65536;
	ofld_read_sock(sk, &rd_desc, xs_tcp_data_recv_p);
out:
	read_unlock(&sk->sk_callback_lock);
}

#if 0
/* Copy of iscsi_tcp_segment_unmap */
static inline void iscsi_tcp_segment_unmap(struct iscsi_segment *segment)
{
	if (segment->sg_mapped) {
		kunmap_atomic(segment->sg_mapped, KM_SOFTIRQ0);
		segment->sg_mapped = NULL;
		segment->data = NULL;
	}
}

/* Replacement for iSCSI's ->data_ready callback */
static void iscsi_ofld_tcp_data_ready(struct sock *sk, int bytes)
{
	struct iscsi_conn *conn = sk->sk_user_data;
	struct iscsi_tcp_conn *tcp_conn = conn->dd_data;
	read_descriptor_t rd_desc;

	read_lock(&sk->sk_callback_lock);

	rd_desc.arg.data = conn;
	rd_desc.count = 1;
	ofld_read_sock(sk, &rd_desc, iscsi_tcp_recv_p);

	read_unlock(&sk->sk_callback_lock);

	iscsi_tcp_segment_unmap(&tcp_conn->in.segment);
}
#endif

int install_special_data_ready(struct sock *sk)
{
	if (!sk->sk_user_data)
		return 0;

	find_rpc_iscsi_callbacks();

	if (sk->sk_data_ready == xs_tcp_data_ready_p)
		sk->sk_data_ready = xs_ofld_tcp_data_ready;
#if 0
	else if (sk->sk_data_ready == iscsi_tcp_data_ready_p)
		sk->sk_data_ready = iscsi_ofld_tcp_data_ready;
#endif
	else
		return 0;
	return 1;
}
EXPORT_SYMBOL(install_special_data_ready);

void restore_special_data_ready(struct sock *sk)
{
	if (sk->sk_data_ready == xs_ofld_tcp_data_ready)
		sk->sk_data_ready = xs_tcp_data_ready_p;
#if 0
	else if (sk->sk_data_ready == iscsi_ofld_tcp_data_ready)
		sk->sk_data_ready = iscsi_tcp_data_ready_p;
#endif
}
EXPORT_SYMBOL(restore_special_data_ready);

