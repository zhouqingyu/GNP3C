/*
 * This file contains pieces of the Linux TCP/IP stack needed for modular
 * TOE support.
 *
 * Copyright (C) 2006-2008 Chelsio Communications.  All rights reserved.
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

/*
 * The following tags are used by the out-of-kernel Makefile to identify
 * supported kernel versions if a module_support-<kver> file is not found.
 * Do not remove these tags.
 * $SUPPORTED KERNEL 2.6.32$
 */
#include <net/tcp.h>
#include <linux/random.h>
#include <linux/highmem.h>
#include <linux/pfn.h>
#include <linux/kprobes.h>
#include <linux/notifier.h>
#include <linux/module.h>
#include "toe_compat.h"
#include <linux/toedev.h>
#include <linux/sunrpc/xprt.h>
#include <net/inet_common.h>
#include <net/offload.h>
#include <linux/highmem.h>
#include <net/ipv6.h>
#include <net/transp_v6.h>
#include <net/ip6_route.h>
#include <net/inet6_hashtables.h>
#include <net/inet6_connection_sock.h>
#include "toe_iscsi.h"

#if defined(SECURE_SEQ)
#include <net/secure_seq.h>
#endif

static struct proto orig_tcp_prot;
static struct proto orig_tcpv6_prot;
static struct proto *tcpv6_prot_p;

static const struct inet_connection_sock_af_ops ipv6_mapped;
static const struct inet_connection_sock_af_ops ipv6_specific;
static struct request_sock_ops *tcp6_request_sock_ops_p;

static unsigned long (*kallsyms_lookup_name_p)(const char *name);
static __u32 (*secure_tcp_sequence_number_p)(__u32 saddr, __u32 daddr,
					     __u16 sport, __u16 dport);

void (*security_inet_conn_established_p)(struct sock *sk, struct sk_buff *skb);

static __u32 (*cookie_v6_init_sequence_p)(struct sock *sk,
					struct sk_buff *skb, __u16 *mssp);
static struct sock * (*cookie_v6_check_p)(struct sock *sk, struct sk_buff *skb);
/* Enable TCP options by default in case we can't locate the actual sysctls. */
static int tcp_options_sysctl = 1;
int *sysctl_tcp_timestamps_p = &tcp_options_sysctl;
int *sysctl_tcp_sack_p = &tcp_options_sysctl;
int *sysctl_tcp_window_scaling_p = &tcp_options_sysctl;
int *sysctl_tcp_ecn_p = &tcp_options_sysctl;

/* The next few definitions track the data_ready callbacks for RPC and iSCSI */
static void (*iscsi_tcp_data_ready_p)(struct sock *sk, int bytes);
static void (*iscsi_sw_tcp_data_ready_p)(struct sock *sk, int bytes);
static sk_read_actor_t iscsi_tcp_recv_p;
static sk_read_actor_t iscsi_sw_tcp_recv_p;
static sk_read_actor_t iscsi_tcp_data_recv_p;
static void (*xs_tcp_data_ready_p)(struct sock *sk, int bytes);
static sk_read_actor_t xs_tcp_data_recv_p;

/*
 * The next definitions provide a replacement for route.h:rt_get_peer(),
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
		(void *)kallsyms_lookup_name_p("iscsi_tcp_data_ready");
	iscsi_sw_tcp_data_ready_p =
		(void *)kallsyms_lookup_name_p("iscsi_sw_tcp_data_ready");
	iscsi_tcp_recv_p = (void *)kallsyms_lookup_name_p("iscsi_tcp_recv");
	iscsi_sw_tcp_recv_p =
		(void *)kallsyms_lookup_name_p("iscsi_sw_tcp_recv");
	iscsi_tcp_data_recv_p =
		(void *)kallsyms_lookup_name_p("iscsi_tcp_data_recv");
	xs_tcp_data_ready_p =
		(void *)kallsyms_lookup_name_p("xs_tcp_data_ready");
	xs_tcp_data_recv_p = (void *)kallsyms_lookup_name_p("xs_tcp_data_recv");
}

static int module_notify_handler(struct notifier_block *this,
				 unsigned long event, void *data)
{
	switch (event) {
	case MODULE_STATE_GOING:
		if (xs_tcp_data_ready_p || iscsi_tcp_data_ready_p)
			find_rpc_iscsi_callbacks();
		break;
	case MODULE_STATE_COMING:
		if (!xs_tcp_data_ready_p || !iscsi_tcp_data_ready_p)
			find_rpc_iscsi_callbacks();
		break;
	}
	return NOTIFY_DONE;
}

static struct notifier_block module_notifier = {
	.notifier_call = module_notify_handler
};

void security_inet_conn_estab(struct sock *sk, struct sk_buff *skb)
{
	if (security_inet_conn_established_p)
		security_inet_conn_established_p(sk, skb);
}
EXPORT_SYMBOL(security_inet_conn_estab);

static int (*skb_splice_bits_p)(struct sk_buff *skb, unsigned int offset,
				struct pipe_inode_info *pipe, unsigned int len,
				unsigned int flags);

int skb_splice_bits_pub(struct sk_buff *skb, unsigned int offset,
			struct pipe_inode_info *pipe, unsigned int len,
			unsigned int flags)
{
	return skb_splice_bits_p(skb, offset, pipe, len, flags);
}
EXPORT_SYMBOL(skb_splice_bits_pub);

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

static int tcp_v4_connect_offload(struct sock *sk, struct sockaddr *uaddr,
				  int addr_len)
{
	struct inet_sock *inet = inet_sk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	struct sockaddr_in *usin = (struct sockaddr_in *)uaddr;
	struct rtable *rt;
	__be32 daddr, nexthop;
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

	tmp = ip_route_connect(&rt, nexthop, inet->inet_saddr,
			       RT_CONN_FLAGS(sk), sk->sk_bound_dev_if,
			       IPPROTO_TCP,
			       inet->inet_sport, usin->sin_port, sk, 1);
	if (tmp < 0) {
		if (tmp == -ENETUNREACH)
			T3_IP_INC_STATS_BH(sock_net(sk), IPSTATS_MIB_OUTNOROUTES);
		return tmp;
	}

	if (rt->rt_flags & (RTCF_MULTICAST | RTCF_BROADCAST)) {
		ip_rt_put(rt);
		return -ENETUNREACH;
	}

	if (!inet->opt || !inet->opt->srr)
		daddr = rt->rt_dst;

	if (!inet->inet_saddr)
		inet->inet_saddr = rt->rt_src;
	inet->inet_rcv_saddr = inet->inet_saddr;

	if (tp->rx_opt.ts_recent_stamp && inet->inet_daddr != daddr) {
		/* Reset inherited state */
		tp->rx_opt.ts_recent	   = 0;
		tp->rx_opt.ts_recent_stamp = 0;
		tp->write_seq		   = 0;
	}

	if (tcp_death_row.sysctl_tw_recycle &&
	    !tp->rx_opt.ts_recent_stamp && rt->rt_dst == daddr) {
		struct inet_peer *peer = rt_get_peer_offload(rt);

		/* VJ's idea. We save last timestamp seen from
		 * the destination in peer table, when entering state TIME-WAIT
		 * and initialize rx_opt.ts_recent from it, when trying new
		 * connection.
		 */

		if (peer &&
		    peer->tcp_ts_stamp + TCP_PAWS_MSL >= get_seconds()) {
			tp->rx_opt.ts_recent_stamp = peer->tcp_ts_stamp;
			tp->rx_opt.ts_recent = peer->tcp_ts;
		}
	}

	inet->inet_dport = usin->sin_port;
	inet->inet_daddr = daddr;

	inet_csk(sk)->icsk_ext_hdr_len = 0;
	if (inet->opt)
		inet_csk(sk)->icsk_ext_hdr_len = inet->opt->optlen;

	tp->rx_opt.mss_clamp = 536;

	/* Socket identity is still unknown (sport may be zero).
	 * However we set state to SYN-SENT and not releasing socket
	 * lock select source port, enter ourselves into the hash tables and
	 * complete initialization after this.
	 */
	tcp_set_state(sk, TCP_SYN_SENT);
	err = inet_hash_connect(&tcp_death_row, sk);
	if (err)
		goto failure;

	err = ip_route_newports(&rt, IPPROTO_TCP, inet->inet_sport,
				inet->inet_dport, sk);
	if (err)
		goto failure;

	/* OK, now commit destination to socket.  */
	sk->sk_gso_type = SKB_GSO_TCPV4;
	sk_setup_caps(sk, &rt->u.dst);

	if (tcp_connect_offload(sk))
		return 0;

	if (!tp->write_seq)
		tp->write_seq = secure_tcp_sequence_number_p(inet->inet_saddr,
							     inet->inet_daddr,
							     inet->inet_sport,
							     usin->sin_port);

	inet->inet_id = tp->write_seq ^ jiffies;

	err = tcp_connect(sk);
	rt = NULL;
	if (err)
		goto failure;

	return 0;

failure:
	/* This unhashes the socket and releases the local port,
	   if necessary */
	tcp_set_state(sk, TCP_CLOSE);
	ip_rt_put(rt);
	sk->sk_route_caps = 0;
	inet->inet_dport = 0;
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

int tcp_sendmsg_offload(struct kiocb *iocb, struct socket *sock,
			       struct msghdr *msg, size_t size)
{
	struct sock *sk = sock->sk;

	if (sk->sk_prot->sendmsg)
		return sk->sk_prot->sendmsg(iocb, sk, msg, size);

	return tcp_sendmsg(iocb, (void *)sock, msg, size);
}
EXPORT_SYMBOL(tcp_sendmsg_offload);

ssize_t tcp_splice_read_offload(struct socket *sock, loff_t *ppos,
				       struct pipe_inode_info *pipe, size_t len,
				       unsigned int flags)
{
	struct sock *sk = sock->sk;

	if (sock_flag(sk, SOCK_OFFLOADED)) {
		const struct sk_ofld_proto *p = (void *)sk->sk_prot;

		return p->splice_read(sk, ppos, pipe, len, flags);
	}
	return tcp_splice_read(sock, ppos, pipe, len, flags);
}
EXPORT_SYMBOL(tcp_splice_read_offload);

static __inline__ __sum16 tcp_v6_check(int len,
				   struct in6_addr *saddr,
				   struct in6_addr *daddr,
				   __wsum base)
{
	return csum_ipv6_magic(saddr, daddr, len, IPPROTO_TCP, base);
}

static int tcp_v6_send_synack(struct sock *sk, struct request_sock *req)
{
	struct inet6_request_sock *treq = inet6_rsk(req);
	struct ipv6_pinfo *np = inet6_sk(sk);
	struct sk_buff * skb;
	struct ipv6_txoptions *opt = NULL;
	struct in6_addr * final_p = NULL, final;
	struct flowi fl;
	struct dst_entry *dst;
	int err = -1;

	memset(&fl, 0, sizeof(fl));
	fl.proto = IPPROTO_TCP;
	ipv6_addr_copy(&fl.fl6_dst, &treq->rmt_addr);
	ipv6_addr_copy(&fl.fl6_src, &treq->loc_addr);
	fl.fl6_flowlabel = 0;
	fl.oif = treq->iif;
	fl.fl_ip_dport = inet_rsk(req)->rmt_port;
	fl.fl_ip_sport = inet_rsk(req)->loc_port;
	security_req_classify_flow(req, &fl);

	opt = np->opt;
	if (opt && opt->srcrt) {
		struct rt0_hdr *rt0 = (struct rt0_hdr *) opt->srcrt;
		ipv6_addr_copy(&final, &fl.fl6_dst);
		ipv6_addr_copy(&fl.fl6_dst, rt0->addr);
		final_p = &final;
	}

	err = ip6_dst_lookup(sk, &dst, &fl);
	if (err)
		goto done;
	if (final_p)
		ipv6_addr_copy(&fl.fl6_dst, final_p);
	if ((err = xfrm_lookup(sock_net(sk), &dst, &fl, sk, 0)) < 0)
		goto done;

	skb = tcp_make_synack(sk, dst, req);
	if (skb) {
		struct tcphdr *th = tcp_hdr(skb);

		th->check = tcp_v6_check(skb->len,
					 &treq->loc_addr, &treq->rmt_addr,
					 csum_partial(th, skb->len, skb->csum));

		ipv6_addr_copy(&fl.fl6_dst, &treq->rmt_addr);
		err = ip6_xmit(sk, skb, &fl, opt, 0);
		err = net_xmit_eval(err);
	}

done:
	if (opt && opt != np->opt)
		sock_kfree_s(sk, opt, opt->tot_len);
	dst_release(dst);
	return err;
}

static inline void syn_flood_warning(struct sk_buff *skb)
{
#ifdef CONFIG_SYN_COOKIES
	if (sysctl_tcp_syncookies)
		printk(KERN_INFO
		       "TCPv6: Possible SYN flooding on port %d. "
		       "Sending cookies.\n", ntohs(tcp_hdr(skb)->dest));
	else
#endif
		printk(KERN_INFO
		       "TCPv6: Possible SYN flooding on port %d. "
		       "Dropping request.\n", ntohs(tcp_hdr(skb)->dest));
}

#ifdef CONFIG_TCP_MD5SIG

static int tcp_v6_md5_hash_pseudoheader(struct tcp_md5sig_pool *hp,
					struct in6_addr *daddr,
					struct in6_addr *saddr, int nbytes)
{
	struct tcp6_pseudohdr *bp;
	struct scatterlist sg;

	bp = &hp->md5_blk.ip6;
	/* 1. TCP pseudo-header (RFC2460) */
	ipv6_addr_copy(&bp->saddr, saddr);
	ipv6_addr_copy(&bp->daddr, daddr);
	bp->protocol = cpu_to_be32(IPPROTO_TCP);
	bp->len = cpu_to_be32(nbytes);

	sg_init_one(&sg, bp, sizeof(*bp));
	return crypto_hash_update(&hp->md5_desc, &sg, sizeof(*bp));
}

static int tcp_v6_md5_hash_skb(char *md5_hash, struct tcp_md5sig_key *key,
			       struct sock *sk, struct request_sock *req,
			       struct sk_buff *skb)
{
	struct in6_addr *saddr, *daddr;
	struct tcp_md5sig_pool *hp;
	struct hash_desc *desc;
	struct tcphdr *th = tcp_hdr(skb);

	if (sk) {
		saddr = &inet6_sk(sk)->saddr;
		daddr = &inet6_sk(sk)->daddr;
	} else if (req) {
		saddr = &inet6_rsk(req)->loc_addr;
		daddr = &inet6_rsk(req)->rmt_addr;
	} else {
		struct ipv6hdr *ip6h = ipv6_hdr(skb);
		saddr = &ip6h->saddr;
		daddr = &ip6h->daddr;
	}

	hp = tcp_get_md5sig_pool();
	if (!hp)
		goto clear_hash_noput;
	desc = &hp->md5_desc;

	if (crypto_hash_init(desc))
		goto clear_hash;

	if (tcp_v6_md5_hash_pseudoheader(hp, daddr, saddr, skb->len))
		goto clear_hash;
	if (tcp_md5_hash_header(hp, th))
		goto clear_hash;
	if (tcp_md5_hash_skb_data(hp, skb, th->doff << 2))
		goto clear_hash;
	if (tcp_md5_hash_key(hp, key))
		goto clear_hash;
	if (crypto_hash_final(desc, md5_hash))
		goto clear_hash;

	tcp_put_md5sig_pool();
	return 0;

clear_hash:
	tcp_put_md5sig_pool();
clear_hash_noput:
	memset(md5_hash, 0, 16);
	return 1;
}

static struct tcp_md5sig_key *tcp_v6_md5_do_lookup(struct sock *sk,
						   struct in6_addr *addr)
{
	struct tcp_sock *tp = tcp_sk(sk);
	int i;

	BUG_ON(tp == NULL);

	if (!tp->md5sig_info || !tp->md5sig_info->entries6)
		return NULL;

	for (i = 0; i < tp->md5sig_info->entries6; i++) {
		if (ipv6_addr_equal(&tp->md5sig_info->keys6[i].addr, addr))
			return &tp->md5sig_info->keys6[i].base;
	}
	return NULL;
}

static struct tcp_md5sig_key *tcp_v6_md5_lookup(struct sock *sk,
						struct sock *addr_sk)
{
	return tcp_v6_md5_do_lookup(sk, &inet6_sk(addr_sk)->daddr);
}

static struct tcp_md5sig_key *tcp_v6_reqsk_md5_lookup(struct sock *sk,
						      struct request_sock *req)
{
	return tcp_v6_md5_do_lookup(sk, &inet6_rsk(req)->rmt_addr);
}

static const struct tcp_request_sock_ops tcp_request_sock_ipv6_ops = {
	.md5_lookup	=	tcp_v6_reqsk_md5_lookup,
	.calc_md5_hash	=	tcp_v6_md5_hash_skb,
};

static int tcp_v6_md5_do_add(struct sock *sk, struct in6_addr *peer,
			     char *newkey, u8 newkeylen)
{
	/* Add key to the list */
	struct tcp_md5sig_key *key;
	struct tcp_sock *tp = tcp_sk(sk);
	struct tcp6_md5sig_key *keys;

	key = tcp_v6_md5_do_lookup(sk, peer);
	if (key) {
		/* modify existing entry - just update that one */
		kfree(key->key);
		key->key = newkey;
		key->keylen = newkeylen;
	} else {
		/* reallocate new list if current one is full. */
		if (!tp->md5sig_info) {
			tp->md5sig_info = kzalloc(sizeof(*tp->md5sig_info),
					sk_allocation(sk, GFP_ATOMIC));
			if (!tp->md5sig_info) {
				kfree(newkey);
				return -ENOMEM;
			}
			sk->sk_route_caps &= ~NETIF_F_GSO_MASK;
		}
		if (tcp_alloc_md5sig_pool(sk) == NULL) {
			kfree(newkey);
			return -ENOMEM;
		}
		if (tp->md5sig_info->alloced6 == tp->md5sig_info->entries6) {
			keys = kmalloc((sizeof (tp->md5sig_info->keys6[0]) *
				       (tp->md5sig_info->entries6 + 1)),
					sk_allocation(sk, GFP_ATOMIC));

			if (!keys) {
				tcp_free_md5sig_pool();
				kfree(newkey);
				return -ENOMEM;
			}

			if (tp->md5sig_info->entries6)
				memmove(keys, tp->md5sig_info->keys6,
					(sizeof (tp->md5sig_info->keys6[0]) *
					 tp->md5sig_info->entries6));

			kfree(tp->md5sig_info->keys6);
			tp->md5sig_info->keys6 = keys;
			tp->md5sig_info->alloced6++;
		}

		ipv6_addr_copy(&tp->md5sig_info->keys6[tp->md5sig_info->entries6].addr,
			       peer);
		tp->md5sig_info->keys6[tp->md5sig_info->entries6].base.key = newkey;
		tp->md5sig_info->keys6[tp->md5sig_info->entries6].base.keylen = newkeylen;

		tp->md5sig_info->entries6++;
	}
	return 0;
}

static int tcp_v6_md5_do_del(struct sock *sk, struct in6_addr *peer)
{
	struct tcp_sock *tp = tcp_sk(sk);
	int i;

	for (i = 0; i < tp->md5sig_info->entries6; i++) {
		if (ipv6_addr_equal(&tp->md5sig_info->keys6[i].addr, peer)) {
			/* Free the key */
			kfree(tp->md5sig_info->keys6[i].base.key);
			tp->md5sig_info->entries6--;

			if (tp->md5sig_info->entries6 == 0) {
				kfree(tp->md5sig_info->keys6);
				tp->md5sig_info->keys6 = NULL;
				tp->md5sig_info->alloced6 = 0;
			} else {
				/* shrink the database */
				if (tp->md5sig_info->entries6 != i)
					memmove(&tp->md5sig_info->keys6[i],
						&tp->md5sig_info->keys6[i+1],
						(tp->md5sig_info->entries6 - i)
						* sizeof (tp->md5sig_info->keys6[0]));
			}
			tcp_free_md5sig_pool();
			return 0;
		}
	}
	return -ENOENT;
}

static int tcp_v6_md5_add_func(struct sock *sk, struct sock *addr_sk,
			       u8 *newkey, __u8 newkeylen)
{
	return tcp_v6_md5_do_add(sk, &inet6_sk(addr_sk)->daddr,
				 newkey, newkeylen);
}

static int tcp_v6_parse_md5_keys (struct sock *sk, char __user *optval,
				  int optlen)
{
	struct tcp_md5sig cmd;
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&cmd.tcpm_addr;
	u8 *newkey;

	if (optlen < sizeof(cmd))
		return -EINVAL;

	if (copy_from_user(&cmd, optval, sizeof(cmd)))
		return -EFAULT;

	if (sin6->sin6_family != AF_INET6)
		return -EINVAL;

	if (!cmd.tcpm_keylen) {
		if (!tcp_sk(sk)->md5sig_info)
			return -ENOENT;
		if (ipv6_addr_v4mapped(&sin6->sin6_addr))
			return tcp_v4_md5_do_del(sk, sin6->sin6_addr.s6_addr32[3]);
		return tcp_v6_md5_do_del(sk, &sin6->sin6_addr);
	}

	if (cmd.tcpm_keylen > TCP_MD5SIG_MAXKEYLEN)
		return -EINVAL;

	if (!tcp_sk(sk)->md5sig_info) {
		struct tcp_sock *tp = tcp_sk(sk);
		struct tcp_md5sig_info *p;

		p = kzalloc(sizeof(struct tcp_md5sig_info),
			    sk_allocation(sk, GFP_KERNEL));
		if (!p)
			return -ENOMEM;

		tp->md5sig_info = p;
		sk->sk_route_caps &= ~NETIF_F_GSO_MASK;
	}

	newkey = kmemdup(cmd.tcpm_key, cmd.tcpm_keylen, GFP_KERNEL);
	if (!newkey)
		return -ENOMEM;
	if (ipv6_addr_v4mapped(&sin6->sin6_addr)) {
		return tcp_v4_md5_do_add(sk, sin6->sin6_addr.s6_addr32[3],
					 newkey, cmd.tcpm_keylen);
	}
	return tcp_v6_md5_do_add(sk, &sin6->sin6_addr, newkey, cmd.tcpm_keylen);
}

static int tcp_v6_inbound_md5_hash (struct sock *sk, struct sk_buff *skb)
{
	__u8 *hash_location = NULL;
	struct tcp_md5sig_key *hash_expected;
	struct ipv6hdr *ip6h = ipv6_hdr(skb);
	struct tcphdr *th = tcp_hdr(skb);
	int genhash;
	u8 newhash[16];

	hash_expected = tcp_v6_md5_do_lookup(sk, &ip6h->saddr);
	hash_location = tcp_parse_md5sig_option(th);

	/* We've parsed the options - do we have a hash? */
	if (!hash_expected && !hash_location)
		return 0;

	if (hash_expected && !hash_location) {
		NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_TCPMD5NOTFOUND);
		return 1;
	}

	if (!hash_expected && hash_location) {
		NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_TCPMD5UNEXPECTED);
		return 1;
	}

	/* check the signature */
	genhash = tcp_v6_md5_hash_skb(newhash,
				      hash_expected,
				      NULL, NULL, skb);

	if (genhash || memcmp(hash_location, newhash, 16) != 0) {
		if (net_ratelimit()) {
			printk(KERN_INFO "MD5 Hash %s for (%pI6, %u)->(%pI6, %u)\n",
			       genhash ? "failed" : "mismatch",
			       &ip6h->saddr, ntohs(th->source),
			       &ip6h->daddr, ntohs(th->dest));
		}
		return 1;
	}
	return 0;
}

static int tcp_v6_md5_hash_hdr(char *md5_hash, struct tcp_md5sig_key *key,
			       struct in6_addr *daddr, struct in6_addr *saddr,
			       struct tcphdr *th)
{
	struct tcp_md5sig_pool *hp;
	struct hash_desc *desc;

	hp = tcp_get_md5sig_pool();
	if (!hp)
		goto clear_hash_noput;
	desc = &hp->md5_desc;

	if (crypto_hash_init(desc))
		goto clear_hash;
	if (tcp_v6_md5_hash_pseudoheader(hp, daddr, saddr, th->doff << 2))
		goto clear_hash;
	if (tcp_md5_hash_header(hp, th))
		goto clear_hash;
	if (tcp_md5_hash_key(hp, key))
		goto clear_hash;
	if (crypto_hash_final(desc, md5_hash))
		goto clear_hash;

	tcp_put_md5sig_pool();
	return 0;

clear_hash:
	tcp_put_md5sig_pool();
clear_hash_noput:
	memset(md5_hash, 0, 16);
	return 1;
}

static const struct tcp_sock_af_ops tcp_sock_ipv6_mapped_specific = {
	.md5_lookup	=	tcp_v4_md5_lookup,
	.calc_md5_hash	=	tcp_v4_md5_hash_skb,
	.md5_add	=	tcp_v6_md5_add_func,
	.md5_parse	=	tcp_v6_parse_md5_keys,
};

static const struct tcp_sock_af_ops tcp_sock_ipv6_specific = {
	.md5_lookup	=	tcp_v6_md5_lookup,
	.calc_md5_hash	=	tcp_v6_md5_hash_skb,
	.md5_add	=	tcp_v6_md5_add_func,
	.md5_parse	=	tcp_v6_parse_md5_keys,
};
#endif

static __u32 tcp_v6_init_sequence(struct sk_buff *skb)
{
	return secure_tcpv6_sequence_number(ipv6_hdr(skb)->daddr.s6_addr32,
					    ipv6_hdr(skb)->saddr.s6_addr32,
					    tcp_hdr(skb)->dest,
					    tcp_hdr(skb)->source);
}

static struct sock *tcp_v6_hnd_req(struct sock *sk,struct sk_buff *skb)
{
	struct request_sock *req, **prev;
	const struct tcphdr *th = tcp_hdr(skb);
	struct sock *nsk;

	/* Find possible connection requests. */
	req = inet6_csk_search_req(sk, &prev, th->source,
				   &ipv6_hdr(skb)->saddr,
				   &ipv6_hdr(skb)->daddr, inet6_iif(skb));
	if (req)
		return tcp_check_req(sk, skb, req, prev);

	nsk = __inet6_lookup_established(sock_net(sk), &tcp_hashinfo,
			&ipv6_hdr(skb)->saddr, th->source,
			&ipv6_hdr(skb)->daddr, ntohs(th->dest), inet6_iif(skb));

	if (nsk) {
		if (nsk->sk_state != TCP_TIME_WAIT) {
			bh_lock_sock(nsk);
			return nsk;
		}
		inet_twsk_put(inet_twsk(nsk));
		return NULL;
	}

#ifdef CONFIG_SYN_COOKIES
	if (!th->rst && !th->syn && th->ack)
		sk = cookie_v6_check_p(sk, skb);
#endif
	return sk;
}

/* FIXME: this is substantially similar to the ipv4 code.
 * Can some kind of merge be done? -- erics
 */
static int tcp_v6_conn_request(struct sock *sk, struct sk_buff *skb)
{
	struct inet6_request_sock *treq;
	struct ipv6_pinfo *np = inet6_sk(sk);
	struct tcp_options_received tmp_opt;
	struct tcp_sock *tp = tcp_sk(sk);
	struct request_sock *req = NULL;
	__u32 isn = TCP_SKB_CB(skb)->when;
#ifdef CONFIG_SYN_COOKIES
	int want_cookie = 0;
#else
#define want_cookie 0
#endif

	if (skb->protocol == htons(ETH_P_IP))
		return tcp_v4_conn_request(sk, skb);

	if (!ipv6_unicast_destination(skb))
		goto drop;

	if (inet_csk_reqsk_queue_is_full(sk) && !isn) {
		if (net_ratelimit())
			syn_flood_warning(skb);
#ifdef CONFIG_SYN_COOKIES
		if (sysctl_tcp_syncookies)
			want_cookie = 1;
		else
#endif
		goto drop;
	}

	if (sk_acceptq_is_full(sk) && inet_csk_reqsk_queue_young(sk) > 1)
		goto drop;

	req = inet6_reqsk_alloc(tcp6_request_sock_ops_p);
	if (req == NULL)
		goto drop;

#ifdef CONFIG_TCP_MD5SIG
	tcp_rsk(req)->af_specific = &tcp_request_sock_ipv6_ops;
#endif

	tcp_clear_options(&tmp_opt);
	tmp_opt.mss_clamp = IPV6_MIN_MTU - sizeof(struct tcphdr) - sizeof(struct ipv6hdr);
	tmp_opt.user_mss = tp->rx_opt.user_mss;

	tcp_parse_options(skb, &tmp_opt, 0);

	if (want_cookie && !tmp_opt.saw_tstamp)
		tcp_clear_options(&tmp_opt);

	tmp_opt.tstamp_ok = tmp_opt.saw_tstamp;
	tcp_openreq_init(req, &tmp_opt, skb);

	treq = inet6_rsk(req);
	ipv6_addr_copy(&treq->rmt_addr, &ipv6_hdr(skb)->saddr);
	ipv6_addr_copy(&treq->loc_addr, &ipv6_hdr(skb)->daddr);
	if (!want_cookie)
		TCP_ECN_create_request(req, tcp_hdr(skb));

	if (want_cookie) {
		isn = cookie_v6_init_sequence_p(sk, skb, &req->mss);
		req->cookie_ts = tmp_opt.tstamp_ok;
	} else if (!isn) {
		if (ipv6_opt_accepted(sk, skb) ||
		    np->rxopt.bits.rxinfo || np->rxopt.bits.rxoinfo ||
		    np->rxopt.bits.rxhlim || np->rxopt.bits.rxohlim) {
			atomic_inc(&skb->users);
			treq->pktopts = skb;
		}
		treq->iif = sk->sk_bound_dev_if;

		/* So that link locals have meaning */
		if (!sk->sk_bound_dev_if &&
		    ipv6_addr_type(&treq->rmt_addr) & IPV6_ADDR_LINKLOCAL)
			treq->iif = inet6_iif(skb);

		isn = tcp_v6_init_sequence(skb);
	}

	tcp_rsk(req)->snt_isn = isn;

	security_inet_conn_request(sk, skb, req);

	if (tcp_v6_send_synack(sk, req))
		goto drop;

	if (!want_cookie) {
		inet6_csk_reqsk_queue_hash_add(sk, req, TCP_TIMEOUT_INIT);
		return 0;
	}

drop:
	if (req)
		reqsk_free(req);

	return 0; /* don't send reset */
}


static struct sock * tcp_v6_syn_recv_sock(struct sock *sk, struct sk_buff *skb,
					  struct request_sock *req,
					  struct dst_entry *dst)
{
	struct inet6_request_sock *treq;
	struct ipv6_pinfo *newnp, *np = inet6_sk(sk);
	struct tcp6_sock *newtcp6sk;
	struct inet_sock *newinet;
	struct tcp_sock *newtp;
	struct sock *newsk;
	struct ipv6_txoptions *opt;
#ifdef CONFIG_TCP_MD5SIG
	struct tcp_md5sig_key *key;
#endif

	if (skb->protocol == htons(ETH_P_IP)) {
		/*
		 *	v6 mapped
		 */

		newsk = tcp_v4_syn_recv_sock(sk, skb, req, dst);

		if (newsk == NULL)
			return NULL;

		newtcp6sk = (struct tcp6_sock *)newsk;
		inet_sk(newsk)->pinet6 = &newtcp6sk->inet6;

		newinet = inet_sk(newsk);
		newnp = inet6_sk(newsk);
		newtp = tcp_sk(newsk);

		memcpy(newnp, np, sizeof(struct ipv6_pinfo));

		ipv6_addr_set(&newnp->daddr, 0, 0, htonl(0x0000FFFF),
			      newinet->daddr);

		ipv6_addr_set(&newnp->saddr, 0, 0, htonl(0x0000FFFF),
			      newinet->saddr);

		ipv6_addr_copy(&newnp->rcv_saddr, &newnp->saddr);

		inet_csk(newsk)->icsk_af_ops = &ipv6_mapped;
		newsk->sk_backlog_rcv = tcp_v4_do_rcv;
#ifdef CONFIG_TCP_MD5SIG
		newtp->af_specific = &tcp_sock_ipv6_mapped_specific;
#endif

		newnp->pktoptions  = NULL;
		newnp->opt	   = NULL;
		newnp->mcast_oif   = inet6_iif(skb);
		newnp->mcast_hops  = ipv6_hdr(skb)->hop_limit;

		/*
		 * No need to charge this sock to the relevant IPv6 refcnt debug socks count
		 * here, tcp_create_openreq_child now does this for us, see the comment in
		 * that function for the gory details. -acme
		 */

		/* It is tricky place. Until this moment IPv4 tcp
		   worked with IPv6 icsk.icsk_af_ops.
		   Sync it now.
		 */
		tcp_sync_mss(newsk, inet_csk(newsk)->icsk_pmtu_cookie);

		return newsk;
	}

	treq = inet6_rsk(req);
	opt = np->opt;

	if (sk_acceptq_is_full(sk))
		goto out_overflow;

	if (dst == NULL) {
		struct in6_addr *final_p = NULL, final;
		struct flowi fl;

		memset(&fl, 0, sizeof(fl));
		fl.proto = IPPROTO_TCP;
		ipv6_addr_copy(&fl.fl6_dst, &treq->rmt_addr);
		if (opt && opt->srcrt) {
			struct rt0_hdr *rt0 = (struct rt0_hdr *) opt->srcrt;
			ipv6_addr_copy(&final, &fl.fl6_dst);
			ipv6_addr_copy(&fl.fl6_dst, rt0->addr);
			final_p = &final;
		}
		ipv6_addr_copy(&fl.fl6_src, &treq->loc_addr);
		fl.oif = sk->sk_bound_dev_if;
		fl.fl_ip_dport = inet_rsk(req)->rmt_port;
		fl.fl_ip_sport = inet_rsk(req)->loc_port;
		security_req_classify_flow(req, &fl);

		if (ip6_dst_lookup(sk, &dst, &fl))
			goto out;

		if (final_p)
			ipv6_addr_copy(&fl.fl6_dst, final_p);

		if ((xfrm_lookup(sock_net(sk), &dst, &fl, sk, 0)) < 0)
			goto out;
	}

	newsk = tcp_create_openreq_child(sk, req, skb);
	if (newsk == NULL)
		goto out;

	/*
	 * No need to charge this sock to the relevant IPv6 refcnt debug socks
	 * count here, tcp_create_openreq_child now does this for us, see the
	 * comment in that function for the gory details. -acme
	 */

	newsk->sk_gso_type = SKB_GSO_TCPV6;
	__ip6_dst_store(newsk, dst, NULL, NULL);

	newtcp6sk = (struct tcp6_sock *)newsk;
	inet_sk(newsk)->pinet6 = &newtcp6sk->inet6;

	newtp = tcp_sk(newsk);
	newinet = inet_sk(newsk);
	newnp = inet6_sk(newsk);

	memcpy(newnp, np, sizeof(struct ipv6_pinfo));

	ipv6_addr_copy(&newnp->daddr, &treq->rmt_addr);
	ipv6_addr_copy(&newnp->saddr, &treq->loc_addr);
	ipv6_addr_copy(&newnp->rcv_saddr, &treq->loc_addr);
	newsk->sk_bound_dev_if = treq->iif;

	/* Now IPv6 options...

	   First: no IPv4 options.
	 */
	newinet->opt = NULL;
	newnp->ipv6_fl_list = NULL;

	/* Clone RX bits */
	newnp->rxopt.all = np->rxopt.all;

	/* Clone pktoptions received with SYN */
	newnp->pktoptions = NULL;
	if (treq->pktopts != NULL) {
		newnp->pktoptions = skb_clone(treq->pktopts, GFP_ATOMIC);
		kfree_skb(treq->pktopts);
		treq->pktopts = NULL;
		if (newnp->pktoptions)
			skb_set_owner_r(newnp->pktoptions, newsk);
	}
	newnp->opt	  = NULL;
	newnp->mcast_oif  = inet6_iif(skb);
	newnp->mcast_hops = ipv6_hdr(skb)->hop_limit;

	/* Clone native IPv6 options from listening socket (if any)

	   Yes, keeping reference count would be much more clever,
	   but we make one more one thing there: reattach optmem
	   to newsk.
	 */
	if (opt) {
		newnp->opt = ipv6_dup_options(newsk, opt);
		if (opt != np->opt)
			sock_kfree_s(sk, opt, opt->tot_len);
	}

	inet_csk(newsk)->icsk_ext_hdr_len = 0;
	if (newnp->opt)
		inet_csk(newsk)->icsk_ext_hdr_len = (newnp->opt->opt_nflen +
						     newnp->opt->opt_flen);

	tcp_mtup_init(newsk);
	tcp_sync_mss(newsk, dst_mtu(dst));
	newtp->advmss = dst_metric(dst, RTAX_ADVMSS);
	tcp_initialize_rcv_mss(newsk);

	newinet->daddr = newinet->saddr = newinet->rcv_saddr = LOOPBACK4_IPV6;

#ifdef CONFIG_TCP_MD5SIG
	/* Copy over the MD5 key from the original socket */
	if ((key = tcp_v6_md5_do_lookup(sk, &newnp->daddr)) != NULL) {
		/* We're using one, so create a matching key
		 * on the newsk structure. If we fail to get
		 * memory, then we end up not copying the key
		 * across. Shucks.
		 */
		char *newkey = kmemdup(key->key, key->keylen, GFP_ATOMIC);
		if (newkey != NULL)
			tcp_v6_md5_do_add(newsk, &newnp->daddr,
					  newkey, key->keylen);
	}
#endif

	__inet6_hash(newsk);
	__inet_inherit_port(sk, newsk);

	return newsk;

out_overflow:
	NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_LISTENOVERFLOWS);
out:
	NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_LISTENDROPS);
	if (opt && opt != np->opt)
		sock_kfree_s(sk, opt, opt->tot_len);
	dst_release(dst);
	return NULL;
}

static const struct inet_connection_sock_af_ops ipv6_mapped = {
	.queue_xmit	   = ip_queue_xmit,
	.send_check	   = tcp_v4_send_check,
	.rebuild_header	   = inet_sk_rebuild_header,
	.conn_request	   = tcp_v6_conn_request,
	.syn_recv_sock	   = tcp_v6_syn_recv_sock,
	.remember_stamp	   = tcp_v4_remember_stamp,
	.net_header_len	   = sizeof(struct iphdr),
	.setsockopt	   = ipv6_setsockopt,
	.getsockopt	   = ipv6_getsockopt,
	.addr2sockaddr	   = inet6_csk_addr2sockaddr,
	.sockaddr_len	   = sizeof(struct sockaddr_in6),
	.bind_conflict	   = inet6_csk_bind_conflict,
#ifdef CONFIG_COMPAT
	.compat_setsockopt = compat_ipv6_setsockopt,
	.compat_getsockopt = compat_ipv6_getsockopt,
#endif
};

static void tcp_v6_send_response(struct sk_buff *skb, u32 seq, u32 ack, u32 win,
				 u32 ts, struct tcp_md5sig_key *key, int rst)
{
	struct tcphdr *th = tcp_hdr(skb), *t1;
	struct sk_buff *buff;
	struct flowi fl;
	struct net *net = dev_net(skb_dst(skb)->dev);
	struct sock *ctl_sk = net->ipv6.tcp_sk;
	unsigned int tot_len = sizeof(struct tcphdr);
	struct dst_entry *dst;
	__be32 *topt;
	gfp_t gfp_mask = GFP_ATOMIC;

	if (ts)
		tot_len += TCPOLEN_TSTAMP_ALIGNED;
#ifdef CONFIG_TCP_MD5SIG
	if (key)
		tot_len += TCPOLEN_MD5SIG_ALIGNED;
#endif

	buff = alloc_skb(MAX_HEADER + sizeof(struct ipv6hdr) + tot_len,
			 gfp_mask);
	if (buff == NULL)
		return;

	skb_reserve(buff, MAX_HEADER + sizeof(struct ipv6hdr) + tot_len);

	t1 = (struct tcphdr *) skb_push(buff, tot_len);
	skb_reset_transport_header(buff);

	/* Swap the send and the receive. */
	memset(t1, 0, sizeof(*t1));
	t1->dest = th->source;
	t1->source = th->dest;
	t1->doff = tot_len / 4;
	t1->seq = htonl(seq);
	t1->ack_seq = htonl(ack);
	t1->ack = !rst || !th->ack;
	t1->rst = rst;
	t1->window = htons(win);

	topt = (__be32 *)(t1 + 1);

	if (ts) {
		*topt++ = htonl((TCPOPT_NOP << 24) | (TCPOPT_NOP << 16) |
				(TCPOPT_TIMESTAMP << 8) | TCPOLEN_TIMESTAMP);
		*topt++ = htonl(tcp_time_stamp);
		*topt++ = htonl(ts);
	}

#ifdef CONFIG_TCP_MD5SIG
	if (key) {
		*topt++ = htonl((TCPOPT_NOP << 24) | (TCPOPT_NOP << 16) |
				(TCPOPT_MD5SIG << 8) | TCPOLEN_MD5SIG);
		tcp_v6_md5_hash_hdr((__u8 *)topt, key,
				    &ipv6_hdr(skb)->saddr,
				    &ipv6_hdr(skb)->daddr, t1);
	}
#endif

	buff->csum = csum_partial(t1, tot_len, 0);

	memset(&fl, 0, sizeof(fl));
	ipv6_addr_copy(&fl.fl6_dst, &ipv6_hdr(skb)->saddr);
	ipv6_addr_copy(&fl.fl6_src, &ipv6_hdr(skb)->daddr);

	t1->check = csum_ipv6_magic(&fl.fl6_src, &fl.fl6_dst,
				    tot_len, IPPROTO_TCP,
				    buff->csum);

	fl.proto = IPPROTO_TCP;
	fl.oif = inet6_iif(skb);
	fl.fl_ip_dport = t1->dest;
	fl.fl_ip_sport = t1->source;
	security_skb_classify_flow(skb, &fl);

	/* Pass a socket to ip6_dst_lookup either it is for RST
	 * Underlying function will use this to retrieve the network
	 * namespace
	 */
	if (!ip6_dst_lookup(ctl_sk, &dst, &fl)) {
		if (xfrm_lookup(net, &dst, &fl, NULL, 0) >= 0) {
			skb_dst_set(buff, dst);
			ip6_xmit(ctl_sk, buff, &fl, NULL, 0);
			TCP_INC_STATS_BH(net, TCP_MIB_OUTSEGS);
			if (rst)
				TCP_INC_STATS_BH(net, TCP_MIB_OUTRSTS);
			return;
		}
	}

	kfree_skb(buff);
}

static void tcp_v6_send_reset(struct sock *sk, struct sk_buff *skb)
{
	struct tcphdr *th = tcp_hdr(skb);
	u32 seq = 0, ack_seq = 0;
	struct tcp_md5sig_key *key = NULL;
	gfp_t gfp_mask = GFP_ATOMIC;

	if (th->rst)
		return;

	if (!ipv6_unicast_destination(skb))
		return;

#ifdef CONFIG_TCP_MD5SIG
	if (sk)
		key = tcp_v6_md5_do_lookup(sk, &ipv6_hdr(skb)->daddr);
#endif
	if (sk)
		gfp_mask = sk_allocation(sk, gfp_mask);

	if (th->ack)
		seq = ntohl(th->ack_seq);
	else
		ack_seq = ntohl(th->seq) + th->syn + th->fin + skb->len -
			  (th->doff << 2);

	tcp_v6_send_response(skb, seq, ack_seq, 0, 0, key, 1);
}

/* The socket must have it's spinlock held when we get
 * here.
 *
 * We have a potential double-lock case here, so even when
 * doing backlog processing we use the BH locking scheme.
 * This is because we cannot sleep with the original spinlock
 * held.
 */
static int tcp_v6_do_rcv(struct sock *sk, struct sk_buff *skb)
{
	struct ipv6_pinfo *np = inet6_sk(sk);
	struct tcp_sock *tp;
	struct sk_buff *opt_skb = NULL;

	/* Imagine: socket is IPv6. IPv4 packet arrives,
	   goes to IPv4 receive handler and backlogged.
	   From backlog it always goes here. Kerboom...
	   Fortunately, tcp_rcv_established and rcv_established
	   handle them correctly, but it is not case with
	   tcp_v6_hnd_req and tcp_v6_send_reset().   --ANK
	 */

	if (skb->protocol == htons(ETH_P_IP))
		return tcp_v4_do_rcv(sk, skb);

#ifdef CONFIG_TCP_MD5SIG
	if (tcp_v6_inbound_md5_hash (sk, skb))
		goto discard;
#endif

	if (sk_filter(sk, skb))
		goto discard;

	/*
	 *	socket locking is here for SMP purposes as backlog rcv
	 *	is currently called with bh processing disabled.
	 */

	/* Do Stevens' IPV6_PKTOPTIONS.

	   Yes, guys, it is the only place in our code, where we
	   may make it not affecting IPv4.
	   The rest of code is protocol independent,
	   and I do not like idea to uglify IPv4.

	   Actually, all the idea behind IPV6_PKTOPTIONS
	   looks not very well thought. For now we latch
	   options, received in the last packet, enqueued
	   by tcp. Feel free to propose better solution.
					       --ANK (980728)
	 */
	if (np->rxopt.all)
		opt_skb = skb_clone(skb, GFP_ATOMIC);

	if (sk->sk_state == TCP_ESTABLISHED) { /* Fast path */
		TCP_CHECK_TIMER(sk);
		if (tcp_rcv_established(sk, skb, tcp_hdr(skb), skb->len))
			goto reset;
		TCP_CHECK_TIMER(sk);
		if (opt_skb)
			goto ipv6_pktoptions;
		return 0;
	}

	if (skb->len < tcp_hdrlen(skb) || tcp_checksum_complete(skb))
		goto csum_err;

	if (sk->sk_state == TCP_LISTEN) {
		struct sock *nsk = tcp_v6_hnd_req(sk, skb);
		if (!nsk)
			goto discard;

		/*
		 * Queue it on the new socket if the new socket is active,
		 * otherwise we just shortcircuit this and continue with
		 * the new socket..
		 */
		if(nsk != sk) {
			if (tcp_child_process(sk, nsk, skb))
				goto reset;
			if (opt_skb)
				__kfree_skb(opt_skb);
			return 0;
		}
	}

	TCP_CHECK_TIMER(sk);
	if (tcp_rcv_state_process(sk, skb, tcp_hdr(skb), skb->len))
		goto reset;
	TCP_CHECK_TIMER(sk);
	if (opt_skb)
		goto ipv6_pktoptions;
	return 0;

reset:
	tcp_v6_send_reset(sk, skb);
discard:
	if (opt_skb)
		__kfree_skb(opt_skb);
	kfree_skb(skb);
	return 0;
csum_err:
	TCP_INC_STATS_BH(sock_net(sk), TCP_MIB_INERRS);
	goto discard;


ipv6_pktoptions:
	/* Do you ask, what is it?

	   1. skb was enqueued by tcp.
	   2. skb is added to tail of read queue, rather than out of order.
	   3. socket is not in passive state.
	   4. Finally, it really contains options, which user wants to receive.
	 */
	tp = tcp_sk(sk);
	if (TCP_SKB_CB(opt_skb)->end_seq == tp->rcv_nxt &&
	    !((1 << sk->sk_state) & (TCPF_CLOSE | TCPF_LISTEN))) {
		if (np->rxopt.bits.rxinfo || np->rxopt.bits.rxoinfo)
			np->mcast_oif = inet6_iif(opt_skb);
		if (np->rxopt.bits.rxhlim || np->rxopt.bits.rxohlim)
			np->mcast_hops = ipv6_hdr(opt_skb)->hop_limit;
		if (ipv6_opt_accepted(sk, opt_skb)) {
			skb_set_owner_r(opt_skb, sk);
			opt_skb = xchg(&np->pktoptions, opt_skb);
		} else {
			__kfree_skb(opt_skb);
			opt_skb = xchg(&np->pktoptions, NULL);
		}
	}

	kfree_skb(opt_skb);
	return 0;
}

static void tcp_v6_hash_offload(struct sock *sk)
{
	orig_tcpv6_prot.hash(sk);
	if (sk->sk_state == TCP_LISTEN)
		start_listen_offload(sk);
}

static void tcp_v6_unhash_offload(struct sock *sk)
{
	if (sk->sk_state == TCP_LISTEN)
		stop_listen_offload(sk);
	orig_tcpv6_prot.unhash(sk);
}

static int tcp_v6_connect_offload(struct sock *sk, struct sockaddr *uaddr,
				  int addr_len)
{
	struct sockaddr_in6 *usin = (struct sockaddr_in6 *) uaddr;
	struct inet_sock *inet = inet_sk(sk);
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct ipv6_pinfo *np = inet6_sk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	struct in6_addr *saddr = NULL, *final_p = NULL, final;
	struct flowi fl;
	struct dst_entry *dst;
	int addr_type;
	int err;

	if (addr_len < SIN6_LEN_RFC2133)
		return -EINVAL;

	if (usin->sin6_family != AF_INET6)
		return(-EAFNOSUPPORT);

	memset(&fl, 0, sizeof(fl));

	if (np->sndflow) {
		fl.fl6_flowlabel = usin->sin6_flowinfo&IPV6_FLOWINFO_MASK;
		IP6_ECN_flow_init(fl.fl6_flowlabel);
		if (fl.fl6_flowlabel&IPV6_FLOWLABEL_MASK) {
			struct ip6_flowlabel *flowlabel;
			flowlabel = fl6_sock_lookup(sk, fl.fl6_flowlabel);
			if (flowlabel == NULL)
				return -EINVAL;
			ipv6_addr_copy(&usin->sin6_addr, &flowlabel->dst);
			fl6_sock_release(flowlabel);
		}
	}

	/*
	 *	connect() to INADDR_ANY means loopback (BSD'ism).
	 */

	if(ipv6_addr_any(&usin->sin6_addr))
		usin->sin6_addr.s6_addr[15] = 0x1;

	addr_type = ipv6_addr_type(&usin->sin6_addr);

	if(addr_type & IPV6_ADDR_MULTICAST)
		return -ENETUNREACH;

	if (addr_type&IPV6_ADDR_LINKLOCAL) {
		if (addr_len >= sizeof(struct sockaddr_in6) &&
		    usin->sin6_scope_id) {
			/* If interface is set while binding, indices
			 * must coincide.
			 */
			if (sk->sk_bound_dev_if &&
			    sk->sk_bound_dev_if != usin->sin6_scope_id)
				return -EINVAL;

			sk->sk_bound_dev_if = usin->sin6_scope_id;
		}

		/* Connect to link-local address requires an interface */
		if (!sk->sk_bound_dev_if)
			return -EINVAL;
	}

	if (tp->rx_opt.ts_recent_stamp &&
	    !ipv6_addr_equal(&np->daddr, &usin->sin6_addr)) {
		tp->rx_opt.ts_recent = 0;
		tp->rx_opt.ts_recent_stamp = 0;
		tp->write_seq = 0;
	}

	ipv6_addr_copy(&np->daddr, &usin->sin6_addr);
	np->flow_label = fl.fl6_flowlabel;

	/*
	 *	TCP over IPv4
	 */

	if (addr_type == IPV6_ADDR_MAPPED) {
		u32 exthdrlen = icsk->icsk_ext_hdr_len;
		struct sockaddr_in sin;

		SOCK_DEBUG(sk, "connect: ipv4 mapped\n");

		if (__ipv6_only_sock(sk))
			return -ENETUNREACH;

		sin.sin_family = AF_INET;
		sin.sin_port = usin->sin6_port;
		sin.sin_addr.s_addr = usin->sin6_addr.s6_addr32[3];

		icsk->icsk_af_ops = &ipv6_mapped;
		sk->sk_backlog_rcv = tcp_v4_do_rcv;
#ifdef CONFIG_TCP_MD5SIG
		tp->af_specific = &tcp_sock_ipv6_mapped_specific;
#endif

		err = tcp_v4_connect(sk, (struct sockaddr *)&sin, sizeof(sin));

		if (err) {
			icsk->icsk_ext_hdr_len = exthdrlen;
			icsk->icsk_af_ops = &ipv6_specific;
			sk->sk_backlog_rcv = tcp_v6_do_rcv;
#ifdef CONFIG_TCP_MD5SIG
			tp->af_specific = &tcp_sock_ipv6_specific;
#endif
			goto failure;
		} else {
			ipv6_addr_set(&np->saddr, 0, 0, htonl(0x0000FFFF),
				      inet->saddr);
			ipv6_addr_set(&np->rcv_saddr, 0, 0, htonl(0x0000FFFF),
				      inet->rcv_saddr);
		}

		return err;
	}

	if (!ipv6_addr_any(&np->rcv_saddr))
		saddr = &np->rcv_saddr;

	fl.proto = IPPROTO_TCP;
	ipv6_addr_copy(&fl.fl6_dst, &np->daddr);
	ipv6_addr_copy(&fl.fl6_src,
		       (saddr ? saddr : &np->saddr));
	fl.oif = sk->sk_bound_dev_if;
	fl.fl_ip_dport = usin->sin6_port;
	fl.fl_ip_sport = inet->sport;

	if (np->opt && np->opt->srcrt) {
		struct rt0_hdr *rt0 = (struct rt0_hdr *)np->opt->srcrt;
		ipv6_addr_copy(&final, &fl.fl6_dst);
		ipv6_addr_copy(&fl.fl6_dst, rt0->addr);
		final_p = &final;
	}

	security_sk_classify_flow(sk, &fl);

	err = ip6_dst_lookup(sk, &dst, &fl);
	if (err)
		goto failure;
	if (final_p)
		ipv6_addr_copy(&fl.fl6_dst, final_p);

	err = __xfrm_lookup(sock_net(sk), &dst, &fl, sk, XFRM_LOOKUP_WAIT);
	if (err < 0) {
		if (err == -EREMOTE)
			err = ip6_dst_blackhole(sk, &dst, &fl);
		if (err < 0)
			goto failure;
	}

	if (saddr == NULL) {
		saddr = &fl.fl6_src;
		ipv6_addr_copy(&np->rcv_saddr, saddr);
	}

	/* set the source address */
	ipv6_addr_copy(&np->saddr, saddr);
	inet->rcv_saddr = LOOPBACK4_IPV6;

	sk->sk_gso_type = SKB_GSO_TCPV6;
	__ip6_dst_store(sk, dst, NULL, NULL);

	icsk->icsk_ext_hdr_len = 0;
	if (np->opt)
		icsk->icsk_ext_hdr_len = (np->opt->opt_flen +
					  np->opt->opt_nflen);

	tp->rx_opt.mss_clamp = IPV6_MIN_MTU - sizeof(struct tcphdr) - sizeof(struct ipv6hdr);

	inet->dport = usin->sin6_port;

	tcp_set_state(sk, TCP_SYN_SENT);
	err = inet6_hash_connect(&tcp_death_row, sk);
	if (err)
		goto late_failure;

	if (tcp_connect_offload(sk))
		return 0;

	if (!tp->write_seq)
		tp->write_seq = secure_tcpv6_sequence_number(np->saddr.s6_addr32,
							     np->daddr.s6_addr32,
							     inet->sport,
							     inet->dport);

	err = tcp_connect(sk);
	if (err)
		goto late_failure;

	return 0;

late_failure:
	tcp_set_state(sk, TCP_CLOSE);
	__sk_dst_reset(sk);
failure:
	inet->dport = 0;
	sk->sk_route_caps = 0;
	return err;
}

static void tcp_v6_send_check(struct sock *sk, int len, struct sk_buff *skb)
{
	struct ipv6_pinfo *np = inet6_sk(sk);
	struct tcphdr *th = tcp_hdr(skb);

	if (skb->ip_summed == CHECKSUM_PARTIAL) {
		th->check = ~csum_ipv6_magic(&np->saddr, &np->daddr, len, IPPROTO_TCP,  0);
		skb->csum_start = skb_transport_header(skb) - skb->head;
		skb->csum_offset = offsetof(struct tcphdr, check);
	} else {
		th->check = csum_ipv6_magic(&np->saddr, &np->daddr, len, IPPROTO_TCP,
					    csum_partial(th, th->doff<<2,
							 skb->csum));
	}
}

static int tcp_v6_remember_stamp(struct sock *sk)
{
	/* Alas, not yet... */
	return 0;
}

static const struct inet_connection_sock_af_ops ipv6_specific = {
	.queue_xmit	   = inet6_csk_xmit,
	.send_check	   = tcp_v6_send_check,
	.rebuild_header	   = inet6_sk_rebuild_header,
	.conn_request	   = tcp_v6_conn_request,
	.syn_recv_sock	   = tcp_v6_syn_recv_sock,
	.remember_stamp	   = tcp_v6_remember_stamp,
	.net_header_len	   = sizeof(struct ipv6hdr),
	.setsockopt	   = ipv6_setsockopt,
	.getsockopt	   = ipv6_getsockopt,
	.addr2sockaddr	   = inet6_csk_addr2sockaddr,
	.sockaddr_len	   = sizeof(struct sockaddr_in6),
	.bind_conflict	   = inet6_csk_bind_conflict,
#ifdef CONFIG_COMPAT
	.compat_setsockopt = compat_ipv6_setsockopt,
	.compat_getsockopt = compat_ipv6_getsockopt,
#endif
};

static int offload_enabled;

#ifdef CONFIG_DEBUG_RODATA
static struct proto_ops offload_inet_stream_ops;
static struct proto_ops *orig_inet6_stream_ops_p;
static struct proto_ops offload_inet6_stream_ops;

void offload_socket_ops(struct sock *sk)
{
	struct socket *sock = sk->sk_socket;

	if (!sock)
		return;

	if (sock->ops == &inet_stream_ops)
		sock->ops = &offload_inet_stream_ops;

	else if (sock->ops == orig_inet6_stream_ops_p)
		sock->ops = &offload_inet6_stream_ops;
}

void restore_socket_ops(struct sock *sk)
{
	struct socket *sock = sk->sk_socket;

	if (!sock)
		return;

	if (sock->ops == &offload_inet_stream_ops)
		sock->ops = &inet_stream_ops;

	if (sock->ops == &offload_inet6_stream_ops)
		sock->ops = orig_inet6_stream_ops_p;
}
EXPORT_SYMBOL(restore_socket_ops);

static int offload_listen_cb(void *dummy, struct sock *sk)
{
	offload_socket_ops(sk);
	return 0;
}

static int restore_listen_cb(void *dummy, struct sock *sk)
{
	restore_socket_ops(sk);
	return 0;
}
#endif

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

#define FIND_SYMBOL(name, ptr) do { \
	ptr = (void *)kallsyms_lookup_name_p(name); \
	if (!ptr) { \
		printk("toecore failure: could not get " name "\n"); \
		return -ENOENT; \
	} \
} while (0)

#define FIND_SYSCTL(name) do { \
	int *p = (void *)kallsyms_lookup_name_p("sysctl_tcp_" # name); \
	if (p) \
		sysctl_tcp_ ## name ## _p = p; \
} while (0)

int prepare_tcp_for_offload(void)
{
	if (offload_enabled)   /* already done */
		return 0;

	if (!kallsyms_lookup_name_p) {
		int err = find_kallsyms_lookup_name();
		if (err) {
			printk(KERN_ERR "find_kallsyms_lookup_name failed\n");
			return err;
		}
	}

	FIND_SYMBOL("skb_splice_bits", skb_splice_bits_p);
	FIND_SYMBOL("secure_tcp_sequence_number", secure_tcp_sequence_number_p);

#ifdef CONFIG_SECURITY_NETWORK
	FIND_SYMBOL("security_inet_conn_established",
		    security_inet_conn_established_p);
#endif

	FIND_SYMBOL("cookie_v6_init_sequence", cookie_v6_init_sequence_p);
	FIND_SYMBOL("cookie_v6_check", cookie_v6_check_p);
	FIND_SYMBOL("tcp6_request_sock_ops", tcp6_request_sock_ops_p);
	FIND_SYMBOL("tcpv6_prot", tcpv6_prot_p);
	FIND_SYMBOL("inet6_stream_ops", orig_inet6_stream_ops_p);
	/*
	 * rt_bind_peer is not a critical function, it's ok if we are unable
	 * to locate it.
	 */
	rt_bind_peer_p = (void *)kallsyms_lookup_name_p("rt_bind_peer");

	/* sysctls are also best effort */
	FIND_SYSCTL(timestamps);
	FIND_SYSCTL(sack);
	FIND_SYSCTL(window_scaling);
	FIND_SYSCTL(ecn);

	find_rpc_iscsi_callbacks();
	register_module_notifier(&module_notifier);

#ifdef CONFIG_DEBUG_RODATA
	offload_inet_stream_ops = inet_stream_ops;
	offload_inet_stream_ops.sendmsg = tcp_sendmsg_offload;
	offload_inet_stream_ops.sendpage = tcp_sendpage_offload;
	offload_inet_stream_ops.splice_read = tcp_splice_read_offload;

	offload_inet6_stream_ops = *orig_inet6_stream_ops_p;
	offload_inet6_stream_ops.sendmsg = tcp_sendmsg_offload;
	offload_inet6_stream_ops.sendpage = tcp_sendpage_offload;
	offload_inet6_stream_ops.splice_read = tcp_splice_read_offload;

	walk_listens(NULL, offload_listen_cb);
#else
	{
		struct proto_ops *iso = (struct proto_ops *)&inet_stream_ops;
		struct proto_ops *iso6 = (struct proto_ops *)&inet6_stream_ops;

		iso->sendmsg = tcp_sendmsg_offload;
		iso->sendpage = tcp_sendpage_offload;
		iso->splice_read = tcp_splice_read_offload;

		iso6->sendmsg = tcp_sendmsg_offload;
		iso6->sendpage = tcp_sendpage_offload;
		iso6->splice_read = tcp_splice_read_offload;
	}
#endif

	orig_tcp_prot = tcp_prot;
	tcp_prot.hash = tcp_v4_hash_offload;
	tcp_prot.unhash = tcp_unhash_offload;
	tcp_prot.connect = tcp_v4_connect_offload;

	orig_tcpv6_prot = *tcpv6_prot_p;
	tcpv6_prot_p->hash = tcp_v6_hash_offload;
	tcpv6_prot_p->unhash = tcp_v6_unhash_offload;
	tcpv6_prot_p->connect = tcp_v6_connect_offload;

	offload_enabled = 1;
	return 0;
}

void restore_tcp_to_nonoffload(void)
{
	if (offload_enabled) {
		unregister_module_notifier(&module_notifier);
#ifdef CONFIG_DEBUG_RODATA
		walk_listens(NULL, restore_listen_cb);
#else
		{
			struct proto_ops *iso = (struct proto_ops *)&inet_stream_ops;
			struct proto_ops *iso6 = (struct proto_ops *)&inet6_stream_ops;

			iso->sendmsg = tcp_sendmsg;
			iso->sendpage = tcp_sendpage;
			iso->splice_read = tcp_splice_read;

			iso6->sendmsg = tcp_sendmsg;
			iso6->sendpage = tcp_sendpage;
			iso6->splice_read = tcp_splice_read;
		}
#endif
		tcp_prot.hash = orig_tcp_prot.hash;
		tcp_prot.unhash = orig_tcp_prot.unhash;
		tcp_prot.connect = orig_tcp_prot.connect;

		tcpv6_prot_p->hash = orig_tcpv6_prot.hash;
		tcpv6_prot_p->unhash = orig_tcpv6_prot.unhash;
		tcpv6_prot_p->connect = orig_tcpv6_prot.connect;

		offload_enabled = 0;
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
static void iscsi_ofld_tcp_data_ready_0(struct sock *sk, int bytes)
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

/* Replacement for iSCSI's ->data_ready callback */
static void iscsi_ofld_tcp_data_ready_2(struct sock *sk, int bytes)
{
	struct iscsi_conn *conn = sk->sk_user_data;
	struct iscsi_tcp_conn *tcp_conn = conn->dd_data;
	read_descriptor_t rd_desc;

	read_lock(&sk->sk_callback_lock);

	rd_desc.arg.data = conn;
	rd_desc.count = 1;
	ofld_read_sock(sk, &rd_desc, iscsi_sw_tcp_recv_p);

	read_unlock(&sk->sk_callback_lock);

	iscsi_tcp_segment_unmap(&tcp_conn->in.segment);
}

/* Replacement for iSCSI's ->data_ready callback, old api */
static void iscsi_ofld_tcp_data_ready_1(struct sock *sk, int bytes)
{
	struct iscsi_conn *conn = sk->sk_user_data;
	read_descriptor_t rd_desc;

	read_lock(&sk->sk_callback_lock);

	rd_desc.arg.data = conn;
	rd_desc.count = 1;
	ofld_read_sock(sk, &rd_desc, iscsi_tcp_data_recv_p);

	read_unlock(&sk->sk_callback_lock);
}

int install_special_data_ready(struct sock *sk)
{
	if (!sk->sk_user_data)
		return 0;

	if (sk->sk_data_ready == xs_tcp_data_ready_p)
		sk->sk_data_ready = xs_ofld_tcp_data_ready;

	else if (sk->sk_data_ready == iscsi_tcp_data_ready_p) {
		if (iscsi_tcp_recv_p)
			sk->sk_data_ready = iscsi_ofld_tcp_data_ready_0;
		else if (iscsi_tcp_data_recv_p)
			sk->sk_data_ready = iscsi_ofld_tcp_data_ready_1;

	} else if (sk->sk_data_ready == iscsi_sw_tcp_data_ready_p) {
		sk->sk_data_ready = iscsi_ofld_tcp_data_ready_2;

	} else
		return 0;
	return 1;
}
EXPORT_SYMBOL(install_special_data_ready);

void restore_special_data_ready(struct sock *sk)
{
	if (sk->sk_data_ready == xs_ofld_tcp_data_ready)
		sk->sk_data_ready = xs_tcp_data_ready_p;

	else if (sk->sk_data_ready == iscsi_ofld_tcp_data_ready_0)
		sk->sk_data_ready = iscsi_tcp_data_ready_p;

	else if (sk->sk_data_ready == iscsi_ofld_tcp_data_ready_1)
		sk->sk_data_ready = iscsi_tcp_data_ready_p;

	else if (sk->sk_data_ready == iscsi_ofld_tcp_data_ready_2)
		sk->sk_data_ready = iscsi_sw_tcp_data_ready_p;
}
EXPORT_SYMBOL(restore_special_data_ready);
