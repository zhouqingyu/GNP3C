/*
 * This file handles offloading of listening sockets.
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

#include "defs.h"
#include <linux/toedev.h>
#include <net/tcp.h>
#include <net/offload.h>
#include "tom.h"
#include "cpl_io_state.h"
#include "t3_cpl.h"
#include "firmware_exports.h"
#include "t3cdev.h"
#include "l2t.h"

static inline int listen_hashfn(const struct sock *sk)
{
	return ((unsigned long)sk >> 10) & (LISTEN_INFO_HASH_SIZE - 1);
}

/*
 * Create and add a listen_info entry to the listen hash table.  This and the
 * listen hash table functions below cannot be called from softirqs.
 */
static struct listen_info *listen_hash_add(struct tom_data *d, struct sock *sk,
					   unsigned int stid)
{
	struct listen_info *p = kmalloc(sizeof(*p), GFP_KERNEL);

	if (p) {
		int bucket = listen_hashfn(sk);

		p->sk = sk;	/* just a key, no need to take a reference */
		p->stid = stid;
		spin_lock(&d->listen_lock);
		p->next = d->listen_hash_tab[bucket];
		d->listen_hash_tab[bucket] = p;
		spin_unlock(&d->listen_lock);
	}
	return p;
}

/*
 * Given a pointer to a listening socket return its server TID by consulting
 * the socket->stid map.  Returns -1 if the socket is not in the map.
 */
static int listen_hash_find(struct tom_data *d, struct sock *sk)
{
	int stid = -1, bucket = listen_hashfn(sk);
	struct listen_info *p;

	spin_lock(&d->listen_lock);
	for (p = d->listen_hash_tab[bucket]; p; p = p->next)
		if (p->sk == sk) {
			stid = p->stid;
			break;
		}
	spin_unlock(&d->listen_lock);
	return stid;
}

/*
 * Delete the listen_info structure for a listening socket.  Returns the server
 * TID for the socket if it is present in the socket->stid map, or -1.
 */
static int listen_hash_del(struct tom_data *d, struct sock *sk)
{
	int stid = -1, bucket = listen_hashfn(sk);
	struct listen_info *p, **prev = &d->listen_hash_tab[bucket];

	spin_lock(&d->listen_lock);
	for (p = *prev; p; prev = &p->next, p = p->next)
		if (p->sk == sk) {
			stid = p->stid;
			*prev = p->next;
			kfree(p);
			break;
		}
	spin_unlock(&d->listen_lock);
	return stid;
}

/*
 * Start a listening server by sending a passive open request to HW.
 */
void t3_listen_start(struct toedev *dev, struct sock *sk,
		     const struct offload_req *r)
{
	int stid, offload;
	struct sk_buff *skb;
	struct cpl_pass_open_req *req;
	struct tom_data *d = TOM_DATA(dev);
	struct listen_ctx *ctx;
	const struct offload_settings *s;

	s = lookup_ofld_policy(dev, r, d->conf.cop_managed_offloading);
	offload = s->offload;
#ifndef LINUX_2_4
	rcu_read_unlock();
#else
	read_unlock(&dev->policy_lock);
#endif
	if (!offload)
		return;

	if (!TOM_TUNABLE(dev, activated))
		return;

	if (listen_hash_find(d, sk) >= 0)   /* already have it */
		return;

	ctx = kmalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return;

	ctx->tom_data = d;
	ctx->lsk = sk;

	stid = cxgb3_alloc_stid(d->cdev, d->client, ctx);
	if (stid < 0)
		goto free_ctx;
	
	sock_hold(sk);

	skb = alloc_skb(sizeof(*req), GFP_KERNEL);
	if (!skb)
		goto free_stid;

	if (!listen_hash_add(d, sk, stid))
		goto free_all;

	req = (struct cpl_pass_open_req *)__skb_put(skb, sizeof(*req));
	req->wr.wr_hi = htonl(V_WR_OP(FW_WROPCODE_FORWARD));
	OPCODE_TID(req) = htonl(MK_OPCODE_TID(CPL_PASS_OPEN_REQ, stid));
#ifdef	LINUX_2_4
	req->local_port = sk->sport;
	req->local_ip = sk->rcv_saddr;
#else
	req->local_port = inet_sk(sk)->inet_sport;
	req->local_ip = inet_sk(sk)->inet_rcv_saddr;
#endif	/* LINUX_2_4 */
	req->peer_port = 0;
	req->peer_ip = 0;
	req->peer_netmask = 0;
	req->opt0h = htonl(F_DELACK | F_TCAM_BYPASS);
	req->opt0l = htonl(V_RCV_BUFSIZ(16));
	req->opt1 = htonl(V_CONN_POLICY(CPL_CONN_POLICY_ASK) |
			  V_OPT1_VLAN(0xfff));

	skb->priority = CPL_PRIORITY_LISTEN;
	cxgb3_ofld_send(d->cdev, skb);
	return;

free_all:
	__kfree_skb(skb);
free_stid:
	cxgb3_free_stid(d->cdev, stid);
	sock_put(sk);
free_ctx:
	kfree(ctx);
}

/*
 * Stop a listening server by sending a close_listsvr request to HW.
 * The server TID is freed when we get the reply.
 */
void t3_listen_stop(struct toedev *dev, struct sock *sk, struct t3cdev *cdev)
{
	struct sk_buff *skb;
	struct cpl_close_listserv_req *req;

	int stid = listen_hash_del(TOM_DATA(dev), sk);
	if (stid < 0)
		return;

	/*
	 * Do this early so embryonic connections are marked as being aborted
	 * while the stid is still open.  This ensures pass_establish messages
	 * that arrive while we are closing the server will be able to locate
	 * the listening socket.
	 */
	t3_reset_synq(sk);

	/* Send the close ASAP to stop further passive opens */
	skb = alloc_skb_nofail(sizeof(*req));
	req = (struct cpl_close_listserv_req *)__skb_put(skb, sizeof(*req));
	req->wr.wr_hi = htonl(V_WR_OP(FW_WROPCODE_FORWARD));
	OPCODE_TID(req) = htonl(MK_OPCODE_TID(CPL_CLOSE_LISTSRV_REQ, stid));
	req->cpu_idx = 0;
	skb->priority = CPL_PRIORITY_LISTEN;
	cxgb3_ofld_send(cdev, skb);

	t3_disconnect_acceptq(sk);
}

/*
 * Process a CPL_CLOSE_LISTSRV_RPL message.  If the status is good we release
 * the STID.
 */
static int do_close_server_rpl(struct t3cdev *cdev, struct sk_buff *skb,
			       void *ctx)
{
	struct cpl_close_listserv_rpl *rpl = cplhdr(skb);
	unsigned int stid = GET_TID(rpl);

	if (rpl->status != CPL_ERR_NONE)
		printk(KERN_ERR "Unexpected CLOSE_LISTSRV_RPL status %u for "
		       "STID %u\n", rpl->status, stid);
	else {
		struct listen_ctx *listen_ctx = (struct listen_ctx *)ctx;

		cxgb3_free_stid(cdev, stid);
		sock_put(listen_ctx->lsk);
		kfree(listen_ctx);
	}

	return CPL_RET_BUF_DONE;
}

/*
 * Process a CPL_PASS_OPEN_RPL message.  Remove the socket from the listen hash
 * table and free the STID if there was any error, otherwise nothing to do.
 */
static int do_pass_open_rpl(struct t3cdev *cdev, struct sk_buff *skb, void *ctx)
{
	struct cpl_pass_open_rpl *rpl = cplhdr(skb);

	if (rpl->status != CPL_ERR_NONE) {
		int stid = GET_TID(rpl);
		struct listen_ctx *listen_ctx = (struct listen_ctx *)ctx;
		struct tom_data *d = listen_ctx->tom_data;
		struct sock *lsk = listen_ctx->lsk;

#if VALIDATE_TID
		if (!lsk)
			return CPL_RET_UNKNOWN_TID | CPL_RET_BUF_DONE;
#endif
		/*
		 * Note: It is safe to unconditionally call listen_hash_del()
		 * at this point without risking unhashing a reincarnation of
		 * an already closed socket (i.e., there is no listen, close,
		 * listen, free the sock for the second listen while processing
		 * a message for the first race) because we are still holding
		 * a reference on the socket.  It is possible that the unhash
		 * will fail because the socket is already closed, but we can't
		 * unhash the wrong socket because it is impossible for the
		 * socket to which this message refers to have reincarnated.
		 */
		listen_hash_del(d, lsk);
		cxgb3_free_stid(cdev, stid);
		sock_put(lsk);
		kfree(listen_ctx);
	}
	return CPL_RET_BUF_DONE;
}

void __init t3_init_listen_cpl_handlers(void)
{
	t3tom_register_cpl_handler(CPL_PASS_OPEN_RPL, do_pass_open_rpl);
	t3tom_register_cpl_handler(CPL_CLOSE_LISTSRV_RPL, do_close_server_rpl);
}

#ifdef CONFIG_PROC_FS
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

#define PROFILE_LISTEN_HASH 1

#if PROFILE_LISTEN_HASH
# define BUCKET_FIELD_NAME "  Bucket"
# define BUCKET_FMT " %d"
# define BUCKET(sk) , listen_hashfn(sk)
#else
# define BUCKET_FIELD_NAME
# define BUCKET_FMT
# define BUCKET(sk)
#endif

/*
 * Return the first entry in the listen hash table that's in
 * a bucket >= start_bucket.
 */
static struct listen_info *listen_get_first(struct seq_file *seq,
					    int start_bucket)
{
	struct tom_data *d = seq->private;

	for (; start_bucket < LISTEN_INFO_HASH_SIZE; ++start_bucket)
		if (d->listen_hash_tab[start_bucket])
			return d->listen_hash_tab[start_bucket];
	return NULL;
}

static struct listen_info *listen_get_next(struct seq_file *seq,
					   const struct listen_info *p)
{
	return p->next ? p->next : listen_get_first(seq,
						    listen_hashfn(p->sk) + 1);
}

/*
 * Must be called with the listen_lock held.
 */
static struct listen_info *listen_get_idx(struct seq_file *seq, loff_t pos)
{
	struct listen_info *p = listen_get_first(seq, 0);

	if (p)
		while (pos && (p = listen_get_next(seq, p)))
			pos--;

	return pos ? NULL : p;
}

static struct listen_info *listen_get_idx_lock(struct seq_file *seq, loff_t pos)
{
	struct tom_data *d = seq->private;

	spin_lock(&d->listen_lock);
	return listen_get_idx(seq, pos);
}

static void *listen_seq_start(struct seq_file *seq, loff_t *pos)
{
	return *pos ? listen_get_idx_lock(seq, *pos - 1) : SEQ_START_TOKEN;
}

static void *listen_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	if (v == SEQ_START_TOKEN)
		v = listen_get_idx_lock(seq, 0);
	else
		v = listen_get_next(seq, v);
	++*pos;
	return v;
}

static void listen_seq_stop(struct seq_file *seq, void *v)
{
	if (v != SEQ_START_TOKEN)
		spin_unlock(&((struct tom_data *)seq->private)->listen_lock);
}

static int listen_seq_show(struct seq_file *seq, void *v)
{
	if (v == SEQ_START_TOKEN)
		seq_puts(seq,
			 "TID     IP address      Port" BUCKET_FIELD_NAME "\n");
	else {
		char ip[20];
		struct listen_info *p = v;
		struct sock *sk = p->sk;
#ifdef	LINUX_2_4
		u32 saddr = sk->rcv_saddr;

		sprintf(ip, "%u.%u.%u.%u", NIPQUAD(saddr));
		seq_printf(seq, "%-7u %-15s %-5u" BUCKET_FMT "\n", p->stid, ip,
			   sk->num BUCKET(sk));
#else
		u32 saddr = inet_sk(sk)->inet_rcv_saddr;

		sprintf(ip, "%u.%u.%u.%u", NIPQUAD(saddr));
		seq_printf(seq, "%-7u %-15s %-5u" BUCKET_FMT "\n", p->stid, ip,
			   inet_sk(sk)->inet_num BUCKET(sk));
#endif	/* LINUX_2_4 */
	}
	return 0;
}

static struct seq_operations listen_seq_ops = {
	.start = listen_seq_start,
	.next = listen_seq_next,
	.stop = listen_seq_stop,
	.show = listen_seq_show
};

static int listen_seq_open(struct inode *inode, struct file *file)
{
	int rc = seq_open(file, &listen_seq_ops);

	if (!rc) {
		struct proc_dir_entry *dp = PDE(inode);
		struct seq_file *seq = file->private_data;

		seq->private = dp->data;
	}
	return rc;
}

static struct file_operations listen_seq_fops = {
	.owner = THIS_MODULE,
	.open = listen_seq_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release
};

#define LISTEN_PROC_NAME "listeners"

/*
 * Create the proc entry for the listening servers under dir.
 */
int t3_listen_proc_setup(struct proc_dir_entry *dir, struct tom_data *d)
{
	struct proc_dir_entry *p;

	if (!dir)
		return -EINVAL;

	p = create_proc_entry(LISTEN_PROC_NAME, S_IRUGO, dir);
	if (!p)
		return -ENOMEM;

	p->proc_fops = &listen_seq_fops;
	p->data = d;
	return 0;
}

void t3_listen_proc_free(struct proc_dir_entry *dir)
{
	if (dir) {
		remove_proc_entry(LISTEN_PROC_NAME, dir);
	}
}
#endif
