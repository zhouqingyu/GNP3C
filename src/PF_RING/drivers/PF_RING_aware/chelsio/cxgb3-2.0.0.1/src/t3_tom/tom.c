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
#include "defs.h"
#include <linux/module.h>
#include <linux/vmalloc.h>
#include <linux/ip.h>
#include <linux/init.h>
#include <linux/netdevice.h>
#include <linux/toedev.h>
#include <net/offload.h>
#include "tom.h"
#include "t3_ddp.h"
#include "cxgb3_ctl_defs.h"
#include "t3cdev.h"
#include "cxgb3_offload.h"
#include "firmware_exports.h"
#include "version.h"
#include "trace.h"

static int activated = 1;
#ifdef T3_TRACE_TOM
static struct dentry *tom_debugfs_root;
#endif

module_param(activated, int, 0644);
MODULE_PARM_DESC(activated, "whether to enable TOE at init time or not");

/*
 * By default, we offload every connection and listener of which we are
 * capable.  Setting cop_managed_offloading to a non-zero value puts
 * offloading decisions under the sole purview of a Connection Offload Policy
 * (COP).  As a consequence, if there is no COP loaded, then no connections,
 * listeners, etc. will be offloaded.  And thus, when this module is first
 * loaded and cop_managed_offloading is set, no offloading will be done until
 * the first COP is loaded.
 *
 * Note that loading a new COP cannot retroactively revoke offloading
 * decisions made by previous COPs.  In order to accomplish that semantic, the
 * existing offloaded services must be restarted with the new COP in effect.
 */
static int cop_managed_offloading = 0;
module_param(cop_managed_offloading, int, 0644);
MODULE_PARM_DESC(cop_managed_offloading,
		 "all connection offloading decision managed by COP");

static LIST_HEAD(cxgb3_list);
static DEFINE_MUTEX(cxgb3_list_lock);

static struct offload_id t3_toe_id_tab[] = {
        { TOE_ID_CHELSIO_T3, 0 },
        { TOE_ID_CHELSIO_T3B, 0 },
        { TOE_ID_CHELSIO_T3C, 0 },
        { 0 }
};

/*
 * Add an skb to the deferred skb queue for processing from process context.
 */
void t3_defer_reply(struct sk_buff *skb, struct toedev *dev,
		    defer_handler_t handler)
{
	struct tom_data *td = TOM_DATA(dev);

	DEFERRED_SKB_CB(skb)->handler = handler;
	spin_lock_bh(&td->deferq.lock);
	__skb_queue_tail(&td->deferq, skb);
	if (skb_queue_len(&td->deferq) == 1)
		schedule_work(&td->deferq_task);
	spin_unlock_bh(&td->deferq.lock);
}

/*
 * Process the defer queue.
 */
DECLARE_TASK_FUNC(process_deferq, task_param)
{
	struct sk_buff *skb;
	struct tom_data *td = WORK2TOMDATA(task_param, deferq_task);

	spin_lock_bh(&td->deferq.lock);
	while ((skb = __skb_dequeue(&td->deferq)) != NULL) {
		spin_unlock_bh(&td->deferq.lock);
		DEFERRED_SKB_CB(skb)->handler(&td->tdev, skb);
		spin_lock_bh(&td->deferq.lock);
	}
	spin_unlock_bh(&td->deferq.lock);
}

/*
 ** Allocate a chunk of memory using kmalloc or, if that fails, vmalloc.
 ** The allocated memory is cleared.
 **/
static void *t3_alloc_mem(unsigned long size)
{
	void *p = kmalloc(size, GFP_KERNEL);

	if (!p)
		p = vmalloc(size);
	if (p)
		memset(p, 0, size);
	return p;
}

#if 0
/*
 * Free memory allocated through t3_alloc_mem().
 */
static void t3_free_mem(void *addr)
{
	unsigned long p = (unsigned long) addr;

	if (p >= VMALLOC_START && p < VMALLOC_END)
		vfree(addr);
	else
		kfree(addr);
}
#endif

/*
 * Process a received packet with an unknown/unexpected CPL opcode.
 */
static int do_bad_cpl(struct t3cdev *cdev, struct sk_buff *skb, void *ctx)
{
	printk(KERN_ERR "%s: received bad CPL command %u\n", cdev->name,
	       *skb->data);
	return CPL_RET_BUF_DONE | CPL_RET_BAD_MSG;
}

/*
 * Handlers for each CPL opcode
 */
static cxgb3_cpl_handler_func tom_cpl_handlers[NUM_CPL_CMDS];

/*
 * Add a new handler to the CPL dispatch table.  A NULL handler may be supplied
 * to unregister an existing handler.
 */
void t3tom_register_cpl_handler(unsigned int opcode, cxgb3_cpl_handler_func h)
{
	if (opcode < NUM_CPL_CMDS)
		tom_cpl_handlers[opcode] = h ? h : do_bad_cpl;
	else
		printk(KERN_ERR "Chelsio T3 TOM: handler registration for "
		       "opcode %u failed\n", opcode);
}
EXPORT_SYMBOL(t3tom_register_cpl_handler);

/*
 * Make a preliminary determination if a connection can be offloaded.  It's OK
 * to fail the offload later if we say we can offload here.  For now this
 * always accepts the offload request unless there are IP options.
 */
static int can_offload(struct toedev *dev, struct sock *sk)
{
	struct tom_data *d = TOM_DATA(dev);
	struct t3cdev *cdev = dev2t3cdev(dev->lldev[0]);
	struct tid_info *t = &(T3C_DATA(cdev))->tid_maps;

	return inet_sk(sk)->opt == NULL && d->conf.activated &&
	       sk->sk_family == PF_INET &&
	    (d->conf.max_conn < 0 ||
	     atomic_read(&t->tids_in_use) + t->atids_in_use < d->conf.max_conn);
}

static int listen_offload(void *dev, struct sock *sk)
{
	if (sk->sk_family == PF_INET) {
		struct offload_req req;
		offload_req_from_sk(&req, sk, OPEN_TYPE_LISTEN);
		t3_listen_start(dev, sk, &req);
	}
	return 0;
}

/*
 * This is called through a notifier chain when a socket listen event is
 * published.  We iterate through all the TOEs we are handling and establish
 * or close listening servers as appropriate.
 */
static int listen_notify_handler(struct notifier_block *this,
				 unsigned long event, void *data)
{
	struct sock *sk = data;
	struct tom_data *p;
	struct offload_req req;

	if (event == OFFLOAD_LISTEN_START)
		offload_req_from_sk(&req, sk, OPEN_TYPE_LISTEN);

	switch (event) {
	case OFFLOAD_LISTEN_START:
	case OFFLOAD_LISTEN_STOP:
		mutex_lock(&cxgb3_list_lock);
		list_for_each_entry(p, &cxgb3_list, list_node) {
			if (event == OFFLOAD_LISTEN_START)
				t3_listen_start(&p->tdev, sk, &req);
			else
				t3_listen_stop(&p->tdev, sk, p->cdev);
		}
		mutex_unlock(&cxgb3_list_lock);
		break;
	}
	return NOTIFY_DONE;
}

static void hw_error_handler(struct t3cdev *cdev, u32 status, u32 error)
{
        struct tid_info *tinfo = &(T3C_DATA(cdev))->tid_maps;
	struct t3c_tid_entry *tstid = (struct t3c_tid_entry *)tinfo->stid_tab;
        struct t3c_tid_entry *ttid = (struct t3c_tid_entry *)tinfo->tid_tab;
        unsigned int tids_in_use;


        switch (status) {
        	case OFFLOAD_STATUS_DOWN:
        	tids_in_use = atomic_read(&tinfo->tids_in_use);

        	while (tids_in_use && (ttid < tstid)) {
                	struct sock *sk = NULL;
                	if (ttid)
                        	sk = (struct sock *)(ttid->ctx);
                	if (sk) {
                        	lock_sock(sk);
                        	sk->sk_err = ECONNRESET;
				t3_release_ddp_resources(sk);
				t3_cleanup_ddp(sk);
                        	release_sock(sk);
                	}
                	ttid++;
        	}
		break;
        }
}

struct cxgb3_client t3c_tom_client = {
	.name = "tom_cxgb3",
	.handlers = tom_cpl_handlers,
	.redirect = NULL,
	.event_handler = hw_error_handler,
};

/*
 * Add a T3 offload device to the list of devices we are managing.
 */
static void t3cdev_add(struct tom_data *t)
{
	mutex_lock(&cxgb3_list_lock);
	list_add_tail(&t->list_node, &cxgb3_list);
	mutex_unlock(&cxgb3_list_lock);
}

/*
 * Remove a T3 offload device from the list of TOEs we are managing.
 */
static void t3cdev_remove(struct tom_data *t)
{
	mutex_lock(&cxgb3_list_lock);
	list_del(&t->list_node);
	mutex_unlock(&cxgb3_list_lock);
}

static inline int cdev2type(struct t3cdev *cdev)
{
	int type = 0;

	switch (cdev->type) {
	case T3A:
		type = TOE_ID_CHELSIO_T3;
		break;
	case T3B:
		type = TOE_ID_CHELSIO_T3B;
		break;
	case T3C:
		type = TOE_ID_CHELSIO_T3C;
		break;
	}
	return type;
}

/*
 * Allocate a TOM data structure,
 * initialize its cpl_handlers
 * and register it as a T3C client
 */
static void t3c_tom_add(struct t3cdev *cdev)
{
	int i;
	unsigned int wr_len;
	struct tom_data *t;
	struct toedev *tdev;
	struct adap_ports *port_info;
	struct port_array pa;
	struct ch_embedded_info e;
	unsigned int type, major, minor, maj, min;

	if (cdev->ctl(cdev, GET_PORT_ARRAY, &pa) < 0)
		return;

	if (cdev->ctl(cdev, GET_EMBEDDED_INFO, &e) < 0)
		return;

	type = G_FW_VERSION_TYPE(e.fw_vers);
	major = G_FW_VERSION_MAJOR(e.fw_vers);
	minor = G_FW_VERSION_MINOR(e.fw_vers);	

	if (type != FW_VERSION_T3 || major != FW_VERSION_MAJOR ||
	    minor != FW_VERSION_MINOR) {
		printk(KERN_WARNING
		       "Wrong FW (Type %u version %u.%u) on %s, "
		       "module needs type %u %u.%u\n", type, major, minor,
			cdev->lldev->name,
			FW_VERSION_T3, FW_VERSION_MAJOR, FW_VERSION_MINOR);
		return;
	}

	major = G_TP_VERSION_MAJOR(e.tp_vers);
	minor = G_TP_VERSION_MINOR(e.tp_vers);	

	if (cdev->type != T3C) {
		maj = TP_VERSION_MAJOR_T3B;
		min = TP_VERSION_MINOR_T3B;
	} else {
		maj = TP_VERSION_MAJOR;
		min = TP_VERSION_MINOR;
	}

	if (major != maj || minor != min) {
		printk(KERN_WARNING
		       "Wrong protocol engine (version %u.%u) on %s, "
		       "module needs %u.%u\n", major, minor,
			cdev->lldev->name,
			maj, min);
		return;
	}

	t = kcalloc(1, sizeof(*t), GFP_KERNEL);
	if (!t)
		return;

	if (cdev->ctl(cdev, GET_WR_LEN, &wr_len) < 0)
		goto out_free_tom;

	port_info = kcalloc(1, sizeof(*port_info), GFP_KERNEL);
	if (!port_info)
		goto out_free_tom;

	if (cdev->ctl(cdev, GET_PORTS, port_info) < 0)
		goto out_free_all;

	t3_init_wr_tab(wr_len);
	t->cdev = cdev;
	t->client = &t3c_tom_client;

	/* Register TCP offload device */
	tdev = &t->tdev;
	tdev->ttid = cdev2type(cdev);
	tdev->nlldev = pa.nports;
	tdev->lldev = pa.lldevs;

	if (register_toedev(tdev, "toe%d")) {
		printk("unable to register offload device");
		goto out_free_all;
	}
	TOM_DATA(tdev) = t;

#ifdef T3_TRACE_TOM
        if (tom_debugfs_root) {
                t->debugfs_root = debugfs_create_dir(tdev->name,
                                                    tom_debugfs_root);
		if (t->debugfs_root) {
			char s[16];
			for (i=0; i<T3_TRACE_TOM_BUFFERS ; i++) {
				sprintf(s, "tid%d", i);
                		t->tb[i] = t3_trace_alloc(t->debugfs_root, s, 512);
			}
		}
        }
#endif

	for (i = 0; i < tdev->nlldev; i++)
		netdev_set_offload(tdev->lldev[i]);

	/* Update bonding devices capabilities */
	t3_update_master_devs(tdev);

	t->ports = port_info;

	INIT_LIST_HEAD(&t->list_node);

	/* Add device to the list of offload devices */
	t3cdev_add(t);

	/* Activate TCP offload device */
	activate_offload(tdev);
	walk_listens(tdev, listen_offload);
	return;

out_free_all:
	kfree(port_info);
out_free_tom:
	kfree(t);
	return;
}

#ifdef CONFIG_PROC_FS
#include <linux/proc_fs.h>

static int tom_info_read_proc(char *buf, char **start, off_t offset,
			      int length, int *eof, void *data)
{
	struct tom_data *d = data;
	int len;

#if defined(CONFIG_T3_ZCOPY_SENDMSG) || defined(CONFIG_T3_ZCOPY_SENDMSG_MODULE)
	len = sprintf(buf,
		      "MSS: %u %u\n",
		      d->conf.mss, atomic_read(&d->tx_dma_pending));
#else
	len = sprintf(buf,
		      "MSS: %u\n",
		      d->conf.mss);
#endif
	if (len > length)
		len = length;
	*eof = 1;
	return len;
}

static void tom_info_proc_free(struct proc_dir_entry *dir)
{
	if (dir)
		remove_proc_entry("info", dir);
}

static int tom_info_proc_setup(struct proc_dir_entry *dir, struct tom_data *d)
{
	struct proc_dir_entry *p;

	if (!dir)
		return -EINVAL;

	p = create_proc_read_entry("info", 0, dir, tom_info_read_proc, d);
	if (!p)
		return -ENOMEM;

	SET_PROC_NODE_OWNER(p, THIS_MODULE);
	return 0;
}

static void tom_proc_init(struct toedev *dev)
{
	t3_listen_proc_setup(dev->proc_dir, TOM_DATA(dev));
	tom_info_proc_setup(dev->proc_dir, TOM_DATA(dev));
}

static void tom_proc_cleanup(struct toedev *dev)
{
	t3_listen_proc_free(dev->proc_dir);
	tom_info_proc_free(dev->proc_dir);
}
#else
#define tom_proc_init(dev)
#define tom_proc_cleanup(dev)
#endif

#ifndef NETEVENT
static void tom_neigh_update(struct toedev *dev, struct neighbour *neigh)
{
	struct tom_data *t = TOM_DATA(dev);
	struct t3cdev *cdev = t->cdev;

	if (cdev->neigh_update)
		cdev->neigh_update(cdev, neigh);
}
#endif

static int tom_ctl(struct toedev *dev, unsigned int req, void *data)
{
	struct tom_data *t = TOM_DATA(dev);
	struct t3cdev *cdev = t->cdev;

	if (cdev->ctl)
		return cdev->ctl(cdev, req, data);

	return -ENOTSUPP;
}

static int t3_toe_attach(struct toedev *dev, const struct offload_id *entry)
{
	struct tom_data *t = TOM_DATA(dev);
	struct t3cdev *cdev = t->cdev;
	struct ddp_params ddp;
	struct ofld_page_info rx_page_info;
	int err;

	skb_queue_head_init(&t->deferq);
	T3_INIT_WORK(&t->deferq_task, process_deferq, t);
	spin_lock_init(&t->listen_lock);
	spin_lock_init(&t->synq_lock);
	t3_init_tunables(t);

	/* Adjust TOE activation for this module */
	t->conf.activated = activated;
	t->conf.cop_managed_offloading = cop_managed_offloading;

	dev->can_offload = can_offload;
	dev->connect = t3_connect;
	dev->failover = t3_failover;
	dev->ctl = tom_ctl;
#ifndef NETEVENT
	dev->neigh_update = tom_neigh_update;
#endif

	err = cdev->ctl(cdev, GET_DDP_PARAMS, &ddp);
	if (err)
		return err;

	err = cdev->ctl(cdev, GET_RX_PAGE_INFO, &rx_page_info);
	if (err)
		return err;

	t->ddp_llimit = ddp.llimit;
	t->ddp_ulimit = ddp.ulimit;
	t->pdev = ddp.pdev;
	t->rx_page_size = rx_page_info.page_size;

	/* OK if this fails, we just can't do DDP */
	t->nppods = (ddp.ulimit + 1 - ddp.llimit) / PPOD_SIZE;
	t->ppod_map = t3_alloc_mem(t->nppods);
	spin_lock_init(&t->ppod_map_lock);

	tom_proc_init(dev);
#ifdef CONFIG_SYSCTL
	t->sysctl = t3_sysctl_register(dev, &t->conf);
#endif

	return 0;
}

extern void install_standard_ops(struct sock *sk);
extern void t3_release_offload_resources(struct sock *sk);

static int t3_toe_detach(struct toedev *dev)
{
        struct tom_data *t = TOM_DATA(dev);
	struct t3cdev *cdev = t->cdev;
	struct tid_info *tinfo = &(T3C_DATA(cdev))->tid_maps;
	struct t3c_tid_entry *tstid = (struct t3c_tid_entry *)tinfo->stid_tab;
	struct t3c_tid_entry *tatid = (struct t3c_tid_entry *)tinfo->atid_tab;
	struct t3c_tid_entry *ttid = (struct t3c_tid_entry *)tinfo->tid_tab;
	unsigned int stids_in_use, atids_in_use, tids_in_use;

	t->conf.activated = 0;

	spin_lock(&tinfo->stid_lock);
	stids_in_use = tinfo->stids_in_use;
	spin_unlock(&tinfo->stid_lock);

	while (stids_in_use && (tstid < tatid)) {
		if (tstid) {
		        struct listen_ctx *listen_ctx = tstid->ctx;
			if (listen_ctx) {
        			struct sock *lsk = listen_ctx->lsk;
        			struct tom_data *d = listen_ctx->tom_data;

				if ((d == t) && (lsk != NULL)) {
					t3_listen_stop(&d->tdev, lsk, d->cdev);
					stids_in_use--;
				}
			}
		}
		tstid++;
	}

        spin_lock(&tinfo->atid_lock);
        atids_in_use = tinfo->atids_in_use;
        spin_unlock(&tinfo->atid_lock);

        while (atids_in_use) {
                if (tatid) {
			struct sock *sk = (struct sock *)(tatid->ctx);
			if (sk) {
                               	sk->sk_err = ECONNRESET;
                                sk->sk_error_report(sk);
                                t3_release_offload_resources(sk);
				sk_wakeup_sleepers(sk, 0);
				tcp_done(sk);
				atids_in_use--;
			}
		}
		tatid++;
	}

        tids_in_use = atomic_read(&tinfo->tids_in_use);

        while (tids_in_use && (ttid < tstid)) {
                struct sock *sk = NULL;
                if (ttid)
                        sk = (struct sock *)(ttid->ctx);
                if (sk) {
			struct tcp_sock *tp = tcp_sk(sk);

                        lock_sock(sk);
                        __skb_queue_purge(&sk->sk_receive_queue);
                        t3_purge_write_queue(sk);

                        if (sk->sk_state != TCP_CLOSE) {
                                sk->sk_err = ECONNRESET;
                                t3_send_reset(sk, CPL_ABORT_SEND_RST, NULL);
                        }

                        while (!sk_in_state(sk, TCPF_CLOSE)) {
                                release_sock(sk);
                                lock_sock(sk);
                        }

                        __skb_queue_purge(&tp->out_of_order_queue);

                        tp->max_window = 0xFFFF << SND_WSCALE(tp);

                        install_standard_ops(sk);
                        tcp_init_xmit_timers(sk);
                        tcp_disconnect(sk, 0);
                        release_sock(sk);
			tids_in_use--;
                }
		ttid++;
        }

	return 0;
}

static struct tom_info t3_tom_info = {
	.attach = t3_toe_attach,
	.detach = t3_toe_detach,
	.id_table = t3_toe_id_tab,
	.name = "Chelsio-T3"
};

static struct notifier_block listen_notifier = {
        .notifier_call = listen_notify_handler
};

static void t3c_tom_remove(struct t3cdev *cdev)
{
        struct adap_ports *port_info;
        struct tom_data *t;
        struct net_device *dev;
        struct toedev *tdev;

        dev = cdev->lldev;
        tdev = TOEDEV(dev);
        t = TOM_DATA(tdev);

        if (deactivate_offload(tdev) == 0) {
		unsigned int i;

#ifdef CONFIG_SYSCTL
                t3_sysctl_unregister(t->sysctl);
#endif
		tom_proc_cleanup(tdev);

                unregister_toedev(tdev);
		unregister_listen_offload_notifier(&listen_notifier);
                unregister_tom(&t3_tom_info);

                port_info = t->ports;

		for (i = 0; i < port_info->nports; i++) {
                	struct net_device *dev = port_info->lldevs[i];
			netdev_clear_offload(dev);
		}

#ifdef T3_TRACE_TOM
                if (t->debugfs_root) {
			unsigned int i;
                        for (i=0; i<T3_TRACE_TOM_BUFFERS ; i++)
                                t3_trace_free(t->tb[i]);
			debugfs_remove(t->debugfs_root);
                }
#endif

                t3cdev_remove(t);

                kfree(port_info);
                kfree(t);
        }
}

static int t3_set_offload_policy(struct net_device *dev,
				 const struct ofld_policy_file *opf,
				 size_t len)
{
	int ret;

	ret = set_offload_policy(TOEDEV(dev), opf);
	if (ret)
		return ret;

	/*
	 * We need to walk the list of current listeners to see if any of them
	 * which are not currently offloaded are now allowed to be offloaded
	 * by the new COP.  Also remember that the new COP cannot
	 * retroactively revoke a previous COP's decision to offload a
	 * connection or listener.  So there's no point in doing the walk if
	 * we've just been handed a NULL COP ...
	 */
	if (opf)
		walk_listens(TOEDEV(dev), listen_offload);
	return 0;
}

/*
 * Initialize the CPL dispatch table.
 */
static void __init init_cpl_handlers(void)
{
	int i;

	for (i = 0; i < NUM_CPL_CMDS; ++i)
		tom_cpl_handlers[i] = do_bad_cpl;

	t3_init_listen_cpl_handlers();
}

#ifndef LINUX_2_4
static
#endif
int __init t3_tom_init(void)
{
	int err;
	struct socket *sock;

#ifdef CONFIG_CHELSIO_T3_OFFLOAD_MODULE
	err = prepare_tom_for_offload();
	if (err)
		return err;
#endif
	err = sock_create_kern(PF_INET, SOCK_STREAM, IPPROTO_TCP, &sock);
	if (err < 0) {
		printk(KERN_ERR "Could not create TCP socket, error %d\n", err);
		return err;
	}

	sock_release(sock);

	init_cpl_handlers();
	if (t3_init_cpl_io() < 0)
		return -1;
	t3_init_offload_ops();

	 /* Register with the TOE device layer. */

	if (register_tom(&t3_tom_info) != 0) {
		printk(KERN_ERR
		       "Unable to register Chelsio T3 TCP offload module.\n");
		return -1;
	}

	register_listen_offload_notifier(&listen_notifier);

#ifdef T3_TRACE_TOM
        tom_debugfs_root = debugfs_create_dir("t3_tom", NULL);
        if (!tom_debugfs_root)
                printk(KERN_WARNING
                        "t3_tom: could not create debugfs entry, continuing\n");
#endif

	/* Register to offloading devices */
	t3c_tom_client.add = t3c_tom_add;
	t3c_tom_client.remove = t3c_tom_remove;
	t3c_tom_client.set_offload_policy = t3_set_offload_policy;
	cxgb3_register_client(&t3c_tom_client);

	return 0;
}

late_initcall(t3_tom_init);   /* initialize after TCP */

#ifdef T3_TRACE_TOM
static void __exit t3_tom_exit(void)
{
	cxgb3_unregister_client(&t3c_tom_client);
	if (tom_debugfs_root)
		debugfs_remove(tom_debugfs_root);
}

module_exit(t3_tom_exit);
#endif

MODULE_DESCRIPTION("TCP offload module for Chelsio T3-based network cards");
MODULE_AUTHOR("Chelsio Communications");
MODULE_LICENSE("GPL");
MODULE_VERSION(TOM_VERSION);
