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
#include <linux/param.h>
#include <linux/slab.h>
#include <linux/sysctl.h>
#include <linux/netdevice.h>
#include <linux/toedev.h>
#include "cpl_io_state.h"
#include "tom.h"
#include "t3cdev.h"
#include "cxgb3_offload.h"
#include "tom_compat.h"

/* This belongs in linux/sysctl.h */
#define CTL_TOE 11

/* sysctl ids for tunables */
enum {
	TOE_CONF_MAX_HOST_SNDBUF = 1,
	TOE_CONF_TX_HOLD_THRES,
	TOE_CONF_MAX_WR,
	TOE_CONF_RX_CREDIT_THRES,
	TOE_CONF_MSS,
	TOE_CONF_DELACK,
	TOE_CONF_MAX_CONN,
	TOE_CONF_SOFT_BACKLOG_LIMIT,
	TOE_CONF_KSEG_DDP,
	TOE_CONF_DDP,
	TOE_CONF_DDP_THRES,
	TOE_CONF_DDP_COPY_LIMIT,
	TOE_CONF_DDP_PSH_WAIT,
	TOE_CONF_DDP_RCVCOALESCE,
#if defined(CONFIG_T3_ZCOPY_SENDMSG) || defined(CONFIG_T3_ZCOPY_SENDMSG_MODULE)
	TOE_CONF_ZCOPY_SENDMSG_PARTIAL_THRES,
	TOE_CONF_ZCOPY_SENDMSG_PARTIAL_COPY,
	TOE_CONF_ZCOPY_SENDMSG_THRES,
	TOE_CONF_ZCOPY_SENDMSG_COPY,
	TOE_CONF_ZCOPY_SENDMSG_RET_PENDING_DMA,
#endif
	TOE_CONF_ACTIVATED,
	TOE_CONF_COP_MANAGED_OFFLOADING,
	TOE_CONF_LAST           /* must be last */
};

static struct tom_tunables default_tunable_vals = {
	.max_host_sndbuf = 32 * 1024,
	.tx_hold_thres = 0,
	.max_wrs = 15,
	.rx_credit_thres = 15 * 1024,
	.mss = 16384,
	.delack = 1,
	.max_conn = -1,
	.soft_backlog_limit = 0,
	.kseg_ddp = 0,
	.ddp = 1,
	.ddp_thres = 14 * 4096,
	.ddp_copy_limit = 13 * 4096,
	.ddp_push_wait = 1,
	.ddp_rcvcoalesce = 0,
#if defined(CONFIG_T3_ZCOPY_SENDMSG) || defined(CONFIG_T3_ZCOPY_SENDMSG_MODULE)
	.zcopy_sendmsg_partial_thres = 40960,
	.zcopy_sendmsg_partial_copy = 4096 * 3,
	.zcopy_sendmsg_thres = 128 * 1024,
	.zcopy_sendmsg_copy = 4096 * 2,
	.zcopy_sendmsg_ret_pending_dma = 1,
#endif
	.activated = 1,
	.cop_managed_offloading = 1,
};

static int min_wrs = 3;	        /* Min # of outstanding WRs for a connection */
static int min_mss = 1;		/* Min length of TX_DATA payload */
static int min_rx_credits = 1;	/* Min RX credit threshold */
static int min_delack = 0;      /* Min value for delayed ACK mode */
static int max_delack = 3;      /* Max value for delayed ACK mode */
static int min_ddp_thres = 0;   /* Min read size to enter DDP */
static int min_ddp_cplmt = 128; /* Min value for DDP copy limit */
static int max_ddp_cplmt = 65536; /* Max value for DDP copy limit */

/* Number of fields in tom_tunables */
#define NUM_TUNABLES (TOE_CONF_LAST - 1)

#if defined(SYSCTL_CTL_NAME)
#define TUNABLE_INT(name, proc_name, field_name) \
	{ .ctl_name = TUNABLE_INT_CTL_NAME(name), \
	  .procname = proc_name,\
	  .data = &default_tunable_vals.field_name,\
	  .maxlen = sizeof(default_tunable_vals.field_name),\
	  .mode = 0644,\
	  .proc_handler = &proc_dointvec }

#define TUNABLE_INT_RANGE(name, proc_name, field_name, minp, maxp) \
	{ .ctl_name = TUNABLE_INT_RANGE_CTL_NAME(name), \
	  .procname = proc_name,\
	  .data = &default_tunable_vals.field_name,\
	  .maxlen = sizeof(default_tunable_vals.field_name),\
	  .mode = 0644,\
	  .proc_handler = &proc_dointvec_minmax,\
          .strategy = &sysctl_intvec, \
	  .extra1 = minp,\
	  .extra2 = maxp }
#else /* >= 2.6.33 */
#define TUNABLE_INT(name, proc_name, field_name) \
	{ .procname = proc_name,\
	  .data = &default_tunable_vals.field_name,\
	  .maxlen = sizeof(default_tunable_vals.field_name),\
	  .mode = 0644,\
	  .proc_handler = &proc_dointvec }

#define TUNABLE_INT_RANGE(name, proc_name, field_name, minp, maxp) \
	{ .procname = proc_name,\
	  .data = &default_tunable_vals.field_name,\
	  .maxlen = sizeof(default_tunable_vals.field_name),\
	  .mode = 0644,\
	  .proc_handler = &proc_dointvec_minmax,\
	  .extra1 = minp,\
	  .extra2 = maxp }
#endif

/*
 * Sysctl table template.  This is cloned for each TOM instance.
 */
struct tom_sysctl_table {
	struct ctl_table_header *sysctl_header;

	char tom_instance_dir_name[TOENAMSIZ + 4];
	ctl_table tunables[NUM_TUNABLES + 1];
	ctl_table tom_instance_dir[2];
	ctl_table root_dir[2];
};

static struct tom_sysctl_table tom_sysctl = {
	.tunables = {
		TUNABLE_INT(MAX_HOST_SNDBUF, "max_host_sndbuf",
			    max_host_sndbuf),
		TUNABLE_INT(TX_HOLD_THRES, "tx_hold_thres", tx_hold_thres),
		TUNABLE_INT_RANGE(MAX_WR, "max_wr", max_wrs, &min_wrs, NULL),
		TUNABLE_INT_RANGE(RX_CREDIT_THRES, "rx_credit_thres",
				  rx_credit_thres, &min_rx_credits, NULL),
		TUNABLE_INT_RANGE(MSS, "mss", mss, &min_mss, NULL),
		TUNABLE_INT_RANGE(DELACK, "delayed_ack", delack, &min_delack,
				  &max_delack),
		TUNABLE_INT(MAX_CONN, "max_conn", max_conn),
		TUNABLE_INT(SOFT_BACKLOG_LIMIT, "soft_backlog_limit",
			    soft_backlog_limit),
		TUNABLE_INT(KSEG_DDP, "kseg_ddp", kseg_ddp),
		TUNABLE_INT(DDP, "ddp", ddp),
		TUNABLE_INT_RANGE(DDP_THRES, "ddp_thres", ddp_thres,
				  &min_ddp_thres, NULL),
		TUNABLE_INT_RANGE(DDP_COPY_LIMIT, "ddp_copy_limit",
				  ddp_copy_limit, &min_ddp_cplmt,
				  &max_ddp_cplmt),
		TUNABLE_INT(DDP_PSH_WAIT, "ddp_push_wait", ddp_push_wait),
		TUNABLE_INT(DDP_RCVCOALESCE, "ddp_rcvcoalesce",
			    ddp_rcvcoalesce),
#if defined(CONFIG_T3_ZCOPY_SENDMSG) || defined(CONFIG_T3_ZCOPY_SENDMSG_MODULE)
		TUNABLE_INT(ZCOPY_SENDMSG_PARTIAL_THRES,
			    "zcopy_sendmsg_partial_thres",
			    zcopy_sendmsg_partial_thres),
		TUNABLE_INT(ZCOPY_SENDMSG_PARTIAL_COPY,
			    "zcopy_sendmsg_partial_copy",
			    zcopy_sendmsg_partial_copy),
		TUNABLE_INT(ZCOPY_SENDMSG_THRES, "zcopy_sendmsg_thres",
			    zcopy_sendmsg_thres),
		TUNABLE_INT(ZCOPY_SENDMSG_COPY, "zcopy_sendmsg_copy",
			    zcopy_sendmsg_copy),
		TUNABLE_INT(ZCOPY_SENDMSG_RET_PENDING_DMA,
			    "zcopy_sendmsg_ret_pending_dma",
			    zcopy_sendmsg_ret_pending_dma),
#endif
		TUNABLE_INT(ACTIVATED, "activated",
			    activated),
		TUNABLE_INT(COP_MANAGED_OFFLOADING, "cop_managed_offloading",
			    cop_managed_offloading),
	},
	.tom_instance_dir = {
		{
#if defined(SYSCTL_CTL_NAME)
			.ctl_name = TOM_INSTANCE_DIR_CTL_NAME,
#endif
			.procname = tom_sysctl.tom_instance_dir_name,
			.mode = 0555,
			.child = tom_sysctl.tunables,
		},
	},
	.root_dir = {
		{
#if defined(SYSCTL_CTL_NAME)
			.ctl_name = ROOT_DIR_CTL_NAME,
#endif
			.procname = "toe",
			.mode = 0555,
			.child = tom_sysctl.tom_instance_dir,
		},
	}
};

/*
 * Register the sysctl table for a TOM instance associated with the supplied
 * TOE device.
 */
struct tom_sysctl_table *t3_sysctl_register(struct toedev *dev,
					    const struct tom_tunables *p)
{
	int i;
	struct tom_data *td = TOM_DATA(dev);
	struct t3c_data *cd = T3C_DATA(td->cdev);
	struct tom_sysctl_table *t = kmalloc(sizeof(*t), GFP_KERNEL);

	if (!t)
		return NULL;

	memcpy(t, &tom_sysctl, sizeof(*t));
	snprintf(t->tom_instance_dir_name, sizeof(t->tom_instance_dir_name),
		 "%s_tom", dev->name);
	for (i = 0; i < NUM_TUNABLES; ++i) {
		t->tunables[i].data +=
			(char *)p - (char *)&default_tunable_vals;
		tom_sysctl_set_de(&t->tunables[i]);
	}

	t->tunables[TOE_CONF_MSS - 1].extra2 = &cd->tx_max_chunk;
	t->tunables[TOE_CONF_MAX_WR - 1].extra2 = &cd->max_wrs;

	t->tom_instance_dir[0].procname = t->tom_instance_dir_name;
	t->tom_instance_dir[0].child = t->tunables;
	tom_sysctl_set_de(&t->tom_instance_dir[0]);
	t->root_dir[0].child = t->tom_instance_dir;
	tom_sysctl_set_de(&t->root_dir[0]);

	t->sysctl_header = tom_register_sysctl_table(t->root_dir, 0);
	if (!t->sysctl_header) {
		kfree(t);
		t = NULL;
	}
	return t;
}

void t3_sysctl_unregister(struct tom_sysctl_table *t)
{
	if (t) {
		unregister_sysctl_table(t->sysctl_header);
		kfree(t);
	}
}

void t3_init_tunables(struct tom_data *t)
{
	t->conf = default_tunable_vals;

	/* Now apply device specific fixups. */
	t->conf.mss = T3C_DATA(t->cdev)->tx_max_chunk;
	t->conf.max_wrs = min(T3C_DATA(t->cdev)->max_wrs,
			      (unsigned int)t->conf.max_wrs);
}
