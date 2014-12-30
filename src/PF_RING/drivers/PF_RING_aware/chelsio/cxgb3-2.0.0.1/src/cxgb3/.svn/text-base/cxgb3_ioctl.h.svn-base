/*
 * This file is part of the Chelsio T3 Ethernet driver for Linux.
 *
 * Copyright (C) 2003-2009 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

#ifndef __CHIOCTL_H__
#define __CHIOCTL_H__

#ifndef AUTOCONF_INCLUDED
#include <linux/autoconf.h>
#endif

/*
 * Ioctl commands specific to this driver.
 */
enum {
	CHELSIO_SETREG			= 1024,
	CHELSIO_GETREG 			= 1025,
	CHELSIO_SETTPI 			= 1026,
	CHELSIO_GETTPI 			= 1027,
	CHELSIO_DEVUP 			= 1028,
	CHELSIO_GETMTUTAB 		= 1029,
	CHELSIO_SETMTUTAB 		= 1030,
	CHELSIO_GETMTU 			= 1031,
	CHELSIO_SET_PM 			= 1032,
	CHELSIO_GET_PM			= 1033,
	CHELSIO_GET_TCAM		= 1034,
	CHELSIO_SET_TCAM		= 1035,
	CHELSIO_GET_TCB			= 1036,
	CHELSIO_READ_TCAM_WORD		= 1037,
	CHELSIO_GET_MEM			= 1038,
	CHELSIO_GET_SGE_CONTEXT		= 1039,
	CHELSIO_GET_SGE_DESC		= 1040,
	CHELSIO_LOAD_FW			= 1041,
	CHELSIO_GET_PROTO		= 1042,
	CHELSIO_SET_PROTO		= 1043,
	CHELSIO_SET_TRACE_FILTER	= 1044,
	CHELSIO_SET_QSET_PARAMS		= 1045,
	CHELSIO_GET_QSET_PARAMS		= 1046,
	CHELSIO_SET_QSET_NUM		= 1047,
	CHELSIO_GET_QSET_NUM		= 1048,
	CHELSIO_SET_PKTSCHED		= 1049,
	CHELSIO_SET_HW_SCHED		= 1051,
	CHELSIO_LOAD_BOOT		= 1054,
	CHELSIO_CLEAR_STATS             = 1055,
	CHELSIO_GET_UP_LA		= 1056,
	CHELSIO_GET_UP_IOQS		= 1057,
	CHELSIO_GET_TRACE_FILTER	= 1058,

	CHELSIO_SET_FILTER		= 1060,
	CHELSIO_DEL_FILTER		= 1061,
	CHELSIO_SET_OFLD_POLICY		= 1062,
	CHELSIO_GET_PKTSCHED            = 1065,
};

/* statistics categories */
enum {
	STATS_PORT  = 1 << 1,
	STATS_QUEUE = 1 << 2,
};
 
struct ch_reg {
	uint32_t cmd;
	uint32_t addr;
	uint32_t val;
};

struct ch_cntxt {
	uint32_t cmd;
	uint32_t cntxt_type;
	uint32_t cntxt_id;
	uint32_t data[4];
};

/* context types */
enum { CNTXT_TYPE_EGRESS, CNTXT_TYPE_FL, CNTXT_TYPE_RSP, CNTXT_TYPE_CQ };

struct ch_desc {
	uint32_t cmd;
	uint32_t queue_num;
	uint32_t idx;
	uint32_t size;
	uint8_t  data[128];
};

struct ch_mem_range {
	uint32_t cmd;
	uint32_t mem_id;
	uint32_t addr;
	uint32_t len;
	uint32_t version;
	uint8_t  buf[0];
};

enum { MEM_CM, MEM_PMRX, MEM_PMTX };   /* ch_mem_range.mem_id values */

struct ch_qset_params {
	uint32_t cmd;
	uint32_t qset_idx;
	int32_t  txq_size[3];
	int32_t  rspq_size;
	int32_t  fl_size[2];
	int32_t  intr_lat;
	int32_t  polling;
	int32_t  lro;
	int32_t  cong_thres;
	int32_t  vector;
	int32_t  qnum;
};

struct ch_pktsched_params {
	uint32_t cmd;
	uint8_t  sched;
	uint8_t  idx;
	uint8_t  min;
	uint8_t  max;
	uint8_t  binding;
};

enum {
	PKTSCHED_PORT = 0,
	PKTSCHED_TUNNELQ =1,
};

struct ch_hw_sched {
	uint32_t cmd;
	uint8_t  sched;
	int8_t   mode;
	int8_t   channel;
	int32_t  kbps;        /* rate in Kbps */
	int32_t  class_ipg;   /* tenths of nanoseconds */
	int32_t  flow_ipg;    /* usec */
};

struct ch_filter_tuple {
	uint32_t sip;
	uint32_t dip;
	uint16_t sport;
	uint16_t dport;
	uint16_t vlan:12;
	uint16_t vlan_prio:3;
};

struct ch_filter {
	uint32_t cmd;
	uint32_t filter_id;
	struct ch_filter_tuple val;
	struct ch_filter_tuple mask;
	uint16_t mac_addr_idx;
	uint8_t mac_hit:1;
	uint8_t proto:2;

	uint8_t want_filter_id:1; /* report filter TID instead of RSS hash */
	uint8_t pass:1;           /* whether to pass or drop packets */
	uint8_t rss:1;            /* use RSS or specified qset */
	uint8_t qset;
};

#ifndef TCB_SIZE
# define TCB_SIZE   128
#endif

/* TCB size in 32-bit words */
#define TCB_WORDS (TCB_SIZE / 4)

struct ch_mtus {
	uint32_t cmd;
	uint32_t nmtus;
	uint16_t mtus[NMTUS];
};

struct ch_pm {
	uint32_t cmd;
	uint32_t tx_pg_sz;
	uint32_t tx_num_pg;
	uint32_t rx_pg_sz;
	uint32_t rx_num_pg;
	uint32_t pm_total;
};

struct ch_tcam {
	uint32_t cmd;
	uint32_t tcam_size;
	uint32_t nservers;
	uint32_t nroutes;
	uint32_t nfilters;
};

struct ch_tcb {
	uint32_t cmd;
	uint32_t tcb_index;
	uint32_t tcb_data[TCB_WORDS];
};

struct ch_tcam_word {
	uint32_t cmd;
	uint32_t addr;
	uint32_t buf[3];
};

struct ch_trace {
	uint32_t cmd;
	uint32_t sip;
	uint32_t sip_mask;
	uint32_t dip;
	uint32_t dip_mask;
	uint16_t sport;
	uint16_t sport_mask;
	uint16_t dport;
	uint16_t dport_mask;
	uint32_t vlan:12;
	uint32_t vlan_mask:12;
	uint32_t intf:4;
	uint32_t intf_mask:4;
	uint8_t  proto;
	uint8_t  proto_mask;
	uint8_t  invert_match:1;
	uint8_t  config_tx:1;
	uint8_t  config_rx:1;
	uint8_t  trace_tx:1;
	uint8_t  trace_rx:1;
};

struct ch_up_la {
	uint32_t cmd;
	uint32_t stopped;
	uint32_t idx;
	uint32_t bufsize;
	u8 *data;
};

struct ch_up_ioqs {
	uint32_t cmd;
	uint32_t ioq_rx_enable;
	uint32_t ioq_tx_enable;
	uint32_t ioq_rx_status;
	uint32_t ioq_tx_status;
	uint32_t bufsize;
	u8 *data;
};

#define SIOCCHIOCTL SIOCDEVPRIVATE

#endif
