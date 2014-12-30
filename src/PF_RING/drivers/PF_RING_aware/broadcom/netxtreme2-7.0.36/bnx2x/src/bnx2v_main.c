/* bnx2v_main.c: Broadcom Everest chips family VF KVM network
 *               driver.
 *
 * Copyright (c) 2007-2011 Broadcom Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation.
 *
 * Maintained by: Eilon Greenstein <eilong@broadcom.com>
 * Written by: Vlad Zolotarov <vladz@broadcom.com>
 *
 *
 */

#include <linux/version.h>
#include <linux/module.h>
#if (LINUX_VERSION_CODE >= 0x020600) /* BNX2X_UPSTREAM */
#include <linux/moduleparam.h>
#endif
#include <linux/kernel.h>
#if (LINUX_VERSION_CODE >= 0x020600) /* BNX2X_UPSTREAM */
#include <linux/device.h>  /* for dev_info() */
#endif
#include <linux/timer.h>
#include <linux/errno.h>
#include <linux/ioport.h>
#include <linux/slab.h>
#include <linux/interrupt.h>
#include <linux/pci.h>
#include <linux/init.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#if (LINUX_VERSION_CODE >= 0x020600) /* BNX2X_UPSTREAM */
#include <linux/dma-mapping.h>
#endif
#include <linux/bitops.h>
#include <linux/irq.h>
#include <linux/delay.h>
#include <asm/byteorder.h>
#include <linux/time.h>
#include <linux/ethtool.h>
#include <linux/mii.h>
#include <linux/if_vlan.h>
#include <net/ip.h>
#if (LINUX_VERSION_CODE < 0x020600) /* ! BNX2X_UPSTREAM */
#include <net/ipv6.h>
#endif
#include <net/tcp.h>
#include <net/checksum.h>
#if (LINUX_VERSION_CODE > 0x020607) /* BNX2X_UPSTREAM */
#include <net/ip6_checksum.h>
#endif
#if (LINUX_VERSION_CODE >= 0x020600) /* BNX2X_UPSTREAM */
#include <linux/workqueue.h>
#endif
#include <linux/crc32.h>
#if (LINUX_VERSION_CODE >= 0x02061b) && !defined(BNX2X_DRIVER_DISK) && !defined(__VMKLNX__) /* BNX2X_UPSTREAM */
#include <linux/crc32c.h>
#endif
#include <linux/prefetch.h>
#include <linux/zlib.h>
#if (LINUX_VERSION_CODE >= 0x020618) /* BNX2X_UPSTREAM */
#include <linux/io.h>
#else
#include <asm/io.h>
#endif
#if defined(BNX2X_UPSTREAM) && !defined(BNX2X_USE_INIT_VALUES) /* BNX2X_UPSTREAM */
#include <linux/stringify.h>
#endif

#if (LINUX_VERSION_CODE < 0x020600) /* ! BNX2X_UPSTREAM */
#define __NO_TPA__		1
#endif


#include "bnx2x.h"
#include "bnx2x_cmn.h"
#include "bnx2x_init.h"
#include "bnx2x_dump.h"
#include "bnx2x_vfpf.h"

#ifdef BCM_IOV /* ! BNX2X_UPSTREAM */
#include "bnx2x_sriov.h"
#endif

#define DRV_MODULE_VERSION	"1.53.13"

#define DRV_MODULE_RELDATE	"$DateTime$"
#define BNX2X_BC_VER		0x040200


#define TX_TIMEOUT		(5*HZ)
#define BNX2V_NUM_TESTS         1

static char version[] __devinitdata =
	"Broadcom NetXtreme II 5771x 10Gigabit Ethernet Driver "
	DRV_MODULE_NAME " " DRV_MODULE_VERSION " (" DRV_MODULE_RELDATE ")\n";

MODULE_AUTHOR("Vlad Zolotarov");
MODULE_DESCRIPTION("Broadcom NetXtreme II "
		   "57712/57712E/57713/57713E Driver");
MODULE_LICENSE("GPL");
MODULE_VERSION(DRV_MODULE_VERSION);

#ifndef BNX2X_UPSTREAM /* ! BNX2X_UPSTREAM */
#if (LINUX_VERSION_CODE >= 0x020600) /* ! BNX2X_UPSTREAM */
MODULE_INFO(cvs_version, "$Revision$");
#endif
#endif

static int multi_mode = 0;
module_param(multi_mode, int, 0);

MODULE_PARM_DESC(multi_mode, " Multi queue mode "
			     "(0 Disable; 1 Enable (default))");
int num_queues = 1;
module_param(num_queues, int, 0);
MODULE_PARM_DESC(num_queues, " Number of queues for multi_mode=1"
				" (default is as a number of CPUs)");

#if defined(__NO_TPA__)
int disable_tpa = 1;
#else /* BNX2X_UPSTREAM */
int disable_tpa;
module_param(disable_tpa, int, 0);
MODULE_PARM_DESC(disable_tpa, " Disable the TPA (LRO) feature");
#endif

int int_mode;
#if (LINUX_VERSION_CODE >= 0x020600) /* BNX2X_UPSTREAM */
module_param(int_mode, int, 0);
MODULE_PARM_DESC(int_mode, " Force interrupt mode (1 INT#x; 2 MSI)");
#endif

static int dropless_fc;
#if (LINUX_VERSION_CODE >= 0x020600) /* BNX2X_UPSTREAM */
module_param(dropless_fc, int, 0);
MODULE_PARM_DESC(dropless_fc, " Pause on exhausted host ring");
#endif

static int poll;
#if (LINUX_VERSION_CODE >= 0x020600) /* BNX2X_UPSTREAM */
module_param(poll, int, 0);
MODULE_PARM_DESC(poll, " Use polling (for debug)");
#endif

static int mrrs = -1;
#if (LINUX_VERSION_CODE >= 0x020600) /* BNX2X_UPSTREAM */
module_param(mrrs, int, 0);
MODULE_PARM_DESC(mrrs, " Force Max Read Req Size (0..3) (for debug)");
#endif

static int debug;
#if (LINUX_VERSION_CODE >= 0x020600) /* BNX2X_UPSTREAM */
module_param(debug, int, 0);
MODULE_PARM_DESC(debug, " Default debug msglevel");
#endif

static int pfc_enabled = 0;
#if (LINUX_VERSION_CODE >= 0x020600) /* BNX2X_UPSTREAM */
module_param(pfc_enabled, int, 0);
MODULE_PARM_DESC(pfc_enabled, " Enables PFC");
#endif

static int pfc_priority_nw = LLFC_TRAFFIC_TYPE_TO_PRIORITY_UNMAPPED;
#if (LINUX_VERSION_CODE >= 0x020600) /* BNX2X_UPSTREAM */
module_param(pfc_priority_nw, int, 0);
MODULE_PARM_DESC(pfc_priority_nw, " PFC priority for NW (0..7)");
#endif

static int pfc_priority_iscsi = LLFC_TRAFFIC_TYPE_TO_PRIORITY_UNMAPPED;
#if (LINUX_VERSION_CODE >= 0x020600) /* BNX2X_UPSTREAM */
module_param(pfc_priority_iscsi, int, 0);
MODULE_PARM_DESC(pfc_priority_iscsi, " PFC priority for iSCSI (0..7)");
#endif

static int pfc_priority_fcoe = LLFC_TRAFFIC_TYPE_TO_PRIORITY_UNMAPPED;
#if (LINUX_VERSION_CODE >= 0x020600) /* BNX2X_UPSTREAM */
module_param(pfc_priority_fcoe, int, 0);
MODULE_PARM_DESC(pfc_priority_fcoe, " PFC priority for FCoE (0..7)");
#endif

static int pfc_non_pauseable_mask = 0;
#if (LINUX_VERSION_CODE >= 0x020600) /* BNX2X_UPSTREAM */
module_param(pfc_non_pauseable_mask, int, 0);
MODULE_PARM_DESC(pfc_non_pauseable_mask, " PFC priority non pauseable mask (0..0xFFFF)");
#endif

#ifdef BCM_IOV	/* ! BNX2X_UPSTREAM */
static int num_vfs;
module_param(num_vfs, int, 0);
MODULE_PARM_DESC(num_vfs, " Number of supported virtual functions "
				"(0 means sriov is disabled)");
#endif

enum bnx2x_board_type {
	BCM57712VF
};

/* indexed by board_type, above */
static struct {
	char *name;
} board_info[] __devinitdata = {
	{ "Broadcom NetXtreme II BCM57712 VF XGb" }
};

#ifndef PCI_DEVICE_ID_NX2_57712VF
#define PCI_DEVICE_ID_NX2_57712VF		0x166F
#endif

static const struct pci_device_id bnx2x_pci_tbl[] = {
	{ PCI_VDEVICE(BROADCOM, PCI_DEVICE_ID_NX2_57712VF), BCM57712VF },
	{ 0 }
};

MODULE_DEVICE_TABLE(pci, bnx2x_pci_tbl);

#ifndef CONFIG_PCI_MSI
#error "VFs are not supported without MSI-X support"
#endif

/* Fills the header setting the response right after the request */
#define FILL_VFPF_MSG_HDR(req, op) \
	do { \
		(req)->hdr.if_ver = PFVF_IF_VERSION; \
		(req)->hdr.opcode = PFVF_OP_##op; \
		(req)->hdr.opcode_ver = PFVF_##op##_VER; \
		(req)->hdr.resp_msg_offset = sizeof(*(req)); \
	} while (0)

/**
 * - Clears mbox first VF2PF_MBOX_SIZE bytes.
 * - Fills the header setting the response right after the
 *    request.
 */
#define PREP_VFPF_MSG(bp, req, op) \
	do { \
		memset(bp->vf2pf_mbox, 0, VF2PF_MBOX_SIZE); \
		FILL_VFPF_MSG_HDR(req, op); \
	} while (0)

/****************************************************************************
* General service functions
****************************************************************************/

static inline void __storm_memset_dma_mapping(struct bnx2x *bp,
				       u32 addr, dma_addr_t mapping)
{
	REG_WR(bp,  addr, U64_LO(mapping));
	REG_WR(bp,  addr + 4, U64_HI(mapping));
}

static inline void __storm_memset_fill(struct bnx2x *bp,
				       u32 addr, size_t size, u32 val)
{
	int i;
	for (i = 0; i < size/4; i++)
		REG_WR(bp,  addr + (i * 4), val);
}

static inline void storm_memset_ustats_zero(struct bnx2x *bp,
					    u8 port, u16 stat_id)
{
	size_t size = sizeof(struct ustorm_per_client_stats);

	u32 addr = BAR_USTRORM_INTMEM +
			USTORM_PER_COUNTER_ID_STATS_OFFSET(port, stat_id);

	__storm_memset_fill(bp, addr, size, 0);
}

static inline void storm_memset_tstats_zero(struct bnx2x *bp,
					    u8 port, u16 stat_id)
{
	size_t size = sizeof(struct tstorm_per_client_stats);

	u32 addr = BAR_TSTRORM_INTMEM +
			TSTORM_PER_COUNTER_ID_STATS_OFFSET(port, stat_id);

	__storm_memset_fill(bp, addr, size, 0);
}

static inline void storm_memset_xstats_zero(struct bnx2x *bp,
					    u8 port, u16 stat_id)
{
	size_t size = sizeof(struct xstorm_per_client_stats);

	u32 addr = BAR_XSTRORM_INTMEM +
			XSTORM_PER_COUNTER_ID_STATS_OFFSET(port, stat_id);

	__storm_memset_fill(bp, addr, size, 0);
}

static inline void storm_memset_spq_addr(struct bnx2x *bp,
					 dma_addr_t mapping, u16 abs_fid)
{
	u32 addr = XSEM_REG_FAST_MEMORY +
			XSTORM_SPQ_PAGE_BASE_OFFSET(abs_fid);

	__storm_memset_dma_mapping(bp, addr, mapping);
}

static inline void storm_memset_xstats_addr(struct bnx2x *bp,
					   dma_addr_t mapping, u16 abs_fid)
{
	u32 addr = BAR_XSTRORM_INTMEM +
		XSTORM_ETH_STATS_QUERY_ADDR_OFFSET(abs_fid);

	__storm_memset_dma_mapping(bp, addr, mapping);
}

static inline void storm_memset_tstats_addr(struct bnx2x *bp,
					   dma_addr_t mapping, u16 abs_fid)
{
	u32 addr = BAR_TSTRORM_INTMEM +
		TSTORM_ETH_STATS_QUERY_ADDR_OFFSET(abs_fid);

	__storm_memset_dma_mapping(bp, addr, mapping);
}

static inline void storm_memset_ustats_addr(struct bnx2x *bp,
					   dma_addr_t mapping, u16 abs_fid)
{
	u32 addr = BAR_USTRORM_INTMEM +
		USTORM_ETH_STATS_QUERY_ADDR_OFFSET(abs_fid);

	__storm_memset_dma_mapping(bp, addr, mapping);
}

static inline void storm_memset_cstats_addr(struct bnx2x *bp,
					   dma_addr_t mapping, u16 abs_fid)
{
	u32 addr = BAR_CSTRORM_INTMEM +
		CSTORM_ETH_STATS_QUERY_ADDR_OFFSET(abs_fid);

	__storm_memset_dma_mapping(bp, addr, mapping);
}

static inline void storm_memset_vf_to_pf(struct bnx2x *bp, u16 abs_fid,
					 u16 pf_id)
{
	REG_WR8(bp, BAR_XSTRORM_INTMEM + XSTORM_VF_TO_PF_OFFSET(abs_fid),
		pf_id);
	REG_WR8(bp, BAR_CSTRORM_INTMEM + CSTORM_VF_TO_PF_OFFSET(abs_fid),
		pf_id);
	REG_WR8(bp, BAR_TSTRORM_INTMEM + TSTORM_VF_TO_PF_OFFSET(abs_fid),
		pf_id);
	REG_WR8(bp, BAR_USTRORM_INTMEM + USTORM_VF_TO_PF_OFFSET(abs_fid),
		pf_id);
}

static inline void storm_memset_func_en(struct bnx2x *bp, u16 abs_fid,
					u8 enable)
{
	REG_WR8(bp, BAR_XSTRORM_INTMEM + XSTORM_FUNC_EN_OFFSET(abs_fid),
		enable);
	REG_WR8(bp, BAR_CSTRORM_INTMEM + CSTORM_FUNC_EN_OFFSET(abs_fid),
		enable);
	REG_WR8(bp, BAR_TSTRORM_INTMEM + TSTORM_FUNC_EN_OFFSET(abs_fid),
		enable);
	REG_WR8(bp, BAR_USTRORM_INTMEM + USTORM_FUNC_EN_OFFSET(abs_fid),
		enable);
}



#if 0
static int bnx2x_mc_assert(struct bnx2x *bp)
{
	char last_idx;
	int i, rc = 0;
	u32 row0, row1, row2, row3;

	/* XSTORM */
	last_idx = REG_RD8(bp, BAR_XSTRORM_INTMEM +
			   XSTORM_ASSERT_LIST_INDEX_OFFSET);
	if (last_idx)
		BNX2X_ERR("XSTORM_ASSERT_LIST_INDEX 0x%x\n", last_idx);

	/* print the asserts */
	for (i = 0; i < STROM_ASSERT_ARRAY_SIZE; i++) {

		row0 = REG_RD(bp, BAR_XSTRORM_INTMEM +
			      XSTORM_ASSERT_LIST_OFFSET(i));
		row1 = REG_RD(bp, BAR_XSTRORM_INTMEM +
			      XSTORM_ASSERT_LIST_OFFSET(i) + 4);
		row2 = REG_RD(bp, BAR_XSTRORM_INTMEM +
			      XSTORM_ASSERT_LIST_OFFSET(i) + 8);
		row3 = REG_RD(bp, BAR_XSTRORM_INTMEM +
			      XSTORM_ASSERT_LIST_OFFSET(i) + 12);

		if (row0 != COMMON_ASM_INVALID_ASSERT_OPCODE) {
			BNX2X_ERR("XSTORM_ASSERT_INDEX 0x%x = 0x%08x"
				  " 0x%08x 0x%08x 0x%08x\n",
				  i, row3, row2, row1, row0);
			rc++;
		} else {
			break;
		}
	}

	/* TSTORM */
	last_idx = REG_RD8(bp, BAR_TSTRORM_INTMEM +
			   TSTORM_ASSERT_LIST_INDEX_OFFSET);
	if (last_idx)
		BNX2X_ERR("TSTORM_ASSERT_LIST_INDEX 0x%x\n", last_idx);

	/* print the asserts */
	for (i = 0; i < STROM_ASSERT_ARRAY_SIZE; i++) {

		row0 = REG_RD(bp, BAR_TSTRORM_INTMEM +
			      TSTORM_ASSERT_LIST_OFFSET(i));
		row1 = REG_RD(bp, BAR_TSTRORM_INTMEM +
			      TSTORM_ASSERT_LIST_OFFSET(i) + 4);
		row2 = REG_RD(bp, BAR_TSTRORM_INTMEM +
			      TSTORM_ASSERT_LIST_OFFSET(i) + 8);
		row3 = REG_RD(bp, BAR_TSTRORM_INTMEM +
			      TSTORM_ASSERT_LIST_OFFSET(i) + 12);

		if (row0 != COMMON_ASM_INVALID_ASSERT_OPCODE) {
			BNX2X_ERR("TSTORM_ASSERT_INDEX 0x%x = 0x%08x"
				  " 0x%08x 0x%08x 0x%08x\n",
				  i, row3, row2, row1, row0);
			rc++;
		} else {
			break;
		}
	}

	/* CSTORM */
	last_idx = REG_RD8(bp, BAR_CSTRORM_INTMEM +
			   CSTORM_ASSERT_LIST_INDEX_OFFSET);
	if (last_idx)
		BNX2X_ERR("CSTORM_ASSERT_LIST_INDEX 0x%x\n", last_idx);

	/* print the asserts */
	for (i = 0; i < STROM_ASSERT_ARRAY_SIZE; i++) {

		row0 = REG_RD(bp, BAR_CSTRORM_INTMEM +
			      CSTORM_ASSERT_LIST_OFFSET(i));
		row1 = REG_RD(bp, BAR_CSTRORM_INTMEM +
			      CSTORM_ASSERT_LIST_OFFSET(i) + 4);
		row2 = REG_RD(bp, BAR_CSTRORM_INTMEM +
			      CSTORM_ASSERT_LIST_OFFSET(i) + 8);
		row3 = REG_RD(bp, BAR_CSTRORM_INTMEM +
			      CSTORM_ASSERT_LIST_OFFSET(i) + 12);

		if (row0 != COMMON_ASM_INVALID_ASSERT_OPCODE) {
			BNX2X_ERR("CSTORM_ASSERT_INDEX 0x%x = 0x%08x"
				  " 0x%08x 0x%08x 0x%08x\n",
				  i, row3, row2, row1, row0);
			rc++;
		} else {
			break;
		}
	}

	/* USTORM */
	last_idx = REG_RD8(bp, BAR_USTRORM_INTMEM +
			   USTORM_ASSERT_LIST_INDEX_OFFSET);
	if (last_idx)
		BNX2X_ERR("USTORM_ASSERT_LIST_INDEX 0x%x\n", last_idx);

	/* print the asserts */
	for (i = 0; i < STROM_ASSERT_ARRAY_SIZE; i++) {

		row0 = REG_RD(bp, BAR_USTRORM_INTMEM +
			      USTORM_ASSERT_LIST_OFFSET(i));
		row1 = REG_RD(bp, BAR_USTRORM_INTMEM +
			      USTORM_ASSERT_LIST_OFFSET(i) + 4);
		row2 = REG_RD(bp, BAR_USTRORM_INTMEM +
			      USTORM_ASSERT_LIST_OFFSET(i) + 8);
		row3 = REG_RD(bp, BAR_USTRORM_INTMEM +
			      USTORM_ASSERT_LIST_OFFSET(i) + 12);

		if (row0 != COMMON_ASM_INVALID_ASSERT_OPCODE) {
			BNX2X_ERR("USTORM_ASSERT_INDEX 0x%x = 0x%08x"
				  " 0x%08x 0x%08x 0x%08x\n",
				  i, row3, row2, row1, row0);
			rc++;
		} else {
			break;
		}
	}

	return rc;
}

#endif

#if 0
static void bnx2x_panic_dump(struct bnx2x *bp)
{
	int i;
	u16 j, start, end;

	bp->stats_state = STATS_STATE_DISABLED;
	DP(BNX2X_MSG_STATS, "stats_state - DISABLED\n");

	BNX2X_ERR("begin crash dump -----------------\n");

	/* Indices */
	/* Common */
	BNX2X_ERR("def_c_idx(0x%x)  def_u_idx(0x%x)  def_x_idx(0x%x)"
		  "  def_t_idx(0x%x)  def_att_idx(0x%x)  attn_state(0x%x)"
		  "  spq_prod_idx(0x%x)\n",
		  bp->def_c_idx, bp->def_u_idx, bp->def_x_idx, bp->def_t_idx,
		  bp->def_att_idx, bp->attn_state, bp->spq_prod_idx);
	BNX2X_ERR("DSB: attn bits(0x%x)  ack(0x%x)  id(0x%x)  idx(0x%x)\n",
		  bp->def_status_blk->atten_status_block.attn_bits,
		  bp->def_status_blk->atten_status_block.attn_bits_ack,
		  bp->def_status_blk->atten_status_block.status_block_id,
		  bp->def_status_blk->atten_status_block.attn_bits_index);
	BNX2X_ERR("     u(");
	for (i = 0; i < HC_USTORM_DEF_SB_NUM_INDICES; i++)
		pr_cont("0x%x%s",
		       bp->def_status_blk->u_def_status_block.index_values[i],
		       (i == HC_USTORM_DEF_SB_NUM_INDICES - 1) ? ")  " : " ");
	pr_cont("idx(0x%x)  func(0x%x)  id(0x%x)  vf(0x%x)  "
			 "igu_id(0x%x)  seg(0x%x)\n",
	       bp->def_status_blk->u_def_status_block.status_block_index,
	       bp->def_status_blk->u_def_status_block.func,
	       bp->def_status_blk->u_def_status_block.status_block_id,
	       bp->def_status_blk->u_def_status_block.vf_data,
	       bp->def_status_blk->u_def_status_block.igu_index,
	       bp->def_status_blk->u_def_status_block.segment);
	BNX2X_ERR("     c(");
	for (i = 0; i < HC_CSTORM_DEF_SB_NUM_INDICES; i++)
		pr_cont("0x%x%s",
		       bp->def_status_blk->c_def_status_block.index_values[i],
		       (i == HC_CSTORM_DEF_SB_NUM_INDICES - 1) ? ")  " : " ");
	pr_cont("idx(0x%x)  func(0x%x)  id(0x%x)  vf(0x%x)  "
			 "igu_id(0x%x)  seg(0x%x)\n",
	       bp->def_status_blk->c_def_status_block.status_block_index,
	       bp->def_status_blk->c_def_status_block.func,
	       bp->def_status_blk->c_def_status_block.status_block_id,
	       bp->def_status_blk->c_def_status_block.vf_data,
	       bp->def_status_blk->c_def_status_block.igu_index,
	       bp->def_status_blk->c_def_status_block.segment);
	BNX2X_ERR("     x(");
	for (i = 0; i < HC_XSTORM_DEF_SB_NUM_INDICES; i++)
		pr_cont("0x%x%s",
		       bp->def_status_blk->x_def_status_block.index_values[i],
		       (i == HC_XSTORM_DEF_SB_NUM_INDICES - 1) ? ")  " : " ");
	pr_cont("idx(0x%x)  func(0x%x)  id(0x%x)  vf(0x%x)  "
			 "igu_id(0x%x)  seg(0x%x)\n",
	       bp->def_status_blk->x_def_status_block.status_block_index,
	       bp->def_status_blk->x_def_status_block.func,
	       bp->def_status_blk->x_def_status_block.status_block_id,
	       bp->def_status_blk->x_def_status_block.vf_data,
	       bp->def_status_blk->x_def_status_block.igu_index,
	       bp->def_status_blk->x_def_status_block.segment);
	BNX2X_ERR("     t(");
	for (i = 0; i < HC_TSTORM_DEF_SB_NUM_INDICES; i++)
		pr_cont("0x%x%s",
		       bp->def_status_blk->t_def_status_block.index_values[i],
		       (i == HC_TSTORM_DEF_SB_NUM_INDICES - 1) ? ")  " : " ");
	pr_cont("idx(0x%x)  func(0x%x)  id(0x%x)  vf(0x%x)  "
			 "igu_id(0x%x)  seg(0x%x)\n",
	       bp->def_status_blk->t_def_status_block.status_block_index,
	       bp->def_status_blk->t_def_status_block.func,
	       bp->def_status_blk->t_def_status_block.status_block_id,
	       bp->def_status_blk->t_def_status_block.vf_data,
	       bp->def_status_blk->t_def_status_block.igu_index,
	       bp->def_status_blk->t_def_status_block.segment);

	/* Rx */
	for_each_rx_queue(bp, i) {
		struct bnx2x_fastpath *fp = &bp->fp[i];

		BNX2X_ERR("fp%d: rx_bd_prod(0x%x)  rx_bd_cons(0x%x)"
			  "  rx_comp_prod(0x%x)"
			  "  rx_comp_cons(0x%x)  *rx_cons_sb(0x%x)\n",
			  i, fp->rx_bd_prod, fp->rx_bd_cons,
			  fp->rx_comp_prod,
			  fp->rx_comp_cons, le16_to_cpu(*fp->rx_cons_sb));
		BNX2X_ERR("     rx_sge_prod(0x%x)  last_max_sge(0x%x)"
			  "  fp_u_idx(0x%x) *sb_u_idx(0x%x)\n",
			  fp->rx_sge_prod, fp->last_max_sge,
			  le16_to_cpu(fp->fp_u_idx),
			  fp->status_blk->u_status_block.status_block_index);
		BNX2X_ERR("     u(");
		for (j = 0; j < HC_USTORM_SB_NUM_INDICES; j++)
			pr_cont("0x%x%s",
			       fp->status_blk->u_status_block.index_values[j],
			       (j == HC_USTORM_SB_NUM_INDICES - 1) ? ")" : " ");
		pr_cont("  idx(0x%x)  func(0x%x)  id(0x%x)  vf(0x%x)"
				 "  igu_id(0x%x)  seg(0x%x)\n",
		       fp->status_blk->u_status_block.status_block_index,
		       fp->status_blk->u_status_block.func,
		       fp->status_blk->u_status_block.status_block_id,
		       fp->status_blk->u_status_block.vf_data,
		       fp->status_blk->u_status_block.igu_index,
		       fp->status_blk->u_status_block.segment);
	}

	/* Tx */
	for_each_tx_queue(bp, i) {
		struct bnx2x_fastpath *fp = &bp->fp[i];

		BNX2X_ERR("fp%d: tx_pkt_prod(0x%x)  tx_pkt_cons(0x%x)"
			  "  tx_bd_prod(0x%x)  tx_bd_cons(0x%x)"
			  "  *tx_cons_sb(0x%x)\n",
			  i, fp->tx_pkt_prod, fp->tx_pkt_cons, fp->tx_bd_prod,
			  fp->tx_bd_cons, le16_to_cpu(*fp->tx_cons_sb));
		BNX2X_ERR("     fp_c_idx(0x%x)  *sb_c_idx(0x%x)"
			  "  tx_db_prod(0x%x)\n", le16_to_cpu(fp->fp_c_idx),
			  fp->status_blk->c_status_block.status_block_index,
			  fp->tx_db.data.prod);
		BNX2X_ERR("     c(");
		for (j = 0; j < HC_CSTORM_SB_NUM_INDICES; j++)
			pr_cont("0x%x%s",
			       fp->status_blk->c_status_block.index_values[j],
			       (j == HC_CSTORM_SB_NUM_INDICES - 1) ? ")" : " ");
		pr_cont("  idx(0x%x)  func(0x%x)  id(0x%x)  vf(0x%x)"
				 "  igu_id(0x%x)  seg(0x%x)\n",
		       fp->status_blk->c_status_block.status_block_index,
		       fp->status_blk->c_status_block.func,
		       fp->status_blk->c_status_block.status_block_id,
		       fp->status_blk->c_status_block.vf_data,
		       fp->status_blk->c_status_block.igu_index,
		       fp->status_blk->c_status_block.segment);
	}

	/* Rings */
	/* Rx */
	for_each_rx_queue(bp, i) {
		struct bnx2x_fastpath *fp = &bp->fp[i];

		start = RX_BD(le16_to_cpu(*fp->rx_cons_sb) - 10);
		end = RX_BD(le16_to_cpu(*fp->rx_cons_sb) + 503);
		for (j = start; j != end; j = RX_BD(j + 1)) {
			u32 *rx_bd = (u32 *)&fp->rx_desc_ring[j];
			struct sw_rx_bd *sw_bd = &fp->rx_buf_ring[j];

			BNX2X_ERR("fp%d: rx_bd[%x]=[%x:%x]  sw_bd=[%p]\n",
				  i, j, rx_bd[1], rx_bd[0], sw_bd->skb);
		}

		start = RX_SGE(fp->rx_sge_prod);
		end = RX_SGE(fp->last_max_sge);
		for (j = start; j != end; j = RX_SGE(j + 1)) {
			u32 *rx_sge = (u32 *)&fp->rx_sge_ring[j];
			struct sw_rx_page *sw_page = &fp->rx_page_ring[j];

			BNX2X_ERR("fp%d: rx_sge[%x]=[%x:%x]  sw_page=[%p]\n",
				  i, j, rx_sge[1], rx_sge[0], sw_page->page);
		}

		start = RCQ_BD(fp->rx_comp_cons - 10);
		end = RCQ_BD(fp->rx_comp_cons + 503);
		for (j = start; j != end; j = RCQ_BD(j + 1)) {
			u32 *cqe = (u32 *)&fp->rx_comp_ring[j];

			BNX2X_ERR("fp%d: cqe[%x]=[%x:%x:%x:%x]\n",
				  i, j, cqe[0], cqe[1], cqe[2], cqe[3]);
		}
	}

	/* Tx */
	for_each_tx_queue(bp, i) {
		struct bnx2x_fastpath *fp = &bp->fp[i];

		start = TX_BD(le16_to_cpu(*fp->tx_cons_sb) - 10);
		end = TX_BD(le16_to_cpu(*fp->tx_cons_sb) + 245);
		for (j = start; j != end; j = TX_BD(j + 1)) {
			struct sw_tx_bd *sw_bd = &fp->tx_buf_ring[j];

			BNX2X_ERR("fp%d: packet[%x]=[%p,%x]\n",
				  i, j, sw_bd->skb, sw_bd->first_bd);
		}

		start = TX_BD(fp->tx_bd_cons - 10);
		end = TX_BD(fp->tx_bd_cons + 254);
		for (j = start; j != end; j = TX_BD(j + 1)) {
			u32 *tx_bd = (u32 *)&fp->tx_desc_ring[j];

			BNX2X_ERR("fp%d: tx_bd[%x]=[%x:%x:%x:%x]\n",
				  i, j, tx_bd[0], tx_bd[1], tx_bd[2], tx_bd[3]);
		}
	}

	/* TBD: think about implementing idle_chk for VF */
#ifndef BNX2X_UPSTREAM /* ! BNX2X_UPSTREAM */
	/*bp->msglevel |= NETIF_MSG_PROBE;

	BNX2X_ERR("Idle check (1st round) ----------\n");
	bnx2x_idle_chk(bp);
	BNX2X_ERR("Idle check (2nd round) ----------\n");
	bnx2x_idle_chk(bp); */
#endif
	/* bnx2x_mc_assert(bp);
	BNX2X_ERR("end crash dump -----------------\n"); */
}
#endif

static int bnx2x_send_msg2pf(struct bnx2x *bp, u8 *done, dma_addr_t msg_mapping)
{
	struct cstorm_vf_zone_data *zone_data = REG_ADDR(bp, PXP_VF_ADDR_CSDM_GLOBAL_START);
	int tout = 5000; /* wait for 5 seconds */

	BNX2X_ERR("zone_data start is %p\n", zone_data);
	BNX2X_ERR("non-trigger data is (%p, %p), msg paddr 0x%llx\n",
		  &zone_data->non_trigger.vf_pf_channel.msg_addr_hi,
		  &zone_data->non_trigger.vf_pf_channel.msg_addr_lo, msg_mapping);

	/* Write message address */
	writel(U64_LO(msg_mapping), &zone_data->non_trigger.vf_pf_channel.msg_addr_lo);
	writel(U64_HI(msg_mapping), &zone_data->non_trigger.vf_pf_channel.msg_addr_hi);

	/* Triger the PF FW */
	writeb(1, &zone_data->trigger.vf_pf_channel.addr_valid);

	/* Wait for PF to complete */
	while ((tout--) && (!*done))
		mdelay(1);

	if (!*done) {
		BNX2X_ERR("PF responce has timed out\n");
		return -EAGAIN;
	}

	return 0;
}

static void bnx2x_igu_int_enable(struct bnx2x *bp)
{
	/* Make sure that interrupts are indeed enabled from here on */
	mmiowb();
}

void bnx2x_int_enable(struct bnx2x *bp)
{
	bnx2x_igu_int_enable(bp);
}

static void bnx2x_igu_int_disable(struct bnx2x *bp)
{
	/* Leave it for now, maybe the will see that we need it */
	mmiowb();
}

void bnx2x_int_disable(struct bnx2x *bp)
{
	bnx2x_igu_int_disable(bp);
}

void bnx2x_int_disable_sync(struct bnx2x *bp, int disable_hw)
{
	int msix = (bp->flags & USING_MSIX_FLAG) ? 1 : 0;
	int i, offset = 0;

	if (disable_hw)
		/* prevent the HW from sending interrupts */
		bnx2x_int_disable(bp);

	/* make sure all ISRs are done */
	if (msix) {
#ifdef BCM_CNIC
		offset++;
#endif
		for_each_eth_queue(bp, i)
			synchronize_irq(bp->msix_table[offset++].vector);
	} else
		synchronize_irq(bp->pdev->irq);
}

/* fast path */

#if (LINUX_VERSION_CODE < 0x020613)
irqreturn_t bnx2x_msix_sp_int(int irq, void *dev_instance,
				     struct pt_regs *regs)
#else /* BNX2X_UPSTREAM */
irqreturn_t bnx2x_msix_sp_int(int irq, void *dev_instance)
#endif
{
	pr_err("Should not get here!!!\n");
	BUG();

	return IRQ_HANDLED;
}

int bnx2x_release_leader_lock(struct bnx2x *bp)
{
	/* Do nothing */
	return 0;
}

/*
 * General service functions
 */

int bnx2x_release_hw_lock(struct bnx2x *bp, u32 resource)
{
	/* Do nothing */
	return 0;
}

/**
 * Looks like a good candidate for setting VF link parameters.
 *
 * @param bp
 */
static void bnx2x_fake_link_set(struct bnx2x *bp)
{
	/* fake link up for emulation */
	bp->port.supported |= (SUPPORTED_10baseT_Half |
			       SUPPORTED_10baseT_Full |
			       SUPPORTED_100baseT_Half |
			       SUPPORTED_100baseT_Full |
			       SUPPORTED_1000baseT_Full |
			       SUPPORTED_2500baseX_Full |
			       SUPPORTED_10000baseT_Full |
			       SUPPORTED_TP |
			       SUPPORTED_FIBRE |
			       SUPPORTED_Autoneg |
			       SUPPORTED_Pause |
			       SUPPORTED_Asym_Pause);
	bp->port.advertising = bp->port.supported;

	bp->link_params.bp = bp;
	bp->link_params.port = BP_PORT(bp);
	bp->link_params.req_duplex[0] = DUPLEX_FULL;
	bp->link_params.req_flow_ctrl[0] = BNX2X_FLOW_CTRL_NONE; //????
	bp->link_params.req_line_speed[0] = SPEED_10000;
	bp->link_params.speed_cap_mask[0] = 0x7f0000;
	bp->link_params.switch_cfg = SWITCH_CFG_10G;

	if (CHIP_REV_IS_FPGA(bp) || (CHIP_REV_IS_EMUL(bp) && CHIP_MODE_IS_4_PORT(bp))) {
			bp->link_vars.mac_type = MAC_TYPE_EMAC;
			bp->link_vars.line_speed = SPEED_1000;
			bp->link_vars.link_status = (LINK_STATUS_LINK_UP |
							 LINK_STATUS_SPEED_AND_DUPLEX_1000TFD);

	} else {
			bp->link_vars.mac_type = MAC_TYPE_BMAC;
			bp->link_vars.line_speed = SPEED_10000;
			bp->link_vars.link_status = (LINK_STATUS_LINK_UP |
							 LINK_STATUS_SPEED_AND_DUPLEX_10GTFD);

	}
	bp->link_vars.link_up = 1;

	bp->link_vars.duplex = DUPLEX_FULL;
	bp->link_vars.flow_ctrl = BNX2X_FLOW_CTRL_NONE;

	//bnx2x_stats_handle(bp, STATS_EVENT_LINK_UP);
	bnx2x_link_report(bp);
}

u8 bnx2x_initial_phy_init(struct bnx2x *bp, int load_mode)
{

	bnx2x_fake_link_set(bp);
	return 0;
}

#if 0
static u8 bnx2x_link_test(struct bnx2x *bp)
{
	return 0;
}
#endif

/**
 * Link status of VF can't change, so just report it.
 *
 * @param bp
 */
void bnx2x__link_status_update(struct bnx2x *bp)
{
	if (bp->state != BNX2X_STATE_OPEN)
		return;

	bp->mf_config[BP_VN(bp)] = 0;

	/* indicate link status */
	bnx2x_link_report(bp);
}

/* end of Link */

/*
 * General service functions
 */

/* Statistics */
void bnx2x_stats_handle(struct bnx2x *bp, enum bnx2x_stats_event event)
{
	/* Do nothing at the moment */
}

/* end of Statistics */

/* nic init */

/*
 * nic init service functions
 */

void bnx2x_set_storm_rx_mode(struct bnx2x *bp)
{
	int mode = bp->rx_mode;
	struct vf_pf_msg_set_q_filters *req = bp->vf2pf_mbox;
	struct pf_vf_msg_resp *resp = (struct pf_vf_msg_resp *)((u8*)req + sizeof(*req));
	int rc;

	/* Set the header */
	PREP_VFPF_MSG(bp, req, SET_Q_FILTERS);

	DP(NETIF_MSG_IFUP, "Rx mode is %d\n", mode);

	switch (mode) {
	case BNX2X_RX_MODE_NONE: /* no Rx */
		req->rx_mask = VFPF_RX_MASK_ACCEPT_NONE;
		break;
	case BNX2X_RX_MODE_NORMAL:
		req->rx_mask = VFPF_RX_MASK_ACCEPT_MATCHED_MULTICAST;
		req->rx_mask |= VFPF_RX_MASK_ACCEPT_MATCHED_UNICAST;
		req->rx_mask |= VFPF_RX_MASK_ACCEPT_BROADCAST;
		break;
	case BNX2X_RX_MODE_ALLMULTI:
		req->rx_mask = VFPF_RX_MASK_ACCEPT_ALL_MULTICAST;
		req->rx_mask |= VFPF_RX_MASK_ACCEPT_MATCHED_UNICAST;
		req->rx_mask |= VFPF_RX_MASK_ACCEPT_BROADCAST;
		break;
	case BNX2X_RX_MODE_PROMISC:
		req->rx_mask = VFPF_RX_MASK_ACCEPT_ALL_UNICAST;
		req->rx_mask |= VFPF_RX_MASK_ACCEPT_ALL_MULTICAST;
		req->rx_mask |= VFPF_RX_MASK_ACCEPT_BROADCAST;
		break;
	default:
		BNX2X_ERR("BAD rx mode (%d)\n", mode);
		return;
	}

	req->flags |= VFPF_SET_Q_FILTERS_RX_MASK_CHANGED;
	req->vf_qid = 0;

	rc = bnx2x_send_msg2pf(bp, &resp->hdr.status, bp->vf2pf_mbox_mapping);
	if (rc)
		BNX2X_ERR("Sending a message failed: %d\n", rc);

	if (resp->hdr.status != PFVF_STATUS_SUCCESS)
		BNX2X_ERR("Set Rx mode failed: %d\n", resp->hdr.status);
}

void bnx2x_drv_pulse(struct bnx2x *bp)
{
	/* Do nothing */
}

static void bnx2x_timer(unsigned long data)
{
	struct bnx2x *bp = (struct bnx2x *) data;

	if (!netif_running(bp->dev))
		return;

	if (poll) {
		struct bnx2x_fastpath *fp = &bp->fp[0];
		int rc;

		bnx2x_tx_int(fp);
		rc = bnx2x_rx_int(fp, 1000);
	}
#if 0 /* No MCP pulse and stats in VF at the moment */
	if (!BP_NOMCP(bp)) {
		int mb_idx = BP_FW_MB_IDX(bp);
		u32 drv_pulse;
		u32 mcp_pulse;

		++bp->fw_drv_pulse_wr_seq;
		bp->fw_drv_pulse_wr_seq &= DRV_PULSE_SEQ_MASK;
		/* TBD - add SYSTEM_TIME */
		drv_pulse = bp->fw_drv_pulse_wr_seq;
		SHMEM_WR(bp, func_mb[mb_idx].drv_pulse_mb, drv_pulse);

		mcp_pulse = (SHMEM_RD(bp, func_mb[mb_idx].mcp_pulse_mb) &
			     MCP_PULSE_SEQ_MASK);
		/* The delta between driver pulse and mcp response
		 * should be 1 (before mcp response) or 0 (after mcp response)
		 */
		if ((drv_pulse != mcp_pulse) &&
		    (drv_pulse != ((mcp_pulse + 1) & MCP_PULSE_SEQ_MASK))) {
			/* someone lost a heartbeat... */
			BNX2X_ERR("drv_pulse (0x%x) != mcp_pulse (0x%x)\n",
				  drv_pulse, mcp_pulse);
		}
	}

	if ((bp->state == BNX2X_STATE_OPEN) ||
	    (bp->state == BNX2X_STATE_DISABLED))
		bnx2x_stats_handle(bp, STATS_EVENT_UPDATE);
#endif

	mod_timer(&bp->timer, jiffies + bp->current_interval);
}


void bnx2x_igu_ack_sb(struct bnx2x *bp, u8 igu_sb_id, u8 segment,
		      u16 index, u8 op, u8 update)
{
	u32 igu_addr = PXP_VF_ADDR_IGU_START + (IGU_CMD_INT_ACK_BASE + igu_sb_id)*8;

	bnx2x_igu_ack_sb_gen(bp, igu_sb_id, segment, index, op, update,
			     igu_addr);
}

static int bnx2x_init_sbs(struct bnx2x *bp)
{
	struct vf_pf_msg_init_vf *req = bp->vf2pf_mbox;
	struct pf_vf_msg_resp *resp = (struct pf_vf_msg_resp *)((u8*)req + sizeof(*req));
	int rc, i;

	/* Tell PF about SB addresses */

	/* Set the header */
	PREP_VFPF_MSG(bp, req, INIT_VF);

	for_each_queue(bp, i) {
		req->sb_addr[i] = (unsigned long)bnx2x_fp(bp, i, status_blk_mapping);
		BNX2X_ERR("req->sb_addr[%d]=0x%llx\n", i, req->sb_addr[i]);
	}

	rc = bnx2x_send_msg2pf(bp, &resp->hdr.status, bp->vf2pf_mbox_mapping);
	if (rc)
		return rc;

	if (resp->hdr.status != PFVF_STATUS_SUCCESS) {
		BNX2X_ERR("INIT VF failed: %d. Breaking...\n", resp->hdr.status);
		return -EAGAIN;
	}

	BNX2X_ERR("INIT VF Succeeded\n");

	return 0;
}

/* This function should not be called for FCoE client */
static void bnx2x_init_fp_sb(struct bnx2x *bp, int fp_idx)
{
	struct bnx2x_fastpath *fp = &bp->fp[fp_idx];
	fp->bp = bp;
	fp->index = fp->cid = fp_idx;
	fp->cl_id = -1; /* Not needed to VF ? */
	fp->igu_sb_id = bp->aquire_resp->resc.hw_sbs[fp_idx].hw_sb_id;
	fp->fw_sb_id = -1; /* unused in VF */
	/* Setup SB indicies */
	fp->rx_cons_sb = BNX2X_RX_SB_INDEX;
	fp->tx_cons_sb = BNX2X_TX_SB_INDEX;

	DP(NETIF_MSG_IFUP, "queue[%d]:  bnx2x_init_sb(%p,%p)  "
				   "cl_id %d  sb %d\n",
		   fp_idx, bp, fp->status_blk.e2_sb, fp->cl_id, fp->igu_sb_id);

	bnx2x_update_fpsb_idx(fp);
}

static void bnx2x_send_setup_q(struct bnx2x *bp, int fp_idx)
{
	struct vf_pf_msg_setup_q *req = bp->vf2pf_mbox;
	struct pf_vf_msg_resp *resp = (struct pf_vf_msg_resp *)((u8*)req + sizeof(*req));
	struct bnx2x_fastpath *fp = &bp->fp[fp_idx];
	u16 tpa_agg_size = 0, flags = 0;
	int rc;

	if (!fp->disable_tpa) {
		tpa_agg_size = min_t(u32,
			(min_t(u32, 8, MAX_SKB_FRAGS) *
			SGE_PAGE_SIZE * PAGES_PER_SGE), 0xffff);
		flags |= VFPF_QUEUE_FLG_TPA;
	}

	/* calculate queue flags */
	flags |= VFPF_QUEUE_FLG_CACHE_ALIGN;
	flags |= IS_MF_SD(bp) ? VFPF_QUEUE_FLG_OV : 0;

#if defined(BCM_VLAN) || !defined(OLD_VLAN) /* BNX2X_UPSTREAM */
	flags |= VFPF_QUEUE_FLG_VLAN;
	DP(NETIF_MSG_IFUP, "vlan removal enabled\n");
#endif
	/* Set the header */
	PREP_VFPF_MSG(bp, req, SETUP_Q);

	/* Common */
	req->vf_qid = fp_idx;
	req->param_valid = VFPF_RXQ_VALID | VFPF_TXQ_VALID;

	/* Rx */
	req->rxq.rcq_addr = fp->rx_comp_mapping;
	BNX2X_ERR("req->rxq.rcq_addr=0x%llx\n", req->rxq.rcq_addr);
	req->rxq.rcq_np_addr = fp->rx_comp_mapping + BCM_PAGE_SIZE;
	req->rxq.rxq_addr = fp->rx_desc_mapping;
	BNX2X_ERR("req->rxq.rxq_addr=0x%llx\n", req->rxq.rxq_addr);
	req->rxq.sge_addr = fp->rx_sge_mapping;
	BNX2X_ERR("req->rxq.sge_addr=0x%llx\n", req->rxq.sge_addr);

	req->rxq.vf_sb = fp_idx;
	req->rxq.sb_index = HC_INDEX_ETH_RX_CQ_CONS;
	req->rxq.hc_rate = 1000000/bp->rx_ticks; /* interrupts/sec */

	req->rxq.mtu = bp->dev->mtu;
	req->rxq.buf_sz = bp->rx_buf_size;
	req->rxq.sge_buf_sz = BCM_PAGE_SIZE * PAGES_PER_SGE;
	req->rxq.tpa_agg_sz = tpa_agg_size;
	req->rxq.max_sge_pkt = SGE_PAGE_ALIGN(bp->dev->mtu) >> SGE_PAGE_SHIFT;
	req->rxq.max_sge_pkt = ((req->rxq.max_sge_pkt + PAGES_PER_SGE - 1) &
			  (~(PAGES_PER_SGE-1))) >> PAGES_PER_SGE_SHIFT;
	BNX2X_ERR("req->rxq.tpa_agg_sz=0x%x\n", req->rxq.tpa_agg_sz);
	req->rxq.flags = flags;
	req->rxq.drop_flags = 0;
	req->rxq.cache_line_log = BNX2X_RX_ALIGN_SHIFT;
	req->rxq.stat_id = -1; /* No stats at the moment */

	/* Tx */
	req->txq.txq_addr = fp->tx_desc_mapping;
	BNX2X_ERR("req->txq.txq_addr=0x%llx\n", req->txq.txq_addr);
	req->txq.vf_sb = fp_idx;
	req->txq.sb_index = C_SB_ETH_TX_CQ_INDEX;
	req->txq.hc_rate = 1000000/bp->tx_ticks; /* interrupts/sec */
	req->txq.flags = flags;
	req->txq.traffic_type = LLFC_TRAFFIC_TYPE_NW;


	rc = bnx2x_send_msg2pf(bp, &resp->hdr.status, bp->vf2pf_mbox_mapping);
	if (rc)
		BNX2X_ERR("Sending SETUP_Q message for queue[%d] failed!\n",
			  fp_idx);

	if (resp->hdr.status != PFVF_STATUS_SUCCESS)
		BNX2X_ERR("Status of SETUP_Q for queue[%d] is %d\n",
			  fp_idx, resp->hdr.status);
}

void bnx2x_nic_init(struct bnx2x *bp, u32 load_code)
{
	int i;

	/* Setup status blocks */
	for_each_eth_queue(bp, i)
		bnx2x_init_fp_sb(bp, i);

	/* ensure status block indices were read */
	rmb();

	bnx2x_init_rx_rings(bp);
	bnx2x_init_tx_rings(bp);

	/* SETUP_Q goes here: Tell PF about Rx and Tx rings */
	for_each_eth_queue(bp, i)
		bnx2x_send_setup_q(bp, i);

	/* flush all before enabling interrupts */
	mb();
	mmiowb();

	bnx2x_int_enable(bp);
}

/* end of nic init */

/*
 * General service functions
 */

#if 0
/* send a NIG loopback debug packet */
static void bnx2x_lb_pckt(struct bnx2x *bp)
{
	u32 wb_write[3];

	/* Ethernet source and destination addresses */
	wb_write[0] = 0x55555555;
	wb_write[1] = 0x55555555;
	wb_write[2] = 0x20;		/* SOP */
	REG_WR_DMAE(bp, NIG_REG_DEBUG_PACKET_LB, wb_write, 3);

	/* NON-IP protocol */
	wb_write[0] = 0x09000000;
	wb_write[1] = 0x55555555;
	wb_write[2] = 0x10;		/* EOP, eop_bvalid = 0 */
	REG_WR_DMAE(bp, NIG_REG_DEBUG_PACKET_LB, wb_write, 3);
}
#endif

void bnx2x_free_mem(struct bnx2x *bp)
{
#ifdef BCM_CNIC
	void *p;
#endif

	/* fastpath */
	bnx2x_free_fp_mem(bp);
	/* end of fastpath */

#ifdef BCM_CNIC
	p  = CHIP_IS_E1x(bp) ? (void*)( bp->cnic_sb.e1x_sb) : (void*)(bp->cnic_sb.e2_sb);
	BNX2X_PCI_FREE(p,
		       bp->cnic_sb_mapping,
		       CHIP_IS_E1x(bp) ?
		       sizeof(struct host_hc_status_block_e1x) :
		       sizeof(struct host_hc_status_block_e2))

	BNX2X_PCI_FREE(bp->t2, bp->t2_mapping, SRC_T2_SZ);
#endif
}

int bnx2x_alloc_mem(struct bnx2x *bp)
{
	/* fastpath */
	if (bnx2x_alloc_fp_mem(bp))
		goto alloc_mem_err;

	/* end of fastpath */

#ifdef BCM_CNIC
	if (CHIP_IS_E1x(bp))
		BNX2X_PCI_ALLOC(bp->cnic_sb.e1x_sb, &bp->cnic_sb_mapping,
				sizeof(struct host_hc_status_block_e1x));
	else
		BNX2X_PCI_ALLOC(bp->cnic_sb.e2_sb, &bp->cnic_sb_mapping,
				sizeof(struct host_hc_status_block_e2));

	/* allocate searcher T2 table */
	BNX2X_PCI_ALLOC(bp->t2, &bp->t2_mapping, SRC_T2_SZ);
#endif
	/** Send INIT_VF command here: tell PF to update SBs
	 *  addresses in the internal memory */
	if (bnx2x_init_sbs(bp))
		goto alloc_mem_err;

	return 0;

alloc_mem_err:
	bnx2x_free_mem(bp);
	return -ENOMEM;
}

/*
 * Init service functions
 */

static inline void _print_struct(u8 *buf, int size)
{
	int i;

	pr_info("[ ");
	for (i = 0; i < size; i++)
		pr_cont("0x%02x ", *(buf + i));

	pr_cont("]\n");
}

int bnx2x_set_eth_mac(struct bnx2x *bp, bool set)
{
	struct vf_pf_msg_set_q_filters *req = bp->vf2pf_mbox;
	struct pf_vf_msg_resp *resp = (struct pf_vf_msg_resp *)((u8*)req + sizeof(*req));
	int rc;

	/* Set the header */
	PREP_VFPF_MSG(bp, req, SET_Q_FILTERS);

	req->flags = VFPF_SET_Q_FILTERS_MAC_VLAN_CHANGED;
	req->vf_qid = 0;
	req->n_mac_vlan_filters = 1;

	req->filters[0].flags = VFPF_Q_FILTER_DEST_MAC_PRESENT;
	memcpy(req->filters[0].dest_mac, bp->dev->dev_addr,
	       sizeof(req->filters[0].dest_mac));

	BNX2X_ERR("Setting VF's MAC to:");
	_print_struct(req->filters[0].dest_mac, sizeof(req->filters[0].dest_mac));

	rc = bnx2x_send_msg2pf(bp, &resp->hdr.status, bp->vf2pf_mbox_mapping);
	if (rc) {
		BNX2X_ERR("SET MAC failed: %d\n", rc);
		return rc;
	}

	if (resp->hdr.status != PFVF_STATUS_SUCCESS)
		BNX2X_ERR("SET MAC failed: %d\n", resp->hdr.status);

	return 0;
}

int bnx2x_setup_leading(struct bnx2x *bp)
{
	/* Should already be completed in SETUP_Q */
	bp->state = BNX2X_STATE_OPEN;
	return 0;
}

int bnx2x_setup_queue(struct bnx2x *bp, struct bnx2x_fastpath *fp,
		       int leading)
{
	/* Already done during SETUP_Q */
	return 0;
}

static int __devinit bnx2x_set_int_mode(struct bnx2x *bp)
{
	int rc = 0;

	switch (int_mode) {
	case INT_MODE_INTx:
	case INT_MODE_MSI:
		BNX2X_ERR("Not supporting either INT#x or MSI!\n");
		BUG();
		break;
	default:
		/* Set number of queues according to bp->multi_mode value */
		bnx2x_set_num_queues(bp);

		DP(NETIF_MSG_IFUP, "set number of queues to %d\n", bp->num_queues);

		/* if we can't use MSI-X we only need one fp,
		 * so try to enable MSI-X with the requested number of fp's
		 * and fallback to MSI or legacy INTx with one fp
		 */
		rc = bnx2x_enable_msix(bp);
		if (rc) {
			/* failed to enable MSI-X */
			if (bp->multi_mode)
				BNX2X_ERR("Multi requested but failed to "
					  "enable MSI-X (%d), "
					  "set number of queues to 1\n",
					  bp->num_queues);
			bp->num_queues = 1 + NON_ETH_CONTEXT_USE;
		}
		break;
	}
#ifdef BNX2X_MULTI_QUEUE /* BNX2X_UPSTREAM */
	bp->dev->real_num_tx_queues = bp->num_queues - OOO_CONTEXT_USE;
#endif
	return rc;
}

void bnx2x_ilt_set_info(struct bnx2x *bp)
{
	/* Nothing to do */
}

static inline int bnx2x_teardown_queue(struct bnx2x *bp, int qidx)
{
	struct vf_pf_msg_q_op *req = bp->vf2pf_mbox;
	struct pf_vf_msg_resp *resp =
		(struct pf_vf_msg_resp *)((u8*)req + sizeof(*req));
	int rc;

	/* Fill the header */
	PREP_VFPF_MSG(bp, req, TEARDOWN_Q);

	req->vf_qid = qidx;

	rc = bnx2x_send_msg2pf(bp, &resp->hdr.status, bp->vf2pf_mbox_mapping);

	if (rc) {
		BNX2X_ERR("Sending TEARDOWN for queue %d failed: %d\n", qidx,
			  rc);
		return rc;
	}

	if (resp->hdr.status != PFVF_STATUS_SUCCESS) {
		BNX2X_ERR("TEARDOWN for queue %d failed: %d\n", qidx,
			  resp->hdr.status);
		return -EINVAL;
	}

	return 0;
}

#define GOOD_ME_REG(me_reg) (((me_reg) & ME_REG_VF_VALID) && \
		    (!((me_reg) & ME_REG_VF_ERR)))

static inline int bnx2x_get_vf_id(struct bnx2x *bp, u32 *vf_id)
{
	u32 me_reg;
	int tout = 1000; /* Wait for 1 sec */

	do {
		me_reg = readl(bp->doorbells);
		if (GOOD_ME_REG(me_reg))
			break;

		usleep_range(1000, 1000);
	} while (tout-- > 0);

	if (!GOOD_ME_REG(me_reg)) {
		BNX2X_ERR("Invalid ME register value: 0x%08x\n", me_reg);
		return -EINVAL;
	}

	*vf_id = (me_reg & ME_REG_VF_NUM_MASK) >> ME_REG_VF_NUM_SHIFT;

	return 0;
}

void bnx2x_chip_cleanup(struct bnx2x *bp, int unload_mode)
{
	int i;
	struct vf_pf_msg_close_vf *req = bp->vf2pf_mbox;
	struct pf_vf_msg_resp     *resp =
		(struct pf_vf_msg_resp *)((u8*)req + sizeof(*req));
	int rc;
	u32 vf_id;

	/* If we haven't got a valid VF id, there is no sence to
	 * continue with sending messages
	 */
	if (bnx2x_get_vf_id(bp, &vf_id))
		goto free_irq;

	/* Close the queues */
	for_each_queue(bp, i)
		bnx2x_teardown_queue(bp, i);

	/* CLOSE VF - an opposit to INIT_VF */

	/* Fill the header */
	PREP_VFPF_MSG(bp, req, CLOSE_VF);

	req->vf_id = vf_id;

	rc = bnx2x_send_msg2pf(bp, &resp->hdr.status, bp->vf2pf_mbox_mapping);

	if (rc)
		BNX2X_ERR("Sending CLOSE failed: %d\n", rc);
	else if (resp->hdr.status != PFVF_STATUS_SUCCESS)
		BNX2X_ERR("Sending CLOSE failed: %d\n", resp->hdr.status);

free_irq:
	/* Disable HW interrupts, NAPI */
	bnx2x_netif_stop(bp, 1);

	/* Release IRQs */
	bnx2x_free_irq(bp);
}

/*
 * bnx2x_nic_unload() flushes the bnx2x_wq, thus reset task is
 * scheduled on a general queue in order to prevent a dead lock.
 */
#if defined(INIT_DELAYED_WORK_DEFERRABLE) || defined(INIT_WORK_NAR) /* BNX2X_UPSTREAM */
static void bnx2x_reset_task(struct work_struct *work)
{
#if (LINUX_VERSION_CODE >= 0x020614) /* BNX2X_UPSTREAM */
	struct bnx2x *bp = container_of(work, struct bnx2x, reset_task.work);
#else
	struct bnx2x *bp = container_of(work, struct bnx2x, reset_task);
#endif
#else
static void bnx2x_reset_task(void *data)
{
	struct bnx2x *bp = (struct bnx2x *)data;
#endif

#ifdef BNX2X_STOP_ON_ERROR
	BNX2X_ERR("reset task called but STOP_ON_ERROR defined"
		  " so reset not done to allow debug dump,\n"
	 KERN_ERR " you will need to reboot when done\n");
	return;
#endif

	rtnl_lock();

	if (!netif_running(bp->dev))
		goto reset_task_exit;

#ifndef BNX2X_UPSTREAM /* ! BNX2X_UPSTREAM */
	if (CHIP_REV_IS_SLOW(bp)) {
		BNX2X_ERR("reset task called on emulation, ignoring\n");
		goto reset_task_exit;
	}
#endif
	bnx2x_nic_unload(bp, UNLOAD_NORMAL);
	bnx2x_nic_load(bp, LOAD_NORMAL);

reset_task_exit:
	rtnl_unlock();
}

/* end of nic load/unload */

/* ethtool_ops */

/*
 * Init service functions
 */

static void __devinit bnx2x_get_common_hwinfo(struct bnx2x *bp)
{
	bp->common.int_block = INT_BLOCK_IGU;
	bp->igu_dsb_id = -1;

	/* Update Chip ID info */
	bp->common.chip_id |= (bp->aquire_resp->pfdev_info.chip_num & 0xffff);

	BNX2X_ERR("VF chip ID=0x%x\n", bp->common.chip_id);

	/* Set DB size. Why is it in PF info? */
	bp->db_size = bp->aquire_resp->pfdev_info.db_size;

	/* TBD: Do we need it at all? */
	bp->common.chip_port_mode = CHIP_2_PORT_MODE;

	bp->link_params.chip_id = bp->common.chip_id;

	bp->common.flash_size = 0;

	/* TBD: Get it from ACQUIRE */
	bp->common.bc_ver = 0;

	bp->flags |= NO_WOL_FLAG;

	BNX2X_DEV_INFO("%sWoL capable\n",
		       (bp->flags & NO_WOL_FLAG) ? "not " : "");

}

#define BNX2V_MAX_Q_NUM	1
static int __devinit bnx2x_get_hwinfo(struct bnx2x *bp)
{
	int rc = 0; /* Wait for 1 second until VF gets up */
	struct vf_pf_msg_acquire *req = bp->vf2pf_mbox;
	struct pf_vf_msg_acquire_resp *resp = bp->aquire_resp;
	u32 vf_id;

	/* Crear both mailbox and acquire respose buffer */
	memset(bp->vf2pf_mbox, 0, VF2PF_MBOX_SIZE + sizeof(*resp));

	/* Fill the header with the default values */
	PREP_VFPF_MSG(bp, req, ACQUIRE);

	req->hdr.resp_msg_offset = VF2PF_MBOX_SIZE;

	if (bnx2x_get_vf_id(bp, &vf_id))
		return -EAGAIN;

	req->vfdev_info.vf_id = vf_id;
	req->vfdev_info.vf_os = 0; /* ?? */
	req->vfdev_info.vf_driver_version = 0; /* ?? */


	req->resc_request.num_rxqs = BNX2V_MAX_Q_NUM;
	req->resc_request.num_txqs = BNX2V_MAX_Q_NUM;
	req->resc_request.num_sbs = BNX2V_MAX_Q_NUM + CNIC_PRESENT;
	req->resc_request.num_mac_filters = 1;
	req->resc_request.num_mc_filters = 10;

	BNX2X_ERR("AQUIRE REQUEST: ");
	_print_struct((u8*)req, sizeof(*req));

	rc = bnx2x_send_msg2pf(bp, &resp->hdr.status, bp->vf2pf_mbox_mapping);

	BNX2X_ERR("AQUIRE RESPONSE: ");
	_print_struct((u8*)resp, sizeof(*resp));
	if (rc)
		return rc;

	if (bp->aquire_resp->hdr.status != PFVF_STATUS_SUCCESS) {
		BNX2X_ERR("Failed to get the requested amount of "
			  "resources: %d. "
			  "Breaking...\n", bp->aquire_resp->hdr.status);
		return -EAGAIN;
	}

	bp->num_queues = BNX2V_MAX_Q_NUM;

	bnx2x_get_common_hwinfo(bp);

#if 0
	if (val & IGU_BLOCK_CONFIGURATION_REG_BACKWARD_COMP_EN) {
		BNX2X_DEV_INFO("!!! IGU Backward Compatible Mode\n");
		bp->common.int_block |= INT_BLOCK_MODE_BW_COMP;
	} else
		BNX2X_DEV_INFO("!!! IGU Normal Mode\n");
#endif
	bp->igu_sb_cnt = BNX2V_MAX_Q_NUM;
	bp->igu_base_sb = bp->aquire_resp->resc.hw_sbs[0].hw_sb_id;

	BNX2X_DEV_INFO("igu_base_sb %d  igu_sb_cnt %d\n",
		       bp->igu_base_sb, bp->igu_sb_cnt);

	bp->mf_ov = 0;
	bp->mf_mode = 0;

	/* Set MAC address here */
	/* TDB: Set some specific address here */
	random_ether_addr(bp->dev->dev_addr);

#if 0
	if (IS_MF(bp)) {
		if (!CHIP_REV_IS_SLOW(bp)) {
			val2 = MF_CFG_RD(bp, func_mf_config[func].mac_upper);
			val = MF_CFG_RD(bp, func_mf_config[func].mac_lower);
		} else {
			val2 = 0x0050;
			val = 0xc22c7090;
			val += (func << 8);
		}
		if ((val2 != FUNC_MF_CFG_UPPERMAC_DEFAULT) &&
		    (val != FUNC_MF_CFG_LOWERMAC_DEFAULT)) {
			bp->dev->dev_addr[0] = (u8)(val2 >> 8 & 0xff);
			bp->dev->dev_addr[1] = (u8)(val2 & 0xff);
			bp->dev->dev_addr[2] = (u8)(val >> 24 & 0xff);
			bp->dev->dev_addr[3] = (u8)(val >> 16 & 0xff);
			bp->dev->dev_addr[4] = (u8)(val >> 8  & 0xff);
			bp->dev->dev_addr[5] = (u8)(val & 0xff);
			memcpy(bp->link_params.mac_addr, bp->dev->dev_addr,
			       ETH_ALEN);
#ifdef ETHTOOL_GPERMADDR /* BNX2X_UPSTREAM */
			memcpy(bp->dev->perm_addr, bp->dev->dev_addr,
			       ETH_ALEN);
#endif
		}

		return rc;
	}

	if (BP_NOMCP(bp)) {
		/* only supposed to happen on emulation/FPGA */
#if (LINUX_VERSION_CODE >= 0x020618) /* BNX2X_UPSTREAM */
		BNX2X_ERROR("warning: random MAC workaround active\n");
		random_ether_addr(bp->dev->dev_addr);
		bp->dev->dev_addr[0] = 0;
#else
		BNX2X_ERROR("warning: constant MAC workaround active\n");
		bp->dev->dev_addr[0] = 0;
		bp->dev->dev_addr[1] = 0x50;
		bp->dev->dev_addr[2] = 0xc2;
		bp->dev->dev_addr[3] = 0x2c;
		bp->dev->dev_addr[4] = (func + 1) * 0x10;
		bp->dev->dev_addr[5] = 0x00;
		memcpy(bp->link_params.mac_addr, bp->dev->dev_addr, ETH_ALEN);
#endif
#ifdef ETHTOOL_GPERMADDR /* BNX2X_UPSTREAM */
		memcpy(bp->dev->perm_addr, bp->dev->dev_addr, ETH_ALEN);
#endif
	}
#endif

	return rc;
}

static int __devinit bnx2x_init_bp(struct bnx2x *bp)
{
	int func;
	int timer_interval;
	int rc;

#ifdef BCM_CNIC
	mutex_init(&bp->cnic_mutex);
#endif

#if defined(INIT_DELAYED_WORK_DEFERRABLE) || defined(INIT_WORK_NAR) /* BNX2X_UPSTREAM */
#if (LINUX_VERSION_CODE >= 0x020614) /* BNX2X_UPSTREAM */
	INIT_DELAYED_WORK(&bp->reset_task, bnx2x_reset_task);
#else
	INIT_WORK(&bp->reset_task, bnx2x_reset_task);
#endif
#else
	INIT_WORK(&bp->reset_task, bnx2x_reset_task, bp);
#endif
	rc = bnx2x_get_hwinfo(bp);

	if (!rc)
		rc = bnx2x_alloc_mem_bp(bp);

	func = BP_FUNC(bp);

	if (CHIP_REV_IS_FPGA(bp))
		dev_err(&bp->pdev->dev, "FPGA detected\n");

	if (BP_NOMCP(bp) && (func == 0))
		dev_err(&bp->pdev->dev, "MCP disabled, must load devices in order!\n");

	bp->multi_mode = multi_mode;

#if (defined(BCM_CNIC) && (LINUX_VERSION_CODE < 0x02061e)) /* ! BNX2X_UPSTREAM */
	bp->dev->select_queue = bnx2x_select_queue;
#endif

	/* Set TPA flags */
	if (disable_tpa) {
		bp->flags &= ~TPA_ENABLE_FLAG;
#if (LINUX_VERSION_CODE >= 0x02061a) /* BNX2X_UPSTREAM */
		bp->dev->features &= ~NETIF_F_LRO;
#endif
	} else {
		bp->flags |= TPA_ENABLE_FLAG;
#if (LINUX_VERSION_CODE >= 0x02061a) /* BNX2X_UPSTREAM */
		bp->dev->features |= NETIF_F_LRO;
#endif
	}

	bp->disable_tpa = disable_tpa;

	bp->dropless_fc = dropless_fc;

	bp->mrrs = mrrs;

	bp->tx_ring_size = MAX_TX_AVAIL;
	bp->rx_ring_size = MAX_RX_AVAIL;

	bp->rx_csum = 1;

	/* make sure that the numbers are in the right granularity */
	bp->tx_ticks = (50 / BNX2X_BTR) * BNX2X_BTR;
	bp->rx_ticks = (25 / BNX2X_BTR) * BNX2X_BTR;

	timer_interval = (CHIP_REV_IS_SLOW(bp) ? 5*HZ : HZ);
	bp->current_interval = (poll ? poll : timer_interval);

	init_timer(&bp->timer);
	bp->timer.expires = jiffies + bp->current_interval;
	bp->timer.data = (unsigned long) bp;
	bp->timer.function = bnx2x_timer;

	return rc;
}

/*
 * ethtool service functions
 */

/* All ethtool functions called with rtnl_lock */

static void bnx2x_get_drvinfo(struct net_device *dev,
			      struct ethtool_drvinfo *info)
{
	struct bnx2x *bp = netdev_priv(dev);
	u8 phy_fw_ver[PHY_FW_VER_LEN];

	strcpy(info->driver, DRV_MODULE_NAME);
	strcpy(info->version, DRV_MODULE_VERSION);

	phy_fw_ver[0] = '\0';

	strncpy(info->fw_version, bp->fw_ver, 32);
	snprintf(info->fw_version + strlen(bp->fw_ver), 32 - strlen(bp->fw_ver),
		 "BC:%d.%d.%d%s%s",
		 (bp->common.bc_ver & 0xff0000) >> 16,
		 (bp->common.bc_ver & 0xff00) >> 8,
		 (bp->common.bc_ver & 0xff),
		 ((phy_fw_ver[0] != '\0') ? " PHY:" : ""), phy_fw_ver);
	strcpy(info->bus_info, pci_name(bp->pdev));
	info->n_stats = 0;
	info->testinfo_len = BNX2V_NUM_TESTS;
	info->eedump_len = 0;
	info->regdump_len = 0;
}

static void bnx2x_get_wol(struct net_device *dev, struct ethtool_wolinfo *wol)
{
	/* No WOL in "KVM world" */
	wol->supported = 0;
	wol->wolopts = 0;
	memset(&wol->sopass, 0, sizeof(wol->sopass));
}

static u32 bnx2x_get_link(struct net_device *dev)
{
	struct bnx2x *bp = netdev_priv(dev);

	if (bp->state != BNX2X_STATE_OPEN)
		return 0;

	/* Link is always up in "KVM world" */
	return 1;
}

static int bnx2x_set_coalesce(struct net_device *dev,
			      struct ethtool_coalesce *coal)
{
	/* TBD: Do we allow this? */
	BUG();

	return 0;
}

/* Can we do self tests on VF? */
static const struct {
	char string[ETH_GSTRING_LEN];
} bnx2x_tests_str_arr[BNX2V_NUM_TESTS] = {
	{ "loopback_test (offline)" }
};

#if 0
#if (LINUX_VERSION_CODE < 0x020620) /* ! BNX2X_UPSTREAM */
static int bnx2x_self_test_count(struct net_device *dev)
{
	return BNX2V_NUM_TESTS;
}
#endif

static int bnx2x_run_loopback(struct bnx2x *bp, int loopback_mode, u8 link_up)
{
	unsigned int pkt_size, num_pkts, i;
	struct sk_buff *skb;
	unsigned char *packet;
	struct bnx2x_fastpath *fp_rx = &bp->fp[0];
	struct bnx2x_fastpath *fp_tx = &bp->fp[0];
	u16 tx_start_idx, tx_idx;
	u16 rx_start_idx, rx_idx;
	u16 pkt_prod, bd_prod;
	struct sw_tx_bd *tx_buf;
	struct eth_tx_start_bd *tx_start_bd;
	struct eth_tx_parse_bd *pbd = NULL;
	dma_addr_t mapping;
	union eth_rx_cqe *cqe;
	u8 cqe_fp_flags;
	struct sw_rx_bd *rx_buf;
	u16 len;
	int rc = -ENODEV;

	/* check the loopback mode */
	switch (loopback_mode) {
	case BNX2X_PHY_LOOPBACK:
		if (bp->link_params.loopback_mode != LOOPBACK_XGXS_10)
			return -EINVAL;
		break;
	case BNX2X_MAC_LOOPBACK:
		bp->link_params.loopback_mode = LOOPBACK_BMAC;
		bnx2x_phy_init(&bp->link_params, &bp->link_vars);
		break;
	default:
		return -EINVAL;
	}

	/* prepare the loopback packet */
	pkt_size = (((bp->dev->mtu < ETH_MAX_PACKET_SIZE) ?
		     bp->dev->mtu : ETH_MAX_PACKET_SIZE) + ETH_HLEN);
	skb = netdev_alloc_skb(bp->dev, bp->rx_buf_size);
	if (!skb) {
		rc = -ENOMEM;
		goto test_loopback_exit;
	}
	packet = skb_put(skb, pkt_size);
	memcpy(packet, bp->dev->dev_addr, ETH_ALEN);
	memset(packet + ETH_ALEN, 0, ETH_ALEN);
	memset(packet + 2*ETH_ALEN, 0x77, (ETH_HLEN - 2*ETH_ALEN));
	for (i = ETH_HLEN; i < pkt_size; i++)
		packet[i] = (unsigned char) (i & 0xff);

	/* send the loopback packet */
	num_pkts = 0;
	tx_start_idx = le16_to_cpu(*fp_tx->tx_cons_sb);
	rx_start_idx = le16_to_cpu(*fp_rx->rx_cons_sb);

	pkt_prod = fp_tx->tx_pkt_prod++;
	tx_buf = &fp_tx->tx_buf_ring[TX_BD(pkt_prod)];
	tx_buf->first_bd = fp_tx->tx_bd_prod;
	tx_buf->skb = skb;
	tx_buf->flags = 0;

	bd_prod = TX_BD(fp_tx->tx_bd_prod);
	tx_start_bd = &fp_tx->tx_desc_ring[bd_prod].start_bd;
	mapping = pci_map_single(bp->pdev, skb->data,
				 skb_headlen(skb), PCI_DMA_TODEVICE);
	tx_start_bd->addr_hi = cpu_to_le32(U64_HI(mapping));
	tx_start_bd->addr_lo = cpu_to_le32(U64_LO(mapping));
	tx_start_bd->nbd = cpu_to_le16(2); /* start + pbd */
	tx_start_bd->nbytes = cpu_to_le16(skb_headlen(skb));
	tx_start_bd->vlan = cpu_to_le16(pkt_prod);
	tx_start_bd->bd_flags.as_bitfield = ETH_TX_BD_FLAGS_START_BD;
	SET_FLAG(tx_start_bd->general_data,
		 ETH_TX_START_BD_ETH_ADDR_TYPE,
		 UNICAST_ADDRESS);
	SET_FLAG(tx_start_bd->general_data,
		 ETH_TX_START_BD_HDR_NBDS,
		 1);

	/* turn on parsing and get a BD */
	bd_prod = TX_BD(NEXT_TX_IDX(bd_prod));
	pbd = &fp_tx->tx_desc_ring[bd_prod].parse_bd;

	memset(pbd, 0, sizeof(struct eth_tx_parse_bd));

	wmb();

	fp_tx->tx_db.data.prod += 2;
	barrier();
	DOORBELL(bp, fp_tx->index, fp_tx->tx_db.raw);

	mmiowb();

	num_pkts++;
	fp_tx->tx_bd_prod += 2; /* start + pbd */
#if (LINUX_VERSION_CODE < 0x02061f) /* ! BNX2X_UPSTREAM */
	/* In kernels starting from 2.6.31 netdev layer does this */
	bp->dev->trans_start = jiffies;
#endif

	udelay(100);

	tx_idx = le16_to_cpu(*fp_tx->tx_cons_sb);
	if (tx_idx != tx_start_idx + num_pkts)
		goto test_loopback_exit;

	rx_idx = le16_to_cpu(*fp_rx->rx_cons_sb);
	if (rx_idx != rx_start_idx + num_pkts)
		goto test_loopback_exit;

	cqe = &fp_rx->rx_comp_ring[RCQ_BD(fp_rx->rx_comp_cons)];
	cqe_fp_flags = cqe->fast_path_cqe.type_error_flags;
	if (CQE_TYPE(cqe_fp_flags) || (cqe_fp_flags & ETH_RX_ERROR_FALGS))
		goto test_loopback_rx_exit;

	len = le16_to_cpu(cqe->fast_path_cqe.pkt_len);
	if (len != pkt_size)
		goto test_loopback_rx_exit;

	rx_buf = &fp_rx->rx_buf_ring[RX_BD(fp_rx->rx_bd_cons)];
	skb = rx_buf->skb;
	skb_reserve(skb, cqe->fast_path_cqe.placement_offset);
	for (i = ETH_HLEN; i < pkt_size; i++)
		if (*(skb->data + i) != (unsigned char) (i & 0xff))
			goto test_loopback_rx_exit;

	rc = 0;

test_loopback_rx_exit:
#if (LINUX_VERSION_CODE < 0x02061b) /* ! BNX2X_UPSTREAM */
	bp->dev->last_rx = jiffies;
#endif

	fp_rx->rx_bd_cons = NEXT_RX_IDX(fp_rx->rx_bd_cons);
	fp_rx->rx_bd_prod = NEXT_RX_IDX(fp_rx->rx_bd_prod);
	fp_rx->rx_comp_cons = NEXT_RCQ_IDX(fp_rx->rx_comp_cons);
	fp_rx->rx_comp_prod = NEXT_RCQ_IDX(fp_rx->rx_comp_prod);

	/* Update producers */
	bnx2x_update_rx_prod(bp, fp_rx, fp_rx->rx_bd_prod, fp_rx->rx_comp_prod,
			     fp_rx->rx_sge_prod);

test_loopback_exit:
	bp->link_params.loopback_mode = LOOPBACK_NONE;

	return rc;
}

static int bnx2x_test_loopback(struct bnx2x *bp, u8 link_up)
{
	int rc = 0, res;

	if (BP_NOMCP(bp))
		return rc;

	if (!netif_running(bp->dev))
		return BNX2X_LOOPBACK_FAILED;

	bnx2x_netif_stop(bp, 1);
	bnx2x_acquire_phy_lock(bp);

	res = bnx2x_run_loopback(bp, BNX2X_PHY_LOOPBACK, link_up);
	if (res) {
		DP(NETIF_MSG_PROBE, "  PHY loopback failed  (res %d)\n", res);
		rc |= BNX2X_PHY_LOOPBACK_FAILED;
	}

	res = bnx2x_run_loopback(bp, BNX2X_MAC_LOOPBACK, link_up);
	if (res) {
		DP(NETIF_MSG_PROBE, "  MAC loopback failed  (res %d)\n", res);
		rc |= BNX2X_MAC_LOOPBACK_FAILED;
	}

	bnx2x_release_phy_lock(bp);
	bnx2x_netif_start(bp);

	return rc;
}


static void bnx2x_self_test(struct net_device *dev,
			    struct ethtool_test *etest, u64 *buf)
{
	struct bnx2x *bp = netdev_priv(dev);

	if (bp->recovery_state != BNX2X_RECOVERY_DONE) {
		netdev_err(dev, "Handling parity error recovery. Try again later\n");
		etest->flags |= ETH_TEST_FL_FAILED;
		return;
	}

	memset(buf, 0, sizeof(u64) * BNX2X_NUM_TESTS);

	if (!netif_running(dev))
		return;

	/* offline tests are not supported in MF mode */
	if (IS_MF(bp))
		etest->flags &= ~ETH_TEST_FL_OFFLINE;

	if (etest->flags & ETH_TEST_FL_OFFLINE) {
		int port = BP_PORT(bp);
		u32 val;
		u8 link_up;

		/* save current value of input enable for TX port IF */
		val = REG_RD(bp, NIG_REG_EGRESS_UMP0_IN_EN + port*4);
		/* disable input for TX port IF */
		REG_WR(bp, NIG_REG_EGRESS_UMP0_IN_EN + port*4, 0);

		link_up = bp->link_vars.link_up;
		bnx2x_nic_unload(bp, UNLOAD_NORMAL);
		bnx2x_nic_load(bp, LOAD_DIAG);
		/* wait until link state is restored */
		bnx2x_wait_for_link(bp, link_up);

		if (bnx2x_test_registers(bp) != 0) {
			buf[0] = 1;
			etest->flags |= ETH_TEST_FL_FAILED;
		}
		if (bnx2x_test_memory(bp) != 0) {
			buf[1] = 1;
			etest->flags |= ETH_TEST_FL_FAILED;
		}
		buf[2] = bnx2x_test_loopback(bp, link_up);
		if (buf[2] != 0)
			etest->flags |= ETH_TEST_FL_FAILED;

		bnx2x_nic_unload(bp, UNLOAD_NORMAL);

		/* restore input for TX port IF */
		REG_WR(bp, NIG_REG_EGRESS_UMP0_IN_EN + port*4, val);

		bnx2x_nic_load(bp, LOAD_NORMAL);
		/* wait until link state is restored */
		bnx2x_wait_for_link(bp, link_up);
	}
	if (bnx2x_test_nvram(bp) != 0) {
		buf[3] = 1;
		etest->flags |= ETH_TEST_FL_FAILED;
	}
	if (bnx2x_test_intr(bp) != 0) {
		buf[4] = 1;
		etest->flags |= ETH_TEST_FL_FAILED;
	}
	if (bp->port.pmf)
		if (bnx2x_link_test(bp) != 0) {
			buf[5] = 1;
			etest->flags |= ETH_TEST_FL_FAILED;
		}
#ifndef BNX2X_UPSTREAM /* ! BNX2X_UPSTREAM */
	/* run the idle check twice */
	bnx2x_idle_chk(bp);
	buf[6] = bnx2x_idle_chk(bp);
	if (buf[6] != 0)
		etest->flags |= ETH_TEST_FL_FAILED;
#endif

#ifdef BNX2X_EXTRA_DEBUG
	bnx2x_panic_dump(bp);
#endif
}

#endif

static struct ethtool_ops bnx2x_ethtool_ops = {
	.get_settings		= bnx2x_get_settings,
	.get_drvinfo		= bnx2x_get_drvinfo,
	.get_wol		= bnx2x_get_wol,
	.get_msglevel		= bnx2x_get_msglevel,
	.set_msglevel		= bnx2x_set_msglevel,
	.get_link		= bnx2x_get_link,
	.get_coalesce		= bnx2x_get_coalesce,
	.set_coalesce		= bnx2x_set_coalesce,
	.get_ringparam		= bnx2x_get_ringparam,
	.set_ringparam		= bnx2x_set_ringparam,
	.get_pauseparam		= bnx2x_get_pauseparam,
	.get_rx_csum		= bnx2x_get_rx_csum,
	.set_rx_csum		= bnx2x_set_rx_csum,
	.get_tx_csum		= ethtool_op_get_tx_csum,
#if (LINUX_VERSION_CODE >= 0x020618) /* BNX2X_UPSTREAM */
	.set_tx_csum		= ethtool_op_set_tx_hw_csum,
#else
	.set_tx_csum		= bnx2x_set_tx_hw_csum,
#endif
#if (LINUX_VERSION_CODE >= 0x02061a) /* BNX2X_UPSTREAM */
	.set_flags		= bnx2x_set_flags,
	.get_flags		= ethtool_op_get_flags,
#endif
	.get_sg			= ethtool_op_get_sg,
	.set_sg			= ethtool_op_set_sg,
#ifdef NETIF_F_TSO /* BNX2X_UPSTREAM */
	.get_tso		= ethtool_op_get_tso,
	.set_tso		= bnx2x_set_tso,
#endif
#if (LINUX_VERSION_CODE < 0x020620) /* ! BNX2X_UPSTREAM */
	//.self_test_count	= bnx2x_self_test_count,
#endif
	//.self_test		= bnx2x_self_test,
#ifdef ETHTOOL_GPERMADDR /* ! BNX2X_UPSTREAM */
#if (LINUX_VERSION_CODE < 0x020617)
	.get_perm_addr		= ethtool_op_get_perm_addr
#endif
#endif
};

/* end of ethtool_ops */

/****************************************************************************
* General service functions
****************************************************************************/
/*
 * net_device service functions
 */

#if (LINUX_VERSION_CODE < 0x020618) /* ! BNX2X_UPSTREAM */
static struct net_device_stats *bnx2x_get_stats(struct net_device *dev)
{
	struct bnx2x *bp = netdev_priv(dev);

	return &bp->net_stats;
}
#endif

/* called with rtnl_lock */
static int bnx2x_open(struct net_device *dev)
{
	struct bnx2x *bp = netdev_priv(dev);

	netif_carrier_off(dev);

	bnx2x_set_power_state(bp, PCI_D0);

	return bnx2x_nic_load(bp, LOAD_OPEN);
}

/* called with rtnl_lock */
static int bnx2x_close(struct net_device *dev)
{
	struct bnx2x *bp = netdev_priv(dev);

	/* Unload the driver, release IRQs */
	bnx2x_nic_unload(bp, UNLOAD_CLOSE);

	/* Power off */
	bnx2x_set_power_state(bp, PCI_D3hot);

	return 0;
}

static int bnx2x_set_mcast_list(struct net_device *dev)
{
	struct bnx2x *bp = netdev_priv(dev);
	struct vf_pf_msg_set_q_filters *req = bp->vf2pf_mbox;
	struct pf_vf_msg_resp *resp = (struct pf_vf_msg_resp *)((u8*)req + sizeof(*req));
	int rc, i = 0;
#if (LINUX_VERSION_CODE >= 0x020622) /* BNX2X_UPSTREAM */
	struct netdev_hw_addr *ha;
#else
	struct dev_mc_list *ha;
#endif

	/* DEBUG DEBUG */
	/* No multicasts for VF at the moment */
	return -1;

	if (bp->state != BNX2X_STATE_OPEN) {
		DP(NETIF_MSG_IFUP, "state is %x, returning\n", bp->state);
		return -EINVAL;
	}

	/* Set the header */
	PREP_VFPF_MSG(bp, req, SET_Q_FILTERS);

	/* Get Rx mode requesed */
	DP(NETIF_MSG_IFUP, "dev->flags = %x\n", dev->flags);

	netdev_for_each_mc_addr(ha, dev) {
#if (LINUX_VERSION_CODE >= 0x02061b) /* BNX2X_UPSTREAM */
		DP(NETIF_MSG_IFUP, "Adding mcast MAC: %pM\n",
		   bnx2x_mc_addr(ha));
#else
		DP(NETIF_MSG_IFUP, "Adding mcast MAC: "
		   "%02x:%02x:%02x:%02x:%02x:%02x\n",
		   bnx2x_mc_addr(ha)[0], bnx2x_mc_addr(ha)[1],
		   bnx2x_mc_addr(ha)[2], bnx2x_mc_addr(ha)[3],
		   bnx2x_mc_addr(ha)[4], bnx2x_mc_addr(ha)[5]);
#endif
		memcpy(req->multicast[i], bnx2x_mc_addr(ha),
		       sizeof(req->multicast[i]));

		i++;
	}

	/* We support for PFVF_MAX_MULTICAST_PER_VF mcast
	   addresses tops */
	if (i >= PFVF_MAX_MULTICAST_PER_VF) {
		DP(NETIF_MSG_IFUP, "VF supports not more than %d "
				   "multicast MAC addresses\n",
		   PFVF_MAX_MULTICAST_PER_VF);
		return -EINVAL;
	}

	req->n_multicast = i;
	req->flags |= VFPF_SET_Q_FILTERS_MULTICAST_CHANGED;

	req->vf_qid = 0;

	rc = bnx2x_send_msg2pf(bp, &resp->hdr.status, bp->vf2pf_mbox_mapping);
	if (rc) {
		BNX2X_ERR("Sending a message failed: %d\n", rc);
		return rc;
	}

	if (resp->hdr.status != PFVF_STATUS_SUCCESS) {
		BNX2X_ERR("Set Rx mode/multicast failed: %d\n",
			  resp->hdr.status);
		return -EINVAL;
	}

	return 0;
}


/* called with netif_tx_lock from dev_mcast.c */
void bnx2x_set_rx_mode(struct net_device *dev)
{
	struct bnx2x *bp = netdev_priv(dev);

	if (bp->state != BNX2X_STATE_OPEN) {
		DP(NETIF_MSG_IFUP, "state is %x, returning\n", bp->state);
		return;
	}

	/* Get Rx mode requesed */
	DP(NETIF_MSG_IFUP, "dev->flags = %x\n", dev->flags);

	/* Default is a normal mode */
	bp->rx_mode = BNX2X_RX_MODE_NORMAL;

	if (dev->flags & IFF_PROMISC) {
		bp->rx_mode = BNX2X_RX_MODE_PROMISC;
	} else if (dev->flags & IFF_ALLMULTI) {
		bp->rx_mode = BNX2X_RX_MODE_ALLMULTI;
	} else /* multicasts */
		bnx2x_set_mcast_list(dev);

	bnx2x_set_storm_rx_mode(bp);
}

#if defined(HAVE_POLL_CONTROLLER) || defined(CONFIG_NET_POLL_CONTROLLER)
static void poll_bnx2x(struct net_device *dev)
{
	struct bnx2x *bp = netdev_priv(dev);

	/* Run it on fp[0]
	   TBD: go over it again when RSS is supported
	 */
#if (LINUX_VERSION_CODE < 0x020613)
	bnx2x_msix_fp_int(-1, bp->fp, NULL);
#else /* BNX2X_UPSTREAM */
	bnx2x_msix_fp_int(-1, bp->fp);
#endif
}
#endif

#if (LINUX_VERSION_CODE >= 0x02061d) /* BNX2X_UPSTREAM */
static const struct net_device_ops bnx2x_netdev_ops = {
	.ndo_open		= bnx2x_open,
	.ndo_stop		= bnx2x_close,
	.ndo_start_xmit		= bnx2x_start_xmit,
#if defined(BNX2X_SAFC) || defined(BCM_CNIC) /* ! BNX2X_UPSTREAM */
	.ndo_select_queue	= bnx2x_select_queue,
#endif
	.ndo_set_multicast_list	= bnx2x_set_rx_mode,
	.ndo_set_mac_address	= bnx2x_change_mac_addr,
	.ndo_validate_addr	= eth_validate_addr,
	.ndo_change_mtu		= bnx2x_change_mtu,
	.ndo_tx_timeout		= bnx2x_tx_timeout,
#ifdef BCM_VLAN /* ! BNX2X_UPSTREAM */
	.ndo_vlan_rx_register	= bnx2x_vlan_rx_register,
#endif
#if defined(HAVE_POLL_CONTROLLER) || defined(CONFIG_NET_POLL_CONTROLLER)
	.ndo_poll_controller	= poll_bnx2x,
#endif
};
#endif

static int __devinit bnx2x_init_dev(struct pci_dev *pdev,
				    struct net_device *dev,
				    unsigned long board_type)
{
	struct bnx2x *bp;
	int rc;

#if (LINUX_VERSION_CODE < 0x020618) /* ! BNX2X_UPSTREAM */
	SET_MODULE_OWNER(dev);
#endif
#if (LINUX_VERSION_CODE >= 0x020419) /* BNX2X_UPSTREAM */
	SET_NETDEV_DEV(dev, &pdev->dev);
#endif
	bp = netdev_priv(dev);

	bp->dev = dev;
	bp->pdev = pdev;
	bp->flags = 0;
	bp->pf_num = PCI_FUNC(pdev->devfn);

	/** TODO: Check that PF has finished the initialization here.
	 *  Otherwise break with error! */

	rc = pci_enable_device(pdev);
	if (rc) {
		dev_err(&pdev->dev, "Cannot enable PCI device, aborting\n");
		goto err_out;
	}

	if (!(pci_resource_flags(pdev, 0) & IORESOURCE_MEM)) {
		dev_err(&pdev->dev, "Cannot find PCI device base address,"
		       " aborting\n");
		rc = -ENODEV;
		goto err_out_disable;
	}

	/* if (!(pci_resource_flags(pdev, 2) & IORESOURCE_MEM)) {
		dev_err(&pdev->dev, "Cannot find second PCI device"
		       " base address, aborting\n");
		rc = -ENODEV;
		goto err_out_disable;
	} */

#if (LINUX_VERSION_CODE >= 0x020614) /* BNX2X_UPSTREAM */
	if (atomic_read(&pdev->enable_cnt) == 1) {
#endif
		BNX2X_ERR("Before pci_request_regions\n");
		rc = pci_request_regions(pdev, DRV_MODULE_NAME);
		if (rc) {
			dev_err(&pdev->dev, "Cannot obtain PCI resources,"
			       " aborting\n");
			goto err_out_disable;
		}

		pci_set_master(pdev);
#if (LINUX_VERSION_CODE >= 0x02060b) /* BNX2X_UPSTREAM */
		pci_save_state(pdev);
#else
		pci_save_state(pdev, bp->pci_state);
#endif
#if (LINUX_VERSION_CODE >= 0x020614) /* BNX2X_UPSTREAM */
	}
#endif

	bp->pm_cap = 0;

	bp->pcie_cap = pci_find_capability(pdev, PCI_CAP_ID_EXP);
	if (bp->pcie_cap == 0)
		//DP(NETIF_MSG_PROBE, "Cannot find PCI Express capability\n");
		BNX2X_ERR("Cannot find PCI Express capability\n");

	if (pci_set_dma_mask(pdev, DMA_BIT_MASK(64)) == 0) {
		BNX2X_ERR("Device supports 64-bit DMA\n");
		bp->flags |= USING_DAC_FLAG;
		if (pci_set_consistent_dma_mask(pdev, DMA_BIT_MASK(64)) != 0) {
			dev_err(&pdev->dev, "pci_set_consistent_dma(64)_mask"
			       " failed, aborting\n");
			rc = -EIO;
			goto err_out_release;
		}

	} else if (pci_set_dma_mask(pdev, DMA_BIT_MASK(32)) != 0) {
		dev_err(&pdev->dev, "System does not support DMA,"
		       " aborting\n");
		rc = -EIO;
		goto err_out_release;
	} else if (pci_set_consistent_dma_mask(pdev, DMA_BIT_MASK(32)) != 0) {
		dev_err(&pdev->dev, "pci_set_consistent_dma(32)_mask"
			       " failed, aborting\n");
		rc = -EIO;
		goto err_out_release;
	}

	dev->mem_start = pci_resource_start(pdev, 0);
	dev->base_addr = dev->mem_start;
	dev->mem_end = pci_resource_end(pdev, 0);

	dev->irq = pdev->irq;

#if (LINUX_VERSION_CODE >= 0x02061c) /* BNX2X_UPSTREAM */
	bp->regview = pci_ioremap_bar(pdev, 0);
#else
	bp->regview = ioremap_nocache(dev->base_addr,
				      pci_resource_len(pdev, 0));
#endif
	if (!bp->regview) {
		dev_err(&pdev->dev, "Cannot map register space, aborting\n");
		rc = -ENOMEM;
		goto err_out_release;
	}

	BNX2X_ERR("BAR size is %lld\n", pci_resource_len(pdev, 0));

	bp->doorbells = (u8*)bp->regview + PXP_VF_ADDR_DB_START;
	/* bp->doorbells = ioremap_nocache(pci_resource_start(pdev, 2),
					min_t(u64, BNX2X_DB_SIZE(bp),
					      pci_resource_len(pdev, 2)));
	if (!bp->doorbells) {
		dev_err(&pdev->dev, "Cannot map doorbell space, aborting\n");
		rc = -ENOMEM;
		goto err_out_unmap;
	} */

	BNX2X_PCI_ALLOC(bp->vf2pf_mbox, &bp->vf2pf_mbox_mapping,
		VF2PF_MBOX_SIZE + sizeof(struct pf_vf_msg_acquire_resp));

	BNX2X_ERR("Allocated mbox: virt %p phys 0x%llx size %ld\n",
		  bp->vf2pf_mbox, bp->vf2pf_mbox_mapping, VF2PF_MBOX_SIZE +
		  sizeof(struct pf_vf_msg_acquire_resp));

	/* Set a pointer tp aquire response buffer */
	bp->aquire_resp = (struct pf_vf_msg_acquire_resp *)((u8*)bp->vf2pf_mbox + VF2PF_MBOX_SIZE);

#if (LINUX_VERSION_CODE < 0x020618) /* ! BNX2X_UPSTREAM */
	dev->get_stats = bnx2x_get_stats;
#endif
	dev->watchdog_timeo = TX_TIMEOUT;
	dev->ethtool_ops = &bnx2x_ethtool_ops;

#if (LINUX_VERSION_CODE >= 0x02061d) /* BNX2X_UPSTREAM */
	dev->netdev_ops = &bnx2x_netdev_ops;
#else
	dev->hard_start_xmit = bnx2x_start_xmit;
	dev->open = bnx2x_open;
	dev->stop = bnx2x_close;
	dev->set_multicast_list = bnx2x_set_rx_mode;
	dev->set_mac_address = bnx2x_change_mac_addr;
	dev->change_mtu = bnx2x_change_mtu;
	dev->tx_timeout = bnx2x_tx_timeout;
#ifdef BCM_VLAN /* ! BNX2X_UPSTREAM */
	dev->vlan_rx_register = bnx2x_vlan_rx_register;
#if (LINUX_VERSION_CODE < 0x020616)
	dev->vlan_rx_kill_vid = bnx2x_vlan_rx_kill_vid;
#endif
#endif
#if defined(HAVE_POLL_CONTROLLER) || defined(CONFIG_NET_POLL_CONTROLLER)
	dev->poll_controller = poll_bnx2x;
#endif
#endif
	dev->features |= NETIF_F_SG;
	dev->features |= NETIF_F_HW_CSUM;
	if (bp->flags & USING_DAC_FLAG)
		dev->features |= NETIF_F_HIGHDMA;
#ifdef NETIF_F_TSO /* BNX2X_UPSTREAM */
	dev->features |= (NETIF_F_TSO | NETIF_F_TSO_ECN);
#endif
#ifdef NETIF_F_TSO6 /* BNX2X_UPSTREAM */
	dev->features |= NETIF_F_TSO6;
#endif
#if defined(BCM_VLAN) || !defined(OLD_VLAN) /* BNX2X_UPSTREAM */
	dev->features |= (NETIF_F_HW_VLAN_TX | NETIF_F_HW_VLAN_RX);

#if (LINUX_VERSION_CODE >= 0x02061a) /* BNX2X_UPSTREAM */
	dev->vlan_features |= NETIF_F_SG;
	dev->vlan_features |= NETIF_F_HW_CSUM;
	if (bp->flags & USING_DAC_FLAG)
		dev->vlan_features |= NETIF_F_HIGHDMA;
	dev->vlan_features |= (NETIF_F_TSO | NETIF_F_TSO_ECN);
	dev->vlan_features |= NETIF_F_TSO6;
#endif
#endif

	return 0;

alloc_mem_err:
	rc = -ENOMEM;
	if (bp->regview) {
		iounmap(bp->regview);
		bp->regview = NULL;
	}

	/* if (bp->doorbells) {
		iounmap(bp->doorbells);
		bp->doorbells = NULL;
	} */

err_out_release:
#if (LINUX_VERSION_CODE >= 0x020614) /* BNX2X_UPSTREAM */
	if (atomic_read(&pdev->enable_cnt) == 1)
#endif
		pci_release_regions(pdev);

err_out_disable:
	pci_disable_device(pdev);
	pci_set_drvdata(pdev, NULL);

err_out:
	return rc;
}

static void __devinit bnx2x_get_pcie_width_speed(struct bnx2x *bp,
						 int *width, int *speed)
{
	u32 val = REG_RD(bp, PCICFG_OFFSET + PCICFG_LINK_CONTROL);

	*width = (val & PCICFG_LINK_WIDTH) >> PCICFG_LINK_WIDTH_SHIFT;

	/* return value of 1=2.5GHz 2=5GHz */
	*speed = (val & PCICFG_LINK_SPEED) >> PCICFG_LINK_SPEED_SHIFT;
}

static int __devinit bnx2x_init_one(struct pci_dev *pdev,
				    const struct pci_device_id *ent)
{
	struct net_device *dev = NULL;
	struct bnx2x *bp;
	int pcie_width, pcie_speed;
	int rc, cid_count;

	switch (ent->driver_data) {

	case BCM57712VF:
		/* Currently multi-queue is not supported for VF */
		cid_count = 1 + CNIC_PRESENT;
		break;

	default:
		dev_err(&pdev->dev, "Unknown board_type (%ld), aborting\n",
			   ent->driver_data);
		return ENODEV;
	}

#ifdef BCM_CNIC
	cid_count += 1;
#endif

	/* dev zeroed in init_etherdev */
#ifdef BNX2X_MULTI_QUEUE /* BNX2X_UPSTREAM */
	dev = alloc_etherdev_mq(sizeof(*bp), cid_count);
#else
	dev = alloc_etherdev(sizeof(*bp));
#endif
	if (!dev) {
		dev_err(&pdev->dev, "Cannot allocate net device\n");
		return -ENOMEM;
	}

	bp = netdev_priv(dev);
	bp->msg_enable = debug;

	/* Set DID, unite it with the data that will be received from PF
	   in acquire */
	bp->common.chip_id = ent->device << 16;

	pci_set_drvdata(pdev, dev);

	bp->l2_cid_count = cid_count;

	rc = bnx2x_init_dev(pdev, dev, ent->driver_data);
	if (rc < 0) {
		free_netdev(dev);
		return rc;
	}

	/* calc qm_cid_count */
	cid_count = L2_FP_COUNT(cid_count);

#ifdef BCM_CNIC
	cid_count += CNIC_CID_MAX;
#endif
	bp->qm_cid_count = roundup(cid_count, QM_CID_ROUND);

	rc = bnx2x_init_bp(bp);
	if (rc)
		goto init_one_exit;

	rc = register_netdev(dev);
	if (rc) {
		dev_err(&pdev->dev, "Cannot register net device\n");
		goto init_one_exit;
	}

	/* Configure interupt mode: try to enable MSI-X/MSI if
	 * needed, set bp->num_queues appropriately.
	 */
	if (bnx2x_set_int_mode(bp)) {
		dev_err(&pdev->dev, "Failed to configure MSI-X\n");
		goto init_one_exit;
	}


	/* Add all NAPI objects */
	bnx2x_add_all_napi(bp);

	bnx2x_get_pcie_width_speed(bp, &pcie_width, &pcie_speed);
	netdev_info(bp->dev, "%s (%c%d) PCI-E x%d %s found at mem %lx,"
	       " IRQ %d, ", board_info[ent->driver_data].name,
	       (CHIP_REV(bp) >> 12) + 'A', (CHIP_METAL(bp) >> 4),
	       pcie_width, (pcie_speed == 2) ? "5GHz (Gen2)" : "2.5GHz",
	       dev->base_addr, bp->pdev->irq);
#if (LINUX_VERSION_CODE >= 0x02061b) /* BNX2X_UPSTREAM */
	pr_cont("node addr %pM\n", dev->dev_addr);
#else
	pr_cont("node addr ");
	{
		int i;

		for (i = 0; i < ETH_ALEN; i++)
			pr_cont("%2.2x", dev->dev_addr[i]);
	}
	pr_cont("\n");
#endif
	return 0;

init_one_exit:
	if (bp->regview)
		iounmap(bp->regview);

	/* if (bp->doorbells)
		iounmap(bp->doorbells); */

	free_netdev(dev);

#if (LINUX_VERSION_CODE >= 0x020614) /* BNX2X_UPSTREAM */
	if (atomic_read(&pdev->enable_cnt) == 1)
#endif
		pci_release_regions(pdev);

	pci_disable_device(pdev);
	pci_set_drvdata(pdev, NULL);

	return rc;
}

static void __devexit bnx2x_remove_one(struct pci_dev *pdev)
{
	struct net_device *dev = pci_get_drvdata(pdev);
	struct bnx2x *bp;
	struct vf_pf_msg_close_vf *req;
	struct pf_vf_msg_resp     *resp;
	int rc;
	u32 vf_id;

	bp = netdev_priv(dev);

	if (!dev) {
		dev_err(&pdev->dev, "BAD net device from bnx2x_init_one\n");
		return;
	}

	unregister_netdev(dev);

	/* Delete all NAPI objects */
	bnx2x_del_all_napi(bp);

	/* Disable MSI/MSI-X */
	bnx2x_disable_msi(bp);

	req = bp->vf2pf_mbox;
	resp = (struct pf_vf_msg_resp *)((u8*)req + sizeof(*req));


	if (!bnx2x_get_vf_id(bp, &vf_id)) {

		/* Set the header */
		PREP_VFPF_MSG(bp, req, RELEASE_VF);

		req->vf_id = vf_id;

		rc = bnx2x_send_msg2pf(bp, &resp->hdr.status, bp->vf2pf_mbox_mapping);

		if (rc)
			BNX2X_ERR("Sending CLOSE failed: %d\n", rc);
	}

#if (LINUX_VERSION_CODE >= 0x020618) /* BNX2X_UPSTREAM */
	/* Make sure RESET task is not scheduled before continuing */
	cancel_delayed_work_sync(&bp->reset_task);
#else
	cancel_delayed_work(&bp->reset_task);
	flush_scheduled_work();
#endif

	if (bp->regview)
		iounmap(bp->regview);

	pci_free_consistent(pdev, VF2PF_MBOX_SIZE +
				sizeof(struct pf_vf_msg_acquire_resp),
				bp->vf2pf_mbox, bp->vf2pf_mbox_mapping);
	bnx2x_free_mem_bp(bp);

	free_netdev(dev);

#if (LINUX_VERSION_CODE >= 0x020614) /* BNX2X_UPSTREAM */
	if (atomic_read(&pdev->enable_cnt) == 1)
#endif
		pci_release_regions(pdev);

	pci_disable_device(pdev);
	pci_set_drvdata(pdev, NULL);
}

static struct pci_driver bnx2x_pci_driver = {
	.name        = DRV_MODULE_NAME,
	.id_table    = bnx2x_pci_tbl,
	.probe       = bnx2x_init_one,
	.remove      = __devexit_p(bnx2x_remove_one),
	.suspend     = bnx2x_suspend,
	.resume      = bnx2x_resume,
};

static int __init bnx2x_init(void)
{
	int rc;

	pr_info("%s", version);

#if (LINUX_VERSION_CODE < 0x02061e) && defined(BNX2X_MULTI_QUEUE)
	get_random_bytes(&bnx2x_skb_tx_hashrnd, sizeof(bnx2x_skb_tx_hashrnd));
#endif

#if (LINUX_VERSION_CODE >= 0x020600) /* BNX2X_UPSTREAM */
	rc = pci_register_driver(&bnx2x_pci_driver);
#else
	rc = pci_module_init(&bnx2x_pci_driver);
#endif
#if (LINUX_VERSION_CODE >= 0x02060a) /* BNX2X_UPSTREAM */
	if (rc) {
		pr_err("Cannot register driver\n");
	}
#endif
	return rc;
}

static void __exit bnx2x_cleanup(void)
{
	pci_unregister_driver(&bnx2x_pci_driver);
}

module_init(bnx2x_init);
module_exit(bnx2x_cleanup);

#if 0
#ifdef BCM_CNIC

/* count denotes the number of new completions we have seen */
static void bnx2x_cnic_sp_post(struct bnx2x *bp, int count)
{
	struct eth_spe *spe;

#ifdef BNX2X_STOP_ON_ERROR
	if (unlikely(bp->panic))
		return;
#endif

	spin_lock_bh(&bp->spq_lock);
	bp->cnic_spq_pending -= count;

	for (; bp->cnic_spq_pending < bp->cnic_eth_dev.max_kwqe_pending;
	     bp->cnic_spq_pending++) {

		if (!bp->cnic_kwq_pending)
			break;

		spe = bnx2x_sp_get_next(bp);
		*spe = *bp->cnic_kwq_cons;

		bp->cnic_kwq_pending--;

		DP(NETIF_MSG_TIMER, "pending on SPQ %d, on KWQ %d count %d\n",
		   bp->cnic_spq_pending, bp->cnic_kwq_pending, count);

		if (bp->cnic_kwq_cons == bp->cnic_kwq_last)
			bp->cnic_kwq_cons = bp->cnic_kwq;
		else
			bp->cnic_kwq_cons++;
	}
	bnx2x_sp_prod_update(bp);
	spin_unlock_bh(&bp->spq_lock);
}

static int bnx2x_cnic_sp_queue(struct net_device *dev,
			       struct kwqe_16 *kwqes[], u32 count)
{
	struct bnx2x *bp = netdev_priv(dev);
	int i;

#ifdef BNX2X_STOP_ON_ERROR
	if (unlikely(bp->panic))
		return -EIO;
#endif

	spin_lock_bh(&bp->spq_lock);

	for (i = 0; i < count; i++) {
		struct eth_spe *spe = (struct eth_spe *)kwqes[i];

		if (bp->cnic_kwq_pending == MAX_SP_DESC_CNT)
			break;

		*bp->cnic_kwq_prod = *spe;

		bp->cnic_kwq_pending++;

		DP(NETIF_MSG_TIMER, "L5 SPQE %x %x %x:%x pos %d\n",
		   spe->hdr.conn_and_cmd_data, spe->hdr.type,
		   spe->data.mac_config_addr.hi,
		   spe->data.mac_config_addr.lo,
		   bp->cnic_kwq_pending);

		if (bp->cnic_kwq_prod == bp->cnic_kwq_last)
			bp->cnic_kwq_prod = bp->cnic_kwq;
		else
			bp->cnic_kwq_prod++;
	}

	spin_unlock_bh(&bp->spq_lock);

	if (bp->cnic_spq_pending < bp->cnic_eth_dev.max_kwqe_pending)
		bnx2x_cnic_sp_post(bp, 0);

	return i;
}

static int bnx2x_cnic_ctl_send(struct bnx2x *bp, struct cnic_ctl_info *ctl)
{
	struct cnic_ops *c_ops;
	int rc = 0;

	mutex_lock(&bp->cnic_mutex);
	c_ops = bp->cnic_ops;
	if (c_ops)
		rc = c_ops->cnic_ctl(bp->cnic_data, ctl);
	mutex_unlock(&bp->cnic_mutex);

	return rc;
}

static int bnx2x_cnic_ctl_send_bh(struct bnx2x *bp, struct cnic_ctl_info *ctl)
{
	struct cnic_ops *c_ops;
	int rc = 0;

	rcu_read_lock();
	c_ops = rcu_dereference(bp->cnic_ops);
	if (c_ops)
		rc = c_ops->cnic_ctl(bp->cnic_data, ctl);
	rcu_read_unlock();

	return rc;
}

/*
 * for commands that have no data
 */
int bnx2x_cnic_notify(struct bnx2x *bp, int cmd)
{
	struct cnic_ctl_info ctl = {0};

	ctl.cmd = cmd;

	return bnx2x_cnic_ctl_send(bp, &ctl);
}

static void bnx2x_cnic_cfc_comp(struct bnx2x *bp, int cid)
{
	struct cnic_ctl_info ctl;

	/* first we tell CNIC and only then we count this as a completion */
	ctl.cmd = CNIC_CTL_COMPLETION_CMD;
	ctl.data.comp.cid = cid;

	bnx2x_cnic_ctl_send_bh(bp, &ctl);
	bnx2x_cnic_sp_post(bp, 1);
}

static int bnx2x_drv_ctl(struct net_device *dev, struct drv_ctl_info *ctl)
{
	struct bnx2x *bp = netdev_priv(dev);

	switch (ctl->cmd) {
	case DRV_CTL_CTXTBL_WR_CMD:
		{
			u32 index = ctl->data.io.offset;
			dma_addr_t addr = ctl->data.io.dma_addr;

			bnx2x_ilt_wr(bp, index, addr);
			return 0;
		}
		break;

	case DRV_CTL_COMPLETION_CMD:
		{
			int count = ctl->data.comp.comp_count;

			bnx2x_cnic_sp_post(bp, count);
			return 0;
		}
		break;

	default:
		BNX2X_ERR("unknown command %x\n", ctl->cmd);
		return -EINVAL;
	}
}

void bnx2x_setup_cnic_irq_info(struct bnx2x *bp)
{
	struct cnic_eth_dev *cp = &bp->cnic_eth_dev;

	if (bp->flags & USING_MSIX_FLAG) {
		cp->drv_state |= CNIC_DRV_STATE_USING_MSIX;
		cp->irq_arr[0].irq_flags |= CNIC_IRQ_FL_MSIX;
		cp->irq_arr[0].vector = bp->msix_table[1].vector;
	} else {
		cp->drv_state &= ~CNIC_DRV_STATE_USING_MSIX;
		cp->irq_arr[0].irq_flags &= ~CNIC_IRQ_FL_MSIX;
	}
	cp->irq_arr[0].status_blk = bp->cnic_sb;
	cp->irq_arr[0].status_blk_num = CNIC_SB_ID(bp);

	cp->num_irq = 1;
}

static int bnx2x_register_cnic(struct net_device *dev, struct cnic_ops *ops,
			       void *data)
{
	struct bnx2x *bp = netdev_priv(dev);
	struct cnic_eth_dev *cp = &bp->cnic_eth_dev;

	if (ops == NULL)
		return -EINVAL;

	bp->cnic_kwq = kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (!bp->cnic_kwq)
		return -ENOMEM;

	bp->cnic_kwq_cons = bp->cnic_kwq;
	bp->cnic_kwq_prod = bp->cnic_kwq;
	bp->cnic_kwq_last = bp->cnic_kwq + MAX_SP_DESC_CNT;

	bp->cnic_spq_pending = 0;
	bp->cnic_kwq_pending = 0;

	bp->cnic_data = data;
	rcu_assign_pointer(bp->cnic_ops, ops);

	cp->num_irq = 0;
	cp->drv_state = CNIC_DRV_STATE_REGD;

	/* write the sb_id on the SB */
	bp->cnic_sb->u_status_block.status_block_id = CNIC_SB_ID(bp);
	bp->cnic_sb->c_status_block.status_block_id = CNIC_SB_ID(bp);

	bnx2x_init_sb(bp, bp->cnic_sb_mapping, BP_FUNC(bp), CNIC_SB_ID(bp),
		      (bp->common.int_block == INT_BLOCK_HC) ?
		      CNIC_SB_ID(bp) : CNIC_IGU_SB_ID(bp));

	bnx2x_setup_cnic_irq_info(bp);

	return 0;
}

static int bnx2x_unregister_cnic(struct net_device *dev)
{
	struct bnx2x *bp = netdev_priv(dev);
	struct cnic_eth_dev *cp = &bp->cnic_eth_dev;

	mutex_lock(&bp->cnic_mutex);
	cp->drv_state = 0;
	rcu_assign_pointer(bp->cnic_ops, NULL);
#if !defined(__VMKLNX__)
	synchronize_rcu();
#endif
	mutex_unlock(&bp->cnic_mutex);
	kfree(bp->cnic_kwq);
	bp->cnic_kwq = NULL;

	return 0;
}

struct cnic_eth_dev *bnx2x_cnic_probe(struct net_device *dev)
{
	struct bnx2x *bp = netdev_priv(dev);
	struct cnic_eth_dev *cp = &bp->cnic_eth_dev;

	cp->drv_owner = THIS_MODULE;
	cp->chip_id = CHIP_ID(bp);
	cp->pdev = bp->pdev;
	cp->io_base = bp->regview;
	cp->max_kwqe_pending = 8;
	cp->ctx_blk_size = CDU_ILT_PAGE_SZ;
	cp->ctx_tbl_offset = FUNC_ILT_BASE(BP_FUNC(bp)) + bnx2x_cid_ilt_lines(bp);
	cp->ctx_tbl_len = CNIC_ILT_LINES;
	cp->starting_cid = bnx2x_cid_ilt_lines(bp) * ILT_PAGE_CIDS;
	cp->drv_submit_kwqes_16 = bnx2x_cnic_sp_queue;
	cp->drv_ctl = bnx2x_drv_ctl;
	cp->drv_register_cnic = bnx2x_register_cnic;
	cp->drv_unregister_cnic = bnx2x_unregister_cnic;

	return cp;
}
EXPORT_SYMBOL(bnx2x_cnic_probe);

#endif /* BCM_CNIC */
#endif

/* Dummy implementation for VF */
u32 bnx2x_dec_load_cnt(struct bnx2x *bp)
{
	return -1;
}

void bnx2x_inc_load_cnt(struct bnx2x *bp)
{
	/* Do nothing */
	return;
}

bool bnx2x_chk_parity_attn(struct bnx2x *bp, bool *global, bool print)
{
	return false;
}

void bnx2x_set_reset_global(struct bnx2x *bp)
{
	/* Do nothing */
	return;
}

void bnx2x_set_reset_in_progress(struct bnx2x *bp)
{
	/* Do nothing */
	return;
}

bool bnx2x_reset_is_done(struct bnx2x *bp, int engine)
{
	return true;
}

void bnx2x_pf_disable(struct bnx2x *bp)
{
	/* Do nothing */
	return;
}

void bnx2x_disable_close_the_gate(struct bnx2x *bp)
{
	/* Do nothing */
}

void bnx2x_rxq_set_mac_filters(struct bnx2x *bp, u16 cl_id,
			       unsigned long accept_flags)
{
	/* Implement over PF2VF chan */
	BUG();
}

void bnx2x_sp_event(struct bnx2x_fastpath *fp,
		    union eth_rx_cqe *rr_cqe)
{
	/* Should not be ever called for VF */
	BUG();
}

void bnx2x_update_rx_prod(struct bnx2x *bp, struct bnx2x_fastpath *fp,
			u16 bd_prod, u16 rx_comp_prod, u16 rx_sge_prod)
{
	u32 start = PXP_VF_ADDR_USDM_QUEUES_START +
		bp->aquire_resp->resc.hw_qid[fp->index]*
		sizeof(struct ustorm_queue_zone_data);

	bnx2x_update_rx_prod_gen(bp, fp, bd_prod, rx_comp_prod, rx_sge_prod,
				 start);
}

#if (LINUX_VERSION_CODE < 0x020613) && (VMWARE_ESX_DDK_VERSION < 40000)
irqreturn_t bnx2x_interrupt(int irq, void *dev_instance,
				   struct pt_regs *regs)
#else /* BNX2X_UPSTREAM */
irqreturn_t bnx2x_interrupt(int irq, void *dev_instance)
#endif
{
	/* Currently INT#x is not supported for VF */
	BUG();
	return IRQ_HANDLED;
}

u32 bnx2x_fw_command(struct bnx2x *bp, u32 command, u32 param)
{
	return FW_MSG_CODE_DRV_LOAD_FUNCTION;
}
