/*
 * Definitions for TCP DDP state management.
 *
 * Copyright (C) 2006-2009 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

#ifndef T3_DDP_STATE_H
#define T3_DDP_STATE_H

/* Should be 1 or 2 indicating single or double kernel buffers. */
#define NUM_DDP_KBUF 2

/* min receive window for a connection to be considered for DDP */
#define MIN_DDP_RCV_WIN (48 << 10)

/* amount of Rx window not available to DDP to avoid window exhaustion */
#define DDP_RSVD_WIN (16 << 10)

/* # of sentinel invalid page pods at the end of a group of valid page pods */
#define NUM_SENTINEL_PPODS 0

/* # of pages a pagepod can hold without needing another pagepod */
#define PPOD_PAGES 4

/* page pods are allocated in groups of this size (must be power of 2) */
#define PPOD_CLUSTER_SIZE 16

/* for each TID we reserve this many page pods up front */
#define RSVD_PPODS_PER_TID 1

struct pagepod {
	__u32 vld_tid;
	__u32 pgsz_tag_color;
	__u32 max_offset;
	__u32 page_offset;
	__u64 rsvd;
	__u64 addr[5];
};

#define PPOD_SIZE sizeof(struct pagepod)

#define S_PPOD_TID    0
#define M_PPOD_TID    0xFFFFFF
#define V_PPOD_TID(x) ((x) << S_PPOD_TID)

#define S_PPOD_VALID    24
#define V_PPOD_VALID(x) ((x) << S_PPOD_VALID)
#define F_PPOD_VALID    V_PPOD_VALID(1U)

#define S_PPOD_COLOR    0
#define M_PPOD_COLOR    0x3F
#define V_PPOD_COLOR(x) ((x) << S_PPOD_COLOR)

#define S_PPOD_TAG    6
#define M_PPOD_TAG    0xFFFFFF
#define V_PPOD_TAG(x) ((x) << S_PPOD_TAG)

#define S_PPOD_PGSZ    30
#define M_PPOD_PGSZ    0x3
#define V_PPOD_PGSZ(x) ((x) << S_PPOD_PGSZ)

struct page;
struct pci_dev;

/* DDP gather lists can specify an offset only for the first page. */
struct ddp_gather_list {
	unsigned int length;
	unsigned int offset;
	unsigned int nelem;
	unsigned int type;
	struct page **pages;
	dma_addr_t phys_addr[0];
};

struct ddp_buf_state {
	unsigned int cur_offset;     /* offset of latest DDP notification */
	unsigned int flags;
	struct ddp_gather_list *gl;
};

struct ddp_state {
	struct pci_dev *pdev;
	struct ddp_buf_state buf_state[2];   /* per buffer state */
	unsigned int ddp_setup;
	unsigned int state;
	int cur_buf;
	unsigned short kbuf_noinval;
	unsigned short kbuf_idx;        /* which HW buffer is used for kbuf */
	struct ddp_gather_list *ubuf;
	unsigned int ubuf_nppods;       /* # of page pods for buffer 1 */
	unsigned int ubuf_tag;
	int get_tcb_count;
	unsigned int kbuf_posted;
	unsigned int ubuf_ddp_ready;
	unsigned int avg_request_len;
	int cancel_ubuf;
	unsigned int kbuf_nppods[NUM_DDP_KBUF];
	unsigned int kbuf_tag[NUM_DDP_KBUF];
	struct ddp_gather_list *kbuf[NUM_DDP_KBUF]; /* kernel buffer for DDP prefetch */
};

enum {
	DDP_TYPE_USER = 1 << 0,
	DDP_TYPE_KERNEL =  1 << 1,
};

enum {
	DDP_ENABLED = 1 << 0,
};

/* buf_state flags */
enum {
	DDP_BF_NOINVAL = 1 << 0,   /* buffer is set to NO_INVALIDATE */
	DDP_BF_NOCOPY  = 1 << 1,   /* DDP to final dest, no copy needed */
	DDP_BF_NOFLIP  = 1 << 2,   /* buffer flips after GET_TCB_RPL */
	DDP_BF_PSH     = 1 << 3,   /* set in skb->flags if the a DDP was 
	                              completed with a segment having the
				      PSH flag set */
	DDP_BF_NODATA  = 1 << 4,   /* buffer completed before filling */ 
};

#endif  /* T3_DDP_STATE_H */
