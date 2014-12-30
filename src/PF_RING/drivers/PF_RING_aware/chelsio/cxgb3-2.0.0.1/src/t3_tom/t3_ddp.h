/*
 * Definitions for TCP DDP.
 *
 * Copyright (C) 20062009 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

#ifndef T3_DDP_H
#define T3_DDP_H

#include "t3_cpl.h"
#include "t3_ddp_state.h"
#include "cpl_io_state.h"

/*
 * Returns 1 if a UBUF DMA buffer might be active.
 */
static inline int t3_ddp_ubuf_pending(struct sock *sk)
{
	struct ddp_state *p = DDP_STATE(sk);

	/* When the TOM_TUNABLE(ddp) is enabled, we're always in ULP_MODE DDP,
	 * but DDP_STATE() is only valid if the connection actually enabled
	 * DDP.
	 */
	if (!p->ddp_setup)
		return 0;

	return (p->buf_state[0].flags & (DDP_BF_NOFLIP | DDP_BF_NOCOPY)) || 
	       (p->buf_state[1].flags & (DDP_BF_NOFLIP | DDP_BF_NOCOPY));
}

int t3_setup_ppods(struct sock *sk, const struct ddp_gather_list *gl,
		   unsigned int nppods, unsigned int tag, unsigned int maxoff,
		   unsigned int pg_off, unsigned int color);
int t3_alloc_ppods(struct tom_data *td, unsigned int n);
void t3_free_ppods(struct tom_data *td, unsigned int tag, unsigned int n);
void t3_free_ddp_gl(struct pci_dev *pdev, struct ddp_gather_list *gl);
int t3_pin_pages(struct pci_dev *pdev, unsigned long uaddr, size_t len,
		 struct ddp_gather_list **newgl,
		 const struct ddp_gather_list *gl);
int t3_map_pages(struct pci_dev *pdev, unsigned long uaddr, size_t len,
                 struct ddp_gather_list **newgl,
                 const struct ddp_gather_list *gl);
int t3_ddp_copy(const struct sk_buff *skb, int offset, struct iovec *to,
		int len);
//void t3_repost_kbuf(struct sock *sk, int modulate, int activate, int nonblock);
void t3_post_kbuf(struct sock *sk, int modulate, int nonblock);
int t3_post_ubuf(struct sock *sk, const struct iovec *iov, int nonblock,
		 int rcv_flags, int modulate, int post_kbuf);
void t3_cancel_ubuf(struct sock *sk, long *timeo);
int t3_overlay_ubuf(struct sock *sk, const struct iovec *iov, int nonblock,
		    int rcv_flags, int modulate, int post_kbuf);
int t3_enter_ddp(struct sock *sk, unsigned int kbuf_size, unsigned int waitall, int nonblock);
void t3_cleanup_ddp(struct sock *sk);
void t3_release_ddp_resources(struct sock *sk);
void t3_cancel_ddpbuf(struct sock *sk, unsigned int bufidx);
void t3_overlay_ddpbuf(struct sock *sk, unsigned int bufidx, unsigned int tag0,
		       unsigned int tag1, unsigned int len);
void t3_setup_ddpbufs(struct sock *sk, unsigned int len0, unsigned int offset0,
		      unsigned int len1, unsigned int offset1,
		      u64 ddp_flags, u64 flag_mask, int modulate);
#endif  /* T3_DDP_H */
