/*
 * This file implements the Chelsio CPL5 message processing.
 *
 * Copyright (C) 2006-2009 Chelsio Communications.  All rights reserved.
 *
 * Written by Dimitris Michailidis (dm@chelsio.com)
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

#include <linux/mm.h>
#include <linux/pci.h>
#include <linux/highmem.h>
#ifndef	LINUX_2_4
#include <linux/dma-mapping.h>
#endif	/* LINUX_2_4 */
#include "defs.h"
#include "tom.h"
#include "t3_ddp.h"
#include "tcb.h"
#include "trace.h"

/*
 * Return the # of page pods needed to accommodate a # of pages.
 */
static inline unsigned int pages2ppods(unsigned int pages)
{
	return (pages + PPOD_PAGES - 1) / PPOD_PAGES + NUM_SENTINEL_PPODS;
}

/**
 *	t3_pin_pages - pin a user memory range and prepare it for DDP
 *	@addr - the starting address
 *	@len - the length of the range
 *	@newgl - contains the pages and physical addresses of the pinned range
 *	@gl - an existing gather list, may be %NULL
 *
 *	Pins the pages in the user-space memory range [addr, addr + len) and
 *	maps them for DMA.  Returns a gather list with the pinned pages and
 *	their physical addresses.  If @gl is non NULL the pages it describes
 *	are compared against the pages for [addr, addr + len), and if the
 *	existing gather list already covers the range a new list is not
 *	allocated.  Returns 0 on success, or a negative errno.  On success if
 *	a new gather list was allocated it is returned in @newgl.
 */ 
int t3_pin_pages(struct pci_dev *pdev, unsigned long addr, size_t len,
		 struct ddp_gather_list **newgl,
		 const struct ddp_gather_list *gl)
{
	int i, err;
	size_t pg_off;
	unsigned int npages;
	struct ddp_gather_list *p;

	if (segment_eq(get_fs(), KERNEL_DS) || !len)
		return -EINVAL;
	if (!access_ok(VERIFY_WRITE, addr, len))
		return -EFAULT;

	pg_off = addr & ~PAGE_MASK;
	npages = (pg_off + len + PAGE_SIZE - 1) >> PAGE_SHIFT;
	p = kmalloc(sizeof(struct ddp_gather_list) +
		    npages * (sizeof(dma_addr_t) + sizeof(struct page *)),
		    GFP_KERNEL);
	if (!p)
		return -ENOMEM;

	p->type = DDP_TYPE_USER;
	p->pages = (struct page **)&p->phys_addr[npages];
	down_read(&current->mm->mmap_sem);
	/*
	 * get_user_pages() will mark the pages dirty so we don't need to do it
	 * later.  See how get_user_pages() uses FOLL_TOUCH | FOLL_WRITE.
	 */
	err = get_user_pages(current, current->mm, addr, npages, 1, 0,
			     p->pages, NULL);
	up_read(&current->mm->mmap_sem);
	if (err != npages) {
		if (err < 0)
			goto free_gl;
		npages = err;
		err = -EFAULT;
		goto unpin;
	}

	if (gl && gl->offset == pg_off && gl->nelem >= npages &&
	    gl->length >= len) {
		for (i = 0; i < npages; ++i)
			if (p->pages[i] != gl->pages[i])
				goto different_gl;
		err = 0;
		goto unpin;
	}

different_gl:
	p->length = len;
	p->offset = pg_off;
	p->nelem = npages;
	p->phys_addr[0] = pci_map_page(pdev, p->pages[0], pg_off,
				       PAGE_SIZE - pg_off,
				       PCI_DMA_FROMDEVICE) - pg_off;
	if (unlikely(t3_pci_dma_mapping_error(pdev, p->phys_addr[0]))) {
                err = -ENOMEM;
		goto unpin;
	}
	for (i = 1; i < npages; ++i) {
		p->phys_addr[i] = pci_map_page(pdev, p->pages[i], 0, PAGE_SIZE,
					       PCI_DMA_FROMDEVICE);
		if (unlikely(t3_pci_dma_mapping_error(pdev, p->phys_addr[i]))) {
			err = -ENOMEM;
			goto unpin;
		}
	}

	*newgl = p;
	return 0;
unpin:
	for (i = 0; i < npages; ++i)
		put_page(p->pages[i]);
free_gl:
	kfree(p);
	*newgl = NULL;
	return err;
}

/**
 *      t3_map_pages - map a kernel memory range and prepare it for DDP
 *	and assumes caller handles page refcounting.
 *	In all other respects same as t3_pin_pages.
 *      @addr - the starting address
 *      @len - the length of the range
 *      @newgl - contains the pages and physical addresses of the range
 *      @gl - an existing gather list, may be %NULL
 */

int t3_map_pages(struct pci_dev *pdev, unsigned long addr, size_t len,
		 struct ddp_gather_list **newgl,
		 const struct ddp_gather_list *gl)
{
	int i, err;
	size_t pg_off;
	unsigned int npages;
	struct ddp_gather_list *p;

	if (!len)
		return -EINVAL;

	pg_off = addr & ~PAGE_MASK;
	npages = (pg_off + len + PAGE_SIZE - 1) >> PAGE_SHIFT;
	p = kmalloc(sizeof(struct ddp_gather_list) +
		    npages * (sizeof(dma_addr_t) + sizeof(struct page *)),
		    GFP_KERNEL);
	if (!p)
		return -ENOMEM;

	p->type = DDP_TYPE_KERNEL;
	p->pages = (struct page **)&p->phys_addr[npages];
	
	for (i=0; i < npages; i++) {
		if ((addr < VMALLOC_START) || (addr >= VMALLOC_END))
			p->pages[i] = virt_to_page((void *)addr);
		else
			p->pages[i] = vmalloc_to_page((void *)addr);
		addr += PAGE_SIZE;
	}
	
	if (gl && gl->offset == pg_off && gl->nelem >= npages &&
	    gl->length >= len) {
		for (i = 0; i < npages; ++i)
			if (p->pages[i] != gl->pages[i]) {
				goto different_gl;
			}
		err = 0;
		goto free_gl;
	}

different_gl:
	p->length = len;
	p->offset = pg_off;
	p->nelem = npages;
	p->phys_addr[0] = pci_map_page(pdev, p->pages[0], pg_off,
				       PAGE_SIZE - pg_off,
				       PCI_DMA_FROMDEVICE) - pg_off;
	if (unlikely(t3_pci_dma_mapping_error(pdev, p->phys_addr[0]))) {
                err = -ENOMEM;
		goto free_gl;
	}
	for (i = 1; i < npages; ++i) {
		p->phys_addr[i] = pci_map_page(pdev, p->pages[i], 0, PAGE_SIZE,
					       PCI_DMA_FROMDEVICE);
		if (unlikely(t3_pci_dma_mapping_error(pdev, p->phys_addr[i]))) {
			err = -ENOMEM;
			goto free_gl;
		}
	}

	*newgl = p;
	return 0;
free_gl:
	kfree(p);
	*newgl = NULL;
	return err;
}

static void unmap_ddp_gl(struct pci_dev *pdev, const struct ddp_gather_list *gl)
{
	int i;

	if (!gl->nelem)
		return;

	pci_unmap_page(pdev, gl->phys_addr[0] + gl->offset,
		       PAGE_SIZE - gl->offset, PCI_DMA_FROMDEVICE);
	for (i = 1; i < gl->nelem; ++i)
		pci_unmap_page(pdev, gl->phys_addr[i], PAGE_SIZE,
			       PCI_DMA_FROMDEVICE);
}

static void ddp_gl_free_pages(struct ddp_gather_list *gl)
{
        int i;

        for (i = 0; i < gl->nelem; ++i)
                        put_page(gl->pages[i]);
}

void t3_free_ddp_gl(struct pci_dev *pdev, struct ddp_gather_list *gl)
{
	unmap_ddp_gl(pdev, gl);
	if (gl->type == DDP_TYPE_USER) {
		ddp_gl_free_pages(gl);
	}
	kfree(gl);
}

/* Max # of page pods for a buffer, enough for 1MB buffer at 4KB page size */
#define MAX_PPODS 64U

/*
 * Allocate page pods for DDP buffer 1 (the user buffer) and set up the tag in
 * the TCB.  We allocate page pods in multiples of PPOD_CLUSTER_SIZE.  First we
 * try to allocate enough page pods to accommodate the whole buffer, subject to
 * the MAX_PPODS limit.  If that fails we try to allocate PPOD_CLUSTER_SIZE page
 * pods before failing entirely.
 */
static int alloc_buf1_ppods(struct sock *sk, struct ddp_state *p,
			    unsigned long addr, unsigned int len)
{
	int tag, npages, nppods;
	struct tom_data *d = TOM_DATA(CPL_IO_STATE(sk)->toedev);

	npages = ((addr & ~PAGE_MASK) + len + PAGE_SIZE - 1) >> PAGE_SHIFT;
	nppods = min(pages2ppods(npages), MAX_PPODS);
	nppods = ALIGN(nppods, PPOD_CLUSTER_SIZE);
	tag = t3_alloc_ppods(d, nppods);
	if (tag < 0 && nppods > PPOD_CLUSTER_SIZE) {
		nppods = PPOD_CLUSTER_SIZE;
		tag = t3_alloc_ppods(d, nppods);
	}
	if (tag < 0)
		return -ENOMEM;

	p->ubuf_nppods = nppods;
	p->ubuf_tag = tag;
#if NUM_DDP_KBUF == 1
	t3_set_ddp_tag(sk, 1, tag << 6);
#endif
	return 0;
}

/*
 * Starting offset for the user DDP buffer.  A non-0 value ensures a DDP flush
 * won't block indefinitely if there's nothing to place (which should be rare).
 */
#define UBUF_OFFSET 1

static inline unsigned long select_ddp_flags(const struct sock *sk, int buf_idx,
					     int nonblock, int rcv_flags)
{
	struct toedev *tdev = CPL_IO_STATE(sk)->toedev;

	if (buf_idx == 1) {
		if (unlikely(rcv_flags & MSG_WAITALL))
			return V_TF_DDP_PUSH_DISABLE_1(1);

		if (nonblock)
			return V_TF_DDP_BUF1_FLUSH(1);

		return V_TF_DDP_BUF1_FLUSH(!TOM_TUNABLE(tdev, ddp_push_wait));
	}

	if (unlikely(rcv_flags & MSG_WAITALL))
		return V_TF_DDP_PUSH_DISABLE_0(1);

	if (nonblock)
		return V_TF_DDP_BUF0_FLUSH(1);

	return V_TF_DDP_BUF0_FLUSH(!TOM_TUNABLE(tdev, ddp_push_wait));
}

/*
 * Reposts the kernel DDP buffer after it has been previously become full and
 * invalidated.  We just need to reset the offset and adjust the DDP flags.
 * Conveniently, we can set the flags and the offset with a single message.
 * Note that this function does not set the buffer length.  Again conveniently
 * our kernel buffer is of fixed size.  If the length needs to be changed it
 * needs to be done separately.
 */
void t3_repost_kbuf(struct sock *sk, unsigned int bufidx, int modulate, 
		    int activate, int nonblock)
{
	struct ddp_state *p = DDP_STATE(sk);
	unsigned long flags;

	p->buf_state[bufidx].cur_offset = p->kbuf[bufidx]->offset;
	p->buf_state[bufidx].flags = p->kbuf_noinval ? DDP_BF_NOINVAL : 0;
	p->buf_state[bufidx].gl = p->kbuf[bufidx];
	p->cur_buf = bufidx;
	p->kbuf_idx = bufidx;
	
	flags = select_ddp_flags(sk, bufidx, nonblock, 0);
	
	if (!bufidx)
	t3_setup_ddpbufs(sk, 0, 0, 0, 0, flags |
			 V_TF_DDP_PSH_NO_INVALIDATE0(p->kbuf_noinval) |
			 V_TF_DDP_PSH_NO_INVALIDATE1(p->kbuf_noinval) |
			 V_TF_DDP_BUF0_VALID(1),
			 V_TF_DDP_BUF0_FLUSH(1) |
			 V_TF_DDP_PSH_NO_INVALIDATE0(1) |
			 V_TF_DDP_PSH_NO_INVALIDATE1(1) | V_TF_DDP_OFF(1) |
			 V_TF_DDP_BUF0_VALID(1) |
			 V_TF_DDP_ACTIVE_BUF(activate), modulate);
	else
	t3_setup_ddpbufs(sk, 0, 0, 0, 0, flags |
			 V_TF_DDP_PSH_NO_INVALIDATE0(p->kbuf_noinval) |
			 V_TF_DDP_PSH_NO_INVALIDATE1(p->kbuf_noinval) |
			 V_TF_DDP_BUF1_VALID(1) | 
			 V_TF_DDP_ACTIVE_BUF(activate),
			 V_TF_DDP_BUF1_FLUSH(1) |
			 V_TF_DDP_PSH_NO_INVALIDATE0(1) | 
			 V_TF_DDP_PSH_NO_INVALIDATE1(1) | V_TF_DDP_OFF(1) |
			 V_TF_DDP_BUF1_VALID(1) | V_TF_DDP_ACTIVE_BUF(1), 
			 modulate);
	
}

/**
 * setup_iovec_ppods - setup HW page pods for a user iovec
 * @sk: the associated socket
 * @iov: the iovec
 * @oft: additional bytes to map before the start of the buffer
 *
 * Pins a user iovec and sets up HW page pods for DDP into it.  We allocate
 * page pods for user buffers on the first call per socket.  Afterwards we
 * limit the buffer length to whatever the existing page pods can accommodate.
 * Returns a negative error code or the length of the mapped buffer.
 *
 * The current implementation handles iovecs with only one entry.
 */
static int setup_iovec_ppods(struct sock *sk, const struct iovec *iov, int oft)
{
	int err;
	unsigned int len;
	struct ddp_gather_list *gl;
	struct ddp_state *p = DDP_STATE(sk);
	unsigned long addr = (unsigned long)iov->iov_base - oft;

	if (unlikely(!p->ubuf_nppods)) {
		err = alloc_buf1_ppods(sk, p, addr, iov->iov_len + oft);
		if (err)
			return err;
	}

	len = (p->ubuf_nppods - NUM_SENTINEL_PPODS) * PPOD_PAGES * PAGE_SIZE;
	len -= addr & ~PAGE_MASK;
	if (len > M_TCB_RX_DDP_BUF0_LEN)
		len = M_TCB_RX_DDP_BUF0_LEN;
	len = min(len, tcp_sk(sk)->rcv_wnd - 32768);
	len = min_t(int, len, iov->iov_len + oft);

	if (len <= p->kbuf[0]->length)
		return -EINVAL;

	if (!segment_eq(get_fs(), KERNEL_DS))
		err = t3_pin_pages(p->pdev, addr, len, &gl, p->ubuf);
	else
		err = t3_map_pages(p->pdev, addr, len, &gl, p->ubuf);
	if (err < 0)
		return err;
	if (gl) {
		if (p->ubuf)
			t3_free_ddp_gl(p->pdev, p->ubuf);
		p->ubuf = gl;
		t3_setup_ppods(sk, gl, pages2ppods(gl->nelem), p->ubuf_tag, len,
			       gl->offset, 0);
	}
	return len;
}
#if 0
/*
 * Post a user buffer as DDP buffer 1.
 */
int t3_post_ubuf(struct sock *sk, const struct iovec *iov,
		 int nonblock, int rcv_flags, int modulate, int post_kbuf)
{
	int len;
	unsigned long flags;
	struct ddp_state *p = DDP_STATE(sk);

	len = setup_iovec_ppods(sk, iov, UBUF_OFFSET);
	if (len < 0)
		return len;

	p->buf_state[1].cur_offset = UBUF_OFFSET;
	p->buf_state[1].flags = DDP_BF_NOCOPY;
	p->buf_state[1].gl = p->ubuf;
	p->cur_buf = 1;

	flags = select_ddp_flags(sk, 1, nonblock, rcv_flags);

	if (post_kbuf) {
		/* kbuf_noinval must be 0 for concurrent posting */
		p->buf_state[0].cur_offset = p->kbuf.offset;
		p->buf_state[0].flags = 0;
		p->buf_state[0].gl = &p->kbuf;
		flags |= V_TF_DDP_BUF0_VALID(1);
	}

	/*
	 * Do not disable DDP off here, HW may have turned it off due to memory
	 * exhaustion and we don't want to reenable it for this connection.
	 */
	t3_setup_ddpbufs(sk, 0, 0, len, UBUF_OFFSET, V_TF_DDP_BUF1_VALID(1) |
			 V_TF_DDP_ACTIVE_BUF(1) | flags,
			 V_TF_DDP_PSH_NO_INVALIDATE(1) |
			 V_TF_DDP_BUF1_FLUSH(1) | V_TF_DDP_PUSH_DISABLE_1(1) |
			 V_TF_DDP_BUF1_VALID(1) | V_TF_DDP_BUF0_VALID(1) |
			 V_TF_DDP_ACTIVE_BUF(1) | V_TF_DDP_INDICATE_OUT(1) |
			 (M_TCB_RX_DDP_BUF0_OFFSET <<
			  (S_TCB_RX_DDP_BUF0_OFFSET + 32)), modulate);
	return 0;
}
#endif


/*
 * 
 */
void t3_cancel_ubuf(struct sock *sk, long *timeo)
{
	struct ddp_state *p = DDP_STATE(sk);
	int rc;
	int ubuf_pending = t3_ddp_ubuf_pending(sk);
	long gettcbtimeo;
	int canceled=0;
	int norcv=0;

#ifdef	LINUX_2_4
	DECLARE_WAITQUEUE(wait, current);
#else
	DEFINE_WAIT(wait);
#endif	/* LINUX_2_4 */

	
	if (!p->ddp_setup || !p->pdev)
		return;

	gettcbtimeo = max_t(long, msecs_to_jiffies(1), *timeo);
	p->cancel_ubuf = 1;

	while (ubuf_pending && !norcv) {
#ifdef T3_TRACE
		T3_TRACE3(TIDTB(sk), 
		  "t3_cancel_ubuf: flags0 0x%x flags1 0x%x get_tcb_count %d",
		  p->buf_state[0].flags & (DDP_BF_NOFLIP | DDP_BF_NOCOPY), 
		  p->buf_state[1].flags & (DDP_BF_NOFLIP | DDP_BF_NOCOPY),
		  p->get_tcb_count);
#endif
		if (!canceled && !p->get_tcb_count) {
			canceled = 1;
			t3_cancel_ddpbuf(sk, p->cur_buf);
		}

#ifdef	LINUX_2_4
		add_wait_queue(sk->sleep, &wait);
#endif	/* LINUX_2_4 */
		do {
#ifdef	LINUX_2_4
			set_current_state(TASK_INTERRUPTIBLE);
#else
			prepare_to_wait(sk_sleep(sk), &wait, 
					TASK_INTERRUPTIBLE);
#endif	/* LINUX_2_4 */
			rc = sk_wait_event(sk, &gettcbtimeo, 
					   !(DDP_STATE(sk)->ddp_setup ? DDP_STATE(sk)->get_tcb_count : 0) &&
					   !(sk->sk_shutdown & RCV_SHUTDOWN));
			p = DDP_STATE(sk);
			
#ifndef LINUX_2_4
			finish_wait(sk_sleep(sk), &wait);
#endif	/* LINUX_2_4 */
			if (signal_pending(current))
				break;

			gettcbtimeo = max_t(long, gettcbtimeo << 1, *timeo);
			norcv = (sk->sk_err == ECONNRESET) || (sk->sk_shutdown & RCV_SHUTDOWN);
		} while ((p->ddp_setup ? p->get_tcb_count : 0) && !norcv);

#ifdef	LINUX_2_4
		set_current_state(TASK_RUNNING);
		remove_wait_queue(sk->sleep, &wait);
#endif	/* LINUX_2_4 */

		ubuf_pending = t3_ddp_ubuf_pending(sk);

		if (signal_pending(current))
			break;
	}

	while (t3_ddp_ubuf_pending(sk) && !norcv) {
		if (!canceled && !p->get_tcb_count) {
			canceled=1;
			t3_cancel_ddpbuf(sk, p->cur_buf);
		}

		do {
			release_sock(sk);
			gettcbtimeo = (net_random() % (HZ / 2)) + 2;
			__set_current_state(TASK_UNINTERRUPTIBLE);
			schedule_timeout(gettcbtimeo);
			lock_sock(sk);
			p = DDP_STATE(sk);
			norcv = (sk->sk_err == ECONNRESET) || (sk->sk_shutdown & RCV_SHUTDOWN);
		} while ((p->ddp_setup ? p->get_tcb_count : 0) && !norcv);
	}

	if (p->ddp_setup)
		p->cancel_ubuf = 0;
		
	return;
}

#define OVERLAY_MASK (V_TF_DDP_PSH_NO_INVALIDATE0(1) | \
		      V_TF_DDP_PSH_NO_INVALIDATE1(1) | \
		      V_TF_DDP_BUF1_FLUSH(1) | \
		      V_TF_DDP_BUF0_FLUSH(1) | \
		      V_TF_DDP_PUSH_DISABLE_1(1) | \
		      V_TF_DDP_PUSH_DISABLE_0(1) | \
		      V_TF_DDP_INDICATE_OUT(1))

/*
 * Post a user buffer as an overlay on top of the current kernel buffer.
 */
int t3_overlay_ubuf(struct sock *sk, const struct iovec *iov,
		    int nonblock, int rcv_flags, int modulate, int post_kbuf)
{
	int len, ubuf_idx;
	unsigned long flags;
	struct ddp_state *p = DDP_STATE(sk);

	if (!p->ddp_setup || !p->pdev)
		return -1;

	len = setup_iovec_ppods(sk, iov, 0);
	if (len < 0)
		return len;

	ubuf_idx = p->kbuf_idx;
	p->buf_state[ubuf_idx].flags = DDP_BF_NOFLIP;
	/* Use existing offset */
	/* Don't need to update .gl, user buffer isn't copied. */
	p->cur_buf = ubuf_idx;

	flags = select_ddp_flags(sk, ubuf_idx, nonblock, rcv_flags);

	if (post_kbuf) {
		struct ddp_buf_state *dbs = &p->buf_state[ubuf_idx ^ 1];

		dbs->cur_offset = 0;
		dbs->flags = 0;
		dbs->gl = p->kbuf[ubuf_idx ^ 1];
		p->kbuf_idx ^= 1;
		flags |= p->kbuf_idx ?
			 V_TF_DDP_BUF1_VALID(1) | V_TF_DDP_PUSH_DISABLE_1(0) :
			 V_TF_DDP_BUF0_VALID(1) | V_TF_DDP_PUSH_DISABLE_0(0);
	}

	if (ubuf_idx == 0) {
		t3_overlay_ddpbuf(sk, 0, p->ubuf_tag << 6, p->kbuf_tag[1] << 6,
				  len);
		t3_setup_ddpbufs(sk, 0, 0, p->kbuf[1]->length, 0,
				 flags,
				 OVERLAY_MASK | flags, 1);
	} else {
		t3_overlay_ddpbuf(sk, 1, p->kbuf_tag[0] << 6, p->ubuf_tag << 6,
				  len);
		t3_setup_ddpbufs(sk, p->kbuf[0]->length, 0, 0, 0,
				 flags,
				 OVERLAY_MASK | flags, 1);
	}
#ifdef T3_TRACE
	T3_TRACE5(TIDTB(sk),
		  "t3_overlay_ubuf: tag %u flags 0x%x mask 0x%x ubuf_idx %d "
		  " kbuf_idx %d",
		   p->ubuf_tag, flags, OVERLAY_MASK, ubuf_idx, p->kbuf_idx);
#endif
	return 0;
}

/*
 * Clean up DDP state that needs to survive until socket close time, such as the
 * DDP buffers.  The buffers are already unmapped at this point as unmapping
 * needs the PCI device and a socket may close long after the device is removed.
 */
void t3_cleanup_ddp(struct sock *sk)
{
	struct ddp_state *p = DDP_STATE(sk);
	int idx;

	if (!p->ddp_setup)
		return;

	for (idx = 0; idx < NUM_DDP_KBUF; idx++)
		if (p->kbuf[idx]) {
			ddp_gl_free_pages(p->kbuf[idx]);
			kfree(p->kbuf[idx]);
		}

	if (p->ubuf) {
		ddp_gl_free_pages(p->ubuf);
		kfree(p->ubuf);
	}
	p->ddp_setup = 0;
}

/*
 * This is a companion to t3_cleanup_ddp() and releases the HW resources
 * associated with a connection's DDP state, such as the page pods.
 * It's called when HW is done with a connection.   The rest of the state
 * remains available until both HW and the app are done with the connection.
 */
void t3_release_ddp_resources(struct sock *sk)
{
	struct ddp_state *p = DDP_STATE(sk);

	if (p->ddp_setup) {
		struct tom_data *d = TOM_DATA(CPL_IO_STATE(sk)->toedev);
		int idx;
		
		for (idx = 0; idx < NUM_DDP_KBUF; idx++) {
			t3_free_ppods(d, p->kbuf_tag[idx], 
				      p->kbuf_nppods[idx]);
			unmap_ddp_gl(p->pdev, p->kbuf[idx]);
		}

		if (p->ubuf_nppods) {
			t3_free_ppods(d, p->ubuf_tag, p->ubuf_nppods);
			p->ubuf_nppods = 0;
		}
		if (p->ubuf)
			unmap_ddp_gl(p->pdev, p->ubuf);

		p->pdev = NULL;
	}
}
#if 0
void t3_post_kbuf(struct sock *sk, int modulate)
{
	struct ddp_state *p = DDP_STATE(sk);

	t3_set_ddp_tag(sk, 0, p->kbuf_tag[0] << 6);
	t3_set_ddp_buf(sk, 0, 0, p->kbuf[0]->length);
	t3_repost_kbuf(sk, modulate, 1);

#ifdef T3_TRACE
	T3_TRACE1(TIDTB(sk),
		  "t3_post_kbuf: cur_buf = kbuf_idx = %u ", p->cur_buf);
#endif
}
#else
void t3_post_kbuf(struct sock *sk, int modulate, int nonblock)
{
	struct ddp_state *p = DDP_STATE(sk);

	t3_set_ddp_tag(sk, p->cur_buf, p->kbuf_tag[p->cur_buf] << 6);
	t3_set_ddp_buf(sk, p->cur_buf, 0, p->kbuf[p->cur_buf]->length);
	t3_repost_kbuf(sk, p->cur_buf, modulate, 1, nonblock);


#ifdef T3_TRACE
	T3_TRACE1(TIDTB(sk),
		  "t3_post_kbuf: cur_buf = kbuf_idx = %u ", p->cur_buf);
#endif
}
#endif

/*
 * Prepare a socket for DDP.  Must be called when the socket is known to be
 * open.
 */
int t3_enter_ddp(struct sock *sk, unsigned int kbuf_size, unsigned int waitall, int nonblock)
{
	int i, err = -ENOMEM;
	unsigned int nppods, kbuf_pages, idx, dack_mode = 0;
	struct ddp_state *p = DDP_STATE(sk);
	struct toedev *tdev = CPL_IO_STATE(sk)->toedev;
	struct tom_data *d = TOM_DATA(tdev);

	if (kbuf_size > M_TCB_RX_DDP_BUF0_LEN)
		return -EINVAL;

	kbuf_pages = (kbuf_size + PAGE_SIZE - 1) >> PAGE_SHIFT;
	nppods = pages2ppods(kbuf_pages);
	
	/* start the initialization of DDP state */
	BUG_ON(p->ddp_setup);
	memset((void *)p, 0, sizeof *p);
	p->ddp_setup = 1;

	p->pdev = d->pdev;
	p->kbuf_noinval = !!waitall;
	
	p->kbuf_tag[NUM_DDP_KBUF - 1] = -1;
	for (idx = 0; idx < NUM_DDP_KBUF; idx++) {
		p->kbuf[idx] = 
		    kmalloc(sizeof (struct ddp_gather_list) + kbuf_pages * 
			    (sizeof(dma_addr_t) + sizeof(struct page *)),
			    GFP_KERNEL);
		if (!p->kbuf[idx])
			goto err;

		p->kbuf_tag[idx] = t3_alloc_ppods(d, nppods);
		if (p->kbuf_tag[idx] < 0)
			goto err;

		p->kbuf_nppods[idx] = nppods;
		p->kbuf[idx]->length = kbuf_size;
		p->kbuf[idx]->offset = 0;
		p->kbuf[idx]->nelem = kbuf_pages;
		p->kbuf[idx]->pages = 
		    (struct page **)&p->kbuf[idx]->phys_addr[kbuf_pages];

		for (i = 0; i < kbuf_pages; ++i) {
			p->kbuf[idx]->pages[i] = alloc_page(sk->sk_allocation);
			if (!p->kbuf[idx]->pages[i]) {
				p->kbuf[idx]->nelem = i;
				goto err;
			}
		}

		for (i = 0; i < kbuf_pages; ++i) {
			p->kbuf[idx]->phys_addr[i] = 
			    pci_map_page(p->pdev, p->kbuf[idx]->pages[i],
					 0, PAGE_SIZE, PCI_DMA_FROMDEVICE);
			if (unlikely(t3_pci_dma_mapping_error(p->pdev,
						p->kbuf[idx]->phys_addr[i]))) {
				err = -ENOMEM;
				goto err;
			}
		}		
		t3_setup_ppods(sk, p->kbuf[idx], nppods, p->kbuf_tag[idx], 
			       p->kbuf[idx]->length, 0, 0);
	}
	t3_set_ddp_tag(sk, 0, p->kbuf_tag[0] << 6);
	t3_set_ddp_buf(sk, 0, 0, p->kbuf[0]->length);
	t3_repost_kbuf(sk, 0, 0, 1, nonblock);

	dack_mode = t3_select_delack(sk);

        if (dack_mode == 1) {
                t3_set_tcb_field(sk, W_TCB_T_FLAGS1, V_TF_RCV_COALESCE_ENABLE(1ULL)|
                                                        V_TF_DACK_MSS(1ULL)|
                                                        V_TF_DACK(1ULL),
                                                        (unsigned long long)TOM_TUNABLE(tdev,ddp_rcvcoalesce)|
                                                        V_TF_DACK(1ULL));
        } else if (dack_mode == 2) {
                t3_set_tcb_field(sk, W_TCB_T_FLAGS1, V_TF_RCV_COALESCE_ENABLE(1ULL)|
                                                        V_TF_DACK_MSS(1ULL)|
                                                        V_TF_DACK(1ULL),
                                                        (unsigned long long)TOM_TUNABLE(tdev,ddp_rcvcoalesce)|
                                                        V_TF_DACK_MSS(1ULL));
        } else if (dack_mode == 3) {
                t3_set_tcb_field(sk, W_TCB_T_FLAGS1, V_TF_RCV_COALESCE_ENABLE(1ULL)|
                                                        V_TF_DACK_MSS(1ULL)|
                                                        V_TF_DACK(1ULL),
                                                        (unsigned long long)TOM_TUNABLE(tdev,ddp_rcvcoalesce)|
                                                        V_TF_DACK(1ULL)|
                                                        V_TF_DACK(1ULL));
        }

#ifdef T3_TRACE
	T3_TRACE4(TIDTB(sk),
		  "t3_enter_ddp: kbuf_size %u waitall %u tag0 %d tag1 %d",
		   kbuf_size, waitall, p->kbuf_tag[0], p->kbuf_tag[1]);
#endif

	return 0;

err:
	t3_release_ddp_resources(sk);
	t3_cleanup_ddp(sk);
	return err;
}

int t3_ddp_copy(const struct sk_buff *skb, int offset, struct iovec *to,
		int len)
{
	int err, page_no, page_off; 
	struct ddp_gather_list *gl = skb_gl(skb);

	if (!gl->pages) {
		dump_stack();
		BUG_ON(1);
	}

	offset += gl->offset + skb_ulp_ddp_offset(skb);
	page_no = offset >> PAGE_SHIFT;
	page_off = offset & ~PAGE_MASK;

	while (len) {
		int copy = min_t(int, len, PAGE_SIZE - page_off);

		err = memcpy_toiovec(to, page_address(gl->pages[page_no]) +
				     page_off, copy);
		if (err)
			return -EFAULT;
		page_no++;
		page_off = 0;
		len -= copy;
	}
	return 0;
}

/* Pagepod allocator */

/*
 * Allocate n page pods.  Returns -1 on failure or the page pod tag.
 */
int t3_alloc_ppods(struct tom_data *td, unsigned int n)
{
	unsigned int i, j;

	if (unlikely(!td->ppod_map))
		return -1;

	spin_lock_bh(&td->ppod_map_lock);
	/*
	 * Look for n consecutive available page pods.
	 * Make sure to guard from scanning beyond the table.
	 */
	for (i = 0; i + n - 1 < td->nppods; ) {
		for (j = 0; j < n; ++j)          /* scan ppod_map[i..i+n-1] */
			if (td->ppod_map[i + j]) {
				i = i + j + 1;
				goto next;
			}

		memset(&td->ppod_map[i], 1, n);   /* allocate range */
		spin_unlock_bh(&td->ppod_map_lock);
		return i;
next:		;
	}
	spin_unlock_bh(&td->ppod_map_lock);
	return -1;
}

void t3_free_ppods(struct tom_data *td, unsigned int tag, unsigned int n)
{
	/* No need to take ppod_lock here */
	memset(&td->ppod_map[tag], 0, n);
}
