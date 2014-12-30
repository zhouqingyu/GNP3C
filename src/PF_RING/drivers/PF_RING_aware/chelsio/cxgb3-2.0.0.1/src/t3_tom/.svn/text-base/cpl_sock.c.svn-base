/*
 * This file implements the interface between the socket layer and
 * the HW TCP/CPL, including the protocol operations for Chelsio's HW TCP.
 *
 * Large portions of this file are taken from net/ipv4/tcp.c.
 * See that file for copyrights of the original code.
 * Any additional code is
 *
 * Copyright (C) 2003-2009 Chelsio Communications.  All rights reserved.
 *
 * Written by Dimitris Michailidis (dm@chelsio.com)
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59
 * Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#include "defs.h"
#include <linux/types.h>
#include <linux/fcntl.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/toedev.h>
#include <linux/module.h>

#if defined(CONFIG_T3_ZCOPY_SENDMSG) || defined(CONFIG_T3_ZCOPY_SENDMSG_MODULE)
#include <linux/pagemap.h>
#include <linux/mm.h>
#endif

#include <net/offload.h>
#include <net/tcp.h>
#include <net/ip.h>
#include <asm/uaccess.h>
#include <asm/ioctls.h>
#include "t3_ddp.h"
#include "tom.h"
#include "tcb.h"
#include "firmware_exports.h"
#include "trace.h"

/*
 * This must be called with the socket locked, otherwise dev may be NULL.
 */
static inline int chelsio_wspace(const struct sock *sk)
{
	struct toedev *dev = CPL_IO_STATE(sk)->toedev;

	return dev ? TOM_TUNABLE(dev, max_host_sndbuf) - sk->sk_wmem_queued : 0;
}

/*
 * TCP socket write_space callback.  Follows sk_stream_write_space().
 */
void t3_write_space(struct sock *sk)
{
	struct socket *sock = sk->sk_socket;

	if (chelsio_wspace(sk) >= sk_stream_min_wspace(sk) && sock) {
		clear_bit(SOCK_NOSPACE, &sock->flags);
		sk_wakeup_sleepers(sk, 1);
		sk_wake_async(sk, 2, POLL_OUT);
	}
}

static inline int tcp_memory_free(struct sock *sk)
{
	return chelsio_wspace(sk) > 0;
}

/*
 * Wait for memory to become available, either space in a socket's send buffer
 * or system memory.
 */
static int wait_for_mem(struct sock *sk, long *timeout)
{
	int sndbuf, err = 0;
	long vm_wait = 0;
	long current_timeo = *timeout;

#ifdef	LINUX_2_4
	DECLARE_WAITQUEUE(wait, current);
#else
	DEFINE_WAIT(wait);
#endif	/* LINUX_2_4 */

	/*
	 * We open code tcp_memory_free() because we need it outside the
	 * socket lock and chelsio_wspace() isn't safe there.
	 */
	sndbuf = TOM_TUNABLE(CPL_IO_STATE(sk)->toedev, max_host_sndbuf);

	if (sndbuf > sk->sk_wmem_queued)
		current_timeo = vm_wait = (net_random() % (HZ / 5)) + 2;

#ifdef	LINUX_2_4
	add_wait_queue(sk->sleep, &wait);
#endif	/* LINUX_2_4 */
	for (;;) {
		set_bit(SOCK_ASYNC_NOSPACE, &sk->sk_socket->flags);

#ifdef	LINUX_2_4
		set_current_state(TASK_INTERRUPTIBLE);
#else
		prepare_to_wait(sk_sleep(sk), &wait, TASK_INTERRUPTIBLE);
#endif	/* LINUX_2_4 */
		if (sk->sk_err || (sk->sk_shutdown & SEND_SHUTDOWN)) {
			err = -EPIPE;
			break;
		}
		if (!*timeout) {
			err = -EAGAIN;
			break;
		}
		if (signal_pending(current)) {
			err = sock_intr_errno(*timeout);
			break;
		}
		clear_bit(SOCK_ASYNC_NOSPACE, &sk->sk_socket->flags);
		if (sndbuf > sk->sk_wmem_queued && !vm_wait)
			break;

		set_bit(SOCK_NOSPACE, &sk->sk_socket->flags);
		sk->sk_write_pending++;
		release_sock(sk);

		if (!sk->sk_err && !(sk->sk_shutdown & SEND_SHUTDOWN) &&
		    (sndbuf <= sk->sk_wmem_queued || vm_wait))
			current_timeo = schedule_timeout(current_timeo);

		lock_sock(sk);
		sk->sk_write_pending--;

		if (vm_wait) {
			vm_wait -= current_timeo;
			current_timeo = *timeout;
			if (current_timeo != MAX_SCHEDULE_TIMEOUT &&
			    (current_timeo -= vm_wait) < 0)
				current_timeo = 0;
			vm_wait = 0;
		}
		*timeout = current_timeo;
	}

#ifdef	LINUX_2_4
	current->state = TASK_RUNNING;
	remove_wait_queue(sk->sleep, &wait);
#else
	finish_wait(sk_sleep(sk), &wait);
#endif	/* LINUX_2_4 */
	return err;
}

static void skb_entail(struct sock *sk, struct sk_buff *skb, int flags)
{
	struct tcp_sock *tp = tcp_sk(sk);

	ULP_SKB_CB(skb)->seq = tp->write_seq;
	ULP_SKB_CB(skb)->flags = flags;
	__skb_queue_tail(&sk->sk_write_queue, skb);
	sk->sk_wmem_queued += skb->truesize;
	// tcp_charge_skb(sk, skb);

	// Do not share pages across sk_buffs
	if (TCP_PAGE(sk) && TCP_OFF(sk)) {
		put_page(TCP_PAGE(sk));
		TCP_PAGE(sk) = NULL;
		TCP_OFF(sk) = 0;
	}
}

/*
 * Returns true if a connection should send more data to the TOE ASAP.
 */
static inline int should_push(struct sock *sk)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	struct toedev *dev = cplios->toedev;

	/*
	 * If there aren't any work requests in flight, or there isn't enough
	 * data in flight, or Nagle is off then send the current TX_DATA
	 * otherwise hold it and wait to accumulate more data.
	 */
	return cplios->wr_avail == cplios->wr_max ||
	    tp->snd_nxt - tp->snd_una <= TOM_TUNABLE(dev, tx_hold_thres) ||
	    (tp->nonagle & TCP_NAGLE_OFF);
}

/*
 * Returns true if a TCP socket is corked.
 */
static inline int corked(const struct tcp_sock *tp, int flags)
{
	return (flags & MSG_MORE) | (tp->nonagle & TCP_NAGLE_CORK);
}

/*
 * Returns true if a send should try to push new data.
 */
static inline int send_should_push(struct sock *sk, int flags)
{
	return should_push(sk) && !corked(tcp_sk(sk), flags);
}

static inline void tx_skb_finalize(struct sk_buff *skb)
{
	struct ulp_skb_cb *cb = ULP_SKB_CB(skb);

#if defined(CONFIG_T3_ZCOPY_SENDMSG) || defined(CONFIG_T3_ZCOPY_SENDMSG_MODULE)
	/*
	 * XXX We don't want to finalize an skb if it's flagged for ZCOPY
	 * XXX since we'll end up losing the flag.  This needs to be looked
	 * XXX at more closely since we're blindly clearing a bunch of flags
	 * XXX here.  Most of these flags (including those for ZCOPY)
	 * XXX probably ought to be retained rather than tossed and we
	 * XXX should certainly have an assert for flags that shouldn't
	 * XXX find their way into this routine ...
	 */
	if (cb->flags & (ULPCB_FLAG_ZCOPY|ULPCB_FLAG_ZCOPY_COW))
		return;
#endif

	cb->flags = ULPCB_FLAG_NO_APPEND | ULPCB_FLAG_NEED_HDR;
}

static inline void mark_urg(struct tcp_sock *tp, int flags,
			    struct sk_buff *skb)
{
	if (unlikely(flags & MSG_OOB)) {
		tp->snd_up = tp->write_seq;
		ULP_SKB_CB(skb)->flags = ULPCB_FLAG_URG | ULPCB_FLAG_BARRIER |
					 ULPCB_FLAG_NO_APPEND |
					 ULPCB_FLAG_NEED_HDR;
	}
}

/*
 * Decide if the last frame on the send queue needs any special annotations
 * (e.g., marked URG) and whether it should be transmitted immediately or
 * held for additional data.  This is the only routine that performs the full
 * suite of tests for a Tx packet and therefore must be called for the last
 * packet added by the various send*() APIs.
 */
static void tcp_push(struct sock *sk, int flags)
{
	int qlen = skb_queue_len(&sk->sk_write_queue);

	if (likely(qlen)) {
		struct tcp_sock *tp = tcp_sk(sk);
		struct sk_buff *skb = sk->sk_write_queue.prev;

		mark_urg(tp, flags, skb);

		if (!(ULP_SKB_CB(skb)->flags & ULPCB_FLAG_NO_APPEND) &&
		    corked(tp, flags)) {
			ULP_SKB_CB(skb)->flags |= ULPCB_FLAG_HOLD;
			return;
		}

		ULP_SKB_CB(skb)->flags &= ~ULPCB_FLAG_HOLD;
		if (qlen == 1 &&
		    ((ULP_SKB_CB(skb)->flags & ULPCB_FLAG_NO_APPEND) ||
		     should_push(sk)))
			t3_push_frames(sk, 1);
	}
}

static void tcp_uncork(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

	if (tp->nonagle & TCP_NAGLE_CORK) {
		tp->nonagle &= ~TCP_NAGLE_CORK;
		tcp_push(sk, 0);
	}
}

/*
 * Try to transmit the send queue if it has just one packet.  This is intended
 * to be called as full packets are added to the send queue by the various
 * send*() APIs when we expect additional packets to be generated by the
 * current API call.  It should not be called for the last packet generated,
 * use the full tcp_push call above for that.
 */
static inline void push_frames_if_head(struct sock *sk)
{
	if (skb_queue_len(&sk->sk_write_queue) == 1)
		t3_push_frames(sk, 1);
}

static struct sk_buff *alloc_tx_skb(struct sock *sk, int size)
{
	struct sk_buff *skb;

	skb = alloc_skb(size + TX_HEADER_LEN, sk->sk_allocation);
	if (likely(skb)) {
		skb_reserve(skb, TX_HEADER_LEN);
		skb_entail(sk, skb, ULPCB_FLAG_NEED_HDR);
	}
	return skb;
}

static int chelsio_sendpage(struct sock *sk, struct page *page, int offset,
			    size_t size, int flags)
{
	long timeo;
	int mss, err, copied = 0;
	struct tcp_sock *tp = tcp_sk(sk);

	lock_sock(sk);
	timeo = sock_sndtimeo(sk, flags & MSG_DONTWAIT);

	/* Wait for connection establishment to finish. */
	if (!sk_in_state(sk, TCPF_ESTABLISHED | TCPF_CLOSE_WAIT) &&
	    (err = sk_stream_wait_connect(sk, &timeo)) != 0)
		goto out_err;

	clear_bit(SOCK_ASYNC_NOSPACE, &sk->sk_socket->flags);

	err = -EPIPE;
	if (sk->sk_err || (sk->sk_shutdown & SEND_SHUTDOWN))
		goto out_err;

	mss = TOM_TUNABLE(CPL_IO_STATE(sk)->toedev, mss);

	cplios_set_flag(sk, CPLIOS_TX_MORE_DATA);
	while (size > 0) {
		int copy, i;
		struct sk_buff *skb = skb_peek_tail(&sk->sk_write_queue);

		if (!skb || (ULP_SKB_CB(skb)->flags & ULPCB_FLAG_NO_APPEND) ||
		    (copy = mss - skb->len) <= 0) {
new_buf:
			if (!tcp_memory_free(sk))
				goto wait_for_sndbuf;

			skb = alloc_tx_skb(sk, 0);
			if (!skb)
				goto wait_for_memory;

			copy = mss;
		}

		if (copy > size)
			copy = size;

		i = skb_shinfo(skb)->nr_frags;
		if (skb_can_coalesce(skb, i, page, offset)) {
			skb_shinfo(skb)->frags[i - 1].size += copy;
		} else if (i < MAX_SKB_FRAGS) {
			get_page(page);
			skb_fill_page_desc(skb, i, page, offset, copy);
		} else {
			tx_skb_finalize(skb);
			push_frames_if_head(sk);
			goto new_buf;
		}

		skb->len += copy;
		if (skb->len == mss)
			tx_skb_finalize(skb);
		skb->data_len += copy;
		skb->truesize += copy;
		sk->sk_wmem_queued += copy;
		tp->write_seq += copy;
		copied += copy;
		offset += copy;
		size -= copy;
		if (!size)
			break;

		if (unlikely(ULP_SKB_CB(skb)->flags & ULPCB_FLAG_NO_APPEND))
			push_frames_if_head(sk);
		continue;

wait_for_sndbuf:
		set_bit(SOCK_NOSPACE, &sk->sk_socket->flags);
wait_for_memory:
		if ((err = wait_for_mem(sk, &timeo)) != 0)
			goto do_error;
	}

out:
	cplios_reset_flag(sk, CPLIOS_TX_MORE_DATA);
	if (copied)
		tcp_push(sk, flags);
done:
	release_sock(sk);
	return copied;

do_error:
	if (copied)
		goto out;
out_err:
	cplios_reset_flag(sk, CPLIOS_TX_MORE_DATA);
	copied = sk_stream_error(sk, flags, err);
	goto done;
}

/*
 * Add a list of skbs to a socket send queue.  This interface is intended for
 * use by in-kernel ULPs.  The skbs must comply with the max size limit of the
 * device and have a headroom of at least TX_HEADER_LEN bytes.
 */
int t3_sendskb(struct sock *sk, struct sk_buff *skb, int flags)
{
	struct sk_buff *next;
	struct tcp_sock *tp = tcp_sk(sk);
	int mss, err, copied = 0;
	long timeo;

	lock_sock(sk);
	timeo = sock_sndtimeo(sk, flags & MSG_DONTWAIT);

	if (!sk_in_state(sk, TCPF_ESTABLISHED | TCPF_CLOSE_WAIT) &&
	    (err = sk_stream_wait_connect(sk, &timeo)) != 0)
		goto out_err;

	clear_bit(SOCK_ASYNC_NOSPACE, &sk->sk_socket->flags);

	err = -EPIPE;
	if (sk->sk_err || (sk->sk_shutdown & SEND_SHUTDOWN))
		goto out_err;

	/*
	 * We check for send buffer space once for the whole skb list.  It
	 * isn't critical if we end up overrunning the send buffer limit as we
	 * do not allocate any new memory.  The benefit is we don't need to
	 * perform intermediate packet pushes.
	 */
	while (!tcp_memory_free(sk)) {
		set_bit(SOCK_NOSPACE, &sk->sk_socket->flags);
		if ((err = wait_for_mem(sk, &timeo)) != 0)
			goto out_err;
	}

	mss = TOM_TUNABLE(CPL_IO_STATE(sk)->toedev, mss);

	while (skb) {
		if (unlikely(skb_headroom(skb) < TX_HEADER_LEN)) {
			err = -EINVAL;
			goto out_err;
		}

		if (unlikely(skb->len > mss)) {
			err = -EMSGSIZE;
			goto out_err;
		}

		next = skb->next;
		skb->next = NULL;
		skb_entail(sk, skb, ULPCB_FLAG_NO_APPEND | ULPCB_FLAG_NEED_HDR);
		copied += skb->len;
		tp->write_seq += skb->len + ulp_extra_len(skb);
		skb = next;
	}
done:
	if (likely(skb_queue_len(&sk->sk_write_queue)))
		t3_push_frames(sk, 1);
	release_sock(sk);
	return copied;

out_err:
	if (copied == 0)
		copied = sk_stream_error(sk, flags, err);
	goto done;
}
EXPORT_SYMBOL(t3_sendskb);

/*
 * Add data to an sk_buff page fragment.
 */
static int tcp_copy_to_page(struct sock *sk, const void __user *from,
			    struct sk_buff *skb, struct page *page, int off,
			    int copy)
{
	if (copy_from_user(page_address(page) + off, from, copy))
		return -EFAULT;

	skb->len += copy;
	skb->data_len += copy;
	skb->truesize += copy;
	sk->sk_wmem_queued += copy;
	return 0;
}

/*
 * Add data to the main data portion of an sk_buff.
 */
static inline int ch_skb_add_data(struct sk_buff *skb, const void __user *from,
				  unsigned int copy)
{
	int orig_len = skb->len;

	if (!copy_from_user(skb_put(skb, copy), from, copy))
		return 0;

	__skb_trim(skb, orig_len);
	return -EFAULT;
}

/*
 * Calculate the size for a new send sk_buff.  It's maximum size so we can
 * pack lots of data into it, unless we plan to send it immediately, in which
 * case we size it more tightly.
 *
 * Note: we don't bother compensating for MSS < PAGE_SIZE because it doesn't
 * arise in normal cases and when it does we are just wasting memory.
 */
static inline int select_size(struct sock *sk, int io_len, int flags)
{
	const int pgbreak = SKB_MAX_HEAD(TX_HEADER_LEN);

	/*
	 * If the data wouldn't fit in the main body anyway, put only the
	 * header in the main body so it can use immediate data and place all
	 * the payload in page fragments.
	 */
	if (io_len > pgbreak)
		return 0;

	/*
	 * If we will be accumulating payload get a large main body.
	 */
	if (!send_should_push(sk, flags))
		return pgbreak;

	return io_len;
}

#if defined(CONFIG_T3_ZCOPY_SENDMSG) || defined(CONFIG_T3_ZCOPY_SENDMSG_MODULE)
/*
 * ZCOPY_SENDMSG maps (if necessary) and pins a user space buffer instead of
 * copying the payload from user- to kernel space. In normal mode of
 * operation, we block until the DMA has completed and it is safe to return
 * (considering that the user might modifies the buffer). Since host bus
 * performance (PCI-E x8 and PCI-X 2.0) now exceeds the wire speed, this
 * actually works pretty well. In addition, I added some tunables to do a
 * hybrid scheme where the end of the user space buffer is copied (at the same
 * the beginning of the buffer is DMAed). The mechanism provides enough
 * pipelinging to achieve 10Gbps linerate on a single connection with moderate
 * CPU utilization.
 *
 * Now, the exception (which as usual makes up for most of the code and 
 * complexity): while unlikely, there are scenarios where we want to return 
 * before the DMA completes (i.e. the DMA might not complete if a connection
 * doesn't drain (somebody unplugged the cable *&%!) or we want to return for 
 * anther reason, i.e. because we got a signal. In that case, we must make 
 * sure that the user doesn't modify the buffer before the DMA has 
 * completed... yes, you guessed correctly, by remapping the buffer as COW and
 * yes, that has some cost associated with it starting with mandatory TLB 
 * flush and potential page fault and buffer copy (what we wanted to avoid).
 * However, it is NOT THE NORMAL case and rare!
 *
 * Written by Felix Marti (felix@chelsio.com)
 */
#include <asm/pgtable.h>
#ifndef	LINUX_2_4
#include <asm/tlbflush.h>
#endif	/* LINUX_2_4 */
#include <linux/hugetlb.h>

#define ZCOPY_PRT(m)

/*
 * zcopy_to_skb() maps the user space buffer (from/size) and fills in the skb
 * page descriptors to point to the buffer.
 */
static int zcopy_to_skb(struct sock *sk, struct sk_buff *skb, 
			unsigned long from, size_t size)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct page *pages[MAX_SKB_FRAGS];
	struct vm_area_struct *vmas[MAX_SKB_FRAGS];
	unsigned int off = from & (PAGE_SIZE - 1);
	int i, res, numpages = (size + off + (PAGE_SIZE - 1)) / PAGE_SIZE;
	unsigned int copied = 0;
	int err = 0;

	ZCOPY_PRT(("zcopy_to_skb: TID %u from %lx size %lu skb %p\n", 
		  CPL_IO_STATE(sk)->tid, from, size, skb));
	BUG_ON(numpages > MAX_SKB_FRAGS);

	down_read(&current->mm->mmap_sem);
	res = get_user_pages(current, current->mm,
			     from & PAGE_MASK, numpages,
			     0, 0,
			     pages, vmas);
	up_read(&current->mm->mmap_sem);
	if (unlikely(res != numpages)) {
		ZCOPY_PRT(("zcopy_to_skb: get_user_pages() returned %u instead"
			   " of %u pages\n", res, numpages));
		if (res < 0) {
			err = res;
			res = 0;
		} else
			err = -EFAULT;
		goto no_zcopy;
	}

	/*
	 * Scan through all of the returned pages to make sure they are
	 * appropriate zero copy candidates.  If any of the pages are
	 * problematic or if the address range crosses a VMA boundry we just
	 * reject the zero copy effort.
	 */
	for (i = 0; i < numpages; i++)
		if (!zcopy_vma(vmas[i]) || vmas[i] != vmas[0]) {
			err = -EINVAL;
			goto no_zcopy;
		}

	for (i = 0; i < numpages; i++) {
		unsigned int page_off, page_size;
		if (i == 0) {
			page_off = off;
			page_size = ((numpages == 1) ? size : PAGE_SIZE - off);
		} else if (i == (numpages - 1)) {
			page_off = 0;
			page_size = size;
		} else {
			page_off = 0;
			page_size = PAGE_SIZE;
		}
		BUG_ON(vmas[i] == 0 || pages[i] == 0);
		skb_fill_page_desc(skb, i, pages[i], page_off, page_size);
		copied += page_size;
		size -= page_size;
		ZCOPY_PRT(("zcopy_to_skb: p[%d] %p off %d size %d vma %p\n", 
			  i, pages[i], 0, page_size, vmas[i]));
	}
	BUG_ON(size);

	skb->len += copied;
	skb->data_len += copied;
	skb->truesize += copied;
	atomic_add(copied, &sk->sk_omem_alloc);
	sk->sk_wmem_queued += copied;
	tp->write_seq += copied;
	skb_vaddr_set(skb, from);

	return err;
 
 no_zcopy:
	for (i = 0; i < res; i++)
		page_cache_release(pages[i]);
	return err;
}

/*
 * If we're on an older kernel, we don't have the pte_offset_map_lock() macro
 * available to prevent race conditions accessing PTEs in an atomic fashion.
 * But on newer kernels, we use that mechanism exclusively and don't take the
 * memory map spin lock ...  This code is modeled on the mprotect() code
 * which does exactly what we want but isn't exported from the kernel.
 */
#if defined(pte_offset_map_lock)

#  define mprotect_page_table_lock(mm) \
	do { } while (0)
#  define mprotect_page_table_unlock(mm) \
	do { } while (0)

#else

#  define mprotect_page_table_lock(mm) \
	do { spin_lock(&(mm)->page_table_lock); } while (0)
#  define mprotect_page_table_unlock(mm) \
	do { spin_unlock(&(mm)->page_table_lock); } while (0)

#  define pgd_none_or_clear_bad(pgd) \
	(pgd_none(*(pgd)) || unlikely(pgd_bad(*(pgd))))
#  define pud_none_or_clear_bad(pud) \
	(pud_none(*(pud)) || unlikely(pud_bad(*(pud))))
#  define pmd_none_or_clear_bad(pmd) \
	(pmd_none(*(pmd)) || unlikely(pmd_bad(*(pmd))))

#  define pte_offset_map_lock(mm, pmd, address, ptl) \
	pte_offset_map(pmd, address)
#  define pte_unmap_unlock(pte, ptl) \
	pte_unmap(pte)

#endif /* !deinfed(pte_offset_map_lock) */

/*
 * We have an skb which has outstanding zero-copy DMA references to user pages
 * but we need to return to the user.  This sometimes happens when an
 * application sets up a timer or the user types a ^C.  Since the DMA hasn't
 * been acknowledged yet, we need to mark all of the pages referenced by the
 * skb as copy-on-write in order to fulfill standard UNIX write() semantics.
 * (I.e. writes to application memory buffers after a write() call returns cannot
 * affect the actual write results.)
 */
static int zcopy_skb_dma_pending(struct sock *sk, struct sk_buff *skb)
{
	struct vm_area_struct *vma;
	unsigned int wr_hdr_len = 
	    ULP_SKB_CB(skb)->flags & ULPCB_FLAG_NEED_HDR ? 
	        0 : sizeof (struct tx_data_wr);
	unsigned int len = skb->len - wr_hdr_len;
	unsigned long address = skb_vaddr(skb);
	unsigned long end = PAGE_ALIGN(address + len);
	int i;

	address &= PAGE_MASK;

	down_write(&current->mm->mmap_sem);
	vma = find_vma(current->mm, skb_vaddr(skb));
#if defined(CONFIG_T3_ZCOPY_HUGEPAGES) && defined(CONFIG_HUGETLB_PAGE)
	if (is_vm_hugetlb_page(vma)) { 
		pte_t *ptep = t3_huge_pte_offset(current->mm, vma->vm_start);
		if (ptep) {
			spin_lock(&current->mm->page_table_lock);
			if (!pte_none(*ptep)) {
				t3_ptep_set_wrprotect(current->mm, address, ptep);
				pte_unmap(ptep);
			}
			spin_unlock(&current->mm->page_table_lock);
		}
		for (i = 0; i < skb_shinfo(skb)->nr_frags; i++) { 
			skb_frag_t *frag = &skb_shinfo(skb)->frags[i];
			atomic_inc(&frag->page->_mapcount);
		}
	} else
#endif
	{
	mprotect_page_table_lock(current->mm);
	for (i = 0; i < skb_shinfo(skb)->nr_frags; i++, address += PAGE_SIZE) { 
		pgd_t *pgd;
		pud_t *pud;
		pmd_t *pmd;
		skb_frag_t *frag = &skb_shinfo(skb)->frags[i];

		/* make sure the page doesn't go away */
		atomic_inc(&frag->page->_mapcount);

		/*
		 * Dive down the PGD/PUD/PMD/PTE hierarchy for the page and
		 * mark it COW.  When we have a ZERO_PAGE() mapping, some
		 * portions of the hierarchy may be missing.  Since the
		 * ZERO_PAGE() is already COW and can never change, there's
		 * nothing we need to do.
		 */
		if ((pgd = pgd_offset(current->mm, address),
		     !(pgd_none(*pgd) || unlikely(pgd_bad(*pgd)))) &&
		    (pud = pud_offset(pgd, address),
		     !(pud_none(*pud) || unlikely(pud_bad(*pud)))) &&
		    (pmd = pmd_offset(pud, address),
		     !(pmd_none(*pmd) || unlikely(pmd_bad(*pmd))))) {
			spinlock_t *ptl __attribute__((unused));
			pte_t *pte = pte_offset_map_lock(current->mm, pmd,
							 address, &ptl);
			if (pte != NULL && pte_present(*pte))
				t3_ptep_set_wrprotect(current->mm, address, pte);
			pte_unmap_unlock(pte, ptl);
		}
	}
	mprotect_page_table_unlock(current->mm);
	}

	t3_flush_tlb_range(vma, skb_vaddr(skb), end);
	up_write(&current->mm->mmap_sem);

	ULP_SKB_CB(skb)->flags &= ~ULPCB_FLAG_ZCOPY;
	ULP_SKB_CB(skb)->flags |= ULPCB_FLAG_ZCOPY_COW;
	atomic_sub(len, &sk->sk_omem_alloc);
#ifdef T3_TRACE
	T3_TRACE5(TIDTB(sk),
		  "zcopy_skb_dma_pending: address 0x%lx len %u mm %p "
		  "mm_count %d need_hdr %d", 
		  address, len, current->mm, 
		  atomic_read(&current->mm->mm_count),
		  ULP_SKB_CB(skb)->flags & ULPCB_FLAG_NEED_HDR);
#endif

	return 0;
}

static void zcopy_skb_dma_complete(struct sock *sk, struct sk_buff *skb)
{
	int i;

	for (i = 0; i < skb_shinfo(skb)->nr_frags; i++) { 
		skb_frag_t *frag = &skb_shinfo(skb)->frags[i];
		atomic_dec(&frag->page->_mapcount);
	}

	ULP_SKB_CB(skb)->flags &= ~ULPCB_FLAG_ZCOPY_COW;
}

static int zcopy_dma_pending(struct sock *sk) 
{
	struct sk_buff *skb;
	int ret = 0;

	wr_queue_walk(sk, skb) {
		if (ULP_SKB_CB(skb)->flags & ULPCB_FLAG_ZCOPY) {
			ret = zcopy_skb_dma_pending(sk, skb);
			if (ret)
				return ret;
		}
	}

	skb_queue_walk(&sk->sk_write_queue, skb) {
		if (ULP_SKB_CB(skb)->flags & ULPCB_FLAG_ZCOPY) {
			ret = zcopy_skb_dma_pending(sk, skb);
			if (ret)
				return ret;
		}
	}

	return 0;
}

void t3_zcopy_cleanup_skb(struct sk_buff *skb)
{
	struct sock *sk = skb->sk;
	unsigned int hdr_len = 0;

	if (!(ULP_SKB_CB(skb)->flags & ULPCB_FLAG_NEED_HDR)) {
		struct tom_data *d = TOM_DATA(CPL_IO_STATE(sk)->toedev);
		hdr_len = sizeof (struct tx_data_wr);
		atomic_sub(skb->len - hdr_len, &d->tx_dma_pending);
	}

	if (ULP_SKB_CB(skb)->flags & ULPCB_FLAG_ZCOPY) {
		ULP_SKB_CB(skb)->flags &= ~ULPCB_FLAG_ZCOPY;
		atomic_sub(skb->len - hdr_len, &sk->sk_omem_alloc);
		if (!atomic_read(&sk->sk_omem_alloc))
			__wake_up(sk_sleep(sk), TASK_INTERRUPTIBLE, 0, NULL);
	} else if (ULP_SKB_CB(skb)->flags & ULPCB_FLAG_ZCOPY_COW)
		zcopy_skb_dma_complete(sk, skb);

	skb_vaddr_set(skb, 0);
}

static void zcopy_wait(struct sock *sk, long timeout)
{
#ifdef	LINUX_2_4
	DECLARE_WAITQUEUE(wait, current);
#else
	DEFINE_WAIT(wait);
#endif	/* LINUX_2_4 */

	timeout = max_t(long, HZ / 2, timeout);
#ifdef	LINUX_2_4
	add_wait_queue(sk->sleep, &wait);
#endif	/* LINUX_2_4 */
	while (atomic_read(&sk->sk_omem_alloc) && !sk->sk_err) {
#ifdef	LINUX_2_4
		set_current_state(TASK_INTERRUPTIBLE);
#else
		prepare_to_wait(sk_sleep(sk), &wait, TASK_INTERRUPTIBLE);
#endif	/* LINUX_2_4 */

		if (TOM_TUNABLE(CPL_IO_STATE(sk)->toedev,
				zcopy_sendmsg_ret_pending_dma)) {
			if (signal_pending(current) || !timeout) {
#ifdef T3_TRACE
				T3_TRACE4(TIDTB(sk), "zcopy_wait: sk_err %d "
					  "signal_pending 0x%x timeout %ld "
					  "sk_omem_alloc %d", sk->sk_err, 
					   signal_pending(current), timeout, 
					   atomic_read(&sk->sk_omem_alloc));
#endif
				if (!zcopy_dma_pending(sk)) {
					BUG_ON(atomic_read(&sk->sk_omem_alloc));
					break;
				}
			}
		} else if (!timeout)
			timeout = HZ / 2;
#ifdef T3_TRACE
		T3_TRACE1(TIDTB(sk), "zcopy_wait: GTS sk_omem_alloc %d",
			  atomic_read(&sk->sk_omem_alloc));
#endif
		release_sock(sk);
		timeout = schedule_timeout(timeout);
		lock_sock(sk);
	}
#ifdef	LINUX_2_4
	current->state = TASK_RUNNING;
	remove_wait_queue(sk->sleep, &wait);
#else
	finish_wait(sk_sleep(sk), &wait);
#endif	/* LINUX_2_4 */
}
#endif

#ifdef	LINUX_2_4
static int chelsio_sendmsg(struct sock *sk,
			   struct msghdr *msg, int size)
#else
static int chelsio_sendmsg(struct kiocb *iocb, struct sock *sk,
			   struct msghdr *msg, size_t size)
#endif	/* LINUX_2_4 */
{
	long timeo;
	struct iovec *iov;
	struct sk_buff *skb = NULL;
	struct tcp_sock *tp = tcp_sk(sk);
	struct toedev *tdev = CPL_IO_STATE(sk)->toedev;
	int mss, iovlen, flags, err, copied = 0, zcopy_size = 0, zcopied = 0;
#if defined(CONFIG_T3_ZCOPY_SENDMSG) || defined(CONFIG_T3_ZCOPY_SENDMSG_MODULE)
	struct tom_data *d;
	int omem_alloc;
#endif

	lock_sock(sk);
#if defined(CONFIG_T3_ZCOPY_SENDMSG) || defined(CONFIG_T3_ZCOPY_SENDMSG_MODULE)
	omem_alloc = atomic_read(&sk->sk_omem_alloc);
	atomic_set(&sk->sk_omem_alloc, 0);
#endif
	flags = msg->msg_flags;
	timeo = sock_sndtimeo(sk, flags & MSG_DONTWAIT);

	if (!sk_in_state(sk, TCPF_ESTABLISHED | TCPF_CLOSE_WAIT) &&
	    (err = sk_stream_wait_connect(sk, &timeo)) != 0)
		goto out_err;

	/* This should be in poll */
	clear_bit(SOCK_ASYNC_NOSPACE, &sk->sk_socket->flags);

	err = -EPIPE;
	if (sk->sk_err || (sk->sk_shutdown & SEND_SHUTDOWN))
		goto out_err;

	mss = TOM_TUNABLE(tdev, mss);

#if defined(CONFIG_T3_ZCOPY_SENDMSG) || defined(CONFIG_T3_ZCOPY_SENDMSG_MODULE)
	d = TOM_DATA(tdev);
	if (size >= TOM_TUNABLE(tdev, zcopy_sendmsg_partial_thres) && 
	    !corked(tp, flags) && !segment_eq(get_fs(), KERNEL_DS)) {
	    	int pending = atomic_read(&d->tx_dma_pending);
		int thres = TOM_TUNABLE(tdev, zcopy_sendmsg_thres);
		if (pending >= thres /*|| size >= thres*/) 
			zcopy_size = size -
			    TOM_TUNABLE(tdev, zcopy_sendmsg_copy);
		else 
			zcopy_size = size - 
			    TOM_TUNABLE(tdev, zcopy_sendmsg_partial_copy);
	}

        /* In the case of NON-BLOCKING IO we don't want to exceed the
         * sendbuffer at all which could cause delays in the zcopy path.
         */
        if ((zcopy_size > 0) && (flags & MSG_DONTWAIT)) {
		int rem = sk->sk_sndbuf - sk->sk_wmem_queued;
		if (rem <= 0) {
                        err = -EAGAIN;
                        goto do_error;
		} else if (size > rem)
			size = rem;
	}
#endif
	cplios_set_flag(sk, CPLIOS_TX_MORE_DATA);
	for (iovlen = msg->msg_iovlen, iov = msg->msg_iov; iovlen--; iov++) {
		int seglen = min(iov->iov_len, size);
		unsigned char __user *from = iov->iov_base;

		while (seglen > 0) {
			int copy, tailroom;

			skb = skb_peek_tail(&sk->sk_write_queue);
			if (!skb || zcopy_size > 0 ||
			    (ULP_SKB_CB(skb)->flags & ULPCB_FLAG_NO_APPEND) ||
			    (copy = mss - skb->len) <= 0) {
new_buf:
				/*
				 * If we're shy on configured allowable buffer
				 * space, let's see if we can ship some to the
				 * card and get our payload queued.  Otherwise
				 * we'll have to wait for buffer space to
				 * become available ...
				 */
				if (skb) {
					tx_skb_finalize(skb);
					push_frames_if_head(sk);
				}
				if (!tcp_memory_free(sk))
					goto wait_for_sndbuf;

				skb = alloc_tx_skb(sk, select_size(sk, size,
								   flags));
				if (unlikely(!skb))
					goto wait_for_memory;

				copy = mss;
			}

			if (copy > seglen)
				copy = seglen;

#if defined(CONFIG_T3_ZCOPY_SENDMSG) || defined(CONFIG_T3_ZCOPY_SENDMSG_MODULE)
			if (zcopy_size > 0) {
				copy = min(copy, (int)((MAX_SKB_FRAGS - 2) * 
						       PAGE_SIZE));
				copy = min(copy, zcopy_size);

				err = zcopy_to_skb(sk, skb, 
						   (unsigned long)from, copy); 
				if (err) {
					if (err == -EFAULT)
						goto do_fault;

					/*
					 * The zcopy failed -- probably
					 * because the buffer is shared or
					 * spans multiple VMAs: revert to
					 * non-zcopy mode.  Disable zcopy and
					 * try again with the normal path ...
					 */
					zcopy_size = 0;
					continue;
				}
				from += copy;
				copied += copy;
				zcopied += copy;
				seglen -= copy;
				size -= copy;
				zcopy_size -= copy;

				tx_skb_finalize(skb);
				ULP_SKB_CB(skb)->flags |=
				    ULPCB_FLAG_COMPL | ULPCB_FLAG_ZCOPY;

				if (!size) {
					cplios_reset_flag(sk, CPLIOS_TX_MORE_DATA);
					t3_push_frames(sk, 1);
					goto done;
				} else {
					t3_push_frames(sk, 1);
					continue;
				}
			}
#endif
			/*
			 * There are two ways for an skb to become full:
			 * a) skb->len == mss
			 * b) the skb's max capacity is reached
			 */
			tailroom = skb_tailroom(skb);
			if (tailroom >= copy) {
				err = ch_skb_add_data(skb, from, copy);
				if (err)
					goto do_fault;
			} else {
				int i = skb_shinfo(skb)->nr_frags;
				struct page *page = TCP_PAGE(sk);
				int merge, off = TCP_OFF(sk);

				if (off < PAGE_SIZE &&
				    skb_can_coalesce(skb, i, page, off)) {
					merge = 1;
					goto copy;
				}

				merge = 0;
				if (i == MAX_SKB_FRAGS)
					goto new_buf;
				if (page && off == PAGE_SIZE) {
					put_page(page);
					TCP_PAGE(sk) = page = NULL;
				}

				if (!page) {
					page = alloc_pages(sk->sk_allocation,
							   0);
					if (!page)
						goto wait_for_memory;
					off = 0;
				}
copy:
				if (copy > PAGE_SIZE - off)
					copy = PAGE_SIZE - off;

				err = tcp_copy_to_page(sk, from, skb, page,
						       off, copy);
				if (unlikely(err)) {
					/*
					 * If the page was new, give it to the
					 * socket so it does not get leaked.
					 */
					if (!TCP_PAGE(sk)) {
						TCP_PAGE(sk) = page;
						TCP_OFF(sk) = 0;
					}
					goto do_error;
				}

				/* Update the skb. */
				if (merge)
					skb_shinfo(skb)->frags[i - 1].size +=
					    copy;
				else {
					skb_fill_page_desc(skb, i, page, off,
							   copy);
					if (off + copy < PAGE_SIZE) {
						/* space left, keep page */
						get_page(page);
						TCP_PAGE(sk) = page;
					} else
						TCP_PAGE(sk) = NULL;
				}

				TCP_OFF(sk) = off + copy;
			}

			if (unlikely(skb->len == mss))
				tx_skb_finalize(skb);
			tp->write_seq += copy;
			from += copy;
			copied += copy;
			seglen -= copy;
			size -= copy;
			if (size == 0)
				goto out;

			if (ULP_SKB_CB(skb)->flags & ULPCB_FLAG_NO_APPEND)
				push_frames_if_head(sk);
			continue;
wait_for_sndbuf:
			set_bit(SOCK_NOSPACE, &sk->sk_socket->flags);
wait_for_memory:
			if ((err = wait_for_mem(sk, &timeo)) != 0)
				goto do_error;
		}
	}
out:
	cplios_reset_flag(sk, CPLIOS_TX_MORE_DATA);
	if (copied != zcopied) {
		if (zcopied && skb) {
			tx_skb_finalize(skb);
			t3_push_frames(sk, 1);
		} else {
			tcp_push(sk, flags);
		}
	}
done:
#if defined(CONFIG_T3_ZCOPY_SENDMSG) || defined(CONFIG_T3_ZCOPY_SENDMSG_MODULE)
	if (zcopied > 0)
		zcopy_wait(sk, timeo);
	atomic_set(&sk->sk_omem_alloc, omem_alloc);
#endif
	release_sock(sk);
	return copied;

do_fault:
	if (!skb->len) {
		__skb_unlink(skb, &sk->sk_write_queue);
		// tcp_free_skb(sk, skb);
		sk->sk_wmem_queued -= skb->truesize;
		__kfree_skb(skb);
	}

do_error:
	if (copied)
		goto out;
out_err:
	cplios_reset_flag(sk, CPLIOS_TX_MORE_DATA);
	copied = sk_stream_error(sk, flags, err);
	goto done;
}


static inline int is_delack_mode_valid(struct toedev *dev, struct sock *sk)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	return cplios->ulp_mode == ULP_MODE_NONE ||
		(cplios->ulp_mode == ULP_MODE_TCPDDP &&
		 dev->ttid >= TOE_ID_CHELSIO_T3);
}

/*
 * Set of states for which we should return RX credits.
 */
#define CREDIT_RETURN_STATE (TCPF_ESTABLISHED | TCPF_FIN_WAIT1 | TCPF_FIN_WAIT2)

/*
 * Called after some received data has been read.  It returns RX credits
 * to the HW for the amount of data processed.
 */
void t3_cleanup_rbuf(struct sock *sk, int copied, int request)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	struct tcp_sock *tp;
	struct toedev *dev;
	int dack_mode, must_send;
	u32 thres, credits, dack = 0;
	unsigned int req_win = (request < (M_TCB_RX_DDP_BUF0_LEN >> 1)) ? request : (M_TCB_RX_DDP_BUF0_LEN >> 1);

	if (!sk_in_state(sk, CREDIT_RETURN_STATE))
		return;
	
	t3_select_window(sk, req_win + 32768);	
	tp = tcp_sk(sk);
	credits = tp->copied_seq - tp->rcv_wup;
	if (unlikely(!credits))
		return;

	dev = cplios->toedev;
	thres = TOM_TUNABLE(dev, rx_credit_thres);

	if (unlikely(thres == 0))
		return;

	if (is_delack_mode_valid(dev, sk)) {
		dack_mode = t3_select_delack(sk);
		if (unlikely(dack_mode != cplios->delack_mode)) {
			u32 r = tp->rcv_nxt - cplios->delack_seq;
			if (r >= tp->rcv_wnd || r >= 16 * MSS_CLAMP(tp))
				dack = F_RX_DACK_CHANGE |
				       V_RX_DACK_MODE(dack_mode);
		}
	} else
		dack = F_RX_DACK_CHANGE | V_RX_DACK_MODE(1);

	/*
	 * For coalescing to work effectively ensure the receive window has
	 * at least 16KB left.
	 */
	must_send = credits + 16384 >= tp->rcv_wnd;

	if (must_send || credits >= thres)
		tp->rcv_wup += t3_send_rx_credits(sk, credits, dack, must_send);
}
EXPORT_SYMBOL(t3_cleanup_rbuf);

static inline struct sk_buff *tcp_recv_skb(struct sock *sk, u32 seq, u32 *off)
{
	struct sk_buff *skb;

	skb_queue_walk(&sk->sk_receive_queue, skb) {
		u32 offset = seq - ULP_SKB_CB(skb)->seq;
		if (offset < skb->len) {
			*off = offset;
			return skb;
		}
	}
	return NULL;
}

/*
 * Returns whether a connection should enable DDP.  This happens when all of
 * the following conditions are met:
 * - the connection's ULP mode is DDP
 * - DDP is not already enabled
 * - the last receive was above the DDP threshold
 * - receive buffers are in user space
 * - receive side isn't shutdown (handled by caller)
 * - the connection's receive window is big enough so that sizable buffers
 *   can be posted without closing the window in the middle of DDP (checked
 *   when the connection is offloaded)
 */
static int sk_should_ddp(const struct sock *sk, const struct tcp_sock *tp,
			 int last_recv_len)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	return cplios->ulp_mode == ULP_MODE_TCPDDP && !DDP_STATE(sk)->ddp_setup &&
	       last_recv_len > TOM_TUNABLE(cplios->toedev, ddp_thres) &&
	       (!segment_eq(get_fs(), KERNEL_DS) || TOM_TUNABLE(cplios->toedev, kseg_ddp)) &&
	       tcp_sk(sk)->rcv_wnd > 
	           (TOM_TUNABLE(cplios->toedev, ddp_copy_limit) + 
		    DDP_RSVD_WIN);
}

static inline int is_ddp(const struct sk_buff *skb)
{
	return skb_gl(skb) != NULL;
}

static inline int is_ddp_psh(const struct sk_buff *skb)
{
        return is_ddp(skb) && (skb_ulp_ddp_flags(skb) & DDP_BF_PSH);
}

/*
 * Copy data from an sk_buff to an iovec.  Deals with RX_DATA, which carry the
 * data in the sk_buff body, and with RX_DATA_DDP, which place the data in a
 * DDP buffer.
 */
static inline int copy_data(const struct sk_buff *skb, int offset,
			    struct iovec *to, int len)
{
	if (likely(!is_ddp(skb)))                             /* RX_DATA */
		return skb_copy_datagram_iovec(skb, offset, to, len);
	if (likely(skb_ulp_ddp_flags(skb) & DDP_BF_NOCOPY)) { /* user DDP */
		to->iov_len -= len;
		to->iov_base += len;
		return 0;
	}
	return t3_ddp_copy(skb, offset, to, len);             /* kernel DDP */
}

/*
 * Peek at data in a socket's receive buffer.
 */
#ifdef	LINUX_2_4
static int peekmsg(struct sock *sk, struct msghdr *msg,
		   int len, int nonblock, int flags)
#else
static int peekmsg(struct kiocb *iocb, struct sock *sk, struct msghdr *msg,
		   size_t len, int nonblock, int flags)
#endif	/* LINUX_2_4 */
{
	long timeo;
	struct sk_buff *skb;
	struct tcp_sock *tp = tcp_sk(sk);
	int copied = 0;
	u32 peek_seq, offset;
	size_t avail;          /* amount of available data in current skb */

	lock_sock(sk);
	timeo = sock_rcvtimeo(sk, nonblock);
	peek_seq = tp->copied_seq;

	do {
		if (unlikely(tp->urg_data && tp->urg_seq == peek_seq)) {
			if (copied)
				break;
			if (signal_pending(current)) {
				copied = timeo ? sock_intr_errno(timeo) :
						 -EAGAIN;
				break;
			}
		}

		skb_queue_walk(&sk->sk_receive_queue, skb) {
			offset = peek_seq - ULP_SKB_CB(skb)->seq;
			if (offset < skb->len)
				goto found_ok_skb;
		}

		/* empty receive queue */
		if (copied)
			break;
		if (sock_flag(sk, SOCK_DONE))
			break;
		if (sk->sk_err) {
			copied = sock_error(sk);
			break;
		}
		if (sk->sk_shutdown & RCV_SHUTDOWN)
			break;
		if (sk->sk_state == TCP_CLOSE) {
			copied = -ENOTCONN;
			break;
		}
		if (!timeo) {
			copied = -EAGAIN;
			break;
		}
		if (signal_pending(current)) {
			copied = sock_intr_errno(timeo);
			break;
		}

		if (sk->sk_backlog.tail) {
			/* Do not sleep, just process backlog. */
			release_sock(sk);
			lock_sock(sk);
		} else
			sk_wait_data(sk, &timeo);

		if (unlikely(peek_seq != tp->copied_seq)) {
			if (net_ratelimit())
				printk(KERN_DEBUG "TCP(%s:%d): Application "
				       "bug, race in MSG_PEEK.\n",
				       current->comm, current->pid);
			peek_seq = tp->copied_seq;
		}
		continue;

found_ok_skb:
		avail = skb->len - offset;
		if (len < avail)
			avail = len;

		/*
		 * Do we have urgent data here?  We need to skip over the
		 * urgent byte.
		 */
		if (unlikely(tp->urg_data)) {
			u32 urg_offset = tp->urg_seq - peek_seq;

			if (urg_offset < avail) {
				/*
				 * The amount of data we are preparing to copy
				 * contains urgent data.
				 */
				if (!urg_offset) { /* First byte is urgent */
					if (!sock_flag(sk, SOCK_URGINLINE)) {
						peek_seq++;
						offset++;
						avail--;
						if (!avail)
							continue;
					}
				} else {
					/* stop short of the urgent data */
					avail = urg_offset;
				}
			}
		}

		/*
		 * If MSG_TRUNC is specified the data is discarded.
		 */
		if (likely(!(flags & MSG_TRUNC)))
			if (copy_data(skb, offset, msg->msg_iov, avail)) {
				if (!copied)
					copied = -EFAULT;
				break;
			}

		peek_seq += avail;
		copied += avail;
		len -= avail;
	} while (len > 0);

	release_sock(sk);
	return copied;
}

static int sk_wait_data_uninterruptible(struct sock *sk)
{
	int rc;
	long timeo = MAX_SCHEDULE_TIMEOUT;
#ifdef	LINUX_2_4
	DECLARE_WAITQUEUE(wait, current);
	add_wait_queue(sk->sleep, &wait);

	set_current_state(TASK_INTERRUPTIBLE);
	set_bit(SOCK_ASYNC_WAITDATA, &sk->sk_socket->flags);
	rc = sk_wait_event(sk, &timeo, !skb_queue_empty(&sk->sk_receive_queue));
	clear_bit(SOCK_ASYNC_WAITDATA, &sk->sk_socket->flags);
	current->state = TASK_RUNNING;
	remove_wait_queue(sk->sleep, &wait);
	return rc;
#else
	DEFINE_WAIT(wait);

	prepare_to_wait(sk_sleep(sk), &wait, TASK_UNINTERRUPTIBLE);
	set_bit(SOCK_ASYNC_WAITDATA, &sk->sk_socket->flags);
	rc = sk_wait_event(sk, &timeo, !skb_queue_empty(&sk->sk_receive_queue));
	clear_bit(SOCK_ASYNC_WAITDATA, &sk->sk_socket->flags);
	finish_wait(sk_sleep(sk), &wait);
	return rc;
#endif	/* LINUX_2_4 */
}

/*
 * Called after a user buffer is posted to await DDP completion.  The waiting
 * mode depends on the receive flags, which in turn determine the HW DDP flags.
 *
 * - Without MSG_WAITALL we set up the DDP buffer with non-zero initial offset
 *   and enable the HW timeout.  In this case we sleep uninterruptably since we
 *   know the buffer will complete or timeout in reasonable time.
 * - With MSG_WAITALL HW timeout is initially disabled.  If a signal arrives
 *   and the DDP is still on-going we turn on the timer and disable
 *   no-invalidate, then sleep uninterruptably until the buffer completes.
 */
static inline int await_ddp_completion(struct sock *sk, int rcv_flags,
				       long *timeo)
{
	if (unlikely(rcv_flags & MSG_WAITALL)) {
		sk_wait_data(sk, timeo);
		if (sk->sk_err || sk->sk_state == TCP_CLOSE ||
		    (sk->sk_shutdown & RCV_SHUTDOWN))
			return 0;

		/* Got signal or timed out */
		t3_set_tcb_field(sk, W_TCB_RX_DDP_FLAGS,
				 V_TF_DDP_PSH_NO_INVALIDATE1(1) |
				 V_TF_DDP_PUSH_DISABLE_1(1), 0);
	}
	return sk_wait_data_uninterruptible(sk);
}

#if 0
/* Controls whether to post DDP kernel and user buffers in parallel. */
#define PARALLEL_DDP_BUFS 1

/* Controls whether we post the DDP user buffer before copying the kernel buf */
#define EARLY_USERBUF_POST 1

/*
 * Receive data from a socket into an application buffer.
 */
#ifdef	LINUX_2_4
static int chelsio_recvmsg(struct sock *sk,
			   struct msghdr *msg, int len, int nonblock,
			   int flags, int *addr_len)
#else
static int chelsio_recvmsg(struct kiocb *iocb, struct sock *sk,
			   struct msghdr *msg, size_t len, int nonblock,
			   int flags, int *addr_len)
#endif	/* LINUX_2_4 */
{
	struct tcp_sock *tp = tcp_sk(sk);
	int copied = 0, buffers_freed = 0, kern_ddp_done = 0;
	unsigned long avail;	/* amount of available data in current skb */
	int target;		/* Read at least this many bytes */
	long timeo;
	int user_ddp_ok, user_ddp_pending = 0;

	/* Urgent data is handled by the SW stack's receive */
#ifdef	LINUX_2_4
	if (unlikely(flags & MSG_OOB))
		return tcp_prot.recvmsg(sk, msg, len, nonblock, flags,
					addr_len);
	if (unlikely(flags & MSG_PEEK))
		return peekmsg(sk, msg, len, nonblock, flags);
#else
	if (unlikely(flags & MSG_OOB))
		return tcp_prot.recvmsg(iocb, sk, msg, len, nonblock, flags,
					addr_len);

	if (unlikely(flags & MSG_PEEK))
		return peekmsg(iocb, sk, msg, len, nonblock, flags);
#endif	/* LINUX_2_4 */

	/*
	 * Note: the code below depends on kern_ddp_done and user_ddp_ok
	 * having only values 0 and 1, or more precisely on the two variables
	 * having values either 0 or odd.  This is due to the logical &s below.
	 * It also depends on DDP buffer completions reported in bit 0 of skb
	 * flags.
	 */
	lock_sock(sk);
	timeo = sock_rcvtimeo(sk, nonblock);
	target = sock_rcvlowat(sk, flags & MSG_WAITALL, len);
	user_ddp_ok = msg->msg_iovlen == 1;

	do {
		struct sk_buff *skb;
		u32 offset;

		if (unlikely(tp->urg_data && tp->urg_seq == tp->copied_seq)) {
			if (copied)
				break;
			if (signal_pending(current)) {
				copied = timeo ? sock_intr_errno(timeo) :
						 -EAGAIN;
				break;
			}
		}

		skb = skb_peek(&sk->sk_receive_queue);
		if (skb)
			goto found_ok_skb;

		/* empty receive queue */
		if (copied >= target && !sk->sk_backlog.tail &&
		    !(kern_ddp_done & user_ddp_ok))
			break;

		if (copied) {
			if (sk->sk_err || sk->sk_state == TCP_CLOSE ||
			    (sk->sk_shutdown & RCV_SHUTDOWN) || !timeo ||
			    signal_pending(current))
				break;
		} else {
			if (sock_flag(sk, SOCK_DONE))
				break;
			if (sk->sk_err) {
				copied = sock_error(sk);
				break;
			}
			if (sk->sk_shutdown & RCV_SHUTDOWN)
				break;
			if (sk->sk_state == TCP_CLOSE) {
				copied = -ENOTCONN; /* SOCK_DONE is off here */
				break;
			}
			if (!timeo) {
				copied = -EAGAIN;
				break;
			}
			if (signal_pending(current)) {
				copied = sock_intr_errno(timeo);
				break;
			}
		}

		if (sk->sk_backlog.tail && !user_ddp_pending) {
			/* Do not sleep, just process backlog. */
			release_sock(sk);
			lock_sock(sk);
			t3_cleanup_rbuf(sk, copied);
			continue;
		}

		if (user_ddp_pending ||
		    ((kern_ddp_done & user_ddp_ok) &&
		     !t3_post_ubuf(sk, msg->msg_iov, nonblock, flags, 1,
				   PARALLEL_DDP_BUFS && copied >= target))) {
			/* One shot at DDP if we already have enough data */
			if (copied >= target) {
#if PARALLEL_DDP_BUFS
# if EARLY_USERBUF_POST
				if (user_ddp_pending)
					t3_repost_kbuf(sk, 1, 0);
# endif
				kern_ddp_done = 0;
#endif
				user_ddp_ok = 0;
			}
			await_ddp_completion(sk, flags, &timeo);
			user_ddp_pending = 0;
		} else if (copied >= target)
			break;
		else {
			if (kern_ddp_done) {
				t3_repost_kbuf(sk, 1, 1);
				kern_ddp_done = 0;
			} else
				t3_cleanup_rbuf(sk, copied);
			sk_wait_data(sk, &timeo);
		}
		continue;

found_ok_skb:
		offset = tp->copied_seq - ULP_SKB_CB(skb)->seq;
		BUG_ON(offset >= skb->len);
		avail = skb->len - offset;
		if (len < avail)
			avail = len;

		/*
		 * Check if the data we are preparing to copy contains urgent
		 * data.  Either stop short of urgent data or skip it if it's
		 * first and we are not delivering urgent data inline.
		 */
		if (unlikely(tp->urg_data)) {
			u32 urg_offset = tp->urg_seq - tp->copied_seq;

			if (urg_offset < avail) {
				if (urg_offset) {
					/* stop short of the urgent data */
					avail = urg_offset;
				} else if (!sock_flag(sk, SOCK_URGINLINE)) {
					/* First byte is urgent, skip */
					tp->copied_seq++;
					offset++;
					avail--;
					if (!avail)
						goto skip_copy;
				}
			}
		}

#if EARLY_USERBUF_POST
		if (user_ddp_ok && avail + offset >= skb->len && len > avail &&
		    (skb_ulp_ddp_flags(skb)->flags & 1)) {
			struct iovec iov;

			iov.iov_len = msg->msg_iov->iov_len - avail;
			iov.iov_base = msg->msg_iov->iov_base + avail;
			user_ddp_pending = !t3_post_ubuf(sk, &iov, nonblock,
							 flags, 1, 0);
		}
#endif
		/*
		 * If MSG_TRUNC is specified the data is discarded.
		 */
		if (likely(!(flags & MSG_TRUNC))) {
			if (copy_data(skb, offset, iov, avail)) {
				if (!copied)
					copied = -EFAULT;
				break;
			}
		} else if (user_ddp_ok) {
			/*
			 * Even though we skipped the copy we need to update
			 * msg->msg_iov since we may be using it for user DDP.
			 */
			msg->msg_iov->iov_len -= avail;
			msg->msg_iov->iov_base += avail;
		}

		tp->copied_seq += avail;
		copied += avail;
		len -= avail;

skip_copy:
		if (tp->urg_data && after(tp->copied_seq, tp->urg_seq))
			tp->urg_data = 0;

		/*
		 * If the buffer is fully consumed free it.  If it's a DDP
		 * buffer also handle any events it indicates.
		 */
		if (avail + offset >= skb->len) {
			unsigned int fl = skb_ulp_ddp_flags(skb);

			tom_eat_skb(sk, skb, 0);
			buffers_freed++;

			if ((fl & DDP_BF_NOCOPY) && !user_ddp_ok)
				break;

			/* only DDP completions have bit 0 of ->flags set */
			kern_ddp_done |= (fl & 1);
		}
	} while (len > 0);

	/*
	 * If we can still receive decide what to do in preparation for the
	 * next receive.  Note that RCV_SHUTDOWN is set if the connection
	 * transitioned to CLOSE but not if it was in that state to begin with.
	 */
	if (likely(!(sk->sk_shutdown & RCV_SHUTDOWN))) {
		if (kern_ddp_done) {
			t3_repost_kbuf(sk, 1, 1);
		} else if (sk_should_ddp(sk, tp, copied) && !nonblock &&
			   msg->msg_iovlen == 1)
			t3_enter_ddp(sk, TOM_TUNABLE(cplios->toedev,
						     ddp_copy_limit), 0);
	}
	if (buffers_freed)
		t3_cleanup_rbuf(sk, copied);

	release_sock(sk);
	return copied;
}
#endif
/*
 * Receive data from a socket into an application buffer.
 */
#ifdef	LINUX_2_4
static int chelsio_recvmsg(struct sock *sk,
			   struct msghdr *msg, int len, int nonblock,
			   int flags, int *addr_len)
#else
static int chelsio_recvmsg(struct kiocb *iocb, struct sock *sk,
			   struct msghdr *msg, size_t len, int nonblock,
			   int flags, int *addr_len)
#endif	/* LINUX_2_4 */
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	int copied = 0, buffers_freed = 0;
	unsigned long avail;	/* amount of available data in current skb */
	int target;		/* Read at least this many bytes */
	int request;
	long timeo;
	int user_ddp_ok, user_ddp_pending = 0;
	struct ddp_state *p;
	struct iovec *iov = msg->msg_iov;

	/* Urgent data is handled by the SW stack's receive */
#ifdef	LINUX_2_4
	if (unlikely(flags & MSG_OOB))
		return tcp_prot.recvmsg(sk, msg, len, nonblock, flags,
					addr_len);
	if (unlikely(flags & MSG_PEEK))
		return peekmsg(sk, msg, len, nonblock, flags);
#else
	if (unlikely(flags & MSG_OOB))
		return tcp_prot.recvmsg(iocb, sk, msg, len, nonblock, flags,
					addr_len);

	if (unlikely(flags & MSG_PEEK))
		return peekmsg(iocb, sk, msg, len, nonblock, flags);
#endif	/* LINUX_2_4 */

	/*
	 * Note: the code below depends on kern_ddp_done and user_ddp_ok
	 * having only values 0 and 1, or more precisely on the two variables
	 * having values either 0 or odd.  This is due to the logical &s below.
	 * It also depends on DDP buffer completions reported in bit 0 of skb
	 * flags.
	 */

	lock_sock(sk);
	timeo = sock_rcvtimeo(sk, nonblock);
	target = sock_rcvlowat(sk, flags & MSG_WAITALL, len);
	request = len;
	user_ddp_ok = (target <= iov->iov_len) && !(MSG_WAITALL && (msg->msg_iovlen > 1));
	p = DDP_STATE(sk);

	/*
	 * Check to see if we need to grow receive window.
	 */
	if (unlikely (cplios_flag(sk , CPLIOS_UPDATE_RCV_WND)))
		t3_cleanup_rbuf(sk, copied, request);
	
	if (p->ddp_setup && !p->ubuf_ddp_ready)
		user_ddp_ok = 0;
	if (p->ddp_setup) {
		p->cancel_ubuf = 0;
	}
	
	do {
		struct sk_buff *skb;
		u32 offset;

		p = DDP_STATE(sk);
again:
#ifdef T3_TRACE
		T3_TRACE4(TIDTB(sk), 
			"chelsio_recvmsg: loop start len %d copied %d "
			"user_ddp_pending %u signal 0x%x",
			len, copied, user_ddp_pending, 
			signal_pending(current));
#endif

		if (unlikely(tp->urg_data && tp->urg_seq == tp->copied_seq)) {
			if (copied)
				break;
			if (signal_pending(current)) {
				copied = timeo ? sock_intr_errno(timeo) :
						 -EAGAIN;
				break;
			}
		}
 
		skb = skb_peek(&sk->sk_receive_queue);
		if (skb)
			goto found_ok_skb;

		/*
		 * The receive queue is empty and here we are asking for more
		 * data.  Before we do anything else, check to see if we have
		 * data queued up to send and if there's available write
		 * space.  If so, push it along and free up the write space.
		 * This is a major win for request-response style
		 * communication patterns and doesn't hurt bulk data
		 * applications.
		 */
		if (cplios->wr_avail &&
		    skb_queue_len(&sk->sk_write_queue) &&
		    t3_push_frames(sk, cplios->wr_avail == cplios->wr_max))
			sk->sk_write_space(sk);

		if (copied >= target && !sk->sk_backlog.tail &&
		    !user_ddp_pending)
			break;

		if (copied) {
#ifdef T3_TRACE
			T3_TRACE5(TIDTB(sk), 
				  "chelsio_recvmsg: copied - break %d %d %d %d %d",
				  sk->sk_err, sk->sk_state == TCP_CLOSE,
				  (sk->sk_shutdown & RCV_SHUTDOWN), !timeo,
				  signal_pending(current));
#endif
		
			if (sk->sk_err || sk->sk_state == TCP_CLOSE ||
			    (sk->sk_shutdown & RCV_SHUTDOWN) || !timeo ||
			    signal_pending(current))
				break;
		} else {
#ifdef T3_TRACE
			T3_TRACE5(TIDTB(sk), 
				  "chelsio_recvmsg: !copied - break %d %d %d %d %d",
				  sock_flag(sk, SOCK_DONE), sk->sk_err,
				  (sk->sk_shutdown & RCV_SHUTDOWN), 
				  sk->sk_state == TCP_CLOSE, !timeo);
#endif
		
			if (sock_flag(sk, SOCK_DONE))
				break;
			if (sk->sk_err) {
				copied = sock_error(sk);
				break;
			}
			if (sk->sk_shutdown & RCV_SHUTDOWN)
				break;
			if (sk->sk_state == TCP_CLOSE) {
				copied = -ENOTCONN; /* SOCK_DONE is off here */
				break;
			}
			if (!timeo) {
				copied = -EAGAIN;
				break;
			}
			if (signal_pending(current)) {
				copied = sock_intr_errno(timeo);
				break;
			}
		}

		if (sk->sk_backlog.tail && !user_ddp_pending) {
			/* Do not sleep, just process backlog. */
			release_sock(sk);
			lock_sock(sk);
			t3_cleanup_rbuf(sk, copied, request);
			continue;
		}
#ifdef T3_TRACE
		T3_TRACE3(TIDTB(sk),
			"user_ddp_ok %d ubuf_ddp_ready %d iov_len %d",
			user_ddp_ok,  p->ddp_setup ? p->ubuf_ddp_ready : -1, iov->iov_len);
#endif        
		if (p->ddp_setup && user_ddp_ok && !user_ddp_pending && 
		    iov->iov_len > p->kbuf[0]->length &&
		    p->ubuf_ddp_ready) {
                        user_ddp_pending = 
			    !t3_overlay_ubuf(sk, iov, nonblock, flags, 1, 1);
			if (user_ddp_pending) {
				p->kbuf_posted++;
				user_ddp_ok = 0;
			}
#ifdef T3_TRACE
                               T3_TRACE3(TIDTB(sk),
                                       "overlay_ubuf kbuf_posted %d iov_len %d len %d",
                                       p->kbuf_posted, iov->iov_len, request);
#endif
		}

		if (p->ddp_setup && !p->kbuf_posted) {
			t3_post_kbuf(sk, 1 , nonblock);
			p->kbuf_posted++;
#ifdef T3_TRACE
			T3_TRACE3(TIDTB(sk),
                        	"post overlay_buf kbuf_posted %d copied %d len %d",
                         	p->kbuf_posted, copied, request);
#endif
		}

		if (user_ddp_pending) {
			/* One shot at DDP if we already have enough data */
			if (copied >= target) {
				user_ddp_ok = 0;
			}
#ifdef T3_TRACE
			T3_TRACE0(TIDTB(sk), "chelsio_recvmsg: AWAIT");
#endif
			sk_wait_data(sk, &timeo);
			// XXX for timers to work
			// XXX await_ddp_completion(sk, flags, &timeo);
#ifdef T3_TRACE
			T3_TRACE0(TIDTB(sk), "chelsio_recvmsg: AWAITed");
#endif
		} else if (copied >= target)
			break;
		else {
			t3_cleanup_rbuf(sk, copied, request);

#ifdef T3_TRACE
			T3_TRACE0(TIDTB(sk), "chelsio_recvmsg: DATA AWAIT");
#endif
			sk_wait_data(sk, &timeo);
#ifdef T3_TRACE
			T3_TRACE0(TIDTB(sk), "chelsio_recvmsg: DATA AWAITed");
#endif
		}
		continue;

found_ok_skb:
		if (!skb->len) {		/* ubuf dma is complete */
#ifdef T3_TRACE
			T3_TRACE1(TIDTB(sk),
			    "chelsio_recvmsg: zero len skb flags 0x%x",
			    skb_ulp_ddp_flags(skb));
#endif
			BUG_ON(!(skb_ulp_ddp_flags(skb) & DDP_BF_NOCOPY));

			user_ddp_pending = 0;
			tom_eat_skb(sk, skb, 0);

			if (!copied && !timeo) {
				copied = -EAGAIN;
				break;
			}

			if (copied < target)
				continue;

			break;
		}

		offset = tp->copied_seq - ULP_SKB_CB(skb)->seq;
		if (offset >= skb->len) {
#ifdef T3_TRACE
		T3_TRACE3(TIDTB(sk),
			  "chelsio_recvmsg: BUG: OFFSET > LEN seq 0x%x skb->len %dflags 0x%x",
			  ULP_SKB_CB(skb)->seq, skb->len, 
			  ULP_SKB_CB(skb)->flags);
#endif
			printk("chelsio_recvmsg: BUG: OFFSET > LEN seq 0x%x "
			       "skb->len %d flags 0x%x",
			       ULP_SKB_CB(skb)->seq, skb->len, 
			       ULP_SKB_CB(skb)->flags);
			BUG_ON(1);
		}
		avail = skb->len - offset;
		if (len < avail) {
			if (is_ddp(skb) && (skb_ulp_ddp_flags(skb) & DDP_BF_NOCOPY)) {
#ifdef T3_TRACE
				T3_TRACE5(TIDTB(sk),
					  "chelsio_recvmsg: BUG: len < avail"
					  " len %u skb->len %d offset %d"
					  " flags 0x%x avail %u",
					  len, skb->len, offset,
					  skb_ulp_ddp_flags(skb), avail);

				printk("chelsio_recvmsg: BUG: tid %u state %d\n"
				       " len < avail skb->len %d offset %dn"
				       " flags 0x%x avail %u len %u\n",
				       cplios->tid, sk->sk_state, skb->len,
				       offset, skb_ulp_ddp_flags(skb),
				       (unsigned int)avail, (unsigned int)len);
#endif
				BUG_ON(1);
			};
			avail = len;
		}
#ifdef T3_TRACE
	T3_TRACE5(TIDTB(sk),
		  "chelsio_recvmsg: seq 0x%x skb->len %d offset %d"
		  " avail %d flags 0x%x",
		  ULP_SKB_CB(skb)->seq, skb->len, offset, avail,
		  ULP_SKB_CB(skb)->flags);
#endif

		/*
		 * Check if the data we are preparing to copy contains urgent
		 * data.  Either stop short of urgent data or skip it if it's
		 * first and we are not delivering urgent data inline.
		 */
		if (unlikely(tp->urg_data)) {
			u32 urg_offset = tp->urg_seq - tp->copied_seq;

			if (urg_offset < avail) {
				if (urg_offset) {
					/* stop short of the urgent data */
					avail = urg_offset;
				} else if (!sock_flag(sk, SOCK_URGINLINE)) {
					/* First byte is urgent, skip */
					tp->copied_seq++;
					offset++;
					avail--;
					if (!avail)
						goto skip_copy;
				}
			}
		}

                if (is_ddp_psh(skb) || offset) {
                        user_ddp_ok = 0;
#ifdef T3_TRACE
                        T3_TRACE0(TIDTB(sk), "chelsio_recvmsg: PSH");
#endif
                }

                if (p->ddp_setup && user_ddp_ok && !user_ddp_pending && 
		    iov->iov_len > p->kbuf[0]->length &&
		    p->ubuf_ddp_ready) {
                        user_ddp_pending = 
			    !t3_overlay_ubuf(sk, iov, nonblock, flags, 1, 1);
			if (user_ddp_pending) {
				p->kbuf_posted++;
				user_ddp_ok = 0;
			}
#ifdef T3_TRACE
			T3_TRACE3(TIDTB(sk),
				  "found_ok_skb: overlay_ubuf kbuf_posted %d"
				  " iov_len %d len %d",
				  p->kbuf_posted, iov->iov_len, request);
#endif

		}
		
		/*
		 * If MSG_TRUNC is specified the data is discarded.
		 */
		if (likely(!(flags & MSG_TRUNC)))
			if (copy_data(skb, offset, iov, avail)) {
				if (!copied)
					copied = -EFAULT;
				break;
			}

		tp->copied_seq += avail;
		copied += avail;
		len -= avail;

skip_copy:
		if (tp->urg_data && after(tp->copied_seq, tp->urg_seq))
			tp->urg_data = 0;

		/*
		 * If the buffer is fully consumed free it.  If it's a DDP
		 * buffer also handle any events it indicates.
		 */
		if (avail + offset >= skb->len) {
			unsigned int fl = skb_ulp_ddp_flags(skb);
			int exitnow, got_psh = 0, nomoredata = 0;
	
			if (p->ddp_setup && is_ddp(skb) && (fl & 1)) {
				if (is_ddp_psh(skb) && user_ddp_pending)
					got_psh = 1;
				if (fl & DDP_BF_NOCOPY)
					user_ddp_pending = 0;
				else if ((fl & DDP_BF_NODATA) && nonblock) {
					p->kbuf_posted--;
					nomoredata = 1;
				} else {
					p->kbuf_posted--;
					p->ubuf_ddp_ready = 1;
				}
			}
	
			tom_eat_skb(sk, skb, 0);
			buffers_freed++;

			exitnow = got_psh || nomoredata;
			if  (copied >= target && !skb_peek(&sk->sk_receive_queue) && exitnow)
				break;
				
		}
	} while (len > 0);
	
	/*
	 * If we can still receive decide what to do in preparation for the
	 * next receive.  Note that RCV_SHUTDOWN is set if the connection
	 * transitioned to CLOSE but not if it was in that state to begin with.
	 */
	if (likely(!(sk->sk_shutdown & RCV_SHUTDOWN))) {
		if (user_ddp_pending) {
			user_ddp_ok = 0;
			t3_cancel_ubuf(sk, &timeo);
			p = DDP_STATE(sk);
			if (skb_peek(&sk->sk_receive_queue)) {
				if (copied < 0)
					copied = 0;
				goto again;
			}
			user_ddp_pending = 0;
		}
	}

	/* Recheck SHUTDOWN conditions as t3_cancel_ubuf can release sock lock */
	if (!(sk->sk_err || sk->sk_state == TCP_CLOSE ||
	      cplios_flag(sk, CPLIOS_ABORT_SHUTDOWN) ||
	      (sk->sk_shutdown & RCV_SHUTDOWN))) {
		if (p->ddp_setup) {
			if (!p->kbuf_posted) {
#ifdef T3_TRACE
			T3_TRACE0(TIDTB(sk),
				  "chelsio_recvmsg: about to exit, repost kbuf");
#endif
			if ((p->avg_request_len < 4096U) && (request < 4096U)) {
                		t3_enable_ddp(sk, 0);
				t3_release_ddp_resources(sk);
				t3_cleanup_ddp(sk);
			} else {
				t3_post_kbuf(sk, 1, nonblock);
				p->kbuf_posted++;
			}
#ifdef T3_TRACE
                        T3_TRACE4(TIDTB(sk),
				  "%s: kbuf_posted %d copied %d len %d",
				  __func__, p->kbuf_posted, copied, request);
#endif
			}
			p->avg_request_len = (p->avg_request_len + request) >> 1;
		} else if (sk_should_ddp(sk, tp, copied)) {
			if (!t3_enter_ddp(sk, TOM_TUNABLE(cplios->toedev,
						     ddp_copy_limit), 0, nonblock)) {
				p = DDP_STATE(sk);
				p->kbuf_posted = 1;
				p->avg_request_len = (p->avg_request_len + request) >> 1;
#ifdef T3_TRACE
                               T3_TRACE4(TIDTB(sk),
					 "%s: enter ddp kbuf_posted %d"
					 " copied %d len %d",
					 __func__, p->kbuf_posted, copied,
					 request);
#endif


			}
		}
	} 

	if (buffers_freed)
		t3_cleanup_rbuf(sk, copied, request);
#ifdef T3_TRACE
	T3_TRACE5(TIDTB(sk),
		  "chelsio_recvmsg <-: copied %d len %d buffers_freed %d"
		  " kbuf_posted %d user_ddp_pending %u",
		  copied, len, buffers_freed, p->ddp_setup ? p->kbuf_posted : -1, 
		  user_ddp_pending);
#endif

	release_sock(sk);
	return copied;
}

/*
 * A visitor-pattern based receive method that runs the supplied receive actor
 * directly over the data in the receive queue.
 *
 * Caller must acquire the socket lock.
 */
int t3_read_sock(struct sock *sk, read_descriptor_t *desc,
		 sk_read_actor_t recv_actor)
{
	u32 offset = 0;
	int used, copied = 0;
	struct sk_buff *skb;
	struct tcp_sock *tp = tcp_sk(sk);

	while ((skb = tcp_recv_skb(sk, tp->copied_seq, &offset)) != NULL) {
		size_t len = skb->len - offset;

		if (unlikely(tp->urg_data)) {
			u32 urg_offset = tp->urg_seq - tp->copied_seq;
			if (urg_offset < len)
				len = urg_offset;
			if (!len)
				break;
		}
		used = recv_actor(desc, skb, offset, len);
		if (unlikely(used < 0)) {
			if (!copied)
				return used;
			break;
		} else if (likely(used <= len)) {
			tp->copied_seq += used;
			copied += used;
			offset += used;
		}
		if (offset != skb->len)
			break;

		tom_eat_skb(sk, skb, 0);
		if (!desc->count)
			break;
	}

	if (copied > 0)
		t3_cleanup_rbuf(sk, copied, 0);

	return copied;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,26)
/*
 * Offload splice_read() implementation.  We need our own because the original
 * calls tcp_read_sock.
 */
#include <linux/splice.h>

struct tcp_splice_state {
	struct pipe_inode_info *pipe;
	size_t len;
	unsigned int flags;
};

static int tcp_splice_data_recv(read_descriptor_t *rd_desc, struct sk_buff *skb,
				unsigned int offset, size_t len)
{
	struct tcp_splice_state *tss = rd_desc->arg.data;

	return skb_splice_bits_pub(skb, offset, tss->pipe, tss->len,
				   tss->flags);
}

static ssize_t chelsio_splice_read(struct sock *sk, loff_t *ppos,
				   struct pipe_inode_info *pipe, size_t len,
				   unsigned int flags)
{
	struct tcp_splice_state tss = {
		.pipe = pipe,
		.len = len,
		.flags = flags,
	};
	int ret;
	long timeo;
	ssize_t spliced;
	read_descriptor_t rd_desc;

	/* We can't seek on a socket input */
	if (unlikely(*ppos))
		return -ESPIPE;

	ret = spliced = 0;
	rd_desc.arg.data = &tss;

	lock_sock(sk);

	timeo = sock_rcvtimeo(sk, flags & SPLICE_F_NONBLOCK);
	while (tss.len) {
		ret = t3_read_sock(sk, &rd_desc, tcp_splice_data_recv);
		if (ret < 0)
			break;
		if (!ret) {
			if (spliced)
				break;
			if (flags & SPLICE_F_NONBLOCK) {
				ret = -EAGAIN;
				break;
			}
			if (sock_flag(sk, SOCK_DONE))
				break;
			if (sk->sk_err) {
				ret = sock_error(sk);
				break;
			}
			if (sk->sk_shutdown & RCV_SHUTDOWN)
				break;
			if (sk->sk_state == TCP_CLOSE) {
				/*
				 * This occurs when user tries to read
				 * from never connected socket.
				 */
				ret = -ENOTCONN;
				break;
			}
			if (!timeo) {
				ret = -EAGAIN;
				break;
			}
			sk_wait_data(sk, &timeo);
			if (signal_pending(current)) {
				ret = sock_intr_errno(timeo);
				break;
			}
			continue;
		}
		tss.len -= ret;
		spliced += ret;
		if (tss.len == 0)
			break;

		release_sock(sk);
		lock_sock(sk);

		if (sk->sk_err || sk->sk_state == TCP_CLOSE ||
		    (sk->sk_shutdown & RCV_SHUTDOWN) || !timeo ||
		    signal_pending(current))
			break;
	}

	release_sock(sk);

	return spliced ? spliced : ret;
}
#endif

/*
 * Close a connection by sending a CPL_CLOSE_CON_REQ message.  Cannot fail
 * under any circumstances.  We take the easy way out and always queue the
 * message to the write_queue.  We can optimize the case where the queue is
 * already empty though the optimization is probably not worth it.
 */
static void close_conn(struct sock *sk)
{
	struct sk_buff *skb;
	struct cpl_close_con_req *req;
	unsigned int tid = CPL_IO_STATE(sk)->tid;

	skb = alloc_skb_nofail(sizeof(struct cpl_close_con_req));
	req = (struct cpl_close_con_req *)__skb_put(skb, sizeof(*req));
	req->wr.wr_hi = htonl(V_WR_OP(FW_WROPCODE_OFLD_CLOSE_CON));
	req->wr.wr_lo = htonl(V_WR_TID(tid));
	OPCODE_TID(req) = htonl(MK_OPCODE_TID(CPL_CLOSE_CON_REQ, tid));
	req->rsvd = htonl(tcp_sk(sk)->write_seq);

	tcp_uncork(sk);
	skb_entail(sk, skb, ULPCB_FLAG_NO_APPEND);
	if (sk->sk_state != TCP_SYN_SENT)
		t3_push_frames(sk, 1);
}

/*
 * State transitions and actions for close.  Note that if we are in SYN_SENT
 * we remain in that state as we cannot control a connection while it's in
 * SYN_SENT; such connections are allowed to establish and are then aborted.
 */
static unsigned char new_state[16] = {
	/* current state:     new state:      action: */
	/* (Invalid)       */ TCP_CLOSE,
	/* TCP_ESTABLISHED */ TCP_FIN_WAIT1 | TCP_ACTION_FIN,
	/* TCP_SYN_SENT    */ TCP_SYN_SENT,
	/* TCP_SYN_RECV    */ TCP_FIN_WAIT1 | TCP_ACTION_FIN,
	/* TCP_FIN_WAIT1   */ TCP_FIN_WAIT1,
	/* TCP_FIN_WAIT2   */ TCP_FIN_WAIT2,
	/* TCP_TIME_WAIT   */ TCP_CLOSE,
	/* TCP_CLOSE       */ TCP_CLOSE,
	/* TCP_CLOSE_WAIT  */ TCP_LAST_ACK | TCP_ACTION_FIN,
	/* TCP_LAST_ACK    */ TCP_LAST_ACK,
	/* TCP_LISTEN      */ TCP_CLOSE,
	/* TCP_CLOSING     */ TCP_CLOSING,
};

/*
 * Perform a state transition during close and return the actions indicated
 * for the transition.  Do not make this function inline, the main reason
 * it exists at all is to avoid multiple inlining of tcp_set_state.
 */
static int make_close_transition(struct sock *sk)
{
	int next = (int)new_state[sk->sk_state];

	tcp_set_state(sk, next & TCP_STATE_MASK);
	return next & TCP_ACTION_FIN;
}

#define SHUTDOWN_ELIGIBLE_STATE (TCPF_ESTABLISHED | TCPF_SYN_RECV | TCPF_CLOSE_WAIT)

/*
 * Shutdown the sending side of a connection. Much like close except
 * that we don't receive shut down or set_sock_flag(sk, SOCK_DEAD).
 *
 * Note: this does not do anything for SYN_SENT state as tcp_shutdown
 * does, however this function is not really called for SYN_SENT because
 * inet_shutdown handles that state specially.  So no harm.
 */
static void chelsio_shutdown(struct sock *sk, int how)
{
	if ((how & SEND_SHUTDOWN) &&
	    sk_in_state(sk, SHUTDOWN_ELIGIBLE_STATE) &&
	    make_close_transition(sk))
		close_conn(sk);
}

static void chelsio_close(struct sock *sk, long timeout)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	int data_lost, old_state;
	struct sk_buff *skb;

	lock_sock(sk);
	sk->sk_shutdown |= SHUTDOWN_MASK;

	/*
	 * We need to flush the receive buffs.  We do this only on the
	 * descriptor close, not protocol-sourced closes, because the
	 * reader process may not have drained the data yet!  Make a note
	 * of whether any received data will be lost so we can decide whether
	 * to FIN or RST.
	 */
	data_lost = skb_queue_len(&sk->sk_receive_queue);
        while ((skb = __skb_dequeue(&sk->sk_receive_queue)) != NULL) {
                skb_gl_set(skb, NULL);
                kfree_skb(skb);
        }

	/*
	 * If the connection is in DDP mode, disable DDP and have any
	 * outstanding data and FIN (!!!) delivered to the host since HW
	 * might fail a ABORT_REQ if a fin is held. 
	 */
	if (cplios->ulp_mode == ULP_MODE_TCPDDP)
		t3_enable_ddp(sk, 0);

	if (sk->sk_state == TCP_CLOSE)  /* Nothing if we are already closed */
		;
	else if (data_lost || sk->sk_state == TCP_SYN_SENT) {
		// Unread data was tossed, zap the connection.
		T3_NET_INC_STATS_USER(sock_net(sk), LINUX_MIB_TCPABORTONCLOSE);
		t3_send_reset(sk, CPL_ABORT_SEND_RST, NULL);
		release_tcp_port(sk);
		goto unlock;
	} else if (sock_flag(sk, SOCK_LINGER) && !sk->sk_lingertime) {
		/* Check zero linger _after_ checking for unread data. */
		sk->sk_prot->disconnect(sk, 0);
		T3_NET_INC_STATS_USER(sock_net(sk), LINUX_MIB_TCPABORTONDATA);
	} else if (make_close_transition(sk)) {	/* Regular FIN-based close */
		close_conn(sk);
	}

	if (timeout)
		sk_stream_wait_close(sk, timeout);

unlock:
	old_state = sk->sk_state;
	sock_hold(sk); /* must last past the potential inet_csk_destroy_sock */
	sock_orphan(sk);
	INC_ORPHAN_COUNT(sk);

	release_sock(sk); /* Final release_sock in connection's lifetime. */

	/*
	 * There are no more user references at this point.  Grab the socket
	 * spinlock and finish the close.
	 */
	local_bh_disable();
	bh_lock_sock(sk);

	/*
	 * Because the socket was orphaned before the bh_lock_sock
	 * either the backlog or a BH may have already destroyed it.
	 * Bail out if so.
	 */
	if (old_state != TCP_CLOSE && sk->sk_state == TCP_CLOSE)
		goto out;

	if (sk->sk_state == TCP_FIN_WAIT2 && tcp_sk(sk)->linger2 < 0 &&
	    !cplios_flag(sk, CPLIOS_ABORT_SHUTDOWN)) {
		struct sk_buff *skb;

		skb = alloc_skb(sizeof(struct cpl_abort_req), GFP_ATOMIC);
		if (skb) {
			t3_send_reset(sk, CPL_ABORT_SEND_RST, skb);
			T3_NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_TCPABORTONLINGER);
		}
	}
#if 0
	if (sk->sk_state != TCP_CLOSE) {
		sk_stream_mem_reclaim(sk);
		if (atomic_read(sk->sk_prot->orphan_count) > sysctl_tcp_max_orphans ||
		    (sk->sk_wmem_queued > SOCK_MIN_SNDBUF &&
		     atomic_read(&tcp_memory_allocated) > sysctl_tcp_mem[2])) {
			if (net_ratelimit())
				printk(KERN_INFO
				       "TCP: too many orphaned sockets\n");
			tcp_set_state(sk, TCP_CLOSE);
			tcp_send_active_reset(sk, GFP_ATOMIC);
			NET_INC_STATS_BH(LINUX_MIB_TCPABORTONMEMORY);
		}
	}
#endif

	if (sk->sk_state == TCP_CLOSE)
		inet_csk_destroy_sock(sk);

out:
	bh_unlock_sock(sk);
	local_bh_enable();
	sock_put(sk);
}

/*
 * Our analog of tcp_free_skb().
 */
static inline void chelsio_tcp_free_skb(struct sock *sk, struct sk_buff *skb)
{
	sk->sk_wmem_queued -= skb->truesize;

#if defined(CONFIG_T3_ZCOPY_SENDMSG) || defined(CONFIG_T3_ZCOPY_SENDMSG_MODULE)
	if (ULP_SKB_CB(skb)->flags & ULPCB_FLAG_ZCOPY_COW)
		t3_zcopy_cleanup_skb(skb);
	else 
		skb_vaddr_set(skb, 0);
#endif

	__kfree_skb(skb);
}

void t3_purge_write_queue(struct sock *sk)
{
	struct sk_buff *skb;

	while ((skb = __skb_dequeue(&sk->sk_write_queue)))
		chelsio_tcp_free_skb(sk, skb);
	// tcp_mem_reclaim(sk);
}

/*
 * Switch a socket to the SW TCP's protocol operations.
 */
void install_standard_ops(struct sock *sk)
{
	/*
	 * Once we switch to the standard TCP operations our destructor
	 * (chelsio_destroy_sock) will not be called.  That function normally
	 * cleans up socket DDP state so we need to do that here to avoid
	 * leaking DDP resources.  Note that while the socket may live on for
	 * a long time DDP isn't usable with the standard ops, so DDP state
	 * can be released at this time.
	 */
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	t3_cleanup_ddp(sk);
	cplios->ulp_mode = ULP_MODE_NONE;
	sk->sk_prot = &tcp_prot;
	sk->sk_backlog_rcv = sk->sk_prot->backlog_rcv;
	restore_socket_ops(sk);
	if (sk->sk_write_space == t3_write_space)
		sk->sk_write_space = sk_stream_write_space;
#ifdef	LINUX_2_4
	if (likely(sk->filter)) {
		sk_filter_release(sk, sk->filter);
		sk->filter = NULL;
	}
#else
	if (likely(sk->sk_filter)) {
		sk_filter_uncharge(sk, sk->sk_filter);
		sk->sk_filter = NULL;
	}
#endif	/* LINUX_2_4 */
	if (sk->sk_user_data)
		restore_special_data_ready(sk);
	sock_reset_flag(sk, SOCK_OFFLOADED);
	cplios->flags = 0;
 	CPL_IO_STATE(sk) = NULL;
 	kfree(cplios);
}

/*
 * Wait until a socket enters on of the given states.
 */
static void wait_for_states(struct sock *sk, unsigned int states)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35)
	wait_queue_head_t _sk_sleep;
#else
	struct socket_wq _sk_wq;
#endif
	struct task_struct *tsk = current;
	DECLARE_WAITQUEUE(wait, tsk);

	/*
	 * We want this to work even when there's no associated struct socket.
	 * In that case we provide a temporary wait_queue_head_t.
	 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35)
	if (sk->sk_sleep == NULL) {
		init_waitqueue_head(&_sk_sleep);
		sk->sk_sleep = &_sk_sleep;
	}
#else
	if (sk->sk_wq == NULL) {
		init_waitqueue_head(&_sk_wq.wait);
		_sk_wq.fasync_list = NULL;
		init_rcu_head_on_stack(&_sk_wq.rcu);
		sk->sk_wq = &_sk_wq;
	}
#endif

	add_wait_queue(sk_sleep(sk), &wait);
	while (!sk_in_state(sk, states)) {
		set_task_state(tsk, TASK_UNINTERRUPTIBLE);
		release_sock(sk);
		if (!sk_in_state(sk, states))
			schedule();
		__set_task_state(tsk, TASK_RUNNING);
		lock_sock(sk);
	}
	remove_wait_queue(sk_sleep(sk), &wait);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35)
	if (sk_sleep(sk) == &_sk_sleep)
		sk->sk_sleep = NULL;
#else
	if (sk->sk_wq == &_sk_wq)
		sk->sk_wq = NULL;
#endif
}

static int chelsio_disconnect(struct sock *sk, int flags)
{
	struct tcp_sock *tp = tcp_sk(sk);

	__skb_queue_purge(&sk->sk_receive_queue);
	t3_purge_write_queue(sk);

	if (sk->sk_state != TCP_CLOSE) {
		sk->sk_err = ECONNRESET;
		t3_send_reset(sk, CPL_ABORT_SEND_RST, NULL);
		wait_for_states(sk, TCPF_CLOSE);
	}

	__skb_queue_purge(&tp->out_of_order_queue);

	/*
	 * We don't know the correct value for max_window but we know an
	 * upper limit.
	 */
	tp->max_window = 0xFFFF << SND_WSCALE(tp);

	/*
	 * Now switch to Linux's TCP operations and let it finish the job.
	 */
	install_standard_ops(sk);
	tcp_init_xmit_timers(sk);
	return tcp_disconnect(sk, flags);
}

/*
 * Our version of tcp_v4_destroy_sock().  We need to do this because
 * tcp_writequeue_purge() that is used in the original doesn't quite match
 * our needs.  If we ever hook into the memory management of the SW stack we
 * may be able to use tcp_v4_destroy_sock() directly.
 */
static t3_type_compat chelsio_destroy_sock(struct sock *sk)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);

	t3_cleanup_ddp(sk);
	cplios->ulp_mode = ULP_MODE_NONE;
	t3_purge_write_queue(sk);

	CPL_IO_STATE(sk) = NULL;
	kfree(cplios);
	return tcp_prot.destroy(sk);
}

/* IP socket options we do not support on offloaded connections */
#define UNSUP_IP_SOCK_OPT ((1 << IP_OPTIONS))

/*
 * Socket option code for IP.  We do not allow certain options while a
 * connection is offloaded.  Some of the other options we handle specially,
 * and the rest are directed to the SW IP for their usual processing.
 */
static int t3_ip_setsockopt(struct sock *sk, int level, int optname,
			    char __user *optval, int optlen, int call_compat)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);

	if (level != SOL_IP)
		return -ENOPROTOOPT;

	/* unsupported options */
	if ((1 << optname) & UNSUP_IP_SOCK_OPT) {
		printk(KERN_WARNING
		       "IP option %d ignored on offloaded TCP connection\n",
		       optname);
		return -ENOPROTOOPT;
	}

	/* specially handled options */
	if (optname == IP_TOS) {
		struct inet_sock *inet = inet_sk(sk);
		int val = 0, err = 0;

		if (optlen >= sizeof(int)) {
			if (get_user(val, (int __user *)optval))
				return -EFAULT;
		} else if (optlen >= sizeof(char)) {
			unsigned char ucval;

			if (get_user(ucval, (unsigned char __user *)optval))
				return -EFAULT;
			val = (int)ucval;
		}

		lock_sock(sk);

		val &= ~3;
		val |= inet->tos & 3;
		if (IPTOS_PREC(val) >= IPTOS_PREC_CRITIC_ECP &&
		    !capable(CAP_NET_ADMIN))
			err = -EPERM;
		else if (inet->tos != val) {
			inet->tos = val;
			sk->sk_priority = rt_tos2priority(val);

			/*
			 * Set the HW TOS only if it's not being used to
			 * determine the scheduling class and if the new
			 * TOS isn't special.
			 */
			if (cplios->sched_cls >= 8 && (val & 0xe0) != 0xc0)
				t3_set_tos(sk);
		}

		release_sock(sk);
		return err;
	}

#ifdef TOM_CONFIG_COMPAT
	if (call_compat && inet_csk(sk)->icsk_af_ops->compat_setsockopt)
		return inet_csk(sk)->icsk_af_ops->compat_setsockopt(sk, level,
						optname, optval, optlen);
#endif
	return inet_csk(sk)->icsk_af_ops->setsockopt(sk, level, optname,
						     optval, optlen);
}

/*
 * Socket option code for TCP.  We override any option processing that needs to
 * be handled specially for a TOE and leave the other options to SW TCP.
 */
static int do_t3_tcp_setsockopt(struct sock *sk, int level, int optname,
				char __user *optval, socklen_t optlen)
{
	struct tcp_sock *tp = tcp_sk(sk);
	int val, err = 0;

	if (optname == TCP_CONGESTION) {
		char name[TCP_CA_NAME_MAX];

		if (optlen < 1)
			return -EINVAL;
		val = strncpy_from_user(name, optval,
					min((socklen_t)(TCP_CA_NAME_MAX - 1),
					    optlen));
		if (val < 0)
			return -EFAULT;
		name[val] = 0;
		return t3_set_cong_control(sk, name);
	}

	if (optlen < sizeof(int))
		return -EINVAL;

	if (get_user(val, (int __user *)optval))
		return -EFAULT;

	lock_sock(sk);

	switch (optname) {
	case TCP_NODELAY: {
		int oldval = tp->nonagle;

		if (val)
			tp->nonagle |= TCP_NAGLE_OFF;
		else
			tp->nonagle &= ~TCP_NAGLE_OFF;

		if (oldval != tp->nonagle)
			t3_set_nagle(sk);
		break;
	}

	case TCP_CORK:
		if (val)
			tp->nonagle |= TCP_NAGLE_CORK;
		else
			tcp_uncork(sk);
		break;

	case TCP_KEEPIDLE:
		if (val < 1 || val > MAX_TCP_KEEPIDLE)
			err = -EINVAL;
		else {
			tp->keepalive_time = val * HZ;
		}
		break;

	case TCP_QUICKACK:
		if (!val) {
			inet_csk(sk)->icsk_ack.pingpong = 1;
		} else {
			inet_csk(sk)->icsk_ack.pingpong = 0;
		}
		break;

	default:
		release_sock(sk);
		err = tcp_setsockopt(sk, level, optname,
				     optval, optlen);
		goto out;
	}
	release_sock(sk);
out:
	return err;
}

static int t3_tcp_setsockopt(struct sock *sk, int level, int optname,
			     char __user *optval, socklen_t optlen)
{
	return level != SOL_TCP ?
		t3_ip_setsockopt(sk, level, optname, optval, optlen, 0) :
		do_t3_tcp_setsockopt(sk, level, optname, optval, optlen);
}

#ifdef TOM_CONFIG_COMPAT
static int t3_compat_tcp_setsockopt(struct sock *sk, int level, int optname,
				    char __user *optval, socklen_t optlen)
{
	return level != SOL_TCP ?
		t3_ip_setsockopt(sk, level, optname, optval, optlen, 1) :
		do_t3_tcp_setsockopt(sk, level, optname, optval, optlen);
}
#endif

#if defined(CONFIG_TCP_OFFLOAD)
static void set_keepalive(struct sock *sk, int on_off)
{
	int old = sock_flag(sk, SOCK_KEEPOPEN) != 0;

	if (sk->sk_state != TCP_CLOSE && (on_off ^ old))
		t3_set_keepalive(sk, on_off);
}
#endif

struct request_sock_ops t3_rsk_ops;

struct sk_ofld_proto t3_tcp_prot;

/*
 * Set up the offload protocol operations vector.  We start with TCP's and
 * override some of the operations.  Note that we do not override the backlog
 * handler here.
 */
void __init t3_init_offload_ops(void)
{
	t3_tcp_prot.proto = tcp_prot;
	t3_init_rsk_ops(&t3_tcp_prot.proto, &t3_rsk_ops, &tcp_prot);

	t3_tcp_prot.proto.close         = chelsio_close;
	t3_tcp_prot.proto.disconnect    = chelsio_disconnect;
	t3_tcp_prot.proto.destroy       = chelsio_destroy_sock;
	t3_tcp_prot.proto.shutdown      = chelsio_shutdown;
	t3_tcp_prot.proto.setsockopt    = t3_tcp_setsockopt;
	t3_tcp_prot.proto.sendmsg       = chelsio_sendmsg;
	t3_tcp_prot.proto.recvmsg       = chelsio_recvmsg;
	t3_tcp_prot.proto.sendpage      = chelsio_sendpage;
#if defined(CONFIG_TCP_OFFLOAD)
	t3_tcp_prot.proto.sendskb       = t3_sendskb;
	t3_tcp_prot.proto.read_sock     = t3_read_sock;
	t3_tcp_prot.proto.set_keepalive = set_keepalive;
#endif
#ifdef TOM_CONFIG_COMPAT
	t3_tcp_prot.proto.compat_setsockopt = t3_compat_tcp_setsockopt;
#endif
	t3_tcp_prot.read_sock = t3_read_sock;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,26)
	t3_tcp_prot.splice_read = chelsio_splice_read;
#endif
}
