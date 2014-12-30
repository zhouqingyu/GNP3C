/*
 * Copyright (c) 2003-2009 Chelsio, Inc. All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/if_vlan.h>
#include <linux/mii.h>
#include <linux/sockios.h>
#include <linux/proc_fs.h>
#include <linux/rtnetlink.h>
#include <asm/uaccess.h>
#include <linux/pci.h>
#include <linux/spinlock.h>
#include <linux/interrupt.h>
#include <linux/timer.h>
#include <linux/cache.h>
#include <asm/atomic.h>
#include <asm/semaphore.h>
#include <asm/bitops.h>
#include <asm/io.h>
#include "common.h"

int atomic_add_return(int i, atomic_t *v)
{
        int __i;
        /* Modern 486+ processor */
        __i = i;
        __asm__ __volatile__(
                LOCK_PREFIX "xaddl %0, %1;"
                :"=r"(i)
                :"m"(v->counter), "0"(i));
        return i + __i;
}

__inline__ int generic_fls(int x)
{
        int r = 32;

        if (!x)
                return 0;
        if (!(x & 0xffff0000)) {
                x <<= 16;
                r -= 16;
        }
        if (!(x & 0xff000000)) {
                x <<= 8;
                r -= 8;
        }
        if (!(x & 0xf0000000)) {
                x <<= 4;
                r -= 4;
        }
        if (!(x & 0xc0000000)) {
                x <<= 2;
                r -= 2;
        }
        if (!(x & 0x80000000)) {
                x <<= 1;
                r -= 1;
        }
        return r;
}

inline int t3_os_pci_save_state(struct adapter *adapter)
{
        return pci_save_state(adapter->pdev, adapter->t3_config_space);
}

inline int t3_os_pci_restore_state(struct adapter *adapter)
{
        return pci_restore_state(adapter->pdev, adapter->t3_config_space);
}

#ifndef CONFIG_PCI_MSI

int pci_enable_msi(struct pci_dev* dev)
{
	return(-EINVAL);
}

int pci_disable_msi(struct pci_dev* dev)
{
	return(-EINVAL);
}

int pci_enable_msix(struct pci_dev* dev, 
				  struct msix_entry *entries, int nvec)
{
	return(-EINVAL);
}

int pci_disable_msix(struct pci_dev* dev)
{
	return(-EINVAL);
}

#endif /* !CONFIG_PCI_MSI */

void *kzalloc(size_t size, gfp_t flags)
{
	void *p;

	p = kmalloc(size, flags);
	if (p != NULL)
		memset(p, 0, size);
        return(p);
}

void *kcalloc(size_t n, size_t size, gfp_t flags)
{
        if (n != 0 && size > ULONG_MAX / n)
                return NULL;
        return kzalloc(n * size, flags);
}

#ifndef ALLOC_NETDEV
struct net_device *alloc_netdev(int sizeof_priv, const char *mask,
                                       void (*setup)(struct net_device *))
{
        struct net_device *dev;
        int alloc_size;

        /* ensure 32-byte alignment of the private area */
        alloc_size = sizeof (*dev) + sizeof_priv + 31;

        dev = (struct net_device *) kmalloc (alloc_size, GFP_KERNEL);
        if (dev == NULL)
        {
                printk(KERN_ERR "alloc_dev: Unable to allocate device memory.\n");
                return NULL;
        }

        memset(dev, 0, alloc_size);

        if (sizeof_priv)
                dev->priv = (void *) (((long)(dev + 1) + 31) & ~31);

        setup(dev);
        strcpy(dev->name, mask);

        return dev;
}
#endif

#define MSEC_PER_SEC    1000L
#define USEC_PER_MSEC   1000L
#define NSEC_PER_USEC   1000L
#define NSEC_PER_MSEC   1000000L
#define USEC_PER_SEC    1000000L
#define NSEC_PER_SEC    1000000000L
#define FSEC_PER_SEC    1000000000000000L

unsigned int jiffies_to_msecs(const unsigned long j)
{
#if HZ <= MSEC_PER_SEC && !(MSEC_PER_SEC % HZ)
        return (MSEC_PER_SEC / HZ) * j;
#elif HZ > MSEC_PER_SEC && !(HZ % MSEC_PER_SEC)
        return (j + (HZ / MSEC_PER_SEC) - 1)/(HZ / MSEC_PER_SEC);
#else
        return (j * MSEC_PER_SEC) / HZ;
#endif
}

unsigned long msecs_to_jiffies(const unsigned int m)
{
        if (m > jiffies_to_msecs(MAX_JIFFY_OFFSET))
                return MAX_JIFFY_OFFSET;
#if HZ <= MSEC_PER_SEC && !(MSEC_PER_SEC % HZ)
        return (m + (MSEC_PER_SEC / HZ) - 1) / (MSEC_PER_SEC / HZ);
#elif HZ > MSEC_PER_SEC && !(HZ % MSEC_PER_SEC)
        return m * (HZ / MSEC_PER_SEC);
#else
        return (m * HZ + MSEC_PER_SEC - 1) / MSEC_PER_SEC;
#endif
}

signed long schedule_timeout_interruptible(signed long timeout)
{
        __set_current_state(TASK_INTERRUPTIBLE);
        return schedule_timeout(timeout);
}

signed long schedule_timeout_uninterruptible(signed long timeout)
{
        __set_current_state(TASK_UNINTERRUPTIBLE);
        return schedule_timeout(timeout);
}

void msleep(unsigned int msecs)
{
        unsigned long timeout = msecs_to_jiffies(msecs) + 1;

        while (timeout)
                timeout = schedule_timeout_uninterruptible(timeout);
}

unsigned long msleep_interruptible(unsigned int msecs)
{
        unsigned long timeout = msecs_to_jiffies(msecs) + 1;

        while (timeout && !signal_pending(current))
                timeout = schedule_timeout_interruptible(timeout);
        return jiffies_to_msecs(timeout);
}


int
pci_set_consistent_dma_mask(struct pci_dev *dev, u64 mask)
{
        if (!pci_dma_supported(dev, mask))
                return -EIO;

#ifdef XXX
        dev->dev.coherent_dma_mask = mask;
#endif

        return 0;
}
