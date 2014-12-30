/*
 * This file is part of the Chelsio T3 Ethernet driver.
 *
 * Copyright (C) 2003-2009 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */
#ifndef __CXGB3_COMPAT_H
#define __CXGB3_COMPAT_H

#include <linux/version.h>
#include "common.h"
#include <linux/pci.h>

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,21)
#include <asm/kdebug.h>

#ifdef RHEL_RELEASE_CODE

#if RHEL_RELEASE_CODE <= RHEL_RELEASE_VERSION(4, 8)
#define unregister_die_notifier(a)
#define register_die_notifier(a)
#endif

#else

#define unregister_die_notifier(a)
#define register_die_notifier(a)

#endif

#ifdef SLE_VERSION

#if SLE_VERSION_CODE <= SLE_VERSION(10,3,0)
#define unregister_die_notifier(a)
#define register_die_notifier(a)
#endif

#endif

#else
#include <linux/kdebug.h>
#endif

/* XXX Verify OS version */
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,13) && \
    LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,5)

#if LINUX_VERSION_CODE == KERNEL_VERSION(2,6,5)

struct msix_entry {
	u16 	vector;	/* kernel uses to write allocated vector */
	u16	entry;	/* driver uses to specify entry, OS writes */
};

static inline void pci_disable_msi(struct pci_dev *dev)
{}

static inline int pci_enable_msix(struct pci_dev* dev, struct msix_entry *entries,
			          int nvec)
{
	return -1;
}

static inline void pci_disable_msix(struct pci_dev* dev)
{}

static inline struct mii_ioctl_data *if_mii(struct ifreq *rq)

{
	return (struct mii_ioctl_data *) &rq->ifr_ifru;
}

#define _spin_trylock spin_trylock

#endif /* KERNEL_VERSION(2.6.5) */

#ifndef ATOMIC_ADD_RETURN
#if defined(CONFIG_X86_64)
static __inline__ int atomic_add_return(int i, atomic_t *v)
{
	int __i = i;
	__asm__ __volatile__(
		LOCK "xaddl %0, %1;"
		:"=r"(i)
		:"m"(v->counter), "0"(i));
	return i + __i;
}

#elif defined(CONFIG_X86)
static __inline__ int atomic_add_return(int i, atomic_t *v)
{
	int __i;
#ifdef CONFIG_M386
	if(unlikely(boot_cpu_data.x86==3))
		goto no_xadd;
#endif
	/* Modern 486+ processor */
	__i = i;
	__asm__ __volatile__(
		LOCK "xaddl %0, %1;"
		:"=r"(i)
		:"m"(v->counter), "0"(i));
	return i + __i;

#ifdef CONFIG_M386
no_xadd: /* Legacy 386 processor */
	local_irq_disable();
	__i = atomic_read(v);
	atomic_set(v, i + __i);
	local_irq_enable();
	return i + __i;
#endif
}

#elif defined(CONFIG_IA64)
#define atomic_add_return(i,v)						\
({									\
	int __ia64_aar_i = (i);						\
	(__builtin_constant_p(i)					\
	 && (   (__ia64_aar_i ==  1) || (__ia64_aar_i ==   4)		\
	     || (__ia64_aar_i ==  8) || (__ia64_aar_i ==  16)		\
	     || (__ia64_aar_i == -1) || (__ia64_aar_i ==  -4)		\
	     || (__ia64_aar_i == -8) || (__ia64_aar_i == -16)))		\
		? ia64_fetch_and_add(__ia64_aar_i, &(v)->counter)	\
		: ia64_atomic_add(__ia64_aar_i, v);			\
})

#elif defined(CONFIG_PPC64)
static __inline__ int atomic_add_return(int a, atomic_t *v)
{
	int t;

	__asm__ __volatile__(
	EIEIO_ON_SMP
"1:	lwarx	%0,0,%2		# atomic_add_return\n\
	add	%0,%1,%0\n\
	stwcx.	%0,0,%2\n\
	bne-	1b"
	ISYNC_ON_SMP
	: "=&r" (t)
	: "r" (a), "r" (&v->counter)
	: "cc", "memory");

	return t;
}

#elif defined(CONFIG_PPC)
static __inline__ int atomic_add_return(int a, atomic_t *v)
{
	int t;

	__asm__ __volatile__(
"1:	lwarx	%0,0,%2		# atomic_add_return\n\
	add	%0,%1,%0\n"
	PPC405_ERR77(0,%2)
"	stwcx.	%0,0,%2 \n\
	bne-	1b"
	SMP_ISYNC
	: "=&r" (t)
	: "r" (a), "r" (&v->counter)
	: "cc", "memory");

	return t;
}
#endif
#endif /* ATOMIC_ADD_RETURN */

#ifndef SPIN_TRYLOCK_IRQSAVE
#define spin_trylock_irqsave(lock, flags) \
({ \
	local_irq_save(flags); \
	_spin_trylock(lock) ? \
	1 : ({ local_irq_restore(flags); 0; }); \
})
#endif


#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,11)
static inline int t3_os_pci_save_state(struct adapter *adapter)
{
	return pci_save_state(adapter->pdev, adapter->t3_config_space);
}

static inline int t3_os_pci_restore_state(struct adapter *adapter)
{
	return pci_restore_state(adapter->pdev, adapter->t3_config_space);
}

static
inline void cancel_rearming_delayed_workqueue(struct workqueue_struct *wq,
					      struct work_struct *work)
{
	while (!cancel_delayed_work(work))
		flush_workqueue(wq);
}

#else
static inline int t3_os_pci_save_state(adapter_t *adapter)
{
	return pci_save_state(adapter->pdev);
}

static inline int t3_os_pci_restore_state(adapter_t *adapter)
{
	return pci_restore_state(adapter->pdev);
}
#endif

static inline int __netif_rx_schedule_prep(struct net_device *dev)
{
	return !test_and_set_bit(__LINK_STATE_RX_SCHED, &dev->state);
}

#ifndef CONFIG_DEBUG_FS
#include <linux/err.h>
/* Adapted from debugfs.h */
static inline struct dentry *debugfs_create_dir(const char *name,
						struct dentry *parent)
{
	return ERR_PTR(-ENODEV);
}

static inline void debugfs_remove(struct dentry *dentry)
{}
#else
#include <linux/debugfs.h>
#endif

static inline void setup_timer(struct timer_list * timer,
				void (*function)(unsigned long),
				unsigned long data)
{
	timer->function = function;
	timer->data = data;
	init_timer(timer);
}

#define DEFINE_MUTEX DECLARE_MUTEX
#define mutex_lock down
#define mutex_unlock up

#undef DEFINE_RWLOCK /* broken RH4u3 definition, rw_lock_t does not exist */
#define DEFINE_RWLOCK(x)	rwlock_t x = RW_LOCK_UNLOCKED

#define gfp_t unsigned

/* 2.6.14 and above */
#elif LINUX_VERSION_CODE > KERNEL_VERSION(2,6,13)
#include <linux/debugfs.h>

static inline int t3_os_pci_save_state(adapter_t *adapter)
{
	return pci_save_state(adapter->pdev);
}

static inline int t3_os_pci_restore_state(adapter_t *adapter)
{
	return pci_restore_state(adapter->pdev);
}

#endif /* LINUX_VERSION_CODE */

#if !defined(NETEVENT)
struct notifier_block;

static inline void register_netevent_notifier(struct notifier_block *nb)
{}

static inline void unregister_netevent_notifier(struct notifier_block *nb)
{}

#if defined(CONFIG_TCP_OFFLOAD_MODULE) && defined(CONFIG_X86)
#define OFLD_USE_KPROBES
#endif

#else
extern int netdev_nit;
#endif


#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)

typedef irqreturn_t (*intr_handler_t)(int, void *, struct pt_regs *);
#define DECLARE_INTR_HANDLER(handler, irq, cookie, regs) \
	static irqreturn_t handler(int irq, void *cookie, struct pt_regs *regs)

intr_handler_t t3_intr_handler(struct adapter *adap, int polling);
static inline void t3_poll_handler(struct adapter *adapter,
				   struct sge_qset *qs)
{
	t3_intr_handler(adapter, qs->rspq.flags & USING_POLLING) (0,
		(adapter->flags & USING_MSIX) ? (void *)qs : (void *)adapter,
		NULL);
}

#define CHECKSUM_PARTIAL CHECKSUM_HW
#define CHECKSUM_COMPLETE CHECKSUM_HW

#ifndef I_PRIVATE
#define i_private u.generic_ip
#endif

#else /* 2.6.19 */
typedef irqreturn_t (*intr_handler_t)(int, void *);
#define DECLARE_INTR_HANDLER(handler, irq, cookie, regs) \
	static irqreturn_t handler(int irq, void *cookie)

intr_handler_t t3_intr_handler(struct adapter *adap, int polling);
static inline void t3_poll_handler(struct adapter *adapter,
		 		   struct sge_qset *qs)
{
	t3_intr_handler(adapter, qs->rspq.flags & USING_POLLING) (0,
		(adapter->flags & USING_MSIX) ? (void *)qs : (void *)adapter);
}

#endif /* 2.6.19 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)
#define DECLARE_TASK_FUNC(task, task_param) \
	static void task(void *task_param)

#define WORK2ADAP(task_param, task) task_param
#define DELWORK2ADAP(task_param, task) task_param
#define WORK2T3CDATA(task_param, task) task_param

#define delayed_work work_struct

#define T3_INIT_WORK INIT_WORK
#define T3_INIT_DELAYED_WORK INIT_WORK

#else /* 2.6.20 */

#define DECLARE_TASK_FUNC(task, task_param) \
	static void task(struct work_struct *task_param)

#define WORK2ADAP(task_param, task) \
	container_of(task_param, struct adapter, task)

#define DELWORK2ADAP(task_param, task) \
	container_of(task_param, struct adapter, task.work)

#define WORK2T3CDATA(task_param, task) \
	container_of(task_param, struct t3c_data, task)

#define T3_INIT_WORK(task_handler, task, adapter) \
	INIT_WORK(task_handler, task)

#define T3_INIT_DELAYED_WORK(task_handler, task, adapter) \
	INIT_DELAYED_WORK(task_handler, task)

#endif /* 2.6.20 */

#if defined(CONFIG_FW_LOADER) || defined(CONFIG_FW_LOADER_MODULE)
#include <linux/firmware.h>
#else
struct firmware {
	size_t size;
	u8 *data;
};

struct device;

static inline int request_firmware(const struct firmware **firmware_p,
				   char *name,
				   struct device *device)
{
	printk(KERN_WARNING
	       "FW_LOADER not set in this kernel. FW upgrade aborted.\n");
	return -1;
}

static inline void release_firmware(const struct firmware *fw)
{}
#endif /* FW_LOADER */

#if !defined(RTNL_TRYLOCK)
#include <linux/rtnetlink.h>
static inline int rtnl_trylock(void)
{
	return !rtnl_shlock_nowait();
}
#endif /* RTNL_TRYLOCK */

#if  LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
#ifndef KZALLOC
static inline void *kzalloc(size_t size, int flags)
{
	void *ret = kmalloc(size, flags);
	if (ret)
		memset(ret, 0, size);
	return ret;
}
#endif /* KZALLOC */
#endif

#ifndef GSO_SIZE
#define gso_size tso_size
#endif /* GSO_SIZE */

#ifndef NIPQUAD_FMT
#define NIPQUAD_FMT "%u.%u.%u.%u"
#endif

/* sysfs compatibility */
#if  LINUX_VERSION_CODE < KERNEL_VERSION(2,6,21)

#define to_net_dev(class) container_of(class, struct net_device, class_dev)

#define cxgb3_compat_device class_device

#define CXGB3_SHOW_FUNC(func, d, attr, buf)			\
	static ssize_t func(struct cxgb3_compat_device *d,	\
			    char *buf)				\

#define CXGB3_STORE_FUNC(func, d, attr, buf, len)		\
	static ssize_t func(struct cxgb3_compat_device *d,	\
			    const char *buf,			\
			    size_t len)

#ifndef  __ATTR
#define __ATTR(_name,_mode,_show,_store) { \
	.attr = {.name = __stringify(_name), .mode = _mode, .owner = THIS_MODULE },	\
	.show	= _show,					\
	.store	= _store,					\
}
#endif

#define CXGB3_DEVICE_ATTR(_name,_mode,_show,_store)		\
struct class_device_attribute dev_attr_##_name = 		\
	__ATTR(_name,_mode,_show,_store)

#ifndef LINUX_2_4
static inline struct kobject *net2kobj(struct net_device *dev)
{
	return &dev->class_dev.kobj;
}
#endif

#else /* sysfs compatibility */

#define cxgb3_compat_device device

#define CXGB3_SHOW_FUNC(func, d, attr, buf)			\
	static ssize_t func(struct cxgb3_compat_device *d,	\
			    struct device_attribute *attr,	\
			    char *buf)				\

#define CXGB3_STORE_FUNC(func, d, attr, buf, len)		\
	static ssize_t func(struct cxgb3_compat_device *d,	\
			    struct device_attribute *attr,	\
			    const char *buf,			\
			    size_t len)

#define CXGB3_DEVICE_ATTR DEVICE_ATTR

static inline struct kobject *net2kobj(struct net_device *dev)
{
	return &dev->dev.kobj;
}

#endif /* sysfs compatibility */

#if !defined(IRQF)
#define IRQF_SHARED SA_SHIRQ
#endif /* IRQF */

#if !defined(VLANGRP)
#include <linux/if_vlan.h>
static inline struct net_device *vlan_group_get_device(struct vlan_group *vg,
						       int vlan_id)
{
	return vg->vlan_devices[vlan_id];
}
#endif /* VLANGRP */

#if !defined(for_each_netdev)
#define for_each_netdev(d) \
	for (d = dev_base; d; d = d->next)
#endif

#include <linux/ip.h>

#if !defined(NEW_SKB_COPY)
static inline void skb_copy_from_linear_data(const struct sk_buff *skb,
					     void *to,
					     const unsigned int len)
{
	memcpy(to, skb->data, len);
}

static inline void skb_copy_from_linear_data_offset(const struct sk_buff *skb,
						    const int offset, void *to,
						    const unsigned int len)
{
	memcpy(to, skb->data + offset, len);
}

static inline void skb_copy_to_linear_data(struct sk_buff *skb,
					   const void *from,
					   const unsigned int len)
{
	memcpy(skb->data, from, len);
}

static inline void skb_copy_to_linear_data_offset(struct sk_buff *skb,
						  const int offset,
						  const void *from,
						  const unsigned int len)
{
	memcpy(skb->data + offset, from, len);
}

#endif

#if defined(NEW_SKB_OFFSET)
static inline void cxgb3_set_skb_header(struct sk_buff *skb,
					struct iphdr *ip_hdr,
					int offset)
{
	skb_set_network_header(skb, offset);
}

#else /* NEW_SKB_OFFSET */
static inline int skb_network_offset(struct sk_buff *skb)
{
	return skb->nh.raw - skb->data;
}

static inline unsigned char *skb_transport_header(const struct sk_buff *skb)
{
	return skb->h.raw;
}

#if !defined(T3_SKB_TRANSPORT_OFFSET)
static inline int skb_transport_offset(const struct sk_buff *skb)
{
	return skb->h.raw - skb->data;
}
#endif

#if !defined(T3_IP_HDR)
static inline struct iphdr *ip_hdr(const struct sk_buff *skb)
{
	return skb->nh.iph;
}
#endif

#if !defined(T3_TCP_HDR)
static inline struct tcphdr *tcp_hdr(const struct sk_buff *skb)
{
	return skb->h.th;
}
#endif

#if !defined(T3_RESET_MAC_HEADER)
static inline void skb_reset_mac_header(struct sk_buff *skb)
{
	skb->mac.raw = skb->data;
}
#endif

#if !defined(T3_MAC_HEADER)
static inline unsigned char *skb_mac_header(struct sk_buff *skb)
{
	return skb->mac.raw;
}
#endif

static inline void skb_reset_network_header(struct sk_buff *skb)
{
	skb->nh.raw = skb->data;
}

static inline void skb_reset_transport_header(struct sk_buff *skb)
{
	skb->h.raw = skb->data;
}

static inline void cxgb3_set_skb_header(struct sk_buff *skb,
					struct iphdr *ip_hdr,
					int offset)
{
	skb->nh.iph = ip_hdr;
}

#endif /* NEW_SKB_OFFSET */

#if !defined(ARP_HDR)
static inline struct arphdr *arp_hdr(const struct sk_buff *skb)
{
        return (struct arphdr *)skb->nh.arph;
}
#endif /* !ARP_HDR */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,23)
#if defined(ETHTOOL_GPERMADDR)
#define CXGB3_ETHTOOL_GPERMADDR ETHTOOL_GPERMADDR
#endif
#endif

#if !defined(TRANSPORT_HEADER)
#define transport_header h.raw
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
#define SET_MODULE_OWNER(module)
#define INET_PROC_DIR init_net.proc_net
#else
#define INET_PROC_DIR proc_net
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,30)
#define SET_PROC_NODE_OWNER(_p, _owner) \
	do { (_p)->owner = (_owner); } while (0)
#else
#define SET_PROC_NODE_OWNER(_p, _owner) \
	do { } while (0)
#endif

#if defined(NAPI_UPDATE)
#define SGE_GET_OFLD_QS(napi, dev) \
	container_of(napi, struct sge_qset, napi)

#define DECLARE_OFLD_POLL(napi, dev, budget) \
	static int ofld_poll(struct napi_struct *napi, int budget)

#define DECLARE_NAPI_RX_HANDLER(napi, dev, budget) \
	static int napi_rx_handler(struct napi_struct *napi, int budget)

#else
#define SGE_GET_OFLD_QS(napi, dev) \
	((struct port_info *)netdev_priv(dev))->qs

#define DECLARE_OFLD_POLL(napi, dev, budget) \
	static int ofld_poll(struct net_device *dev, int *budget)

#define DECLARE_NAPI_RX_HANDLER(napi, dev, budget) \
	static int napi_rx_handler(struct net_device *dev, int *budget)

#endif /* NAPI_UPDATE */


#if !defined(VLAN_DEV_API)
#include <linux/if_vlan.h>
#if defined(VLAN_DEV_INFO)
static inline struct vlan_dev_info *vlan_dev_info(const struct net_device *dev)
{
	return VLAN_DEV_INFO(dev);
}
#endif

static inline u16 vlan_dev_vlan_id(const struct net_device *dev)
{
	return vlan_dev_info(dev)->vlan_id;
}

static inline struct net_device *vlan_dev_real_dev(const struct net_device *dev)
{
	return vlan_dev_info(dev)->real_dev;
}
#else /* VLAN_DEV_API */
#if defined(RHEL_RELEASE_CODE)
#if RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(5,7) && \
    RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(6,0)
#include <linux/if_vlan.h>
static inline u16 vlan_dev_vlan_id(const struct net_device *dev)
{
	return VLAN_DEV_INFO(dev)->vlan_id;
}
#endif
#endif /* RHEL_RELEASE_CODE */
#endif /* VLAN_DEV_API */

#if defined(PDEV_MAPPING)
static inline int t3_pci_dma_mapping_error(struct pci_dev *pdev,
					   dma_addr_t dma_addr)
{
	return pci_dma_mapping_error(pdev, dma_addr);
}
#else
static inline int t3_pci_dma_mapping_error(struct pci_dev *pdev,
					   dma_addr_t dma_addr)
{
	return pci_dma_mapping_error(dma_addr);
}
#endif

#ifndef DMA_BIT_MASK
#define DMA_BIT_MASK(n)	(((n) == 64) ? ~0ULL : ((1ULL<<(n))-1))
#endif

#if !defined(MQ_TX)
struct netdev_queue {};

static inline void t3_compat_set_num_tx_queues(struct net_device *dev,
					       int n)
{}

static inline struct netdev_queue * netdev_get_tx_queue(struct net_device *dev,
				 			int qidx)
{
	return NULL;
}

#define netif_tx_start_all_queues netif_start_queue
#define netif_tx_stop_all_queues netif_stop_queue

static inline void t3_netif_tx_stop_queue(struct net_device *dev,
					  struct netdev_queue *txq)
{
	netif_stop_queue(dev);
}

static inline void t3_netif_tx_wake_queue(struct net_device *dev,
					  struct netdev_queue *txq)
{
	netif_wake_queue(dev);
}

static inline int t3_netif_tx_queue_stopped(struct net_device *dev,
					    struct netdev_queue *txq)
{
	return netif_queue_stopped(dev);
}

#ifndef ALLOC_ETHERDEV_MQ_DEF
#include <linux/etherdevice.h>
static inline struct net_device * alloc_etherdev_mq(int sizeof_priv,
						    int n_txq)
{
	return alloc_etherdev(sizeof_priv);
}
#else
#if defined(RHEL_RELEASE_CODE)
/* RHEL 5.6 (and above) expects number of queues to be 1 (hardcoded) */
#if RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(5, 6)
#define alloc_etherdev_mq(sizeof_priv, n_txq)	alloc_etherdev(sizeof_priv)
#endif /* RHEL_RELEASE_VERSION(5, 6) */
#endif /* RHEL_RELEASE_CODE */
#endif /* ALLOC_ETHERDEV_MQ_DEF */
	
#else /* The stack supports TX multiqueues */
static inline void t3_compat_set_num_tx_queues(struct net_device *dev,
					       int n)
{
	dev->real_num_tx_queues = n;
}

static inline void t3_netif_tx_stop_queue(struct net_device *dev,
					  struct netdev_queue *txq)
{
	netif_tx_stop_queue(txq);
}

static inline void t3_netif_tx_wake_queue(struct net_device *dev,
					  struct netdev_queue *txq)
{
	netif_tx_wake_queue(txq);
}

static inline int t3_netif_tx_queue_stopped(struct net_device *dev,
					    struct netdev_queue *txq)
{
	return netif_tx_queue_stopped(txq);
}

#endif

#if !defined(SKB_RECORD_RX_QUEUE)
static inline void skb_record_rx_queue(struct sk_buff *skb, u16 rx_queue)
{}
#endif

#if !defined(CXGB3_NIPQUAD)
#define NIPQUAD(addr) \
	((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[3]
#define NIPQUAD_FMT "%u.%u.%u.%u"
#endif

#if !defined(USECS_TO_JIFFIES)
static inline unsigned long usecs_to_jiffies(const unsigned int u)
{
	if (u > jiffies_to_usecs(MAX_JIFFY_OFFSET))
		return MAX_JIFFY_OFFSET;
#if HZ <= USEC_PER_SEC && !(USEC_PER_SEC % HZ)
	return (u + (USEC_PER_SEC / HZ) - 1) / (USEC_PER_SEC / HZ);
#elif HZ > USEC_PER_SEC && !(HZ % USEC_PER_SEC)
	return u * (HZ / USEC_PER_SEC);
#else
	return (USEC_TO_HZ_MUL32 * u + USEC_TO_HZ_ADJ32)
		>> USEC_TO_HZ_SHR32;
#endif
}
#endif

#endif
