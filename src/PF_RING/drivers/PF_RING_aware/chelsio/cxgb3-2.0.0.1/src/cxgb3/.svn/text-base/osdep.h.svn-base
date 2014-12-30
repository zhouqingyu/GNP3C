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

#ifndef __CHELSIO_OSDEP_H
#define __CHELSIO_OSDEP_H

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/ctype.h>
#include <linux/delay.h>
#include <linux/init.h>
#include <linux/netdevice.h>
#include <linux/ethtool.h>
#include <linux/mii.h>
#include <linux/version.h>
#include "version.h"

#define CH_ERR(adap, fmt, ...)   dev_err(&adap->pdev->dev, fmt, ## __VA_ARGS__)
#define CH_WARN(adap, fmt, ...)  dev_warn(&adap->pdev->dev, fmt, ## __VA_ARGS__)
#define CH_ALERT(adap, fmt, ...) \
	dev_printk(KERN_ALERT, &adap->pdev->dev, fmt, ## __VA_ARGS__)

/*
 * More powerful macro that selectively prints messages based on msg_enable.
 * For info and debugging messages.
 */
#define CH_MSG(adapter, level, category, fmt, ...) do { \
	if ((adapter)->msg_enable & NETIF_MSG_##category) \
		dev_printk(KERN_##level, &adapter->pdev->dev, fmt, \
			   ## __VA_ARGS__); \
} while (0)

#ifdef DEBUG
# define CH_DBG(adapter, category, fmt, ...) \
	CH_MSG(adapter, DEBUG, category, fmt, ## __VA_ARGS__)
#else
# define CH_DBG(adapter, category, fmt, ...)
#endif

/* Additional NETIF_MSG_* categories */
#define NETIF_MSG_OFLD 0x4000000
#define NETIF_MSG_MMIO 0x8000000

#define IFF_FILTER_ETH_P_SLOW 0x4

typedef struct adapter adapter_t;
typedef struct port_info pinfo_t;

/**
 * struct t3_rx_mode - encapsulates the Rx mode for a port
 * @dev: the net_device associated with the port
 * @mclist: the multicast address list for the port
 * @idx: current position within the multicast list
 *
 * This structure is passed to the MAC routines that configure the Rx mode
 * of a port.  The structure is opaque to the common code.  It invokes a few
 * functions on this structure including promisc_rx_mode()
 * that returns whether the port should be in promiscuous mode,
 * allmulti_rx_mode() to check if the port should be in ALLMULTI mode,
 * and t3_get_next_mcaddr() that returns the multicast addresses for the
 * port one at a time.
 */
struct t3_rx_mode {
	struct net_device *dev;
	struct dev_mc_list *mclist;
	unsigned int idx;
};

static inline void init_rx_mode(struct t3_rx_mode *p, struct net_device *dev)
{
	p->dev = dev;
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,34)
	p->mclist = dev->mc_list;
#else
	p->mclist = NULL;
#endif
	p->idx = 0;
}

#define promisc_rx_mode(rm)  ((rm)->dev->flags & IFF_PROMISC) 
#define allmulti_rx_mode(rm) ((rm)->dev->flags & IFF_ALLMULTI) 

/**
 * t3_get_next_mcaddr - return the next L2 multicast address for a port
 * @rm: the Rx mode info
 *
 * Returns the next Ethernet multicast address for a port or %NULL if there are
 * no more.
 */
static inline u8 *t3_get_next_mcaddr(struct t3_rx_mode *rm)
{
	u8 *addr = NULL;

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,34)
	if (rm->mclist && rm->idx < rm->dev->mc_count) {
		addr = rm->mclist->dmi_addr;
		rm->mclist = rm->mclist->next;
		rm->idx++;
	}
#else
	struct netdev_hw_addr *ha;
	int cur = 0;	

	netdev_for_each_mc_addr(ha, rm->dev) {
		if (cur == rm->idx) {
			addr = ha->addr;
			rm->idx++;
		}
		cur++;
	}
#endif

	return addr;
}

enum {
	TP_TMR_RES = 200,	/* TP timer resolution in usec */
	MAX_NPORTS = 4,		/* max # of ports */
	TP_SRAM_OFFSET = 4096,	/* TP SRAM content offset in eeprom */
	TP_SRAM_LEN = 2112,	/* TP SRAM content offset in eeprom */
};

/* compatibility stuff for older kernels */
#ifndef PCI_EXP_LNKSTA
#define PCI_EXP_LNKSTA          18      /* Link Status */
#endif

#ifndef PCI_EXP_LNKCTL
#define PCI_EXP_LNKCTL		16	/* Link Control */
#endif

#ifndef PCI_EXP_LNKCAP
#define PCI_EXP_LNKCAP		12	/* Link Capabilities */
#endif

#ifndef PCI_EXP_DEVCTL
#define PCI_EXP_DEVCTL		8	/* Device Control */
#endif

#ifndef PCI_EXP_DEVCTL_PAYLOAD
#define  PCI_EXP_DEVCTL_PAYLOAD	0x00e0	/* Max_Payload_Size */
#endif

#ifndef PCI_EXP_DEVCTL_READRQ
#define  PCI_EXP_DEVCTL_READRQ  0x7000  /* Max_Read_Request_Size */
#endif

#ifndef BMCR_SPEED1000
#define BMCR_SPEED1000		0x0040  /* MSB of Speed (1000) */
#endif

#ifndef MII_CTRL1000
#define MII_CTRL1000            0x09    /* 1000BASE-T control */
#define ADVERTISE_1000FULL      0x0200  /* Advertise 1000BASE-T full duplex */
#define ADVERTISE_1000HALF      0x0100  /* Advertise 1000BASE-T half duplex */
#endif

#ifndef ADVERTISE_PAUSE_CAP
#define ADVERTISE_PAUSE_CAP     0x0400  /* Try for pause               */
#define ADVERTISE_PAUSE_ASYM    0x0800  /* Try for asymetric pause     */
#endif

#ifndef ADVERTISED_Pause
#define ADVERTISED_Pause        (1 << 13)
#define ADVERTISED_Asym_Pause   (1 << 14)
#endif

#ifndef NETDEV_TX_OK
#define NETDEV_TX_OK 0		/* driver took care of packet */
#define NETDEV_TX_BUSY 1	/* driver tx path was busy*/
#define NETDEV_TX_LOCKED -1	/* driver tx lock was already taken */
#endif

#ifndef ADVERTISE_1000XFULL
#define ADVERTISE_1000XFULL	0x0020
#endif

#ifndef ADVERTISE_1000XHALF
#define ADVERTISE_1000XHALF	0x0040
#endif

#ifndef ADVERTISE_1000XPAUSE
#define ADVERTISE_1000XPAUSE	0x0080
#endif

#ifndef ADVERTISE_1000XPSE_ASYM
#define ADVERTISE_1000XPSE_ASYM 0x0100
#endif

/* Note: cxgb3_compat.h assumes that struct adapter is already defined. 
 * delayed_work is used in struct adapter definition, hence backporting
 * its definition here.
 */
#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)
#define delayed_work work_struct
#endif

#ifdef	LINUX_2_4
#include "linux_2_4_compat.h"
#include "linux_2_4_compat_workqueue.h"
#endif

#ifdef CONFIG_XEN
#define CHELSIO_FREE_TXBUF_ASAP 1	/* VMs need TX bufs freed ASAP */
#endif

#endif  /* !__CHELSIO_OSDEP_H */
