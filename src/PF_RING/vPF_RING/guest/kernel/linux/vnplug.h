#ifndef KERNEL_VNPLUG_H
#define KERNEL_VNPLUG_H


/* Enhanced supports */
#define VNPLUG_CTRL 	 /* enables the control interface over virtio */
#define VNPLUG_MULTI_IRQ /* enables support for multiple interrupts in userspace */


#ifdef __KERNEL__

#include <linux/device.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/idr.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/kobject.h>
#include <linux/interrupt.h>
#include <linux/pci.h>
#include <asm/io.h>

#define VNPLUG_DEVICE_NAME 		"vnplug"

#define PCI_VENDOR_ID_SILICOM		0x1374
#define PCI_DEVICE_ID_VNPLUG_DEV	0x00ff

#define VNPLUG_REG_REGION_SIZE		PAGE_SIZE

#else /* __KERNEL__ */

#include <stdint.h> /* uint32_t, etc. */

#define VNPLUG_REG_REGION_SIZE 		4096
/* Note: no VNPLUG_X_MM_REGION_SIZE, it is dynamic! */

#endif /* __KERNEL__ */

/*
 * Region bar_id=0
 * | device id (4) | doorbell (4) | region bar_id=2 size (4) | region bar_id=3 size (4) | ... |
 *
 * Region bar_id=1
 * | MSI-X (4K) |
 *
 * Region bar_id=2..5
 * | mapped memory (2^n) |
 */

#define VNPLUG_REG_OFF_ID		0x00
#define VNPLUG_REG_OFF_DOORBELL		0x04
#define VNPLUG_REG_OFF_BASE_MM_SIZE	0x08

#define VNPLUG_REG_REGION_ID     	0
#define VNPLUG_BASE_MM_REGION_ID     	1

#ifdef __KERNEL__

#define VNPLUG_PCI_REG_BAR_ID     	0
#define VNPLUG_PCI_MSI_BAR_ID     	1
#define VNPLUG_PCI_BASE_MM_BAR_ID     	2

#define VNPLUG_MAX_MM_BARS		4

/* mmap regions: MM BARSs + registers BAR */
#define VNPLUG_MAX_REGIONS VNPLUG_MAX_MM_BARS + 1 

#define VNPLUG_MAX_MSI_VECTORS		16

struct vnplug_device {
	struct device			*dev;
	int				 minor;
	atomic_t			 event;
	wait_queue_head_t		 wait;
#ifdef VNPLUG_MULTI_IRQ
	atomic_t			*event_s;
	wait_queue_head_t		*wait_s;
#endif /* VNPLUG_MULTI_IRQ */
	struct vnplug_info		*info;
};

struct vnplug_mem {
        unsigned long           	 addr;
        unsigned long           	 size;
        void __iomem            	*internal_addr;
};

struct vnplug_info {
	struct pci_dev 		*dev;
	char 			(*msix_names)[16]; /* 16 chars for a name should be enough */
	struct msix_entry 	*msix_entries;
	int 			nvectors;
	struct vnplug_device	*vnplug_dev;
	struct vnplug_mem	mem[VNPLUG_MAX_REGIONS];
};

struct vnplug_listener {
	struct vnplug_device 	*dev;
	s32 			 event_count;
#ifdef VNPLUG_MULTI_IRQ
	s32			*event_count_s;
#endif /* VNPLUG_MULTI_IRQ */
};

#endif /* __KERNEL__ */

#ifdef VNPLUG_CTRL

#ifdef __KERNEL__

#include <linux/module.h>
#include <linux/virtio.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/virtio_config.h>

#define VNPLUG_CTRL_DEVICE_NAME		"vnplug_ctrl"

/* Macros and data structures taken from 'hw/vnplug-ctrl.h' (host side): */

#define PCI_DEVICE_ID_VNPLUG_CTRL	0x100f

#define VIRTIO_ID_VNPLUG_CTRL		15

/* The feature bitmap for vnplug-ctrl over virtio */
#define VNPLUG_CTRL_STATUS		0  /* vnplug_ctrl_status available */

struct vnplug_ctrl_virtio_config
{
	/* See VNPLUG_CTRL_STATUS feature bit */
	#define VNPLUG_CTRL_STATUS_UP	1
	uint16_t status;

	uint16_t padding; //I'm an alignment maniac :D
}; //__attribute__((packed));

/* guest mod -> host */
struct vnplug_ctrl_msg_hdr {
	/* g2h message type */
	#define VNPLUG_CTRL_MSG_FORWARD	0 /* Forward the message to the client identified by id */
	uint32_t type;
	
	/* client id */
	uint32_t id;

	/* payload size is not required with current implementation (iov's len)*/
}; //__attribute__((packed));

struct vnplug_ctrl_info
{
	struct device		*dev;

	struct virtio_device *vdev;
	struct virtqueue *g2h_vq;

	unsigned int status;
};

#endif /* __KERNEL__ */

/* return values */
#define VNPLUG_CTRL_MSG_RET_SUCCESS		0
#define VNPLUG_CTRL_MSG_RET_CLIENT_NOT_FOUND	-1
#define VNPLUG_CTRL_MSG_RET_CLIENT_ERROR	-2

/* guest lib -> guest mod */
struct vnplug_ctrl_msg {
	uint32_t 	id; /* client id */
	uint32_t        payload_len;
	uint32_t        ret_payload_len; /* return value lenght */
	char		payload[0];
	/* ret_payload is at the and of payload */
};

#endif /* VNPLUG_CTRL */

#endif /* KERNEL_VNPLUG_H */
