/*
 * vNPlug CTRL (Virtio)
 *
 * Authors:
 *
 * 	Alfredo Cardigliano <cardigliano@ntop.org>
 *
 * This work is licensed under the terms of the GNU GPL version 2. 
 *
 */

#ifndef VNPLUG_CTRL_H
#define VNPLUG_CTRL_H

#include "virtio.h"

#include "pci.h"
#define PCI_DEVICE_ID_VNPLUG_CTRL	0x100f

/* The ID for vnplug_ctrl */
#define VIRTIO_ID_VNPLUG_CTRL 15



/* The feature bitmap for vnplug-ctrl over virtio */
#define VNPLUG_CTRL_STATUS			 0  /* vnplug_ctrl_status available */

struct vnplug_ctrl_virtio_config
{
	/* See VNPLUG_CTRL_STATUS feature bit */
#define VNPLUG_CTRL_STATUS_UP 1 
	uint16_t status;

	uint16_t padding; //I'm an alignment maniac :D
}; //__attribute__((packed));



struct vnplug_ctrl_msg_hdr {
#define VNPLUG_CTRL_MSG_FORWARD   0 /* Forward the message to the client identified by id */
	uint32_t type;

	uint32_t id;

	/* return values */
/* positive values from handlers are forwarded to guest as they are */
#define VNPLUG_CTRL_MSG_RET_SUCCESS 		 0 /* success if ret value >= this value */
#define VNPLUG_CTRL_MSG_RET_CLIENT_NOT_FOUND 	-1
#define VNPLUG_CTRL_MSG_RET_CLIENT_ERROR 	-2
}; //__attribute__((packed));



/* TODO do we really need these here?*/
VirtIODevice *vnplug_ctrl_init(DeviceState *dev);
void vnplug_ctrl_exit(VirtIODevice *vdev);

#endif
