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

#include "iov.h"
#include "vnplug-ctrl.h"
#include "virtio.h"
/* NOPATCH
#include "virtio-pci.c" // ugly, I know
*/
#include "vnplug.h"

//#define VNPLUG_CTRL_DEBUG

#ifdef VNPLUG_CTRL_DEBUG
#define VNPLUG_CTRL_DEBUG_PRINTF(fmt, ...)	do {printf("[vNPlug-CTRL] " fmt, ## __VA_ARGS__); } while (0)
#else
#define VNPLUG_CTRL_DEBUG_PRINTF(fmt, ...)
#endif

typedef struct VirtIOvNPlugCTRL
{
	VirtIODevice vdev;
	VirtQueue *g2h_vq;
	
	VMChangeStateEntry *vm_state;
	uint16_t status;
	DeviceState *qdev;
} VirtIOvNPlugCTRL;

#define VirtIODevice2VirtIOvNPlugCTRL(vdev) ((VirtIOvNPlugCTRL *) vdev)

/* Clients list */
static QLIST_HEAD(vnplug_ctrl_clients_head, vNPlugCTRLClientInfo) vnplug_ctrl_clients = 
	   QLIST_HEAD_INITIALIZER(vnplug_ctrl_clients);

/* ******************************************************************************* */
/* ************************************************************************* UTILS */

static struct vNPlugCTRLClientInfo *vnplug_ctrl_client_by_id(uint32_t client_id)
{
	struct vNPlugCTRLClientInfo *c; 

	QLIST_FOREACH(c, &vnplug_ctrl_clients, list) {
		VNPLUG_CTRL_DEBUG_PRINTF("we are looking for client id: %d. found client id: %d \n", client_id, c->id);	
		if (c->id == client_id)
			return c;
	}

	return NULL;
}

/* ******************************************************************************* */
/* ************************************************************** VNPLUG INTERFACE */

int  vnplug_ctrl_register_client  (struct vNPlugCTRLClientInfo *client)
{
	QLIST_INSERT_HEAD(&vnplug_ctrl_clients, client, list);

	VNPLUG_CTRL_DEBUG_PRINTF("registered new client '%s' with id %d \n", client->name, client->id);	

	return 0;
}

void vnplug_ctrl_unregister_client(struct vNPlugCTRLClientInfo *client)
{
	VNPLUG_CTRL_DEBUG_PRINTF("unregistering client '%s' with id %d\n", client->name, client->id);

	// do I need to do something more here?

	QLIST_REMOVE(client, list);
}

/* ******************************************************************************* */
/* ************************************************************************ VIRTIO */

static void vnplug_ctrl_handle_g2h(VirtIODevice *vdev, VirtQueue *vq)
{
	//VirtIOvNPlugCTRL *s = VirtIODevice2VirtIOvNPlugCTRL(vdev);
	VirtQueueElement elem;

	while (virtqueue_pop(vq, &elem)) {

	ssize_t len = 0;
	struct iovec *out_sg = &elem.out_sg[0];
	struct iovec *in_sg =  &elem.in_sg [0];
	struct vnplug_ctrl_msg_hdr *msg;
	int32_t *status_p;
	int32_t status = 0x00000000;
	struct vNPlugCTRLClientInfo *client;

	VNPLUG_CTRL_DEBUG_PRINTF("vnplug_ctrl_handle_g2h: message received [ out_num=%u in_num=%u ]\n", elem.out_num, elem.in_num);

	if (elem.out_num < 1 || out_sg->iov_len != sizeof(struct vnplug_ctrl_msg_hdr)) {
		fprintf(stderr, "[vNPlug-CTRL] vnplug_ctrl_handle_g2h: vnplug_ctrl_msg_hdr not found\n");
		exit(1);
	}

	if (elem.in_num < 1 || in_sg->iov_len != sizeof(int32_t)) {
		fprintf(stderr, "[vNPlug-CTRL] vnplug_ctrl_handle_g2h: buffer with return status not found\n");
		exit(1);
	}
	status_p = in_sg->iov_base;

	msg = (struct vnplug_ctrl_msg_hdr *) out_sg->iov_base;

	VNPLUG_CTRL_DEBUG_PRINTF("vnplug_ctrl_handle_g2h: hdr.type=%u hdr.id=%u\n", msg->type, msg->id);

	len += sizeof(struct vnplug_ctrl_msg_hdr);

	switch (msg->type)
	{
		case VNPLUG_CTRL_MSG_FORWARD:
			/* accessing additional buffers in the sg (payload) */
			out_sg++;
			if (elem.out_num < 2 || out_sg->iov_len == 0) {
					fprintf(stderr, "[vNPlug-CTRL] vnplug_ctrl_handle_g2h: payload expected but not found\n");
	 				exit(1);
			}

			/* accessing an optional ret payload */
			in_sg++;

			if ((client = vnplug_ctrl_client_by_id(msg->id))){
				if (( status = client->msg_handler(
						out_sg->iov_base, 
						out_sg->iov_len,
						(elem.in_num>1 && in_sg->iov_len>0) ? in_sg->iov_base : NULL,
						(elem.in_num>1 && in_sg->iov_len>0) ? in_sg->iov_len  : 0)) 
					< VNPLUG_CTRL_MSG_RET_SUCCESS )
				status = VNPLUG_CTRL_MSG_RET_CLIENT_ERROR;
			} else {
				status = VNPLUG_CTRL_MSG_RET_CLIENT_NOT_FOUND;
				VNPLUG_CTRL_DEBUG_PRINTF("vnplug_ctrl_handle_g2h: client not found\n");
			}

			len += out_sg->iov_len 
				+ ((elem.in_num>1 && in_sg->iov_len>0) ? in_sg->iov_len  : 0);
			break;

		default:
			VNPLUG_CTRL_DEBUG_PRINTF("vnplug_ctrl_handle_g2h: unrecognized msg type\n");	
	}

	memcpy(status_p, &status, sizeof(int32_t));
	len += sizeof(int32_t);

	VNPLUG_CTRL_DEBUG_PRINTF("vnplug_ctrl_handle_g2h: return value is %d\n", *status_p);

	/* len = "size of in" or "size of out+in" ? */
		virtqueue_push(vq, &elem, len);
		virtio_notify(vdev, vq);
	}
}

static void vnplug_ctrl_get_config(VirtIODevice *vdev, uint8_t *config_data)
{
	VirtIOvNPlugCTRL *dev = VirtIODevice2VirtIOvNPlugCTRL(vdev);
	struct vnplug_ctrl_virtio_config config;

	VNPLUG_CTRL_DEBUG_PRINTF("vnplug_ctrl_get_config: call\n");

	config.status = dev->status; 

	memcpy(config_data, &config, sizeof(config));
}

static void vnplug_ctrl_set_config(VirtIODevice *vdev, const uint8_t *config_data)
{
	//VirtIOvNPlugCTRL *dev = VirtIODevice2VirtIOvNPlugCTRL(vdev);
	struct vnplug_ctrl_virtio_config config;

	VNPLUG_CTRL_DEBUG_PRINTF("vnplug_ctrl_set_config: call\n");

	memcpy(&config, config_data, sizeof(config));

	/* do something with your new configuration */
}

static uint32_t vnplug_ctrl_get_features(VirtIODevice *vdev, uint32_t f)
{
	//VirtIOvNPlugCTRL *dev = VirtIODevice2VirtIOvNPlugCTRL(vdev);

	VNPLUG_CTRL_DEBUG_PRINTF("vnplug_ctrl_get_features: call\n");

	/* Set here you should set your features bitmap with supported features */

	f |= (1 << VNPLUG_CTRL_STATUS); 

	/* or remove features depending on some support, example: */
	/* features &= ~(0x1 << VNPLUG_CTRL_STATUS); */

	return f;
}

static uint32_t vnplug_ctrl_bad_features(VirtIODevice *vdev)
{
	uint32_t features = 0;

	VNPLUG_CTRL_DEBUG_PRINTF("vnplug_ctrl_bad_features: call\n");

	return features;
}

static void vnplug_ctrl_set_features(VirtIODevice *vdev, uint32_t features)
{
	//VirtIOvNPlugCTRL *s = VirtIODevice2VirtIOvNPlugCTRL(vdev);

	VNPLUG_CTRL_DEBUG_PRINTF("vnplug_ctrl_set_features: call\n");

	/*
	 * Use the features bitmap to set your settings
	 */
}

static void vnplug_ctrl_reset(VirtIODevice *vdev)
{
	//VirtIOvNPlugCTRL *s = VirtIODevice2VirtIOvNPlugCTRL(vdev);  
	
	VNPLUG_CTRL_DEBUG_PRINTF("vnplug_ctrl_reset: call\n");

	/*
	 * Reset here settings and data structures
	 */
}

static void vnplug_ctrl_set_status(struct VirtIODevice *vdev, uint8_t status)
{
	//VirtIOvNPlugCTRL *s = VirtIODevice2VirtIOvNPlugCTRL(vdev);

	VNPLUG_CTRL_DEBUG_PRINTF("vnplug_ctrl_set_status: call with status=%u\n", status);

	/*
	 * Update informations according to the status
	 */
}

static void /* int */ vnplug_ctrl_set_params(int blk_enable, int shared, void *opaque)
{
	/*
	VirtIOvNPlugCTRL *s = opaque;

	if (1) { // TODO: replace with "running vnplug devices"
		fprintf(stderr, "[vNPlug-CTRL] vnplug_ctrl_set_param: Virtual devices running, it is not possible to migrate/save\n");
		return -EINVAL;
	}

	return 0;
	*/
}

static void vnplug_ctrl_save(QEMUFile *f, void *opaque)
{
	VirtIOvNPlugCTRL *s = opaque;

	VNPLUG_CTRL_DEBUG_PRINTF("vnplug_ctrl_save: call\n");

	virtio_save(&s->vdev, f);
   
	/*
	 * Maybe you should tell clients to stop&save
	 * and resume when vnplug_ctrl_load is called
	 */

	/* Save your data, example: */
	qemu_put_be16(f, s->status);
}

static int vnplug_ctrl_load(QEMUFile *f, void *opaque, int version_id)
{
	VirtIOvNPlugCTRL *s = opaque;

	VNPLUG_CTRL_DEBUG_PRINTF("vnplug_ctrl_load: call\n");

	if (version_id != 1)
		return -EINVAL;

	virtio_load(&s->vdev, f);

	/* Read your data, example: */
	s->status = qemu_get_be16(f);

	return 0;
}

static void vnplug_ctrl_vmstate_change(void *opaque, int running, RunState state)
{
	VirtIOvNPlugCTRL *s = opaque;

	VNPLUG_CTRL_DEBUG_PRINTF("vnplug_ctrl_vmstate_change: call with running=%d\n", running);

	/* 
	 * This is called when vm is started/stopped, 
	 * it will start/stop the backend if appropriate 
	 * e.g. after migration. 
	 */
	vnplug_ctrl_set_status(&s->vdev, s->vdev.status);
}

VirtIODevice *vnplug_ctrl_init(DeviceState *dev)
{
	VirtIOvNPlugCTRL *s;

	VNPLUG_CTRL_DEBUG_PRINTF("vnplug_ctrl_init: call\n");

	s = (VirtIOvNPlugCTRL *)virtio_common_init("vnplug-ctrl",
						   VIRTIO_ID_VNPLUG_CTRL,
						   sizeof(struct vnplug_ctrl_virtio_config),
						   sizeof(VirtIOvNPlugCTRL));

	s->vdev.get_config   = vnplug_ctrl_get_config;
	s->vdev.set_config   = vnplug_ctrl_set_config;
	s->vdev.get_features = vnplug_ctrl_get_features;
	s->vdev.set_features = vnplug_ctrl_set_features;
	s->vdev.bad_features = vnplug_ctrl_bad_features;
	s->vdev.reset	     = vnplug_ctrl_reset;
	s->vdev.set_status   = vnplug_ctrl_set_status;

	s->g2h_vq = virtio_add_queue(&s->vdev, 32 /* vq size */, vnplug_ctrl_handle_g2h);

	//TESTregister_savevm(dev, "vnplug-ctrl", -1, 1, vnplug_ctrl_save, vnplug_ctrl_load, s);
	register_savevm_live(dev, "vnplug-ctrl", -1, 1, vnplug_ctrl_set_params, NULL, vnplug_ctrl_save, vnplug_ctrl_load, s);

	s->vm_state = qemu_add_vm_change_state_handler(vnplug_ctrl_vmstate_change, s);

	return &s->vdev;
}

void vnplug_ctrl_exit(VirtIODevice *vdev)
{
	VirtIOvNPlugCTRL *s = DO_UPCAST(VirtIOvNPlugCTRL, vdev, vdev); 

	VNPLUG_CTRL_DEBUG_PRINTF("vnplug_ctrl_exit: call\n");

	qemu_del_vm_change_state_handler(s->vm_state);

	vnplug_ctrl_set_status(vdev, 0);

	unregister_savevm(s->qdev, "vnplug-ctrl", s);

	virtio_cleanup(&s->vdev);
}

/* NOPATCH
static int vnplug_ctrl_init_pci(PCIDevice *pci_dev)
{
	VirtIOPCIProxy *proxy = DO_UPCAST(VirtIOPCIProxy, pci_dev, pci_dev);
	VirtIODevice *vdev;

	vdev = vnplug_ctrl_init(&pci_dev->qdev);

	virtio_init_pci(proxy, vdev);

	proxy->nvectors = vdev->nvectors;
	return 0;
}

static int vnplug_ctrl_exit_pci(PCIDevice *pci_dev)
{
	VirtIOPCIProxy *proxy = DO_UPCAST(VirtIOPCIProxy, pci_dev, pci_dev);

	vnplug_ctrl_exit(proxy->vdev);
	return virtio_exit_pci(pci_dev);
}

static PCIDeviceInfo vnplug_ctrl_info = {
	.qdev.name  = "vnplug",
	.qdev.alias = "vnplug",
	.qdev.size  = sizeof(VirtIOPCIProxy),
	.init	   = vnplug_ctrl_init_pci,
	.exit	   = vnplug_ctrl_exit_pci,
	//.romfile    = "pxe-vnplug.rom",
	.vendor_id  = PCI_VENDOR_ID_REDHAT_QUMRANET,
	.device_id  = PCI_DEVICE_ID_VNPLUG_CTRL,
	.revision   = VIRTIO_PCI_ABI_VERSION,
	.class_id   = PCI_CLASS_NETWORK_ETHERNET,
	.qdev.props = (Property[]) {
		DEFINE_VIRTIO_COMMON_FEATURES(VirtIOPCIProxy, host_features),
		DEFINE_PROP_END_OF_LIST(),
	},
	.qdev.reset = virtio_pci_reset,
};

static void vnplug_ctrl_register_devices(void)
{
	// Useless and can overwrite clients depending on the init order
	// QLIST_INIT(&vnplug_ctrl_clients);

	VNPLUG_CTRL_DEBUG_PRINTF("registering to qdev..\n");
	pci_qdev_register(&vnplug_ctrl_info);
}

device_init(vnplug_ctrl_register_devices);
*/
