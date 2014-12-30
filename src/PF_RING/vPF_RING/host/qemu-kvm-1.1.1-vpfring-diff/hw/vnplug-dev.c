/*
 * vNPlugDev (PCI Device)
 *
 * Authors:
 *
 * 	Alfredo Cardigliano <cardigliano@ntop.org>
 *
 * This work is licensed under the terms of the GNU GPL version 2. 
 *
 */

#include <sys/mman.h>
#include <sys/types.h>
#include <sys/eventfd.h>

#include "hw.h"
#include "pc.h"
#include "pci.h"
#include "msix.h"
#include "kvm.h"
#include "migration.h" 
#include "qerror.h"

#include "vnplug.h"
#include "vnplug-dev.h"

//#define VNPLUGDEV_DEBUG

#ifdef VNPLUGDEV_DEBUG
#define VNPLUGDEV_DEBUG_PRINTF(fmt, ...)	do {printf("[vNPlugDev] " fmt, ## __VA_ARGS__); } while (0)
#else
#define VNPLUGDEV_DEBUG_PRINTF(fmt, ...)
#endif

static uint32_t vnplug_device_id_counter = 0;

/* ******************************************************************************************* */

/* called when the guest writes to the registers region */
static void vnplug_dev_io_write(void *opaque, target_phys_addr_t addr, uint64_t val, unsigned size)
{
	struct vNPlugDev *s = opaque;

	addr &= 0xffc;

	VNPLUGDEV_DEBUG_PRINTF("io_writel: registers[" TARGET_FMT_plx "] = %" PRIu64 "\n", addr, val);

	if (!((struct vNPlugDevClientInfo *) s->dev_client)->io_writel_handler)
		fprintf(stderr, "[vNPlugDev] io_writel: client handler undefined\n");
	else
		((struct vNPlugDevClientInfo *) s->dev_client)->io_writel_handler((struct vNPlugDevClientInfo *) s->dev_client, addr, val);
}

/* ******************************************************************************************* */

/* called when the guest reads from the registers region */
static uint64_t vnplug_dev_io_read(void *opaque, target_phys_addr_t addr, unsigned size)
{
	struct vNPlugDev *s = opaque;
	uint32_t ret = 0;

	addr &= 0xffc;

	if (addr == VNPLUGDEV_REG_OFF_ID){
		ret = s->dev_id;
		goto return_ret;
	}

	if ( addr >= VNPLUGDEV_REG_OFF_BASE_MM_SIZE && 
	     addr <  VNPLUGDEV_REG_OFF_BASE_MM_SIZE + VNPLUGDEV_MAX_MM_BARS * sizeof(uint32_t) && 
	   !(addr &  0x3)){
		ret = s->mm_dev_size[(addr-VNPLUGDEV_REG_OFF_BASE_MM_SIZE)>>2];
		goto return_ret;
	}

	if (((struct vNPlugDevClientInfo *) s->dev_client)->io_readl_handler){
		ret = ((struct vNPlugDevClientInfo *) s->dev_client)->io_readl_handler((struct vNPlugDevClientInfo *) s->dev_client, addr);
		goto return_ret;
	}

	fprintf(stderr, "[vNPlugDev] io_read: client handler undefined\n");
	ret = 0;

return_ret:
	VNPLUGDEV_DEBUG_PRINTF("io_read: registers[" TARGET_FMT_plx "] value=%u\n", addr, ret);
	return ret;
}

/* ******************************************************************************************* */

static const MemoryRegionOps vnplug_dev_mmio_ops = {
	.read = vnplug_dev_io_read,
	.write = vnplug_dev_io_write,
	.endianness = DEVICE_NATIVE_ENDIAN,
	.impl = {
		.min_access_size = 4,
		.max_access_size = 4,
	},
};

/* ******************************************************************************************* */

/* to setup irqfds use on=1, to unset them use on=0 */
static int setup_irqfds(struct vNPlugDev *s, int on) {
	int i, err = 0;

	for (i = 0; i < s->vectors; i++) {
		/* irqfd support: interrupts are injected when a signal on an eventfd occurs */
		if ( ( err = kvm_set_irqfd(s->dev.msix_irq_entries[i].gsi, s->backend_eventfds[i], on) ) < 0)
			fprintf(stderr, "[vNPlugDev] irqfd warning (err=%d). Not available, or already set?\n", err);
		else {
			VNPLUGDEV_DEBUG_PRINTF("irqfd %s for host event %d [gsi=%u]\n", on ? "on" : "off", i, s->dev.msix_irq_entries[i].gsi);
		}
	}

	return err;
}

/* ******************************************************************************************* */

/* to setup ioeventfds use on=1, to unset them use on=0 */
static int setup_ioeventfds(struct vNPlugDev *s, int on) {
	int i, err = 0;

	for (i = 0; i < s->guest_events_n; i++) {
		/*  setting ioeventfd support to raise an event when a write on 
		 *  mmio_pci_addr + VNPLUGDEV_REG_OFF_DOORBELL occurs, passing i as the value to match
		 *  (the relative io_writel handler will not be called) */
		
		/* TODO Check if ioeventfds are working with this code */

		if (on) memory_region_add_eventfd(&s->mmio, VNPLUGDEV_REG_OFF_DOORBELL, 4, true, i, s->guest_eventfds[i]);
		else    memory_region_del_eventfd(&s->mmio, VNPLUGDEV_REG_OFF_DOORBELL, 4, true, i, s->guest_eventfds[i]);

		//if ( (err = kvm_set_ioeventfd_mmio(s->guest_eventfds[i], s->mmio_pci_addr + VNPLUGDEV_REG_OFF_DOORBELL, i, on, 4 /* long */)) < 0) {
		//	fprintf(stderr, "[vNPlugDev] ioeventfd warning (err=%d). Not available, or already set?\n", err);
		//} else {
		VNPLUGDEV_DEBUG_PRINTF("ioeventfd %s for guest event %d\n", on ? "on" : "off", i);
		//}
	}

	return err;
}

/* ******************************************************************************************* */

static void vnplug_dev_reset(DeviceState *d)
{
	struct vNPlugDev *s = DO_UPCAST(struct vNPlugDev, dev.qdev, d);
	int i;
	
	VNPLUGDEV_DEBUG_PRINTF("reset called\n");

	msix_reset(&s->dev);
	for (i = 0; i < s->vectors; i++) {
		if (msix_vector_use(&s->dev, i) != 0) {
			VNPLUGDEV_DEBUG_PRINTF("error setting msix vector to used\n");
		}
	}

	return;
}

/* ******************************************************************************************* */

static void vnplug_dev_setup_msix(struct vNPlugDev * s) 
{
	int i;

	memory_region_init(&s->msix_bar, "vnplug-dev-msix", 0x1000 /* MSIX_PAGE_SIZE */); 

	if (msix_init(&s->dev, s->vectors, &s->msix_bar, 1, 0) == 0) {
		/* MSI region */
		pci_register_bar(&s->dev, 1, PCI_BASE_ADDRESS_SPACE_MEMORY, &s->msix_bar);

		VNPLUGDEV_DEBUG_PRINTF("msix initialized (%d vectors)\n", s->vectors);
	} else {
		VNPLUGDEV_DEBUG_PRINTF("msix initialization failed\n");
		exit(1);
	}
	
	for (i = 0; i < s->vectors; i++) {
		if (msix_vector_use(&s->dev, i) != 0) {
			VNPLUGDEV_DEBUG_PRINTF("error setting msix vector to used\n");
		}
	}
}

/* ******************************************************************************************* */

static const VMStateDescription vmstate_vnplug_device = {
	.name = "vnplug-dev",
	.fields = (VMStateField []) {
		VMSTATE_END_OF_LIST()
	}
};

/* ******************************************************************************************* */

static void vnplug_dev_write_config(PCIDevice *pci_dev, uint32_t address, uint32_t val, int len)
{
	pci_default_write_config(pci_dev, address, val, len);
	msix_write_config(pci_dev, address, val, len);
}

/* ******************************************************************************************* */

static int pci_vnplug_dev_init(PCIDevice *dev)
{
	struct vNPlugDev *s = DO_UPCAST(struct vNPlugDev, dev, dev);
	uint8_t *pci_conf;
	int i;
	char ram_block_name[32];

	struct vNPlugDevClientInfo *client = (struct vNPlugDevClientInfo *) s->dev_client;
	if (!client){
		fprintf(stderr, "[vNPlugDev] undefined vNPlug-dev client info\n"); 
		exit(-1);
	}

	s->dev_id = vnplug_device_id_counter++;

	vmstate_register(&dev->qdev, s->dev_id, &vmstate_vnplug_device, s);

	error_set(&s->migration_blocker, QERR_DEVICE_FEATURE_BLOCKS_MIGRATION, "vnplug-dev", "not supported");
	migrate_add_blocker(s->migration_blocker);

	pci_conf = s->dev.config;
	pci_conf[PCI_COMMAND] = PCI_COMMAND_IO | PCI_COMMAND_MEMORY;
	pci_conf[PCI_HEADER_TYPE] = PCI_HEADER_TYPE_NORMAL;
	pci_config_set_interrupt_pin(pci_conf, 1);

	s->mm_dev_size   [0] = s->mm_dev_size_0;
	s->mm_dev_vma_ptr[0] = s->mm_dev_vma_ptr_0;
	s->mm_dev_size   [1] = s->mm_dev_size_1;
	s->mm_dev_vma_ptr[1] = s->mm_dev_vma_ptr_1;
	s->mm_dev_size   [2] = s->mm_dev_size_2;
	s->mm_dev_vma_ptr[2] = s->mm_dev_vma_ptr_2;
	s->mm_dev_size   [3] = s->mm_dev_size_3;
	s->mm_dev_vma_ptr[3] = s->mm_dev_vma_ptr_3;

	s->vectors = s->backend_events_n;

	VNPLUGDEV_DEBUG_PRINTF("setting up %d guest eventdfds\n", s->guest_events_n);

	s->guest_eventfds	= g_malloc0(s->guest_events_n * sizeof(int));
	for (i=0;i<s->guest_events_n;i++){
		if ((s->guest_eventfds[i] = eventfd(0, 0)) < 0) {
			fprintf(stderr, "[vNPlugDev] failed to create eventfd\n");
			exit(-1);
		}
	}

	VNPLUGDEV_DEBUG_PRINTF("setting up %d backend eventdfds\n", s->vectors);

	s->backend_eventfds = g_malloc0(s->vectors * sizeof(int));
	for (i=0;i<s->vectors;i++){
		if ((s->backend_eventfds[i] = eventfd(0, 0)) < 0) {
			fprintf(stderr, "[vNPlugDev] failed to create eventfd\n");
			exit(-1);
		}
	}

	VNPLUGDEV_DEBUG_PRINTF("setting mmio read/write handlers for device %u [ passing opaque (struct vNPlugDev *) = %p ]\n", s->dev_id, s);

	memory_region_init_io(&s->mmio, &vnplug_dev_mmio_ops, s, "vnplug-dev-mmio", VNPLUGDEV_REG_BAR_SIZE);

	/* setup guest to host events via ioeventfd */

	setup_ioeventfds(s, 1);

	/* region for registers */
	pci_register_bar(&s->dev, 0, PCI_BASE_ADDRESS_SPACE_MEMORY, &s->mmio);

	/* setup host to guest events via MSI */

	VNPLUGDEV_DEBUG_PRINTF("setting up %d MSI-X vectors\n", s->vectors);

	/* region for msi and msix initialization */
	vnplug_dev_setup_msix(s);
		
	VNPLUGDEV_DEBUG_PRINTF("setting up the irqfd support\n");

	setup_irqfds(s, 1);

	for (i=0; i<VNPLUGDEV_MAX_MM_BARS; i++)
		if (s->mm_dev_size[i] && s->mm_dev_vma_ptr[i]){

			/* Checking size (it must be power of two) */
			if ((s->mm_dev_size[i] & (s->mm_dev_size[i] - 1)) != 0){
				fprintf(stderr, "[vNPlugDev] device memory %d size is not power of 2\n", i); 
				exit(-1);
			}

			/* ram block with mmapped memory to share */
			snprintf(ram_block_name, 32, "vnplug-dev-%u.bar%d", s->dev_id, VNPLUGDEV_BASE_MM_BAR+i);
			
			memory_region_init_ram_ptr(&s->mm[i], ram_block_name, s->mm_dev_size[i], (void *) s->mm_dev_vma_ptr[i]);

			vmstate_register_ram(&s->mm[i], &s->dev.qdev);

			VNPLUGDEV_DEBUG_PRINTF("ram block %d allocated from ptr %" PRIu64 " and size %u at ram addr %" PRIu64 "\n", 
			                       i, s->mm_dev_vma_ptr[i], s->mm_dev_size[i], s->mm[i].ram_addr);

			/* region for shared memory */
			pci_register_bar(&s->dev, VNPLUGDEV_BASE_MM_BAR+i, PCI_BASE_ADDRESS_SPACE_MEMORY, &s->mm[i]);
		}

	if (!s->dev_client || !(client->set_init_data_handler)){
		fprintf(stderr, "[vNPlugDev] client or client handlers undefined\n");
		exit(-1);
	}

	s->dev.config_write = vnplug_dev_write_config;

	/* setting dev id and eventfds on client */
	client->set_init_data_handler(client, s->dev_id, s->backend_events_n, s->backend_eventfds, s->guest_events_n, s->guest_eventfds);
  
	return 0;
}

/* ******************************************************************************************* */

static int pci_vnplug_dev_uninit(PCIDevice *dev)
{
	int i;
	struct vNPlugDev *s = DO_UPCAST(struct vNPlugDev, dev, dev);
	struct vNPlugDevClientInfo *client = (struct vNPlugDevClientInfo *) s->dev_client;

	if (client && client->pre_unplug_handler)
		client->pre_unplug_handler(client);

	migrate_del_blocker(s->migration_blocker); 
	error_free(s->migration_blocker);

	setup_irqfds(s, 0);

	setup_ioeventfds(s, 0);

	for (i=0; i<VNPLUGDEV_MAX_MM_BARS; i++) {
		if (s->mm_dev_size[i] && s->mm_dev_vma_ptr[i]){
			vmstate_unregister_ram(&s->mm[i], &s->dev.qdev);
			memory_region_destroy(&s->mm[i]);
			VNPLUGDEV_DEBUG_PRINTF("BAR%d unmapped\n", VNPLUGDEV_BASE_MM_BAR+i);
		}
	}

	msix_unuse_all_vectors(dev);
	msix_uninit(dev, &s->msix_bar);
	memory_region_destroy(&s->msix_bar);

	VNPLUGDEV_DEBUG_PRINTF("BAR1 (MSIX) uninitialized and unmapped\n");

	memory_region_destroy(&s->mmio);

	VNPLUGDEV_DEBUG_PRINTF("BAR0 (registers) unmapped\n");

	for (i = 0; i < s->vectors; i++)
		close(s->backend_eventfds[i]);

	VNPLUGDEV_DEBUG_PRINTF("backend eventfds closed\n");

	for (i = 0; i < s->guest_events_n; i++)
		close(s->guest_eventfds[i]);

	VNPLUGDEV_DEBUG_PRINTF("guest eventfds closed\n");

	g_free(s->backend_eventfds);
	g_free(s->guest_eventfds);

	vmstate_unregister(&dev->qdev, &vmstate_vnplug_device, s);

	if (client && client->post_unplug_handler)
		client->post_unplug_handler(client);
 
	VNPLUGDEV_DEBUG_PRINTF("uninitalization done\n");
	
	return 0;
}

/* ******************************************************************************************* */

static Property vnplug_dev_properties[] = {

	/* Note: 
	 * - generated in pci_vnplug_dev_init: DEFINE_PROP_UINT32("dev_id", struct vNPlugDev, dev_id, 0),
	 * - ptrs changed to uint64: DEFINE_PROP_PTR("vma_ptr", struct vNPlugDev, mm_dev_vma_ptr), 
	 */

	DEFINE_PROP_UINT32("backend_events_n", struct vNPlugDev, backend_events_n, 1),
	DEFINE_PROP_UINT32("guest_events_n", struct vNPlugDev, guest_events_n, 1), 

	DEFINE_PROP_UINT32("vma_size", struct vNPlugDev, mm_dev_size_0, 0),
	DEFINE_PROP_UINT64("vma_ptr",  struct vNPlugDev, mm_dev_vma_ptr_0, 0),

	DEFINE_PROP_UINT32("vma_size_1", struct vNPlugDev, mm_dev_size_1, 0),
	DEFINE_PROP_UINT64("vma_ptr_1",  struct vNPlugDev, mm_dev_vma_ptr_1, 0),

	DEFINE_PROP_UINT32("vma_size_2", struct vNPlugDev, mm_dev_size_2, 0),
	DEFINE_PROP_UINT64("vma_ptr_2",  struct vNPlugDev, mm_dev_vma_ptr_2, 0),

	DEFINE_PROP_UINT32("vma_size_3", struct vNPlugDev, mm_dev_size_3, 0),
	DEFINE_PROP_UINT64("vma_ptr_3",  struct vNPlugDev, mm_dev_vma_ptr_3, 0),

	DEFINE_PROP_UINT64("client_info_ptr", struct vNPlugDev, dev_client, 0),
	DEFINE_PROP_END_OF_LIST(),
};

static void vnplug_dev_class_init(ObjectClass *klass, void *data)
{
	DeviceClass *dc = DEVICE_CLASS(klass);
	PCIDeviceClass *k = PCI_DEVICE_CLASS(klass);

	k->init = pci_vnplug_dev_init;
	k->exit = pci_vnplug_dev_uninit;
	k->vendor_id = PCI_VENDOR_ID_SILICOM;
	k->device_id = PCI_DEVICE_ID_VNPLUG_DEV;
	k->class_id = PCI_CLASS_MEMORY_RAM;
	dc->reset = vnplug_dev_reset;
	dc->props = vnplug_dev_properties;
}

static TypeInfo vnplug_dev_info = {
	.name          = "vnplug-dev",
	.parent        = TYPE_PCI_DEVICE,
	.instance_size = sizeof(struct vNPlugDev),
	.class_init    = vnplug_dev_class_init,
};

static void vnplug_dev_register_types(void)
{
	type_register_static(&vnplug_dev_info);
}

type_init(vnplug_dev_register_types)

