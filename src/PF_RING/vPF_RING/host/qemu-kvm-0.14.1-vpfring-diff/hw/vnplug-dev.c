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

static void vnplug_dev_io_writew(void *opaque, target_phys_addr_t addr, uint32_t val)
{
	VNPLUGDEV_DEBUG_PRINTF("io_writew: unhandled\n");
}

/* ******************************************************************************************* */

/* called when the guest writes to the registers region */
static void vnplug_dev_io_writel(void *opaque, target_phys_addr_t addr, uint32_t val)
{
	struct vNPlugDev *s = opaque;

	addr &= 0xffc;

	VNPLUGDEV_DEBUG_PRINTF("io_writel: registers[" TARGET_FMT_plx "] = %u\n", addr, val);

	if (!((struct vNPlugDevClientInfo *) s->dev_client)->io_writel_handler)
		fprintf(stderr, "[vNPlugDev] io_writel: client handler undefined\n");
	else
		((struct vNPlugDevClientInfo *) s->dev_client)->io_writel_handler((struct vNPlugDevClientInfo *) s->dev_client, addr, val);
}

/* ******************************************************************************************* */

static void vnplug_dev_io_writeb(void *opaque, target_phys_addr_t addr, uint32_t val)
{
	VNPLUGDEV_DEBUG_PRINTF("io_writeb: unhandled\n");
}

/* ******************************************************************************************* */

static uint32_t vnplug_dev_io_readw(void *opaque, target_phys_addr_t addr)
{
	VNPLUGDEV_DEBUG_PRINTF("io_readw: unhandled\n");
	return 0;
}

/* ******************************************************************************************* */

/* called when the guest reads from the registers region */
static uint32_t vnplug_dev_io_readl(void *opaque, target_phys_addr_t addr)
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
		ret = s->dev_size[(addr-VNPLUGDEV_REG_OFF_BASE_MM_SIZE)>>2];
		goto return_ret;
	}

	if (((struct vNPlugDevClientInfo *) s->dev_client)->io_readl_handler){
		ret = ((struct vNPlugDevClientInfo *) s->dev_client)->io_readl_handler((struct vNPlugDevClientInfo *) s->dev_client, addr);
		goto return_ret;
	}

	fprintf(stderr, "[vNPlugDev] io_readl: client handler undefined\n");
	ret = 0;

return_ret:
	VNPLUGDEV_DEBUG_PRINTF("io_readl: registers[" TARGET_FMT_plx "] value=%u\n", addr, ret);
	return ret;
}

/* ******************************************************************************************* */

static uint32_t vnplug_dev_io_readb(void *opaque, target_phys_addr_t addr)
{
	VNPLUGDEV_DEBUG_PRINTF("io_readb: unhandled, returning 0\n");
	return 0;
}

/* ******************************************************************************************* */

static CPUReadMemoryFunc * const vnplug_dev_mmio_read[3] = {
	vnplug_dev_io_readb,
	vnplug_dev_io_readw,
	vnplug_dev_io_readl,
};

static CPUWriteMemoryFunc * const vnplug_dev_mmio_write[3] = {
	vnplug_dev_io_writeb,
	vnplug_dev_io_writew,
	vnplug_dev_io_writel,
};

/* ******************************************************************************************* */

/* to setup irqfds use on=1, to unset them use on=0 */
static int setup_irqfds(struct vNPlugDev *s, int on) {
	int i, err = 0;

	for (i = 0; i < s->vectors; i++)
	/* irqfd support: interrupts are injected when a signal on an eventfd occurs */
	if ( ( err = kvm_set_irqfd(s->dev.msix_irq_entries[i].gsi, s->backend_eventfds[i], on) ) < 0)
			fprintf(stderr, "[vNPlugDev] irqfd warning (err=%d). Not available, or already set?\n", err);
	else {
		VNPLUGDEV_DEBUG_PRINTF("irqfd on=%d for host event %d\n", on, i);
	}

	return err;
}


/* ******************************************************************************************* */

/* to setup ioeventfds use on=1, to unset them use on=0 */
static int setup_ioeventfds(struct vNPlugDev *s, int on) {
	int i, err = 0;

	for (i = 0; i < s->guest_events_n; i++)
	/*  setting ioeventfd support to raise an event when a write on 
	 *  mmio_addr + VNPLUGDEV_REG_OFF_DOORBELL occurs, passing i as the value to match
	 *  (the relative io_writel handler will not be called) */
	if ( (err = kvm_set_ioeventfd_mmio_long(s->guest_eventfds[i], s->mmio_addr + VNPLUGDEV_REG_OFF_DOORBELL, i, on)) < 0)
			fprintf(stderr, "[vNPlugDev] ioeventfd warning (err=%d). Not available, or already set?\n", err);
	else {
		VNPLUGDEV_DEBUG_PRINTF("ioeventfd on=%d for guest event %d\n", on, i);
	}

	return err;
}

/* ******************************************************************************************* */

static void vnplug_dev_reset(DeviceState *d)
{
	//struct vNPlugDev *s = DO_UPCAST(struct vNPlugDev, dev.qdev, d);
	return;
}

/* ******************************************************************************************* */

/* region 2..5 (mmap-ed memory) map handler */
static void vnplug_dev_mm_map(PCIDevice *pci_dev, int region_num, pcibus_t addr, pcibus_t size, int type)
{
	struct vNPlugDev *s = DO_UPCAST(struct vNPlugDev, dev, pci_dev);

	// BAR0=registers, BAR1=MSI, BAR2..5=mm
	int index = region_num - VNPLUGDEV_BASE_MM_BAR;

	VNPLUGDEV_DEBUG_PRINTF("registering shared memory %d at guest pci addr=%" FMT_PCIBUS ", guest hw addr=%" PRIu64 ", with size=%" FMT_PCIBUS "\n", index, addr, s->dev_offset[index], size);

	if (index < 0 || index > VNPLUGDEV_MAX_MM_BARS-1) {
		fprintf(stderr, "[vNPlugDev] mm bar index out of range: %d\n", index);
		return;
	}

	s->mm_pci_addr[index] = addr;

	if (s->dev_offset[index] > 0) 
		cpu_register_physical_memory(s->mm_pci_addr[index], s->dev_size[index], s->dev_offset[index]);
}

/* ******************************************************************************************* */

static void vnplug_dev_mmio_map(PCIDevice *pci_dev, int region_num, pcibus_t addr, pcibus_t size, int type)
{
	struct vNPlugDev *s = DO_UPCAST(struct vNPlugDev, dev, pci_dev);

	VNPLUGDEV_DEBUG_PRINTF("registering mmio memory\n");

	s->mmio_addr = addr;
	cpu_register_physical_memory(addr + 0, VNPLUGDEV_REG_BAR_SIZE, s->dev_mmio_io_addr);

	setup_ioeventfds(s, 1);
}

/* ******************************************************************************************* */

static void vnplug_dev_setup_msi(struct vNPlugDev * s) 
{
	int i;

	if (msix_init(&s->dev, s->vectors, 1, 0) == 0) {
		/* MSI region */
		pci_register_bar(&s->dev, 1, msix_bar_size(&s->dev), PCI_BASE_ADDRESS_SPACE_MEMORY, msix_mmio_map);

		VNPLUGDEV_DEBUG_PRINTF("msix initialized (%d vectors)\n", s->vectors);
	} else {
		VNPLUGDEV_DEBUG_PRINTF("msix initialization failed\n");
		exit(1);
	}

	for (i = 0; i < s->vectors; i++) {
		msix_vector_use(&s->dev, i);
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
	register_device_unmigratable(&dev->qdev, vmstate_vnplug_device.name, s);

	pci_conf = s->dev.config;
	pci_config_set_vendor_id(pci_conf, PCI_VENDOR_ID_SILICOM);
	pci_conf[0x02] = (PCI_DEVICE_ID_VNPLUG_DEV) & 0xff;
	pci_conf[0x03] = (PCI_DEVICE_ID_VNPLUG_DEV >> 8) & 0xff;
	pci_conf[PCI_COMMAND] = PCI_COMMAND_IO | PCI_COMMAND_MEMORY;
	pci_config_set_class(pci_conf, PCI_CLASS_MEMORY_RAM);
	pci_conf[PCI_HEADER_TYPE] = PCI_HEADER_TYPE_NORMAL;
	pci_config_set_interrupt_pin(pci_conf, 1);

	for (i=0; i<VNPLUGDEV_MAX_MM_BARS; i++){
		s->mm_pci_addr[i] = 0;
		s->dev_offset [i] = 0;
	}
	s->dev_size   [0] = s->dev_size_0;
	s->dev_vma_ptr[0] = s->dev_vma_ptr_0;
	s->dev_size   [1] = s->dev_size_1;
	s->dev_vma_ptr[1] = s->dev_vma_ptr_1;
	s->dev_size   [2] = s->dev_size_2;
	s->dev_vma_ptr[2] = s->dev_vma_ptr_2;
	s->dev_size   [3] = s->dev_size_3;
	s->dev_vma_ptr[3] = s->dev_vma_ptr_3;

	VNPLUGDEV_DEBUG_PRINTF("setting mmio read/write handlers for device %u [ passing opaque (struct vNPlugDev *) = %p ]\n", s->dev_id, s);

	s->dev_mmio_io_addr = cpu_register_io_memory(vnplug_dev_mmio_read, vnplug_dev_mmio_write, s, DEVICE_NATIVE_ENDIAN);

	/* region for registers */
	pci_register_bar(&s->dev, 0, VNPLUGDEV_REG_BAR_SIZE, PCI_BASE_ADDRESS_SPACE_MEMORY, vnplug_dev_mmio_map);

	/* setup host to guest events via MSI */

	s->vectors = s->backend_events_n;

	VNPLUGDEV_DEBUG_PRINTF("setting up %d MSI-X vectors\n", s->vectors);

	/* msi init & region for msi */
	vnplug_dev_setup_msi(s);
	
	VNPLUGDEV_DEBUG_PRINTF("setting up %d backend eventdfds\n", s->vectors);
	s->backend_eventfds	= qemu_mallocz(s->vectors * sizeof(int));
	for (i=0;i<s->vectors;i++){
		if ((s->backend_eventfds[i] = eventfd(0, 0)) < 0) {
			fprintf(stderr, "[vNPlugDev] failed to create eventfd\n");
			exit(-1);
		}
	}
	
	VNPLUGDEV_DEBUG_PRINTF("setting up the irqfd support\n");
	
	setup_irqfds(s, 1);

	VNPLUGDEV_DEBUG_PRINTF("setting up %d guest eventdfds\n", s->guest_events_n);
	s->guest_eventfds	= qemu_mallocz(s->guest_events_n * sizeof(int));
	for (i=0;i<s->guest_events_n;i++){
		if ((s->guest_eventfds[i] = eventfd(0, 0)) < 0) {
			fprintf(stderr, "[vNPlugDev] failed to create eventfd\n");
		exit(-1);
	}
	}

	for (i=0; i<VNPLUGDEV_MAX_MM_BARS; i++)
		if (s->dev_size[i] && s->dev_vma_ptr[i]){

			/* Checking size (it must be power of two) */
			if ((s->dev_size[i] & (s->dev_size[i] - 1)) != 0){
				fprintf(stderr, "[vNPlugDev] device memory %d size is not power of 2\n", i); 
				exit(-1);
			}

			/* ram block with mmapped memory to share */
			snprintf(ram_block_name, 32, "vnplug-dev-%u.bar%d", s->dev_id, VNPLUGDEV_BASE_MM_BAR+i);
			s->dev_offset[i] = qemu_ram_alloc_from_ptr(&s->dev.qdev, ram_block_name, s->dev_size[i], (void *) s->dev_vma_ptr[i]);

			VNPLUGDEV_DEBUG_PRINTF("ram block %d allocated from ptr %" PRIu64 " and size %u at guest hw addr %" PRIu64 "\n", i, s->dev_vma_ptr[i], s->dev_size[i], s->dev_offset[i]);

			/* region for shared memory */
			pci_register_bar(&s->dev, VNPLUGDEV_BASE_MM_BAR+i, s->dev_size[i], PCI_BASE_ADDRESS_SPACE_MEMORY, vnplug_dev_mm_map);
		}

	if (!s->dev_client || !(client->set_init_data_handler)){
		fprintf(stderr, "[vNPlugDev] client or client handlers undefined\n");
		exit(-1);
	}

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

	setup_irqfds(s, 0);

	setup_ioeventfds(s, 0);

	for (i=0; i<VNPLUGDEV_MAX_MM_BARS; i++)
		if (s->dev_size[i] && s->dev_vma_ptr[i]){
		if (s->mm_pci_addr[i]){
				cpu_register_physical_memory(s->mm_pci_addr[i], s->dev_size[i], IO_MEM_UNASSIGNED);
		VNPLUGDEV_DEBUG_PRINTF("vnplug BAR%d unregistered\n", VNPLUGDEV_BASE_MM_BAR+i); 
			}
		if (s->dev_offset[i]){
				qemu_ram_unmap(s->dev_offset[i]);
		VNPLUGDEV_DEBUG_PRINTF("vnplug BAR%d unmapped\n", VNPLUGDEV_BASE_MM_BAR+i);
			}
		}

	cpu_unregister_io_memory(s->dev_mmio_io_addr);

	vmstate_unregister(&dev->qdev, &vmstate_vnplug_device, s);

	for (i = 0; i < s->vectors; i++)
		close(s->backend_eventfds[i]);

	for (i = 0; i < s->guest_events_n; i++) {
		close(s->guest_eventfds[i]);
	}

	qemu_free(s->backend_eventfds);
	qemu_free(s->guest_eventfds);

	msix_uninit(dev); 

	if (client && client->post_unplug_handler)
		client->post_unplug_handler(client);
 
	VNPLUGDEV_DEBUG_PRINTF("vnplug device uninitalization done\n");
	
	return 0;
}

/* ******************************************************************************************* */

static PCIDeviceInfo vnplug_dev_info = {
	.qdev.name  = "vnplug-dev",
	.qdev.size  = sizeof(struct vNPlugDev),
	.qdev.reset = vnplug_dev_reset,
	.init	   = pci_vnplug_dev_init,
	.exit	   = pci_vnplug_dev_uninit,
	.qdev.props = (Property[]) {
		DEFINE_PROP_UINT32("backend_events_n", struct vNPlugDev, backend_events_n, 1),
		DEFINE_PROP_UINT32("guest_events_n", struct vNPlugDev, guest_events_n, 1), 
		//generated in pci_vnplug_dev_init: DEFINE_PROP_UINT32("dev_id", struct vNPlugDev, dev_id, 0),

		DEFINE_PROP_UINT32("vma_size", struct vNPlugDev, dev_size_0, 0),
		//ptrs changed to uint64: DEFINE_PROP_PTR("vma_ptr", struct vNPlugDev, dev_vma_ptr),
		DEFINE_PROP_UINT64("vma_ptr",  struct vNPlugDev, dev_vma_ptr_0, 0),

		DEFINE_PROP_UINT32("vma_size_1", struct vNPlugDev, dev_size_1, 0),
		DEFINE_PROP_UINT64("vma_ptr_1",  struct vNPlugDev, dev_vma_ptr_1, 0),

		DEFINE_PROP_UINT32("vma_size_2", struct vNPlugDev, dev_size_2, 0),
		DEFINE_PROP_UINT64("vma_ptr_2",  struct vNPlugDev, dev_vma_ptr_2, 0),

		DEFINE_PROP_UINT32("vma_size_3", struct vNPlugDev, dev_size_3, 0),
		DEFINE_PROP_UINT64("vma_ptr_3",  struct vNPlugDev, dev_vma_ptr_3, 0),

		DEFINE_PROP_UINT64("client_info_ptr", struct vNPlugDev, dev_client, 0),
		DEFINE_PROP_END_OF_LIST(),
	}
};

static void vnplug_dev_register_devices(void)
{
	pci_qdev_register(&vnplug_dev_info);
}

device_init(vnplug_dev_register_devices)
