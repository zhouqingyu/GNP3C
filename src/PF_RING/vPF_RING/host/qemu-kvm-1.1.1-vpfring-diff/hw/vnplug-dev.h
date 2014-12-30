#ifndef VNPLUG_DEV_H
#define VNPLUG_DEV_H

#define PCI_VENDOR_ID_SILICOM		0x1374
#define PCI_DEVICE_ID_VNPLUG_DEV	0x00ff

#define VNPLUGDEV_REG_BAR_SIZE TARGET_PAGE_SIZE

#define VNPLUGDEV_REG_OFF_ID		0x00
#define VNPLUGDEV_REG_OFF_DOORBELL	0x04
#define VNPLUGDEV_REG_OFF_BASE_MM_SIZE	0x08

#define VNPLUGDEV_BASE_MM_BAR		   2
#define VNPLUGDEV_MAX_MM_BARS		   4

struct EventfdEntry {
	PCIDevice		*pdev;
	int32_t			 vector;
};

struct vNPlugDev {
	PCIDevice		 dev;

	Error			*migration_blocker;

	uint32_t		 dev_id;
	uint32_t		 doorbell;

	uint32_t		 mm_dev_size[VNPLUGDEV_MAX_MM_BARS];
	uint64_t /* void* */ 	 mm_dev_vma_ptr[VNPLUGDEV_MAX_MM_BARS];

	/* close your eyes (qdev properties) */
	uint32_t		 mm_dev_size_0;
	uint64_t		 mm_dev_vma_ptr_0;

	uint32_t		 mm_dev_size_1;
	uint64_t		 mm_dev_vma_ptr_1;

	uint32_t		 mm_dev_size_2;
	uint64_t		 mm_dev_vma_ptr_2;

	uint32_t		 mm_dev_size_3;
	uint64_t		 mm_dev_vma_ptr_3;
	/* reopen your eyes */

	MemoryRegion		 mmio;
	MemoryRegion		 msix_bar;
	MemoryRegion		 mm[VNPLUGDEV_MAX_MM_BARS];
	
	uint32_t		 vectors;

	uint32_t		 backend_events_n;
	int 			*backend_eventfds;

	uint32_t		 guest_events_n;
	int 			*guest_eventfds;

	uint64_t /* struct vNPlugDevClientInfo* */ dev_client;
};

#endif /* VNPLUG_DEV_H */
