/*
 * vNPlug Driver
 *
 * Authors:
 *
 * 	Alfredo Cardigliano <cardigliano@ntop.org>
 *
 * This work is licensed under the terms of the GNU GPL version 2. 
 *
 */	

#include <linux/vnplug.h>

//#define VNPLUG_DEBUG

#include <linux/version.h>

static struct class 			*vnplug_class;
static int 				 vnplug_major;
static DEFINE_IDR(			 vnplug_idr );
static DEFINE_MUTEX(			 vnplug_minor_lock);
static const struct file_operations 	 vnplug_fops;

#ifdef VNPLUG_CTRL
static int 				 vnplug_ctrl_major;
static DEFINE_MUTEX(			 vnplug_ctrl_lock);
static struct vnplug_ctrl_info 		*vnplug_ctrl_info = NULL;

#if defined(RHEL_RELEASE_CODE)
#if (RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(6,0))
#define REDHAT_PATCHED_KERNEL
#endif
#endif

/* ************************************************************************************************** */
/* ********************************************************************** VNPLUG CTRL VIRTIO HANDLERS */

static void vnplug_ctrl_virtio_g2h_callback(struct virtqueue *svq)
{
	//struct vnplug_ctrl_info *vi = svq->vdev->priv;

#ifdef VNPLUG_DEBUG
	printk("[vNPlug-ctrl] g2h callback called\n");
#endif

	/* Host has read some buffers we sent, 
	 * f.i. we can suppress further interrupts with:
	 *  g2h->vq_ops->disable_cb(svq);
	 * and check if we have to send something..
	 */

	/* Actually for g2h messages we are sending and waiting
	 * for a response, so we don't really need this callback */
}

/* ************************************************************************************************** */

static int32_t vnplug_ctrl_virtio_send_msg(struct vnplug_ctrl_info *vi, uint32_t type, uint32_t id, void *payload, uint32_t payload_size, void *ret_payload, uint32_t ret_payload_size)
{
	struct scatterlist sg[4];
	uint32_t len;
	uint32_t out = 2; // header + payload
	uint32_t in  = 1 + (ret_payload_size>0); // return status + ret_payload

	struct vnplug_ctrl_msg_hdr msg_hdr;
	int32_t status  = 0xffffffff;

	/* Maybe you want to check some support in the features, example: */
	//BUG_ON(!virtio_has_feature(vi->vdev, VIRTIO_VNPLUG_CTRL_MSG_FORWARDING));

	msg_hdr.type 		= type;
	msg_hdr.id   		= id;

	sg_init_table(sg, out + in);

	sg_set_buf(&sg[0],		&msg_hdr,	sizeof(msg_hdr));
	sg_set_buf(&sg[1],		payload,	payload_size);
	sg_set_buf(&sg[out + 0],	&status,	sizeof(status));
	if (ret_payload_size)
		sg_set_buf(&sg[out + 1],ret_payload,	ret_payload_size);

#ifdef VNPLUG_DEBUG
	printk("[vNPlug-ctrl] sending msg on g2h vq [ type=%u, client id=%u, payload size=%u, ret payload size=%u ]\n", msg_hdr.type, msg_hdr.id, payload_size, ret_payload_size);
#endif

	BUG_ON(
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,36) || defined(REDHAT_PATCHED_KERNEL))
	virtqueue_add_buf(vi->g2h_vq, sg, out, in, vi)
#else
	vi->g2h_vq->vq_ops->add_buf(vi->g2h_vq, sg, out, in, vi)
#endif
	< 0);

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,36) || defined(REDHAT_PATCHED_KERNEL))
	virtqueue_kick(vi->g2h_vq);
#else
	vi->g2h_vq->vq_ops->kick(vi->g2h_vq);
#endif

	/* We sent a in-stack buffer, so we have to spin for a response.
	 * The kick causes an ioport write, trapping into the hypervisor, 
	 * so the request should be handled immediately.
	 */
	while (!
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,36) || defined(REDHAT_PATCHED_KERNEL))
	virtqueue_get_buf(vi->g2h_vq, &len)
#else
	vi->g2h_vq->vq_ops->get_buf(vi->g2h_vq, &len)
#endif
	) //TODO maybe we should check for the tag
		cpu_relax();

	return status;
}

/* ************************************************************************************************** */
/* ******************************************************************** VNPLUG CTRL DEVICE OPERATIONS */

static int vnplug_ctrl_open(struct inode *inode, struct file *filep)
{
	/* this is not needed, but it's nice and requires minor future changes */
	filep->private_data = vnplug_ctrl_info;

	try_module_get(THIS_MODULE);
	return 0;
}

/* ************************************************************************************************** */

static int vnplug_ctrl_release(struct inode *inode, struct file *filep)
{
	module_put(THIS_MODULE);
	return 0;
}

/* ************************************************************************************************** */

static ssize_t vnplug_ctrl_write(struct file *filep, const char __user *buf, size_t count, loff_t *ppos)
{
	struct vnplug_ctrl_info *vi = filep->private_data;
	struct vnplug_ctrl_msg msg;
	char *kbuf;
	char *ret_kbuf = NULL;
	ssize_t retval;

	if (count <= sizeof(msg))
	{
		retval = -EINVAL;
		goto exit;
	}

	if ((retval = copy_from_user(&msg, buf, sizeof(msg)))){
		retval = -ENOMEM;
		goto exit;
	}

	if ((count - sizeof(msg)) != (msg.payload_len + msg.ret_payload_len)){
		retval = -EINVAL;
		goto exit;
	}

	if (!(kbuf = kmalloc(msg.payload_len, GFP_ATOMIC))){
		retval = -ENOMEM;
		goto exit;
	}

	if (msg.ret_payload_len){
		if (!(ret_kbuf = kmalloc(msg.ret_payload_len, GFP_ATOMIC))){
			retval = -ENOMEM;
			goto free_kbuf;
		}
	}

	if ((retval = copy_from_user(kbuf, (buf + sizeof(msg)), msg.payload_len))){
		retval = -ENOMEM;
		goto free;
	}

#ifdef VNPLUG_DEBUG
	printk("[vNPlug-ctrl] sending ctrl msg [ id=%u, payload size=%u, ret payload size=%u ]\n", msg.id, msg.payload_len, msg.ret_payload_len);
#endif

	retval = vnplug_ctrl_virtio_send_msg(vi,
		VNPLUG_CTRL_MSG_FORWARD, 
		msg.id,
		kbuf,
		msg.payload_len,
		ret_kbuf,
		msg.ret_payload_len
	) & 0xffffffff /* int32_t */ ;

#ifdef VNPLUG_DEBUG
	printk("[vNPlug-ctrl] ctrl return value: %d\n", (int32_t) retval);
#endif

	if (msg.ret_payload_len){
	/* copying back return data */
		if (copy_to_user((void __user *) (buf + sizeof(msg) + msg.payload_len), ret_kbuf, msg.ret_payload_len)){
#ifdef VNPLUG_DEBUG
			printk("[vNPlug-ctrl] error: cannot copy %lu bytes [ buf add=%p, ret payload addr=%p, msg len=%lu, ret payload len=%lu ]\n", 
				(unsigned long int) retval,
				buf,
				(void __user *) (buf + sizeof(msg) + msg.payload_len),
				sizeof(msg),
				(unsigned long int) msg.ret_payload_len);
#endif
			retval = -ENOMEM;
			goto free;
		}
	}
free:
	if (msg.ret_payload_len)
		kfree(ret_kbuf);
free_kbuf:
	kfree(kbuf);
exit:
	return retval;
}

/* ************************************************************************************************** */
/* ****************************************************************** VNPLUG CTRL DEVICE REGISTRATION */

static void vnplug_ctrl_virtio_update_status(struct vnplug_ctrl_info *vi)
{
	uint32_t v;

	if (!virtio_has_feature(vi->vdev, VNPLUG_CTRL_STATUS))
		return;

	vi->vdev->config->get(	vi->vdev, 
				offsetof(struct vnplug_ctrl_virtio_config, status),
				  	&v, sizeof(v));

	v &= VNPLUG_CTRL_STATUS_UP;

	if (vi->status == v)
		return;

	vi->status = v;

	/* Maybe here you need to do something accoprding to the new status */
}

/* ************************************************************************************************** */

static void vnplug_ctrl_virtio_config_changed(struct virtio_device *vdev)
{
	struct vnplug_ctrl_info *vi = vdev->priv;

	vnplug_ctrl_virtio_update_status(vi);
}

/* ************************************************************************************************** */

static int vnplug_ctrl_virtio_probe(struct virtio_device *vdev)
{
	int ret;
	struct vnplug_ctrl_info *vi;
#define VNPLUG_CTRL_VIRTIO_N_VQS 1
	struct virtqueue *vqs[VNPLUG_CTRL_VIRTIO_N_VQS];
	vq_callback_t *callbacks[] = {vnplug_ctrl_virtio_g2h_callback};
	const char *names[] = { "g2h" };

	/* Here you can check for host features, and according to them 
	 * you can do something or get some configuration value, example:
	 * if (virtio_has_feature(vdev, VNPLUG_CTRL_STATUS)) 
	 * 	vdev->config->get(vdev, offsetof(struct vnplug_ctrl_virtio_config, status),
	 * 			  destination_buffer, len);
	 */

	if (!(vi = kmalloc(sizeof(struct vnplug_ctrl_info), GFP_ATOMIC)))
		return -ENOMEM;

	memset(vi, 0, sizeof(struct vnplug_ctrl_info));
	vi->vdev = vdev;
	vdev->priv = vi;

	if ((ret = vdev->config->find_vqs(vdev, VNPLUG_CTRL_VIRTIO_N_VQS, vqs, callbacks, names)))
		goto free;

	vi->g2h_vq = vqs[0];

	/* We can have max ONE ctrl device (we don't need to manage minors) */
	vnplug_ctrl_info = vi;

	/*Creating char device (to interact with userspace) */
	vi->dev = device_create(
		vnplug_class, 
		NULL,
		MKDEV(vnplug_ctrl_major, 0), 
		vi,
		"vnplug_ctrl");
	
	if (IS_ERR(vi->dev)) {
		ret = -ENODEV;
		goto free_vqs;
	}

	vi->status = VNPLUG_CTRL_STATUS_UP;
	vnplug_ctrl_virtio_update_status(vi);

#ifdef VNPLUG_DEBUG
	printk("[vNPlug] registered vNPlug-CTRL device\n");
#endif

	return 0;

//device_destroy:
//	device_destroy(vnplug_class, MKDEV(vnplug_ctrl_major, 0));
free_vqs:
	vdev->config->del_vqs(vdev);
free:
	kfree(vi);

	return ret;
}

/* ************************************************************************************************** */

static void __devexit vnplug_ctrl_virtio_remove(struct virtio_device *vdev)
{
	struct vnplug_ctrl_info *vi = vdev->priv;

	/* Stop all the virtqueues. */
	vdev->config->reset(vdev);

	vdev->config->del_vqs(vi->vdev);

	kfree(vi);

#ifdef VNPLUG_DEBUG
	printk("[vNPlug] vNPlug-CTRL device unregistered\n");
#endif
}

#endif /* VNPLUG_CTRL */

/* ************************************************************************************************** */
/* ************************************************************************* VNPLUG DEVICE OPERATIONS */

static int vnplug_open(struct inode *inode, struct file *filep)
{
	struct vnplug_device *idev;
	struct vnplug_listener *listener;
	int ret = 0;

	mutex_lock(&vnplug_minor_lock);
	idev = idr_find(&vnplug_idr, iminor(inode));
	mutex_unlock(&vnplug_minor_lock);
	if (!idev) {
		ret = -ENODEV;
		goto exit;
	}

	if (!try_module_get(THIS_MODULE)) {
		ret = -ENODEV;
		goto exit;
	}

	if (!(listener = kmalloc(sizeof(*listener), GFP_KERNEL))){
		ret = -ENOMEM;
		goto mod_put;
	}

	listener->dev = idev;
	listener->event_count = atomic_read(&idev->event);
#ifdef VNPLUG_MULTI_IRQ
	{ /* MSI-X */
	int i;
	if (!(listener->event_count_s = kmalloc(idev->info->nvectors * sizeof(*listener->event_count_s), GFP_KERNEL))) {
		ret = -ENOMEM;
		goto free;
	}
	for (i=0;i<idev->info->nvectors;i++)
		listener->event_count_s[i] = atomic_read(&idev->event_s[i]);
	}
#endif /* VNPLUG_MULTI_IRQ */
	filep->private_data = listener;

	return 0;

#ifdef VNPLUG_MULTI_IRQ
free:
	kfree(listener);
#endif /* VNPLUG_MULTI_IRQ */
mod_put:
	module_put(THIS_MODULE);
exit:
	return ret;
}

/* ************************************************************************************************** */

static int vnplug_release(struct inode *inode, struct file *filep)
{
	struct vnplug_listener *listener = filep->private_data;
	// struct vnplug_device *idev = listener->dev;
	filep->private_data = NULL;
	module_put(THIS_MODULE);
#ifdef VNPLUG_MULTI_IRQ
	kfree(listener->event_count_s);
#endif /* VNPLUG_MULTI_IRQ */
	kfree(listener);
	return 0;
}

/* ************************************************************************************************** */

/* Note: When VNPLUG_MULTI_IRQ is defined it's possible to wait for all 
 * or just one specific interrupt (MSI-X vector). But, only 
 * with the read it's possible to wait for a specific interrupt with 
 * this implementation. The count parameter contains the interrupt id,
 * instead of the buffer size (always sizeof(s32))
 *  count = 0 indicates all interrupts
 *  count = N indicates the interrupt N-1
 * */
static ssize_t vnplug_read(struct file *filep, char __user *buf, size_t count, loff_t *ppos)
{
	struct vnplug_listener *listener = filep->private_data;
	struct vnplug_device *idev = listener->dev;
	DECLARE_WAITQUEUE(wait, current);
	ssize_t retval;
	s32 event_count;

#ifdef VNPLUG_MULTI_IRQ
	if (count < 0 || count > idev->info->nvectors)
		return -EINVAL;
#else /* VNPLUG_MULTI_IRQ */

	if (count != sizeof(s32))
		return -EINVAL;

#endif /* VNPLUG_MULTI_IRQ */

#ifdef VNPLUG_MULTI_IRQ
	if (count > 0){ /* MSI-X with specific interrupt */
		add_wait_queue(&idev->wait_s[count-1], &wait);
	}
	else /* Regular IRQ or MSI-X with all interrupts */
#endif /* VNPLUG_MULTI_IRQ */

	add_wait_queue(&idev->wait, &wait);


	do {
		set_current_state(TASK_INTERRUPTIBLE);

#ifdef VNPLUG_MULTI_IRQ
		if (count > 0){ /* MSI-X with specific interrupt */
			event_count = atomic_read(&idev->event_s[count-1]);
 #ifdef VNPLUG_DEBUG
 			printk("[vNPlug] IRQ %d has %d events\n", (int) count-1, event_count);
 #endif
			if (event_count != listener->event_count_s[count-1]) {
				if (copy_to_user(buf, &event_count, sizeof(s32)))
					retval = -EFAULT;
				else {
					listener->event_count_s[count-1] = event_count;
					retval = sizeof(s32);
				}
				break;
			}
		}
		else { /* Regular IRQ or MSI-X with all interrupts */
#endif /* VNPLUG_MULTI_IRQ */

		event_count = atomic_read(&idev->event);

		if (event_count != listener->event_count) {
			if (copy_to_user(buf, &event_count, sizeof(s32)))
				retval = -EFAULT;
			else {
				listener->event_count = event_count;
				retval = sizeof(s32);
			}
			break;
		}

#ifdef VNPLUG_MULTI_IRQ
		}
#endif /* VNPLUG_MULTI_IRQ */

		if (filep->f_flags & O_NONBLOCK) {
			retval = -EAGAIN;
			break;
		}

		if (signal_pending(current)) {
			retval = -ERESTARTSYS;
			break;
		}

		schedule();
	} while (1);

	__set_current_state(TASK_RUNNING);

#ifdef VNPLUG_MULTI_IRQ
	if (count > 0) /* MSI-X with specific interrupt */
		remove_wait_queue(&idev->wait_s[count-1], &wait);
	else
#endif /* VNPLUG_MULTI_IRQ */

	remove_wait_queue(&idev->wait, &wait);

	return retval;
}

/* ************************************************************************************************** */

static int vnplug_mmap(struct file *filep, struct vm_area_struct *vma)
{
	struct vnplug_listener *listener = filep->private_data;
	struct vnplug_device *idev = listener->dev;
	unsigned long requested_pages, actual_pages;
	int i;

	if (vma->vm_end < vma->vm_start)
		return -EINVAL;

	vma->vm_private_data = idev;

	for (i = 0; i < VNPLUG_MAX_REGIONS; i++) {
		if (idev->info->mem[i].size == 0)
			return -EINVAL;
		/* we are using vm_pgoff as region id
		   (use region_id*PAGE_SIZE in mmap) */
		if (vma->vm_pgoff == i) 
			break;
	}
	if (i == VNPLUG_MAX_REGIONS)
		return -EINVAL;

	requested_pages = (vma->vm_end - vma->vm_start) >> PAGE_SHIFT;
	actual_pages = ( (idev->info->mem[i].addr & ~PAGE_MASK) 
			+ idev->info->mem[i].size + PAGE_SIZE -1 ) >> PAGE_SHIFT;
	if (requested_pages > actual_pages)
		return -EINVAL;

	vma->vm_flags |= VM_IO | VM_RESERVED;
	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);

#ifdef VNPLUG_DEBUG
		printk("[vNPlug] mmapping addr=%lu>>PAGE_SHIFT on vm_start=%lu\n", idev->info->mem[i].addr, vma->vm_start);
#endif

	return remap_pfn_range(
		vma,
		vma->vm_start,
		idev->info->mem[i].addr >> PAGE_SHIFT,
		vma->vm_end - vma->vm_start,
		vma->vm_page_prot);
}

/* ************************************************************************************************** */
/* ************************************************************** VNPLUG DEVICE INTERRUPTS MANAGEMENT */

void vnplug_event_notify(struct vnplug_info *info, int irq)
{
	struct vnplug_device *idev = info->vnplug_dev;

#ifdef VNPLUG_MULTI_IRQ
	{ /* MSI-X */
	int i;
	for (i = 0; i < idev->info->nvectors; i++){
			if (likely(idev->info->msix_entries[i].vector == irq)){
			atomic_inc(&idev->event_s[i]);
			wake_up_interruptible(&idev->wait_s[i]);
			break;
		}
	}
	}
#endif /* VNPLUG_MULTI_IRQ */ 

	atomic_inc(&idev->event);
	wake_up_interruptible(&idev->wait);
}

/* ************************************************************************************************** */

static irqreturn_t vnplug_msix_handler(int irq, void *opaque)
{
	struct vnplug_info * dev_info = (struct vnplug_info *) opaque;

#ifdef VNPLUG_DEBUG
	printk("[VNPlug] Received MSI-X interrupt %d\n", irq);
#endif

	vnplug_event_notify(dev_info, irq);
	return IRQ_HANDLED;
}

/* ************************************************************************************************** */

static void vnplug_free_msix_vectors(struct vnplug_info *dev_info, const int max_vector)
{
	int i;

	for (i = 0; i < max_vector; i++)
		free_irq(dev_info->msix_entries[i].vector, dev_info);
	
	pci_disable_msix(dev_info->dev); //TODO check this
}

/* ************************************************************************************************** */

static int vnplug_request_msix_vectors(struct vnplug_info *dev_info)
{
	int i, err;
	const char *name = VNPLUG_DEVICE_NAME;

	/* Since we do not known the number of MSI vectors, so we use VNPLUG_MAX_MSI_VECTORS to avoid unsafe operations
	such as: n = err = pci_enable_msix(dev_info->dev, (struct msix_entry *) 1, 0xffff); */

	if (!(dev_info->msix_entries = kmalloc(VNPLUG_MAX_MSI_VECTORS * sizeof(*dev_info->msix_entries), GFP_KERNEL)))
		return -ENOSPC;

	if (!(dev_info->msix_names = kmalloc(VNPLUG_MAX_MSI_VECTORS * sizeof(*dev_info->msix_names), GFP_KERNEL))){
		kfree(dev_info->msix_entries);
		return -ENOSPC;
	}

#ifdef VNPLUG_DEBUG
	printk("[vNPlug] MSI-X data structures allocated\n");
#endif


	for (i = 0; i < VNPLUG_MAX_MSI_VECTORS; i++) 
		dev_info->msix_entries[i].entry = i;

	dev_info->nvectors = VNPLUG_MAX_MSI_VECTORS; 

	/* pci_enable_msix - A return of:
	 * = 0 - indicates successful configuration of MSI-X capability structure with new allocated MSI-X vectors.
	 * < 0 - indicates a failure.
	 * > 0 - indicates that driver request is exceeding the number of vectors available, 
	 *	   driver should use the returned value to re-send its request.
	 */
	err = pci_enable_msix(dev_info->dev, dev_info->msix_entries, dev_info->nvectors);
	if (err < 0)
		goto free;
	
	if (err > 0){
		dev_info->nvectors = err;

#ifdef VNPLUG_DEBUG
		printk("[vNPlug] Number of MSI-X vectors: %d\n", err);
#endif

		err = pci_enable_msix(dev_info->dev, dev_info->msix_entries, dev_info->nvectors);

#ifdef VNPLUG_DEBUG
		printk("[vNPlug] Enabling MSI-X. Return value is %d\n", err);
#endif

		if (err != 0)
			goto free;
	}

	for (i = 0; i < dev_info->nvectors; i++) {
		snprintf(dev_info->msix_names[i], sizeof(*dev_info->msix_names), "%s-config", name);

		err = request_irq(dev_info->msix_entries[i].vector, vnplug_msix_handler, 0, dev_info->msix_names[i], dev_info);

		if (err) {
			vnplug_free_msix_vectors(dev_info, i - 1);
			goto free;
		}
	}

	return 0;
free:
	kfree(dev_info->msix_entries);
	kfree(dev_info->msix_names);
	return err;
}

/* ************************************************************************************************** */
/* *********************************************************************** VNPLUG DEVICE REGISTRATION */ 
static int vnplug_get_minor(struct vnplug_device *idev)
{
	int id;
	int ret = -ENOMEM;

	mutex_lock(&vnplug_minor_lock);
	if (!idr_pre_get(&vnplug_idr, GFP_KERNEL))
		goto exit;

	if ((ret = idr_get_new(&vnplug_idr, idev, &id)) < 0)
		goto exit;

	idev->minor = id & MAX_ID_MASK;
exit:
	mutex_unlock(&vnplug_minor_lock);
	return ret;
}

/* ************************************************************************************************** */

static void vnplug_free_minor(struct vnplug_device *idev)
{
	mutex_lock(&vnplug_minor_lock);
	idr_remove(&vnplug_idr, idev->minor);
	mutex_unlock(&vnplug_minor_lock);
}

/* ************************************************************************************************** */

static int __devinit vnplug_pci_probe(struct pci_dev *dev, const struct pci_device_id *id)
{
	struct vnplug_info * dev_info;
	struct vnplug_device *idev;
	int i;

	if (!(dev_info = kzalloc(sizeof(struct vnplug_info), GFP_KERNEL)))
		return -ENOMEM;

	if (!(idev = kzalloc(sizeof(*idev), GFP_KERNEL))){
		kfree(dev_info);
		return -ENOMEM;
	}

	/* pci_enable_device - initialize device (enable I/O and memory, wake up the device if it was suspended) */
	if (pci_enable_device(dev))
		goto free;

	/* pci_request_regions - mark all PCI regions associated with the device as being reserved by the owner */
	if (pci_request_regions(dev, VNPLUG_DEVICE_NAME))
		goto disable;

	/* pci_resource_start - return the bus start address of the bar */
	dev_info->mem[VNPLUG_REG_REGION_ID].addr = pci_resource_start(dev, VNPLUG_PCI_REG_BAR_ID);
	if (!dev_info->mem[VNPLUG_REG_REGION_ID].addr)
		goto release;

	/* pci_ioremap_bar - make sure the BAR is actually a memory resource and calls ioremap_nocache.
	 *
	 * ioremap_nocache - map bus memory into CPU space
	 * ioremap_nocache performs a platform specific sequence of operations to
	 * make bus memory CPU accessible via the readb/readw/readl/writeb/
	 * writew/writel functions and the other mmio helpers. The returned
	 * address is not guaranteed to be usable directly as a virtual
	 * address.
	 * This version of ioremap ensures that the memory is marked uncachable
	 * on the CPU as well as honouring existing caching rules from things like
	 * the PCI bus. Note that there are other caches and buffers on many
	 * busses. In particular driver authors should read up on PCI writes.
	 * It's useful if some control registers are in such an area and
	 * write combining or read caching is not desirable.
	 * */
	dev_info->mem[VNPLUG_REG_REGION_ID].internal_addr = pci_ioremap_bar(dev, VNPLUG_PCI_REG_BAR_ID);
	if (!dev_info->mem[VNPLUG_REG_REGION_ID].internal_addr) {
		goto release;
	}

	/* region size: (pci_resource_end - pci_resource_start) */	
	dev_info->mem[VNPLUG_REG_REGION_ID].size = pci_resource_len(dev, VNPLUG_PCI_REG_BAR_ID);

#ifdef VNPLUG_DEBUG
	printk("[vNPlug] memory ioremap done on device %u. [ registers addr=%lu internal_addr=%p size=%lu ]\n",
		*((uint32_t *) dev_info->mem[VNPLUG_REG_REGION_ID].internal_addr + VNPLUG_REG_OFF_ID),
		dev_info->mem[VNPLUG_REG_REGION_ID].addr,
		dev_info->mem[VNPLUG_REG_REGION_ID].internal_addr,
		dev_info->mem[VNPLUG_REG_REGION_ID].size);
#endif

	for (i=0; i<VNPLUG_MAX_MM_BARS; i++){

		dev_info->mem[VNPLUG_BASE_MM_REGION_ID+i].addr = pci_resource_start(dev, VNPLUG_PCI_BASE_MM_BAR_ID+i);
		if (!dev_info->mem[VNPLUG_BASE_MM_REGION_ID+i].addr)
			continue;
	
		dev_info->mem[VNPLUG_BASE_MM_REGION_ID+i].internal_addr = pci_ioremap_bar(dev, VNPLUG_PCI_BASE_MM_BAR_ID+i);
		if (!dev_info->mem[VNPLUG_BASE_MM_REGION_ID+i].internal_addr)
			goto unmap_s;

		dev_info->mem[VNPLUG_BASE_MM_REGION_ID+i].size = pci_resource_len(dev, VNPLUG_PCI_BASE_MM_BAR_ID+i);

#ifdef VNPLUG_DEBUG
		printk("[vNPlug] [ region%d addr=%lu internal_addr=%p size=%lu ]\n",
			i,
			dev_info->mem[VNPLUG_BASE_MM_REGION_ID+i].addr,
			dev_info->mem[VNPLUG_BASE_MM_REGION_ID+i].internal_addr,
			dev_info->mem[VNPLUG_BASE_MM_REGION_ID+i].size);
#endif
	}

	dev_info->dev = dev;

	if (vnplug_request_msix_vectors(dev_info) != 0) {
#ifdef VNPLUG_DEBUG
		printk("[vNPlug] Error requesting MSI-X vectors\n");
#endif
		goto unmap_s;
	}

	idev->info = dev_info;
	init_waitqueue_head(&idev->wait);
	atomic_set(&idev->event, 0);

#ifdef VNPLUG_MULTI_IRQ
	{ /* MSI-X */
	int i;

	if (!(idev->wait_s = kmalloc(dev_info->nvectors * sizeof(*idev->wait_s), GFP_KERNEL)))
		goto unmap1_m;

	if (!(idev->event_s = kmalloc(dev_info->nvectors * sizeof(*idev->event_s), GFP_KERNEL)))
		goto free_wait_m;

	for (i = 0; i < dev_info->nvectors; i++){
		init_waitqueue_head(&idev->wait_s[i]);
		atomic_set(&idev->event_s[i], 0);
	}
	}
#endif /* VNPLUG_MULTI_IRQ */

	if (vnplug_get_minor(idev))
		goto unmap1;

	idev->dev = device_create(
		vnplug_class, 
		&dev->dev,
		MKDEV(vnplug_major, idev->minor), 
		idev,
		"vnplug%d", 
		idev->minor);

	if (IS_ERR(idev->dev)) 
		goto free_minor;
	
	dev_info->vnplug_dev = idev;

	pci_set_drvdata(dev, dev_info);

//#ifdef VNPLUG_DEBUG
	printk("[vNPlug] Registered new device [id=%u]\n", *((uint32_t *) dev_info->mem[VNPLUG_REG_REGION_ID].internal_addr + VNPLUG_REG_OFF_ID));
//#endif

	return 0;

//dev_destroy:
//	device_destroy(vnplug_class, MKDEV(vnplug_major, idev->minor));
free_minor:
	vnplug_free_minor(idev);
unmap1:
#ifdef VNPLUG_MULTI_IRQ	
	kfree(idev->event_s);
free_wait_m:
	kfree(idev->wait_s);
unmap1_m:
#endif /* VNPLUG_MULTI_IRQ */
	vnplug_free_msix_vectors(idev->info, idev->info->nvectors);
unmap_s:
	for (i=0; i<VNPLUG_MAX_MM_BARS; i++)
		if (dev_info->mem[VNPLUG_BASE_MM_REGION_ID+i].addr)
			iounmap(dev_info->mem[VNPLUG_BASE_MM_REGION_ID+i].internal_addr);	
	iounmap(dev_info->mem[VNPLUG_REG_REGION_ID].internal_addr);
release:
	pci_release_regions(dev);
disable:
	pci_disable_device(dev);
free:
	kfree (idev);
	kfree (dev_info);
#ifdef VNPLUG_DEBUG
	printk("[vNPlug] Error registering device\n");
#endif
	return -ENODEV;
}

/* ************************************************************************************************** */

static void vnplug_pci_remove(struct pci_dev *dev)
{
	struct vnplug_info *dev_info = pci_get_drvdata(dev);
	struct vnplug_device *idev;
	int i;
	if (!dev_info || !(idev = dev_info->vnplug_dev))
		return;
	
	vnplug_free_minor(idev);
	dev_set_drvdata(idev->dev, NULL);
	device_destroy(vnplug_class, MKDEV(vnplug_major, idev->minor));

#ifdef VNPLUG_MULTI_IRQ	
	kfree(idev->event_s);
	kfree(idev->wait_s);
#endif /* VNPLUG_MULTI_IRQ */
	vnplug_free_msix_vectors(dev_info, dev_info->nvectors);	

	for (i=0; i<VNPLUG_MAX_MM_BARS; i++)
		if (dev_info->mem[VNPLUG_BASE_MM_REGION_ID+i].addr)
			iounmap(dev_info->mem[VNPLUG_BASE_MM_REGION_ID+i].internal_addr);
	iounmap(dev_info->mem[VNPLUG_REG_REGION_ID].internal_addr);
	pci_release_regions(dev);
	pci_disable_device(dev);
	pci_set_drvdata(dev, NULL);

	kfree (idev);
	kfree (dev_info);

//#ifdef VNPLUG_DEBUG
	printk("[vNPlug] Device unregistered\n");
//#endif
}

/* ************************************************************************************************** */
/* ************************************************************ DEVICE & CTRL REGISTRATION STRUCTURES */

static const struct file_operations vnplug_fops = {
	.owner		= THIS_MODULE,
	.open		= vnplug_open,
	.release	= vnplug_release,
	.read		= vnplug_read,
	.mmap		= vnplug_mmap,
};

#ifdef VNPLUG_CTRL
/* ************************************************************************************************** */

static const struct file_operations vnplug_ctrl_fops = {
	.open		= vnplug_ctrl_open,
	.release	= vnplug_ctrl_release,
	.write		= vnplug_ctrl_write,
};

/* ************************************************************************************************** */

static struct virtio_device_id vnplug_ctrl_virtio_id_table[] = {
	{ VIRTIO_ID_VNPLUG_CTRL, VIRTIO_DEV_ANY_ID },
	{ 0 },
};

static unsigned int vnplug_ctrl_virtio_features[] = {
	VNPLUG_CTRL_STATUS	
};

static struct virtio_driver vnplug_ctrl_virtio_driver = {
	.feature_table 		= vnplug_ctrl_virtio_features,
	.feature_table_size 	= ARRAY_SIZE(vnplug_ctrl_virtio_features),
	.driver.name 		= KBUILD_MODNAME,
	.driver.owner 		= THIS_MODULE,
	.id_table 		= vnplug_ctrl_virtio_id_table,
	.probe 			= vnplug_ctrl_virtio_probe,
	.remove 		= __devexit_p(vnplug_ctrl_virtio_remove),
	.config_changed 	= vnplug_ctrl_virtio_config_changed,
};
#endif /* VNPLUG_CTRL */

/* ************************************************************************************************** */

static struct pci_device_id vnplug_pci_ids[] __devinitdata = {
	{
		.vendor 	= PCI_VENDOR_ID_SILICOM,
		.device 	= PCI_DEVICE_ID_VNPLUG_DEV,
		.subvendor 	= PCI_ANY_ID,
		.subdevice 	= PCI_ANY_ID,
	},
	{ 0, }
};

static struct pci_driver vnplug_pci_driver = {
	.name 			= VNPLUG_DEVICE_NAME,
	.id_table 		= vnplug_pci_ids,
	.probe 			= vnplug_pci_probe,
	.remove 		= vnplug_pci_remove,
};

/* ************************************************************************************************** */
/* *********************************************************************** VNPLUG MODULE REGISTRATION */

static int __init vnplug_init_module(void)
{
	int ret;

	/* char device registration */

	if ((ret = vnplug_major = register_chrdev(0, VNPLUG_DEVICE_NAME, &vnplug_fops)) < 0) 
		goto exit;

#ifdef VNPLUG_DEBUG
	printk("[vNPlug] Registering driver. Major device number is %d\n", vnplug_major);
#endif

	vnplug_class = class_create(THIS_MODULE, VNPLUG_DEVICE_NAME);
	if (IS_ERR(vnplug_class)){
		ret = -ENOMEM;
		goto clean_major;
	}

	/* pci driver registration */

	if ((ret = pci_register_driver(&vnplug_pci_driver)) < 0)
		goto class_destroy;

#ifdef VNPLUG_CTRL
	if ((vnplug_ctrl_major = register_chrdev(0, VNPLUG_CTRL_DEVICE_NAME, &vnplug_ctrl_fops)) < 0){
		ret = vnplug_ctrl_major;
		goto unregister;
	}

	if ((ret = register_virtio_driver(&vnplug_ctrl_virtio_driver))) {
		printk("[vNPlug] Error registering Virtio driver\n");
		goto clean_ctrl_major;
	}
#endif /* VNPLUG_CTRL */

//#ifdef VNPLUG_DEBUG
	printk("[vNPlug] Driver loaded successfully\n");
//#endif

	return ret;

#ifdef VNPLUG_CTRL
clean_ctrl_major:
	unregister_chrdev(vnplug_ctrl_major, VNPLUG_CTRL_DEVICE_NAME);
unregister:
	pci_unregister_driver(&vnplug_pci_driver);
#endif /* VNPLUG_CTRL */
class_destroy:
	class_destroy(vnplug_class);
clean_major:
	unregister_chrdev(vnplug_major, VNPLUG_DEVICE_NAME);
exit:
#ifdef VNPLUG_DEBUG
	printk("[vNPlug] Error registering driver\n");
#endif
	return ret;
}

/* ************************************************************************************************** */

static void __exit vnplug_exit_module(void)
{
#ifdef VNPLUG_CTRL
	unregister_virtio_driver(&vnplug_ctrl_virtio_driver);
	device_destroy(vnplug_class, MKDEV(vnplug_ctrl_major, 0));
	unregister_chrdev(vnplug_ctrl_major, VNPLUG_CTRL_DEVICE_NAME);
#endif /* VNPLUG_CTRL */
	pci_unregister_driver(&vnplug_pci_driver);
	class_destroy(vnplug_class);
	unregister_chrdev(vnplug_major, VNPLUG_DEVICE_NAME);

//#ifdef VNPLUG_DEBUG
	printk("[vNPlug] Driver unloaded\n");
//#endif
}

module_init(vnplug_init_module);
module_exit(vnplug_exit_module);

MODULE_DEVICE_TABLE(pci, vnplug_pci_ids);
MODULE_DESCRIPTION("vNPlug driver");
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Alfredo Cardigliano");
