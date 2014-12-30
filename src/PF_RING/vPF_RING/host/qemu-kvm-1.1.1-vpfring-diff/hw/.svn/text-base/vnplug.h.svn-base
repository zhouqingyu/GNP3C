#ifndef VNPLUG_H
#define VNPLUG_H

/* CTRL */

struct vNPlugCTRLClientInfo {
	int		 id;
	const char	*name;
	int		(*msg_handler)(void *message, uint32_t size, void *ret_message, uint32_t ret_size);

	QLIST_ENTRY(vNPlugCTRLClientInfo) list;
};



int  vnplug_ctrl_register_client  (struct vNPlugCTRLClientInfo *client);
void vnplug_ctrl_unregister_client(struct vNPlugCTRLClientInfo *client);

/* DEVICE */

struct vNPlugDevClientInfo {
	void		*priv;
	void		( *set_init_data_handler)(
				struct vNPlugDevClientInfo   *client, uint32_t dev_id,
				uint32_t backend_eventfds_n, int *backend_eventfds, 
				uint32_t guest_eventfds_n,   int *guest_eventfds);
	void		( *pre_unplug_handler)(
				struct vNPlugDevClientInfo   *client);
	void		( *post_unplug_handler)(
				struct vNPlugDevClientInfo   *client);
	uint32_t	(*io_readl_handler)(
				struct vNPlugDevClientInfo   *client,
				target_phys_addr_t addr);
	void		(*io_writel_handler)(
				struct vNPlugDevClientInfo   *client,
				target_phys_addr_t addr, 
				uint32_t val);
};

#endif
