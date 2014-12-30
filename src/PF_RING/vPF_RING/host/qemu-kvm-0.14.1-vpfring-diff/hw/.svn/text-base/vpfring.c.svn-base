/*
 * vPFRing - a vNPlug client (Virtual PF_RING)
 *
 * Authors:
 *
 * 	Alfredo Cardigliano <cardigliano@ntop.org>
 *
 * This work is licensed under the terms of the GNU GPL version 2. 
 *
 */

#include "vpfring.h"

//#define VPFRING_DEBUG

#ifdef VPFRING_DEBUG
#define VPFRING_DEBUG_PRINTF(fmt, ...)	do {printf("[vPFRing] " fmt, ## __VA_ARGS__); } while (0)
#else
#define VPFRING_DEBUG_PRINTF(fmt, ...)
#endif

static QLIST_HEAD(vpfring_devices_head, vPFRingInfo) vpfring_devices = 
	QLIST_HEAD_INITIALIZER(vpfring_devices);

static struct vPFRingInfo *vpfring_device_by_id(uint32_t device_id)
{
	struct vPFRingInfo *i;
	
	QLIST_FOREACH(i, &vpfring_devices, list) {
		if (i->dev_id == device_id){
			VPFRING_DEBUG_PRINTF("vPFRing device %d found\n", device_id);
			return i;
		}
	}

	VPFRING_DEBUG_PRINTF("error: vPFRing device %d not found!\n", device_id);
	return NULL;
}

/* ******************************************************************************************* */

uint32_t vpfring_io_readl(struct vNPlugDevClientInfo *client, target_phys_addr_t addr)
{
	//struct vPFRingInfo *vpfri = client->priv;
	//VPFRING_DEBUG_PRINTF("io_readl handler call for dev with id=%d\n", vpfri->dev_id);
	return 0;
}

/* ******************************************************************************************* */

void vpfring_io_writel(struct vNPlugDevClientInfo *client, target_phys_addr_t addr, uint32_t val)
{
	//struct vPFRingInfo *vpfri = client->priv;	
	//VPFRING_DEBUG_PRINTF("io_readl handler call for dev with id=%d\n", vpfri->dev_id); 
}

/* ******************************************************************************************* */

static int vpfring_ring_add(struct vPFRingAddMsg *amsg, void *ret_message, uint32_t ret_size)
{
	struct vPFRingInfo *vpfri;
	struct vNPlugDevClientInfo *client;
	char tmpstr[32];
	int ret = -1;

	vpfri = qemu_mallocz(sizeof(*vpfri));
	if (!vpfri)
		goto exit;

	client = qemu_mallocz(sizeof(*client));
	if (!client)
		goto free_vpfri;

	client->set_init_data_handler 	= vpfring_set_init_data;
	client->pre_unplug_handler	  = vpfring_stop;
	client->post_unplug_handler	= vpfring_close_and_free;
	client->io_readl_handler 	= vpfring_io_readl;
	client->io_writel_handler 	= vpfring_io_writel;
	client->priv = vpfri;
	vpfri->vnplug_client = client;

	VPFRING_DEBUG_PRINTF("opening ring\n"); 

	vpfri->ring = pfring_open(
		amsg->device_name,
		amsg->promisc,
		amsg->caplen,
		amsg->reentrant);

	if (vpfri->ring == NULL)
		goto free_client;
	
	/* the dev_id will be set in the init_data handler, called from qdev_device_add */
	vpfri->dev_id = 0xffffffff;

	VPFRING_DEBUG_PRINTF("registering vPFRing device\n"); 

	QLIST_INSERT_HEAD(&vpfring_devices, vpfri, list);

	VPFRING_DEBUG_PRINTF("creating vNPlug device\n"); 

	QemuOpts *opts;
	opts = qemu_opts_create(qemu_find_opts("device"), NULL, 0);
	/* it's ugly but there is no other clean way.. */
	qemu_opt_set(opts, "driver", "vnplug-dev");
	qemu_opt_set(opts, "backend_events_n", "1"); 
	qemu_opt_set(opts, "guest_events_n", "1");

	snprintf(tmpstr, 32, "%u", vpfri->ring->slots_info->tot_mem);
	qemu_opt_set(opts, "vma_size", tmpstr);
	snprintf(tmpstr, 32, "%" PRIu64, (uint64_t) vpfri->ring->buffer);
	qemu_opt_set(opts, "vma_ptr", tmpstr);

	snprintf(tmpstr, 32, "%" PRIu64, (uint64_t) client);
	qemu_opt_set(opts, "client_info_ptr", tmpstr);

	vpfri->qdev = qdev_device_add(opts);

	if (vpfri->qdev == NULL)
		goto close_ring;
	
	/* after qdev_device_add returns, dev_id should be updated to the correct value */
	if (vpfri->dev_id != 0xffffffff){
		VPFRING_DEBUG_PRINTF("vNPlug device created successfully [ id=%u, state=%d ]\n", vpfri->dev_id, vpfri->qdev->state); 
	} else {
		fprintf(stderr, "[vPFRing] Error occurs while creating the vNPlug device: ID not set.\n");
		goto unregister;
	}

	return vpfri->dev_id;

unregister:
	QLIST_REMOVE(vpfri, list);
close_ring:
	pfring_close(vpfri->ring);
free_client:
	qemu_free(client);
free_vpfri:
	qemu_free(vpfri);
exit:
	return ret;
}

/* ******************************************************************************************* */

static void vpfring_ring_del(struct vPFRingInfo *vpfri)
{
	if (vpfri == NULL){
		VPFRING_DEBUG_PRINTF("error deleting device (null)");
		return;
	}

	VPFRING_DEBUG_PRINTF("deleting vPFRing device %d\n", vpfri->dev_id);

	VPFRING_DEBUG_PRINTF("unplugging vNPlug device\n");
	qdev_unplug(vpfri->qdev);

	/* Note: this is called by qdev_unplug */
	//qdev_free(vpfri->qdev);

	/* Note: stop		   -> pre_unplug_handler 
	 *	   close and free -> post_unplug_handler */
}

/* ******************************************************************************************* */

int vpfring_ctrl_message_rcv(void *message, uint32_t size, void *ret_message, uint32_t ret_size)
{
	struct vPFRingMsg *msg = (struct vPFRingMsg *) message;
	struct vPFRingInfo *vpfri = NULL;
	int ret_val;

	if (size != (sizeof(*msg) + msg->payload_len)){
		VPFRING_DEBUG_PRINTF("vpfring_ctrl_message_rcv: wrong message size=%u. expected size=%lu!\n", size, sizeof(*msg) + msg->payload_len);
	 	return -1;
	}

	if (msg->type != VPFRING_CTRL_MSG_DEVICE_ADD) {
		if (!(vpfri = vpfring_device_by_id(msg->device_id))) {	
			fprintf(stderr, "[vPFRing] Error: vpfring_ctrl_message_rcv: Wrong device id=%u, device not found!\n", msg->device_id);
			return -1;
		}
	} 

	switch (msg->type)
	{

		case VPFRING_CTRL_MSG_SET_DIRECTION:
			VPFRING_DEBUG_PRINTF("message VPFRING_CTRL_MSG_SET_DIRECTION received\n");

			if (msg->payload_len != sizeof(struct vPFRingSetDirectionMsg)){
				VPFRING_DEBUG_PRINTF("skipping! vPFRingSetClusterMsg with wrong size\n");
				return -1;
			}
			
			return pfring_set_direction(vpfri->ring, 
				((struct vPFRingSetDirectionMsg *) msg->payload)->direction);

		case VPFRING_CTRL_MSG_SET_CLUSTER:
			{
			struct vPFRingSetClusterMsg *cmsg;
			VPFRING_DEBUG_PRINTF("message VPFRING_CTRL_MSG_SET_CLUSTER received\n");

			if (msg->payload_len != sizeof(struct vPFRingSetClusterMsg)){
				VPFRING_DEBUG_PRINTF("skipping! vPFRingSetClusterMsg with wrong size\n");
				return -1;
			}
			
			cmsg = (struct vPFRingSetClusterMsg *) msg->payload;

			return pfring_set_cluster(vpfri->ring, cmsg->cluster_id, cmsg->cluster_type);
			}

		case VPFRING_CTRL_MSG_SET_MASTER_ID:
			{
			struct vPFRingSetMasterIdMsg *midmsg;
			VPFRING_DEBUG_PRINTF("message VPFRING_CTRL_MSG_SET_MASTER_ID received\n");

			if (msg->payload_len != sizeof(struct vPFRingSetMasterIdMsg)){
				VPFRING_DEBUG_PRINTF("skipping! vPFRingSetMasterIdMsg with wrong size\n");
				return -1;
			}
			
			midmsg = (struct vPFRingSetMasterIdMsg *) msg->payload;

			return pfring_set_master_id(vpfri->ring, midmsg->master_id);
			}

		case VPFRING_CTRL_MSG_SET_CHANNEL_ID:
			{
			struct vPFRingSetChannelIdMsg *cidmsg;
			VPFRING_DEBUG_PRINTF("message VPFRING_CTRL_MSG_SET_CHANNEL_ID received\n");

			if (msg->payload_len != sizeof(struct vPFRingSetChannelIdMsg)){
				VPFRING_DEBUG_PRINTF("skipping! vPFRingSetChannelIdMsg with wrong size\n");
				return -1;
			}
			
			cidmsg = (struct vPFRingSetChannelIdMsg *) msg->payload;

			return pfring_set_channel_id(vpfri->ring, cidmsg->channel_id);
			}

		case VPFRING_CTRL_MSG_ADD_HW_RULE:
			{
			struct vPFRingAddHwRuleMsg *hwrmsg;
			VPFRING_DEBUG_PRINTF("message VPFRING_CTRL_MSG_ADD_HW_RULE received\n");

			if (msg->payload_len != sizeof(struct vPFRingAddHwRuleMsg)){
				VPFRING_DEBUG_PRINTF("skipping! vPFRingAddHwRuleMsg with wrong size\n");
				return -1;
			}
			
			hwrmsg = (struct vPFRingAddHwRuleMsg *) msg->payload;

			return pfring_add_hw_rule(vpfri->ring, &hwrmsg->rule);
			}

		case VPFRING_CTRL_MSG_REMOVE_HW_RULE:
			{
			struct vPFRingRemoveHwRuleMsg *hwrmsg;
			VPFRING_DEBUG_PRINTF("message VPFRING_CTRL_MSG_REMOVE_HW_RULE received\n");

			if (msg->payload_len != sizeof(struct vPFRingRemoveHwRuleMsg)){
				VPFRING_DEBUG_PRINTF("skipping! vPFRingRemoveHwRuleMsg with wrong size\n");
				return -1;
			}
			
			hwrmsg = (struct vPFRingRemoveHwRuleMsg *) msg->payload;

			return pfring_remove_hw_rule(vpfri->ring, hwrmsg->rule_id);
			}


		case VPFRING_CTRL_MSG_REMOVE_FROM_CLUSTER:
			VPFRING_DEBUG_PRINTF("message VPFRING_CTRL_MSG_REMOVE_FROM_CLUSTER received\n");

			return pfring_remove_from_cluster(vpfri->ring);

		case VPFRING_CTRL_MSG_PURGE_IDLE_SET_RULES:
			{
			struct vPFRingPurgeIdleHashRulesMsg *pisrmsg;
			VPFRING_DEBUG_PRINTF("message VPFRING_CTRL_MSG_PURGE_IDLE_SET_RULES received\n");

			if (msg->payload_len != sizeof(struct vPFRingPurgeIdleHashRulesMsg)){
				VPFRING_DEBUG_PRINTF("skipping! vPFRingPurgeIdleHashRulesMsg with wrong size\n");
				return -1;
			}
			
			pisrmsg = (struct vPFRingPurgeIdleHashRulesMsg *) msg->payload;

			return pfring_purge_idle_hash_rules(vpfri->ring, pisrmsg->inactivity_sec);
			}

		case VPFRING_CTRL_MSG_SET_APPLICATION_NAME:
			VPFRING_DEBUG_PRINTF("message VPFRING_CTRL_MSG_SET_APPLICATION_NAME received\n");

			if (msg->payload_len != sizeof(struct vPFRingSetApplicationNameMsg)){
				VPFRING_DEBUG_PRINTF("skipping! vPFRingSetApplicationNameMsg with wrong size\n");
				return -1;
			}
			
			return pfring_set_application_name(
				vpfri->ring, 
				((struct vPFRingSetApplicationNameMsg *) msg->payload)->name);
			
		case VPFRING_CTRL_MSG_DEVICE_ADD:
			VPFRING_DEBUG_PRINTF("message VPFRING_CTRL_MSG_DEVICE_ADD received\n");

			if (msg->payload_len < sizeof(struct vPFRingAddMsg)){
				VPFRING_DEBUG_PRINTF("skipping! vPFRingAddMsg with wrong size\n");
				return -1;
			}
	
			return vpfring_ring_add((struct vPFRingAddMsg *) msg->payload, ret_message, ret_size);
		
		case VPFRING_CTRL_MSG_BIND:
			VPFRING_DEBUG_PRINTF("message VPFRING_CTRL_MSG_BIND received\n");

			if (msg->payload_len != sizeof(struct vPFRingBindMsg)){
				VPFRING_DEBUG_PRINTF("skipping! vPFRingBindMsg with wrong size\n");
				return -1;
			}
			
			return pfring_bind(
				vpfri->ring, 
				((struct vPFRingBindMsg *) msg->payload)->device_name);

		case VPFRING_CTRL_MSG_SET_POLL_WATERMARK:
			VPFRING_DEBUG_PRINTF("message VPFRING_CTRL_MSG_SET_POLL_WATERMARK received\n");

			if (msg->payload_len != sizeof(struct vPFRingSetPollWatermarkMsg)){
				VPFRING_DEBUG_PRINTF("skipping! vPFRingSetPollWatermarkMsg with wrong size\n");
				return -1;
			}
			
			return pfring_set_poll_watermark(
				vpfri->ring, 
				((struct vPFRingSetPollWatermarkMsg *) msg->payload)->watermark);

		case VPFRING_CTRL_MSG_DEVICE_DEL:
			VPFRING_DEBUG_PRINTF("message VPFRING_CTRL_MSG_DEVICE_DEL received\n");

			vpfring_ring_del(vpfri);
			break;

		case VPFRING_CTRL_MSG_GET_FILTERING_RULE_STATS:
			{
			struct vPFRingGetFilteringRuleStatsMsg *gfrsmsg;
			VPFRING_DEBUG_PRINTF("message VPFRING_CTRL_MSG_VERSION received\n");

			if (msg->payload_len != sizeof(struct vPFRingGetFilteringRuleStatsMsg)){
				VPFRING_DEBUG_PRINTF("skipping! vPFRingGetFilteringRuleStatsMsg with wrong size\n");
				return -1;
			}

			if (ret_message == NULL || ret_size <= 0){
				VPFRING_DEBUG_PRINTF("skipping! return buffer not found or empty\n");
				return -1;
			}

			gfrsmsg = (struct vPFRingGetFilteringRuleStatsMsg *) msg->payload;

			if (gfrsmsg->stats_len != ret_size){
				VPFRING_DEBUG_PRINTF("skipping! something wrong..\n");
				return -1;
			}

			return pfring_get_filtering_rule_stats(vpfri->ring, 
				gfrsmsg->rule_id,
				ret_message,
				&gfrsmsg->stats_len);
			}
	
		case VPFRING_CTRL_MSG_GET_NUM_RX_CHANNELS:
			VPFRING_DEBUG_PRINTF("message VPFRING_CTRL_MSG_GET_NUM_RX_CHANNELS received\n");
			
			return pfring_get_num_rx_channels(vpfri->ring);

		case VPFRING_CTRL_MSG_GET_RING_ID:
			VPFRING_DEBUG_PRINTF("message VPFRING_CTRL_MSG_GET_RING_ID received\n");
			
			return pfring_get_ring_id(vpfri->ring);

		case VPFRING_CTRL_MSG_GET_PACKET_CONSUMER_MODE:
			VPFRING_DEBUG_PRINTF("message VPFRING_CTRL_MSG_GET_PACKET_CONSUMER_MODE received\n");
			
			return pfring_get_packet_consumer_mode(vpfri->ring);

		case VPFRING_CTRL_MSG_SET_PACKET_CONSUMER_MODE:
			{
			struct vPFRingSetPacketConsumerModeMsg *pcmmsg;
			VPFRING_DEBUG_PRINTF("message VPFRING_CTRL_MSG_SET_PACKET_CONSUMER_MODE received\n");

			if (msg->payload_len < sizeof(struct vPFRingSetPacketConsumerModeMsg)){
				VPFRING_DEBUG_PRINTF("skipping! vPFRingSetPacketConsumerModeMsg with wrong size\n");
				return -1;
			}
			
			pcmmsg = (struct vPFRingSetPacketConsumerModeMsg *) msg->payload;

			return pfring_set_packet_consumer_mode(vpfri->ring, pcmmsg->plugin_id, pcmmsg->plugin_data, pcmmsg->plugin_data_len);
			}

		case VPFRING_CTRL_MSG_SET_VIRTUAL_DEVICE:
			VPFRING_DEBUG_PRINTF("message VPFRING_CTRL_MSG_SET_VIRTUAL_DEVICE received\n");

			if (msg->payload_len != sizeof(virtual_filtering_device_info)){
				VPFRING_DEBUG_PRINTF("skipping! payload with wrong size\n");
				return -1;
			}
			
			return pfring_set_virtual_device(vpfri->ring, (virtual_filtering_device_info *) msg->payload);

		case VPFRING_CTRL_MSG_GET_HASH_FILTERING_RULE_STATS:
			{
			struct vPFRingGetHashFilteringRuleStatsMsg *hfrsmsg;
			uint32_t stats_len_c;
			VPFRING_DEBUG_PRINTF("message VPFRING_CTRL_MSG_GET_HASH_FILTERING_RULE_STATS received\n");

			if (msg->payload_len != sizeof(struct vPFRingGetHashFilteringRuleStatsMsg)){
				VPFRING_DEBUG_PRINTF("skipping! vPFRingGetHashFilteringRuleStatsMsg with wrong size\n");
				return -1;
			}
			
			hfrsmsg = (struct vPFRingGetHashFilteringRuleStatsMsg *) msg->payload;

			if (ret_message == NULL || ret_size != hfrsmsg->stats_len ){
				VPFRING_DEBUG_PRINTF("skipping! return buffer with wrong size\n");
				return -1;
			}
			
			stats_len_c = hfrsmsg->stats_len;

			return pfring_get_hash_filtering_rule_stats(vpfri->ring, &hfrsmsg->rule, (char *) ret_message, &stats_len_c);
			}

		case VPFRING_CTRL_MSG_ADD_FILTERING_RULE:
			VPFRING_DEBUG_PRINTF("message VPFRING_CTRL_MSG_ADD_FILTERING_RULE received\n");

			if (msg->payload_len != sizeof(filtering_rule)){
				VPFRING_DEBUG_PRINTF("skipping! payload with wrong size\n");
				return -1;
			}
			
			return pfring_add_filtering_rule(vpfri->ring, (filtering_rule *) msg->payload);

		case VPFRING_CTRL_MSG_HANDLE_HASH_FILTERING_RULE:
			{
			struct vPFRingHandleHashFilteringRuleMsg *hfrmsg;
			VPFRING_DEBUG_PRINTF("message VPFRING_CTRL_MSG_HANDLE_HASH_FILTERING_RULE received\n");

			if (msg->payload_len != sizeof(struct vPFRingHandleHashFilteringRuleMsg)){
				VPFRING_DEBUG_PRINTF("skipping! vPFRingHandleHashFilteringRuleMsg with wrong size\n");
				return -1;
			}
			
			hfrmsg = (struct vPFRingHandleHashFilteringRuleMsg *) msg->payload;

			return pfring_handle_hash_filtering_rule(vpfri->ring, &hfrmsg->rule_to_add, hfrmsg->add_rule);
			}

		case VPFRING_CTRL_MSG_ENABLE_RING:
			VPFRING_DEBUG_PRINTF("message VPFRING_CTRL_MSG_ENABLE_RING received\n");
			
			return pfring_enable_ring(vpfri->ring);

		case VPFRING_CTRL_MSG_DISABLE_RING:
			VPFRING_DEBUG_PRINTF("message VPFRING_CTRL_MSG_DISABLE_RING received\n");
			
			return pfring_disable_ring(vpfri->ring);

		case VPFRING_CTRL_MSG_REMOVE_FILTERING_RULE:
			VPFRING_DEBUG_PRINTF("message VPFRING_CTRL_MSG_REMOVE_FILTERING_RULE received\n");

			if (msg->payload_len != sizeof(struct vPFRingRemoveFilteringRuleMsg)){
				VPFRING_DEBUG_PRINTF("skipping! vPFRingRemoveFilteringRuleMsg with wrong size\n");
				return -1;
			}
			
			return pfring_remove_filtering_rule(
				vpfri->ring, 
				((struct vPFRingRemoveFilteringRuleMsg *) msg->payload)->rule_id);

		case VPFRING_CTRL_MSG_TOGGLE_FILTERING_POLICY:
			VPFRING_DEBUG_PRINTF("message VPFRING_CTRL_MSG_TOGGLE_FILTERING_POLICY received\n");

			if (msg->payload_len != sizeof(struct vPFRingToggleFilteringPolicyMsg)){
				VPFRING_DEBUG_PRINTF("skipping! vPFRingToggleFilteringPolicyMsg with wrong size\n");
				return -1;
			}
			
			return pfring_toggle_filtering_policy(
				vpfri->ring, 
				((struct vPFRingToggleFilteringPolicyMsg *) msg->payload)->rules_default_accept_policy);

		case VPFRING_CTRL_MSG_VERSION:
			VPFRING_DEBUG_PRINTF("message VPFRING_CTRL_MSG_VERSION received\n");

			if (ret_message == NULL || ret_size != sizeof(u_int32_t)){
				VPFRING_DEBUG_PRINTF("skipping! return buffer with wrong size\n");
				return -1;
			}
			
			ret_val = pfring_version(vpfri->ring, (u_int32_t *) ret_message);
			VPFRING_DEBUG_PRINTF("PF_RING version is v.%d.%d.%d\n",
				(*((u_int32_t *) ret_message) & 0xFFFF0000) >> 16,
				(*((u_int32_t *) ret_message) & 0x0000FF00) >> 8,
				*((u_int32_t *) ret_message) & 0x000000FF);
			return ret_val;
		
		case VPFRING_CTRL_MSG_SET_SAMPLING_RATE:
			VPFRING_DEBUG_PRINTF("message VPFRING_CTRL_MSG_SET_SAMPLING_RATE received\n");

			if (msg->payload_len != sizeof(struct vPFRingSetSamplingRateMsg)){
				VPFRING_DEBUG_PRINTF("skipping! vPFRingSetSamplingRateMsg with wrong size\n");
				return -1;
			}
			
			return pfring_set_sampling_rate(
				vpfri->ring, 
				((struct vPFRingSetSamplingRateMsg *) msg->payload)->rate);

		case VPFRING_CTRL_MSG_GET_BOUND_DEVICE_ADDRESS:
			VPFRING_DEBUG_PRINTF("message VPFRING_CTRL_MSG_GET_BOUND_DEVICE_ADDRESS received\n");

			if (msg->payload_len != sizeof(u_char) * 6){
				VPFRING_DEBUG_PRINTF("skipping! device address with wrong size\n");
				return -1;
			}

			if (ret_message == NULL || ret_size != (sizeof(u_char) * 6)){
				VPFRING_DEBUG_PRINTF("skipping! return buffer with wrong size\n");
				return -1;
			}

			memcpy(ret_message, msg->payload, sizeof(u_char) * 6);
			
			ret_val = pfring_get_bound_device_address(vpfri->ring, (u_char *) ret_message);

			return ret_val;

		case VPFRING_CTRL_MSG_GET_SLOT_HEADER_LEN:
			VPFRING_DEBUG_PRINTF("message VPFRING_CTRL_MSG_GET_SLOT_HEADER_LEN received\n");
			
			return pfring_get_slot_header_len(vpfri->ring);

		case VPFRING_CTRL_MSG_GET_NUM_QUEUED_PKTS:
			VPFRING_DEBUG_PRINTF("message VPFRING_CTRL_MSG_GET_NUM_QUEUED_PKTS received\n");
			
			return pfring_get_num_queued_pkts(vpfri->ring);

		case VPFRING_CTRL_MSG_ENABLE_RSS_REHASH:
			VPFRING_DEBUG_PRINTF("message VPFRING_CTRL_MSG_ENABLE_RSS_REHASH received\n");
			
			return pfring_enable_rss_rehash(vpfri->ring);

		default:
			VPFRING_DEBUG_PRINTF("vpfring_ctrl_message_rcv: unrecognized msessage type!\n");
	 		return -1;
	}
	
	return 0; //success (non negative value)
}

/* ******************************************************************************************* */

void vpfring_set_init_data(struct vNPlugDevClientInfo *client, uint32_t dev_id, uint32_t backend_eventfds_n, int *backend_eventfds, uint32_t guest_eventfds_n, int *guest_eventfds)
{
	struct vPFRingInfo *vpfri = client->priv;
	struct vpfring_eventfd_info eventfd_i;

	/* setting the device id */
	vpfri->dev_id = dev_id;

	VPFRING_DEBUG_PRINTF("setting eventfds for vNPlug device with id=%d\n", vpfri->dev_id);

	/* we are using just one eventfd, maybe later we can need more.. */
	if (backend_eventfds_n>=1){
		eventfd_i.fd = backend_eventfds[0];
		eventfd_i.id = VPFRING_HOST_EVENT_RX_INT;
		setsockopt(vpfri->ring->fd, 0, SO_SET_VPFRING_HOST_EVENTFD, &eventfd_i, sizeof(eventfd_i));
	} else
	fprintf(stderr, "[vPFRing] error: backend eventfd missing!\n");

	/* setting guest eventfd for guest notifications (unused, present in the experimental version) */
	//if (guest_eventfds_n>=1){
	//	eventfd_i.fd = guest_eventfds[0];
	//	eventfd_i.id = VPFRING_GUEST_EVENT_REQ_RX_INT;
	//	setsockopt(vpfri->ring->fd, 0, SO_SET_VPFRING_GUEST_EVENTFD, &eventfd_i, sizeof(eventfd_i));
	//} else
	//fprintf(stderr, "[vPFRing] error: backend eventfd missing!\n");
}

/* ******************************************************************************************* */

void vpfring_stop(struct vNPlugDevClientInfo *client)
{
	struct vPFRingInfo *vpfri = client->priv;

	if (vpfri == NULL){
		VPFRING_DEBUG_PRINTF("error stopping ring (null)");
		return;
	}

	VPFRING_DEBUG_PRINTF("stopping ring [device=%d]\n", vpfri->dev_id);

	/* stopping eventfd signals from backend */
	setsockopt(vpfri->ring->fd, 0, SO_SET_VPFRING_CLEAN_EVENTFDS, NULL, 0);

	QLIST_REMOVE(vpfri, list);
}

/* ******************************************************************************************* */

void vpfring_close_and_free(struct vNPlugDevClientInfo *client)
{
	struct vPFRingInfo *vpfri = client->priv;

	if (vpfri == NULL){
		VPFRING_DEBUG_PRINTF("error closing ring (null)");
		return;
	}

	VPFRING_DEBUG_PRINTF("closing ring [device=%d]\n", vpfri->dev_id);

	pfring_close(vpfri->ring);

	qemu_free(vpfri->vnplug_client);
	qemu_free(vpfri);
}

/* ******************************************************************************************* */

static struct vNPlugCTRLClientInfo vpfring_client_info = {
	.id		  = VNPLUG_CLIENT_ID_VPFRING,
	.name		= "vpfring",
	.msg_handler = vpfring_ctrl_message_rcv,
};

static void vpfring_register(void)
{
	QLIST_INIT(&vpfring_devices);

	VPFRING_DEBUG_PRINTF("registering to vnplug..\n");
	vnplug_ctrl_register_client(&vpfring_client_info);
}

device_init(vpfring_register);
