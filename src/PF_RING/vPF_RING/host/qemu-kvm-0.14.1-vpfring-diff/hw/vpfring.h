#ifndef VPFRING_H
#define VPFRING

#include <sys/mman.h>
#include <sys/types.h>
#include <sys/eventfd.h>

#include <stdio.h>
#include <stdarg.h>
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/sockios.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/un.h>
#include <sys/time.h>
#include <time.h>
#include <pthread.h>
#include <linux/if_ether.h>

#include "iov.h"
#include "pci.h"

#include <linux/pf_ring.h>
#include <pfring.h>

#include "vnplug.h"

#define VNPLUG_CLIENT_ID_VPFRING 85

struct vPFRingInfo{
	pfring 		*ring;
	uint32_t 	 dev_id;
	DeviceState	*qdev;
	struct vNPlugDevClientInfo *vnplug_client;	

	QLIST_ENTRY(vPFRingInfo) list;
};


/* vPFRing control messages (structures defined both here and in vPFRing lib) */


/* vPFRingMsg types */
#define VPFRING_CTRL_MSG_SET_DIRECTION			 0 /* payload: vPFRingSetDirectionMsg */
#define VPFRING_CTRL_MSG_SET_CLUSTER			 1 /* payload: vPFRingSetClusterMsg */
#define VPFRING_CTRL_MSG_SET_MASTER_ID			 2 /* payload: vPFRingSetMasterIdMsg */
#define VPFRING_CTRL_MSG_SET_CHANNEL_ID			 3 /* payload: vPFRingSetChannelIdMsg */
#define VPFRING_CTRL_MSG_ADD_HW_RULE			 4 /* payload: vPFRingAddHwRuleMsg */
#define VPFRING_CTRL_MSG_REMOVE_HW_RULE			 5 /* payload: vPFRingRemoveHwRuleMsg */
#define VPFRING_CTRL_MSG_REMOVE_FROM_CLUSTER		 6
#define VPFRING_CTRL_MSG_PURGE_IDLE_SET_RULES		 7 /* payload: vPFRingPurgeIdleSetRulesMsg */
#define VPFRING_CTRL_MSG_SET_APPLICATION_NAME		 8 /* payload: vPFRingSetApplicationNameMsg */
#define VPFRING_CTRL_MSG_DEVICE_ADD			 9 /* payload: vPFRingAddMsg */
#define VPFRING_CTRL_MSG_BIND				10 /* payload: vPFRingBindMsg */
#define VPFRING_CTRL_MSG_SET_POLL_WATERMARK		11 /* payload: vPFRingPollWatermarkMsg */
#define VPFRING_CTRL_MSG_DEVICE_DEL			12
#define VPFRING_CTRL_MSG_GET_FILTERING_RULE_STATS	13 /* payload: vPFRingGetFilteringRuleStatsMsg */
#define VPFRING_CTRL_MSG_GET_NUM_RX_CHANNELS		14
#define VPFRING_CTRL_MSG_GET_RING_ID			15
#define VPFRING_CTRL_MSG_GET_PACKET_CONSUMER_MODE	16
#define VPFRING_CTRL_MSG_SET_PACKET_CONSUMER_MODE	17 /* payload: vPFRingSetPacketConsumerModeMsg */
#define VPFRING_CTRL_MSG_SET_VIRTUAL_DEVICE			 18 /* payload: virtual_filtering_device_info */
#define VPFRING_CTRL_MSG_GET_HASH_FILTERING_RULE_STATS	19 /* payload: vPFRingGetHashFilteringRuleStatsMsg */
#define VPFRING_CTRL_MSG_ADD_FILTERING_RULE		20 /* payload: filtering_rule */
#define VPFRING_CTRL_MSG_HANDLE_HASH_FILTERING_RULE	21 /* payload: vPFRingHandleHashFilteringRule */
#define VPFRING_CTRL_MSG_ENABLE_RING			22
#define VPFRING_CTRL_MSG_DISABLE_RING			23
#define VPFRING_CTRL_MSG_REMOVE_FILTERING_RULE		24 /* payload: vPFRingRemoveFilteringRuleMsg */
#define VPFRING_CTRL_MSG_TOGGLE_FILTERING_POLICY	25 /* payload: vPFRingToggleFilteringPolicyMsg */
#define VPFRING_CTRL_MSG_VERSION			26
#define VPFRING_CTRL_MSG_SET_SAMPLING_RATE		27 /* payload: vPFRingSetSamplingRateMsg */
#define VPFRING_CTRL_MSG_GET_BOUND_DEVICE_ADDRESS	   28
#define VPFRING_CTRL_MSG_GET_SLOT_HEADER_LEN		29
#define VPFRING_CTRL_MSG_GET_NUM_QUEUED_PKTS		30
#define VPFRING_CTRL_MSG_ENABLE_RSS_REHASH		31

#define VPFRING_CTRL_MAX_DEV_NAME  64


struct vPFRingMsg {
	uint32_t		type;
	uint32_t		device_id;
	uint32_t		payload_len;
	char			payload[0];
};


struct vPFRingSetDirectionMsg {
	uint32_t	direction;
};

struct vPFRingSetClusterMsg {
	uint32_t	cluster_id;
	uint32_t	cluster_type;
};

struct vPFRingSetMasterIdMsg {
	uint32_t	master_id;
};

struct vPFRingSetChannelIdMsg {
	int32_t		channel_id;
};

struct vPFRingAddHwRuleMsg{
	hw_filtering_rule rule;
};

struct vPFRingRemoveHwRuleMsg{
	uint16_t	rule_id;
	uint16_t	__padding;
};

struct vPFRingPurgeIdleHashRulesMsg{
	uint16_t	inactivity_sec;
	uint16_t	__padding;
};

struct vPFRingSetApplicationNameMsg {
	char		name[VPFRING_CTRL_MAX_DEV_NAME];
};

struct vPFRingAddMsg /* PLUG + open_consumer */ {
		char			device_name[VPFRING_CTRL_MAX_DEV_NAME];
	uint32_t		caplen;
	uint8_t		 promisc;
	uint8_t		 reentrant;
	uint16_t		 __padding;
};

struct vPFRingBindMsg {
		char			device_name[VPFRING_CTRL_MAX_DEV_NAME];
};

struct vPFRingSetPollWatermarkMsg{
	uint16_t	watermark;
	uint16_t	__padding;
};

struct vPFRingGetFilteringRuleStatsMsg{
	uint16_t	rule_id;
	uint16_t	__padding;
	uint32_t	stats_len;
};

struct vPFRingSetPacketConsumerModeMsg{
	uint8_t		plugin_id;
	char		__padding[3]; 
	uint32_t	plugin_data_len;
	char		plugin_data[0];
};

struct vPFRingGetHashFilteringRuleStatsMsg{
	uint32_t		stats_len;
	hash_filtering_rule rule;
};

struct vPFRingHandleHashFilteringRuleMsg{
	uint8_t		add_rule;
	char		__padding[3];
	hash_filtering_rule rule_to_add;
};

struct vPFRingRemoveFilteringRuleMsg{
	uint16_t	rule_id;
	uint16_t	__padding;
};

struct vPFRingToggleFilteringPolicyMsg{
	uint8_t		rules_default_accept_policy;
	char		__padding[3];
};

struct vPFRingSetSamplingRateMsg{
	uint32_t	rate;
};


/* END vPFRing control messages */


/* private prototypes */
void		vpfring_set_init_data	(struct vNPlugDevClientInfo *client, uint32_t dev_id, uint32_t backend_eventfds_n, int *backend_eventfds, uint32_t guest_eventfds_n, int *guest_eventfds);
void		vpfring_stop		(struct vNPlugDevClientInfo *client);
void		vpfring_close_and_free	(struct vNPlugDevClientInfo *client);
uint32_t	vpfring_io_readl	(struct vNPlugDevClientInfo *client, target_phys_addr_t addr);
void		vpfring_io_writel	(struct vNPlugDevClientInfo *client, target_phys_addr_t addr, uint32_t val);
int		vpfring_ctrl_message_rcv(void *message, uint32_t size, void *ret_message, uint32_t ret_size);

#endif
