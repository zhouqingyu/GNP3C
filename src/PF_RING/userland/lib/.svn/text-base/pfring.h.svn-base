/*
 *
 * (C) 2005-13 - ntop.org
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesses General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 */

#ifndef _PFRING_H_
#define _PFRING_H_

#include <sys/types.h>
#include <stdio.h>
#include <stdarg.h>

#ifndef HAVE_PCAP
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <linux/sockios.h>
#endif

#include <linux/if_packet.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>
#include <time.h>
#include <poll.h>
#include <string.h>
#include <pthread.h>
#include <linux/pf_ring.h>
#include <linux/if_ether.h>

#ifdef HAVE_REDIRECTOR
#include <librdi.h>
#endif

#define MAX_CAPLEN             65535
#define PAGE_SIZE               4096

#define DEFAULT_POLL_DURATION   500

#define POLL_SLEEP_STEP           10 /* ns = 0.1 ms */
#define POLL_SLEEP_MIN          POLL_SLEEP_STEP
#define POLL_SLEEP_MAX          1000 /* ns */
#define POLL_QUEUE_MIN_LEN       500 /* # packets */

#ifndef HAVE_RW_LOCK
#define pthread_rwlock_t       pthread_mutex_t
#define pthread_rwlock_init    pthread_mutex_init
#define pthread_rwlock_rdlock  pthread_mutex_lock
#define pthread_rwlock_wrlock  pthread_mutex_lock
#define pthread_rwlock_unlock  pthread_mutex_unlock
#define pthread_rwlock_destroy pthread_mutex_destroy
#endif

#ifndef max
#define max(a, b) (a > b ? a : b)
#endif

#define timespec_is_before(a, b) \
  ((((a)->tv_sec<(b)->tv_sec)||(((a)->tv_sec==(b)->tv_sec)&&((a)->tv_nsec<(b)->tv_nsec)))?1:0)

/* ********************************* */

#define likely(x)       __builtin_expect((x),1)
#define unlikely(x)     __builtin_expect((x),0)

/* ********************************* */

/*
  See also __builtin_prefetch
  http://gcc.gnu.org/onlinedocs/gcc/Other-Builtins.html
*/
#define prefetch(x) __asm volatile("prefetcht0 %0" :: "m" (*(const unsigned long *)x));

/* ********************************* */

#ifdef  __cplusplus
extern "C" {
#endif

#ifdef SAFE_RING_MODE
  static char staticBucket[2048];
#endif

  typedef void (*pfringProcesssPacket)(const struct pfring_pkthdr *h, const u_char *p, const u_char *user_bytes);

  /* ********************************* */

  typedef struct __pfring pfring; /* Forward declaration */

  /* ********************************* */

#define MAX_NUM_BUNDLE_ELEMENTS 32
  
  typedef enum {
    pick_round_robin = 0,
    pick_fifo
  } bundle_read_policy;

  typedef struct {
    bundle_read_policy policy;
    u_int16_t num_sockets, last_read_socket;
    pfring *sockets[MAX_NUM_BUNDLE_ELEMENTS];
    struct pollfd pfd[MAX_NUM_BUNDLE_ELEMENTS];
  } pfring_bundle;

  /* ********************************* */

  typedef struct {
    u_int64_t recv, drop;
  } pfring_stat;

  /* ********************************* */

  typedef enum {
    hardware_and_software = 0,
    hardware_only,
    software_only
  } filtering_mode;

  /* ********************************* */

  typedef void pfring_pkt_buff;
  
  /* ********************************* */
  
  struct __pfring {
    u_int8_t initialized, enabled, long_header, rss_mode, force_timestamp, strip_hw_timestamp, 
             disable_parsing, disable_timestamp;
    packet_direction direction; /* Specify the capture direction for packets */
    socket_mode mode;

    /* Hardware Timestamp */
    struct {
      u_int8_t force_timestamp, is_silicom_hw_timestamp_card, enable_hw_timestamp;
      u_int32_t last_hw_timestamp_sec, last_hw_timestamp_nsec;
    } hw_ts;

    struct {
      u_int8_t enabled_rx_packet_send;
      struct pfring_pkthdr *last_received_hdr; /*
						 Header of the past packet
						 that has been received on this socket
					       */
    } tx;

    /* TODO these fields should be moved in ->priv_data */
    /* DNA (Direct NIC Access) */
    struct {
      u_int8_t dna_mapped_device;
      u_int32_t sampling_counter;
      u_int16_t num_rx_pkts_before_dna_sync, num_tx_pkts_before_dna_sync; 
      u_int16_t dna_rx_sync_watermark, dna_tx_sync_watermark;
      u_int64_t tot_dna_read_pkts, tot_dna_lost_pkts;
      u_int32_t rx_reg, tx_reg, last_rx_slot_read;
      u_int32_t num_rx_slots_per_chunk, num_tx_slots_per_chunk;
      
      dna_device dna_dev;    
      dna_indexes *indexes_ptr;
      u_int32_t *rx_reg_ptr, *tx_reg_ptr, *mpc_reg_ptr, *qprdc_reg_ptr, 
	*rnbc_reg_ptr, *rqdpc_reg_ptr, *gorc_reg_ptr;
      dna_device_operation last_dna_operation;
    } dna;

    void       *priv_data; /* module private data */

    void      (*close)                        (pfring *);
    int	      (*stats)                        (pfring *, pfring_stat *);
    int       (*recv)                         (pfring *, u_char**, u_int, struct pfring_pkthdr *, u_int8_t);
    int       (*set_poll_watermark)           (pfring *, u_int16_t);
    int       (*set_poll_duration)            (pfring *, u_int);
    int       (*set_tx_watermark)             (pfring *, u_int16_t);
    int       (*set_channel_id)               (pfring *, u_int32_t);
    int       (*set_channel_mask)             (pfring *, u_int32_t);
    int       (*set_application_name)         (pfring *, char *);
    int       (*set_application_stats)        (pfring *, char *);
    char*     (*get_appl_stats_file_name)     (pfring *ring, char *path, u_int path_len);
    int       (*bind)                         (pfring *, char *);
    int       (*send)                         (pfring *, char *, u_int, u_int8_t);
    int       (*send_ifindex)                 (pfring *, char *, u_int, u_int8_t, int);
    int       (*send_parsed)                  (pfring *, char *, struct pfring_pkthdr *, u_int8_t);
    int       (*send_get_time)                (pfring *, char *, u_int, struct timespec *);
    u_int8_t  (*get_num_rx_channels)          (pfring *);
    int       (*set_sampling_rate)            (pfring *, u_int32_t);
    int       (*get_selectable_fd)            (pfring *);
    int       (*set_direction)                (pfring *, packet_direction);
    int       (*set_socket_mode)              (pfring *, socket_mode);
    int       (*set_cluster)                  (pfring *, u_int, cluster_type);
    int       (*remove_from_cluster)          (pfring *);
    int       (*set_master_id)                (pfring *, u_int32_t);
    int       (*set_master)                   (pfring *, pfring *);
    u_int16_t (*get_ring_id)                  (pfring *);
    u_int32_t (*get_num_queued_pkts)          (pfring *);
    u_int8_t  (*get_packet_consumer_mode)     (pfring *);
    int       (*set_packet_consumer_mode)     (pfring *, u_int8_t, char *, u_int);
    int       (*get_hash_filtering_rule_stats)(pfring *, hash_filtering_rule *, char *, u_int *);
    int       (*handle_hash_filtering_rule)   (pfring *, hash_filtering_rule *, u_char);
    int       (*purge_idle_hash_rules)        (pfring *, u_int16_t);
    int       (*add_filtering_rule)           (pfring *, filtering_rule *);
    int       (*remove_filtering_rule)        (pfring *, u_int16_t);
    int       (*purge_idle_rules)             (pfring *, u_int16_t);
    int       (*get_filtering_rule_stats)     (pfring *, u_int16_t, char *, u_int *);
    int       (*toggle_filtering_policy)      (pfring *, u_int8_t);
    int       (*enable_rss_rehash)            (pfring *);
    int       (*poll)                         (pfring *, u_int);
    int       (*is_pkt_available)             (pfring *);
    int       (*next_pkt_time)                (pfring *, struct timespec *);
    int       (*next_pkt_raw_timestamp)       (pfring *, u_int64_t *ts);
    int       (*version)                      (pfring *, u_int32_t *);
    int       (*get_bound_device_address)     (pfring *, u_char [6]);
    int       (*get_bound_device_ifindex)     (pfring *, int *);
    int       (*get_device_ifindex)           (pfring *, char *, int *);
    u_int16_t (*get_slot_header_len)          (pfring *);
    int       (*set_virtual_device)           (pfring *, virtual_filtering_device_info *);
    int       (*add_hw_rule)                  (pfring *, hw_filtering_rule *);
    int       (*remove_hw_rule)               (pfring *, u_int16_t);
    int       (*loopback_test)                (pfring *, char *, u_int, u_int);
    int       (*enable_ring)                  (pfring *);
    int       (*disable_ring)                 (pfring *);
    void      (*shutdown)                     (pfring *);
    int       (*set_bpf_filter)               (pfring *, char *);
    int       (*remove_bpf_filter)            (pfring *);
    int       (*get_device_clock)             (pfring *, struct timespec *);
    int       (*set_device_clock)             (pfring *, struct timespec *);
    int       (*adjust_device_clock)          (pfring *, struct timespec *, int8_t);
    void      (*sync_indexes_with_kernel)     (pfring *);
    int       (*send_last_rx_packet)          (pfring *, int);
    u_char*   (*get_pkt_buff_data)            (pfring *, pfring_pkt_buff *);
    int       (*set_pkt_buff_len)             (pfring *, pfring_pkt_buff *, u_int32_t);
    int       (*set_pkt_buff_ifindex)         (pfring *, pfring_pkt_buff *, int);
    int       (*add_pkt_buff_ifindex)         (pfring *, pfring_pkt_buff *, int);
    pfring_pkt_buff* (*alloc_pkt_buff)        (pfring *);
    void      (*release_pkt_buff)             (pfring *, pfring_pkt_buff *);
    int       (*recv_pkt_buff)                (pfring *, pfring_pkt_buff *, struct pfring_pkthdr *, u_int8_t);
    int       (*send_pkt_buff)                (pfring *, pfring_pkt_buff *, u_int8_t);
    void      (*flush_tx_packets)             (pfring *);
    int       (*register_zerocopy_tx_ring)    (pfring *, pfring *);

    /* DNA only */
    int      (*dna_init)             (pfring *);
    void     (*dna_term)             (pfring *);   
    int      (*dna_enable)           (pfring *);
    u_int8_t (*dna_check_packet_to_read) (pfring *, u_int8_t);
    u_char*  (*dna_next_packet)      (pfring *, u_char **, u_int, struct pfring_pkthdr *);

    u_int    (*dna_get_num_tx_slots)(pfring *ring);
    u_int    (*dna_get_num_rx_slots)(pfring *ring);
    u_int    (*dna_get_next_free_tx_slot)(pfring *ring);
    u_char*  (*dna_copy_tx_packet_into_slot)(pfring *ring, u_int32_t tx_slot_id, char *buffer, u_int len);
    u_int8_t (*dna_tx_ready)(pfring *);

    /* Silicom Redirector Only */
    struct {
      int8_t device_id, port_id;
    } rdi;

    filtering_mode ft_mode;
    pfring_device_type ft_device_type;
    void *qat; /* Intel QAT PM */

    /* All devices */
    char *buffer, *slots, *device_name;
    u_int32_t caplen;
    u_int16_t slot_header_len, mtu_len /* 0 = unknown */;
    u_int32_t sampling_rate;
    u_int8_t kernel_packet_consumer, is_shutting_down, socket_default_accept_policy;
    int fd;
    FlowSlotInfo *slots_info;
    u_int poll_sleep;
    u_int16_t poll_duration;
    u_int8_t promisc, clear_promisc, reentrant, break_recv_loop;
    u_long num_poll_calls;
    pthread_rwlock_t rx_lock, tx_lock;

    struct sockaddr_ll sock_tx;

    /* Reflector socket (copy RX packets onto it) */
    pfring *reflector_socket;

    /* Semi-DNA devices (1- copy) */
    pfring *one_copy_rx_pfring;
  };

  /* ********************************* */

  #define PF_RING_DNA_SYMMETRIC_RSS    1 << 0
  #define PF_RING_REENTRANT            1 << 1
  #define PF_RING_LONG_HEADER          1 << 2
  #define PF_RING_PROMISC              1 << 3
  #define PF_RING_TIMESTAMP            1 << 4
  #define PF_RING_HW_TIMESTAMP         1 << 5
  #define PF_RING_RX_PACKET_BOUNCE     1 << 6
  #define PF_RING_DNA_FIXED_RSS_Q_0    1 << 7
  #define PF_RING_STRIP_HW_TIMESTAMP   1 << 8
  #define PF_RING_DO_NOT_PARSE         1 << 9  /* parsing already disabled in zero-copy */
  #define PF_RING_DO_NOT_TIMESTAMP     1 << 10 /* sw timestamp already disabled in zero-copy */

  /* ********************************* */

  pfring* pfring_open(const char *device_name, u_int32_t caplen, u_int32_t flags);
  pfring* pfring_open_consumer(const char *device_name, u_int32_t caplen, u_int32_t flags,
			       u_int8_t consumer_plugin_id,
			       char* consumer_data, u_int consumer_data_len);
  u_int8_t pfring_open_multichannel(const char *device_name, u_int32_t caplen, 
				    u_int32_t flags, pfring* ring[MAX_NUM_RX_CHANNELS]);

  void pfring_shutdown(pfring *ring);
  void pfring_config(u_short cpu_percentage);
  int  pfring_loop(pfring *ring, pfringProcesssPacket looper, 
		   const u_char *user_bytes, u_int8_t wait_for_packet);
  void pfring_breakloop(pfring *);
  
  void pfring_close(pfring *ring);
  int pfring_stats(pfring *ring, pfring_stat *stats);
  int pfring_recv(pfring *ring, u_char** buffer, u_int buffer_len,
		  struct pfring_pkthdr *hdr, u_int8_t wait_for_incoming_packet);
  int pfring_recv_parsed(pfring *ring, u_char** buffer, u_int buffer_len,
		  struct pfring_pkthdr *hdr, u_int8_t wait_for_incoming_packet,
		  u_int8_t level /* 1..4 */, u_int8_t add_timestamp, u_int8_t add_hash);
  int pfring_set_poll_watermark(pfring *ring, u_int16_t watermark);
  int pfring_set_poll_duration(pfring *ring, u_int duration);
  int pfring_set_tx_watermark(pfring *ring, u_int16_t watermark);
  int pfring_add_hw_rule(pfring *ring, hw_filtering_rule *rule);
  int pfring_remove_hw_rule(pfring *ring, u_int16_t rule_id);
  int pfring_set_channel_id(pfring *ring, u_int32_t channel_id);
  int pfring_set_channel_mask(pfring *ring, u_int32_t channel_mask);
  int pfring_set_application_name(pfring *ring, char *name);
  int pfring_set_application_stats(pfring *ring, char *stats);
  char* pfring_get_appl_stats_file_name(pfring *ring, char *path, u_int path_len);
  int pfring_bind(pfring *ring, char *device_name);
  int pfring_send(pfring *ring, char *pkt, u_int pkt_len, u_int8_t flush_packet);
  int pfring_send_ifindex(pfring *ring, char *pkt, u_int pkt_len, u_int8_t flush_packet, int if_index);
  int pfring_send_parsed(pfring *ring, char *pkt, struct pfring_pkthdr *hdr, u_int8_t flush_packet);
  int pfring_send_get_time(pfring *ring, char *pkt, u_int pkt_len, struct timespec *ts);
  u_int8_t pfring_get_num_rx_channels(pfring *ring);
  int pfring_set_sampling_rate(pfring *ring, u_int32_t rate /* 1 = no sampling */);
  int pfring_get_selectable_fd(pfring *ring);
  int pfring_set_direction(pfring *ring, packet_direction direction);
  int pfring_set_socket_mode(pfring *ring, socket_mode mode);
  int pfring_set_cluster(pfring *ring, u_int clusterId, cluster_type the_type);
  int pfring_remove_from_cluster(pfring *ring);
  int pfring_set_master_id(pfring *ring, u_int32_t master_id);
  int pfring_set_master(pfring *ring, pfring *master);
  u_int16_t pfring_get_ring_id(pfring *ring);
  u_int32_t pfring_get_num_queued_pkts(pfring *ring);
  u_int8_t pfring_get_packet_consumer_mode(pfring *ring);
  int pfring_set_packet_consumer_mode(pfring *ring, u_int8_t plugin_id,
				      char *plugin_data, u_int plugin_data_len);
  int pfring_handle_hash_filtering_rule(pfring *ring,
					hash_filtering_rule* rule_to_add,
					u_char add_rule);
  int pfring_add_filtering_rule(pfring *ring, filtering_rule* rule_to_add);
  int pfring_remove_filtering_rule(pfring *ring, u_int16_t rule_id);
  int pfring_purge_idle_hash_rules(pfring *ring, u_int16_t inactivity_sec);
  int pfring_purge_idle_rules(pfring *ring, u_int16_t inactivity_sec);
  int pfring_get_hash_filtering_rule_stats(pfring *ring,
					   hash_filtering_rule* rule,
					   char* stats, u_int *stats_len);
  int pfring_get_filtering_rule_stats(pfring *ring, u_int16_t rule_id,
				      char* stats, u_int *stats_len);
  int pfring_toggle_filtering_policy(pfring *ring, u_int8_t rules_default_accept_policy);
  int pfring_enable_rss_rehash(pfring *ring);
  int pfring_poll(pfring *ring, u_int wait_duration);
  int pfring_is_pkt_available(pfring *ring);
  int pfring_next_pkt_time(pfring *ring, struct timespec *ts);
  int pfring_next_pkt_raw_timestamp(pfring *ring, u_int64_t *timestamp_ns);
  int pfring_version(pfring *ring, u_int32_t *version);
  int pfring_set_reflector_device(pfring *ring, char *device_name);
  int pfring_get_bound_device_address(pfring *ring, u_char mac_address[6]);
  u_int16_t pfring_get_slot_header_len(pfring *ring);
  int pfring_get_bound_device_ifindex(pfring *ring, int *if_index);
  int pfring_get_device_ifindex(pfring *ring, char *device_name, int *if_index);
  int pfring_set_virtual_device(pfring *ring, virtual_filtering_device_info *info);
  int pfring_loopback_test(pfring *ring, char *buffer, u_int buffer_len, u_int test_len);
  int pfring_enable_ring(pfring *ring);
  int pfring_disable_ring(pfring *ring);
  int pfring_set_bpf_filter(pfring *ring, char *filter_buffer);
  int pfring_remove_bpf_filter(pfring *ring);
  int pfring_set_filtering_mode(pfring *ring, filtering_mode mode);
  int pfring_get_device_clock(pfring *ring, struct timespec *ts);
  int pfring_set_device_clock(pfring *ring, struct timespec *ts);
  int pfring_adjust_device_clock(pfring *ring, struct timespec *offset, int8_t sign);
  void pfring_sync_indexes_with_kernel(pfring *ring);
  int pfring_send_last_rx_packet(pfring *ring, int tx_interface_id);
  int pfring_get_link_status(pfring *ring);

  u_int pfring_get_num_tx_slots(pfring* ring);
  u_int pfring_get_num_rx_slots(pfring* ring);
  int   pfring_copy_tx_packet_into_slot(pfring* ring, u_int16_t tx_slot_id, char* buffer, u_int len);

  u_char* pfring_get_pkt_buff_data(pfring *ring, pfring_pkt_buff *pkt_handle);
  int pfring_set_pkt_buff_len(pfring *ring, pfring_pkt_buff *pkt_handle, u_int32_t len);
  int pfring_set_pkt_buff_ifindex(pfring *ring, pfring_pkt_buff *pkt_handle, int if_index);
  int pfring_add_pkt_buff_ifindex(pfring *ring, pfring_pkt_buff *pkt_handle, int if_index);
  pfring_pkt_buff* pfring_alloc_pkt_buff(pfring *ring);
  void pfring_release_pkt_buff(pfring *ring, pfring_pkt_buff *pkt_handle);
  int pfring_recv_pkt_buff(pfring *ring, pfring_pkt_buff *pkt_handle, struct pfring_pkthdr *hdr, u_int8_t wait_for_incoming_packet); /* Note: this function fills the buffer pointed by pkt_handle */
  int pfring_send_pkt_buff(pfring *ring, pfring_pkt_buff *pkt_handle, u_int8_t flush_packet); /* Note: this function reset the buffer pointed by pkt_handle */
  int pfring_flush_tx_packets(pfring *ring);
  int pfring_search_payload(pfring *ring, char *string_to_search);
  int pfring_register_zerocopy_tx_ring(pfring *ring, pfring *tx_ring);

  /* PF_RING Socket bundle */
  void pfring_bundle_init(pfring_bundle *bundle, bundle_read_policy p);
  int pfring_bundle_add(pfring_bundle *bundle, pfring *ring);
  int pfring_bundle_poll(pfring_bundle *bundle, u_int wait_duration);
  int pfring_bundle_read(pfring_bundle *bundle, 
			 u_char** buffer, u_int buffer_len,
			 struct pfring_pkthdr *hdr,
			 u_int8_t wait_for_incoming_packet);
  void pfring_bundle_destroy(pfring_bundle *bundle);
  void pfring_bundle_close(pfring_bundle *bundle);  

  /* Utils (defined in pfring_utils.c) */
  int pfring_parse_pkt(u_char *pkt, struct pfring_pkthdr *hdr, u_int8_t level /* 2..4 */, 
		       u_int8_t add_timestamp /* 0,1 */, u_int8_t add_hash /* 0,1 */);
  int pfring_set_if_promisc(const char *device, int set_promisc);
  char* pfring_format_numbers(double val, char *buf, u_int buf_len, u_int8_t add_decimals);
  int pfring_enable_hw_timestamp(pfring* ring, char *device_name, u_int8_t enable_rx, u_int8_t enable_tx);
  int pfring_get_mtu_size(pfring* ring);
  int pfring_print_parsed_pkt(char *buff, u_int buff_len, const u_char *p, const struct pfring_pkthdr *h);
  int pfring_print_pkt(char *buff, u_int buff_len, const u_char *p, u_int len, u_int caplen);

  /* ********************************* */

  typedef struct {
    char   *name;
    int   (*open)  (pfring *);
  } pfring_module_info;

#ifdef HAVE_ZERO
#include "pfring_zero.h"
#endif

#ifdef  __cplusplus
}
#endif

#endif /* _PFRING_H_ */
