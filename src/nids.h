/*
  Copyright (c) 1999 Rafal Wojtczuk <nergal@avet.com.pl>. All rights reserved.
  See the file COPYING for license details.
*/

#ifndef _NIDS_NIDS_H
#define _NIDS_NIDS_H
#define NIDS_MAJOR 1
#define NIDS_MINOR 20
#include <sys/types.h>
#include<unistd.h>
#include<sys/ipc.h>
#include<sys/sem.h>

#include "project.h"

#define DIRECTION_CLIENT_RECEIVE  1
#define DIRECTION_SERVER_RECEIVE  2
#define ERRBUF_SIZE 4096
 

enum
{
  NIDS_WARN_IP = 1,
  NIDS_WARN_TCP,
  NIDS_WARN_UDP,
  NIDS_WARN_SCAN
};

enum
{
  NIDS_WARN_UNDEFINED = 0,
  NIDS_WARN_IP_OVERSIZED,
  NIDS_WARN_IP_INVLIST,
  NIDS_WARN_IP_OVERLAP,
  NIDS_WARN_IP_HDR,
  NIDS_WARN_IP_SRR,
  NIDS_WARN_TCP_TOOMUCH,
  NIDS_WARN_TCP_HDR,
  NIDS_WARN_TCP_BIGQUEUE,
  NIDS_WARN_TCP_BADFLAGS
};

#define NIDS_JUST_EST 1
#define NIDS_DATA 2
#define NIDS_CLOSE 3
#define NIDS_RESET 4
#define NIDS_TIMED_OUT 5
#define NIDS_EXITING   6	/* nids is exiting; last chance to get data */

#define NIDS_DO_CHKSUM  0
#define NIDS_DONT_CHKSUM 1


#define MGT_DEAUTH			0x0C	/* de-authentication */


/*** Frame Control Types ***/

#define FC_TYPE_MGT			0x00	/* management type */
#define FC_TYPE_CTL			0x01	/* control type */
#define FC_TYPE_DATA		0x02	/* data type */
#define FC_TYPE_RESR		0x03	/* reserved for later use */


/* manefest constants to make Mac Headers more straitforward */
#define mh_fc			fc1.fc1_frame_control
#define mh_version		fc1.fc2.fc2_version
#define mh_type			fc1.fc2.fc2_type
#define mh_subtype		fc1.fc2.fc2_subtype
#define mh_to_ds		fc1.fc2.fc2_to_ds
#define mh_from_ds		fc1.fc2.fc2_from_ds
#define mh_more_frag	fc1.fc2.fc2_more_frag
#define mh_retry		fc1.fc2.fc2_retry
#define mh_pwr_man		fc1.fc2.fc2_pwr_man
#define mh_more_data	fc1.fc2.fc2_more_data
#define mh_wep			fc1.fc2.fc2_wep
#define mh_order		fc1.fc2.fc2_order
#define mh_aid			mh_duration_id
#define mh_ra			mh_mac1
#define mh_da			mh_mac1
#define mh_ps_bssid		mh_mac1
#define mh_cf_bssid		mh_mac2
#define mh_ta			mh_mac2
#define mh_sa			mh_mac2
#define mh_bssid		mh_mac3
#define mh_seq			seq1.seq1_seq
#define mh_frag_num		seq1.seq2.seq2_frag_num
#define mh_seq_num		seq1.seq2.seq2_seq_num





struct ieee80211_radiotap_header {
        u_int8_t        it_version;     /* set to 0 */
        u_int8_t        it_pad;
        u_int16_t       it_len;         /* entire length */
        u_int32_t       it_present;     /* fields present */
};

/* wireless frame types, mostly from tcpdump (wam) */
#define FC_TYPE(fc)             (((fc) >> 2) & 0x3)
#define FC_SUBTYPE(fc)          (((fc) >> 4) & 0xF)
#define DATA_FRAME_IS_QOS(x)    ((x) & 0x08)
#define FC_WEP(fc)              ((fc) & 0x4000)
#define FC_TO_DS(fc)            ((fc) & 0x0100)
#define FC_FROM_DS(fc)          ((fc) & 0x0200)
#define T_MGMT 0x0		/* management */
#define T_CTRL 0x1		/* control */
#define T_DATA 0x2		/* data */
#define T_RESV 0x3		/* reserved */
#define EXTRACT_LE_16BITS(p) \
	((unsigned short)*((const unsigned char *)(p) + 1) << 8 | \
	(unsigned short)*((const unsigned char *)(p) + 0))
#define EXTRACT_16BITS(p)	((unsigned short)ntohs(*(const unsigned short *)(p)))
#define LLC_FRAME_SIZE 8
#define LLC_OFFSET_TO_TYPE_FIELD 6
#define ETHERTYPE_IP 0x0800

struct mac80211{
   unsigned char des[6];
   unsigned char src[6];
   unsigned char ap[6];
};

struct half_stream{
  char state;
  char collect;
  char collect_urg;

  char *data;
  int offset;
  int count;
  int count_new;
  int bufsize;
  int rmem_alloc;

  int urg_count;
  u_int acked;
  u_int seq;
  u_int ack_seq;
  u_int first_data_seq;
  u_char urgdata;
  u_char count_new_urg;
  u_char urg_seen;
  u_int urg_ptr;
  u_short window;
  u_char ts_on;
  u_char wscale_on;
  u_int curr_ts; 
  u_int wscale;
  struct skbuff *list;
  struct skbuff *listtail;
};

struct tcp_stream{
  struct tuple4 addr;
  char nids_state;
  struct lurker_node *listeners;
  struct half_stream client;
  struct half_stream server;
  struct tcp_stream *next_node;
  struct tcp_stream *prev_node;
  int hash_index;
  struct tcp_stream *next_time;
  struct tcp_stream *prev_time;
  int read;
  struct tcp_stream *next_free;
  long  lasttime;
  int totallost;
};

struct nids_prm{
  int n_tcp_streams;
  int n_hosts;
  char *device;
  char *filename;
  int sk_buff_size;
  int dev_addon;
  void (*syslog) ();
  int syslog_level;
  int scan_num_hosts;
  int scan_delay;
  int scan_num_ports;
  void (*no_mem) (char *);
  int (*ip_filter) ();
  char *pcap_filter;
  int promisc;
  int one_loop_less;
  int pcap_timeout;
  int mytimecount;
};

int nids_init (void);
void nids_register_ip_frag (void (*));
void nids_register_ip (void (*));
void nids_register_tcp (void (*));
void nids_register_udp (void (*));
void nids_killtcp (struct tcp_stream *);
void nids_discard (struct tcp_stream *, int);
void nids_run (void);
int nids_getfd (void);
int nids_dispatch (int);
int nids_next (void);



union semun 
{
   int val;
   struct semid_ds *buf;
   unsigned short *array;
};

struct MInfo minfo,tminfo;

extern struct nids_prm nids_params;
extern char *nids_warnings[];
extern char nids_errbuf[];
extern struct pcap_pkthdr *nids_last_pcap_header;
//extern int packet_queue_head;
//extern pthread_mutex_t mutex_packet;

//extern pthread_mutex_t tcp_lost_mutex;

//extern struct Tcp_Data *tcp_data_table[];
//extern pthread_mutex_t mutex_tcp_data_table;// mutex lock for tcp_data_table

struct nids_chksum_ctl {
	u_int netaddr;
	u_int mask;
	u_int action;
	u_int reserved;
};
extern void nids_register_chksum_ctl(struct nids_chksum_ctl *, int);

struct MInfo
{
  unsigned char mbssid[1000][20];
  int mchannel[1000];
  unsigned char mstation[1000][20];
  int netcount;
  int stationcount;
};


#ifdef __linux__
extern int set_all_promisc();
#endif

#define int_ntoa(x)	inet_ntoa(*((struct in_addr *)&x))
extern int ip_options_compile(char *);
extern int raw_init();

#endif /* _NIDS_NIDS_H */
