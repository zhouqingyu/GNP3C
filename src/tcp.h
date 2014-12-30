#ifndef _NIDS_TCP_H
#define _NIDS_TCP_H
#define WAIT_MEMORY_MAX 65053500

#include "nids.h"
struct skbuff {
  struct skbuff *next;
  struct skbuff *prev;

  void *data;
  u_int len;
  u_int truesize;
  u_int urg_ptr;
  
  char fin;
  char urg;
  u_int seq;
  u_int ack;
};

int tcp_init(int);
void process_tcp(u_char *, int);
void process_icmp(u_char *);
void clear_stream_buffers();
extern void
add_from_skb(struct tcp_stream * a_tcp, struct half_stream * rcv,
	     struct half_stream * snd,
	     u_char *data, u_int datalen,
	     u_int this_seq, char fin, char urg, u_int urg_ptr);
extern int tcp_stream_table_size;
extern struct tcp_stream **tcp_stream_table;

#endif /* _NIDS_TCP_H */
