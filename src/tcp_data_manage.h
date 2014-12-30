#ifndef _TCP_DATA_MANAGE_H_

#define _TCP_DATA_MANAGE_H_

#include <pthread.h>
#include <time.h>
#include "list.h"
#include "nids.h"

#define TCP_STREAM_MAX 10000

struct Tcp_Data{
   int hash_index;
   char identify[200];
   struct tuple4 ip_and_port;
   time_t last_update_time;
   struct List *client_rev;
   struct List *server_rev;
   struct List *promisc;
   struct Tcp_Data *next;
   time_t access_time;
};

extern struct Tcp_Data *tcp_data_table[TCP_STREAM_MAX];
extern pthread_mutex_t mutex_tcp_data_table;// mutex lock for tcp_data_table

extern void tcp_data_manage_init();
#endif 