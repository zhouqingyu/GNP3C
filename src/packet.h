#ifndef PACKET_H
#define PACKET_H

#include "project.h"

extern int packet_queue_head;
extern struct project_prm project_params;
extern struct Packet packets[];
extern pthread_mutex_t mutex_packet;
extern struct Configuration configuration;
extern void recv_packet_function();

#endif
